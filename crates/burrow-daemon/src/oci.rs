//! Turning an OCI image into a burrow template.
//!
//! This is how every template is made: burrow ships no image of its own, so a
//! node's templates are whatever OCI images have been pulled onto it.
//!
//! The conversion is filesystem-level, not runtime-level. An OCI image is an
//! ordered stack of tar layers plus a config; a burrow template is a single
//! ext4 image whose init is the burrow agent. So the layers are applied in
//! order to a staging directory, the agent and its mount points are added, and
//! the result is written out with `mkfs.ext4 -d`: no loop devices, no mounting,
//! no privileges beyond what the node already has.
//!
//! What is *not* carried over is how the image expects to be run as a
//! container. Entrypoint, user and signals belong to a container runtime, and
//! burrow runs a VM whose PID 1 is its own agent. The environment and working
//! directory are kept, because those are what a shell inside the sandbox would
//! otherwise get wrong.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tonic::Status;

use crate::blobs::{BlobStore, Digest};

/// Media types this understands, offered on every manifest request so a
/// registry can answer with whichever it has.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// Where a bare name like `alpine` is assumed to live.
const DEFAULT_REGISTRY: &str = "registry-1.docker.io";
/// Docker Hub keeps official images under `library/`.
const DEFAULT_NAMESPACE: &str = "library";

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    /// A tag, or a `sha256:…` digest.
    pub reference: String,
}

impl Reference {
    /// Parses `[registry/]repository[:tag|@digest]` the way a container
    /// runtime would.
    ///
    /// The registry is only recognised as such when the first segment looks
    /// like a host: it contains a dot or a colon, or is exactly `localhost`.
    /// Without that rule `alpine/git` would be read as the registry `alpine`.
    pub fn parse(text: &str) -> Result<Self, Status> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Status::invalid_argument("image reference is empty"));
        }

        let (head, reference) = match text.split_once('@') {
            Some((head, digest)) => {
                if !digest.starts_with("sha256:") || Digest::parse(&digest[7..]).is_none() {
                    return Err(Status::invalid_argument(format!(
                        "not a usable digest: {digest}"
                    )));
                }
                (head, digest.to_string())
            }
            None => {
                // A colon in the last path segment is a tag; one earlier is a
                // registry port.
                match text.rsplit_once(':') {
                    Some((head, tag)) if !tag.contains('/') => (head, tag.to_string()),
                    _ => (text, "latest".to_string()),
                }
            }
        };

        let (registry, repository) = match head.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            _ => (DEFAULT_REGISTRY.to_string(), head.to_string()),
        };

        // Only Docker Hub has the implicit `library/` namespace.
        let repository = if registry == DEFAULT_REGISTRY && !repository.contains('/') {
            format!("{DEFAULT_NAMESPACE}/{repository}")
        } else {
            repository
        };

        if repository.is_empty() {
            return Err(Status::invalid_argument(format!(
                "no repository in {text:?}"
            )));
        }
        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    /// Registries speak TLS unless explicitly excused.
    ///
    /// Self-hosted and development registries are routinely plain HTTP, so
    /// there has to be a way to reach them. Opt-in per host rather than a
    /// global switch: silently downgrading a pull would put image bytes and
    /// credentials on the network in the clear.
    fn scheme(&self, insecure: &[String]) -> &'static str {
        if insecure.iter().any(|host| host == &self.registry) {
            "http"
        } else {
            "https"
        }
    }

    fn manifest_url(&self, insecure: &[String]) -> String {
        format!(
            "{}://{}/v2/{}/manifests/{}",
            self.scheme(insecure),
            self.registry,
            self.repository,
            self.reference
        )
    }

    fn blob_url(&self, digest: &str, insecure: &[String]) -> String {
        format!(
            "{}://{}/v2/{}/blobs/{}",
            self.scheme(insecure),
            self.registry,
            self.repository,
            digest
        )
    }
}
//
// Only the fields burrow needs. Registries send a great deal more, and
// deserialising all of it would make this brittle against media types that
// grow fields.

#[derive(Debug, Deserialize)]
struct Index {
    manifests: Vec<IndexEntry>,
}

#[derive(Debug, Deserialize)]
struct IndexEntry {
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    size: u64,
}

#[derive(Debug, Deserialize)]
struct ImageConfigEnvelope {
    #[serde(default)]
    config: ImageConfigInner,
}

#[derive(Debug, Default, Deserialize)]
struct ImageConfigInner {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "WorkingDir", default)]
    working_dir: String,
}

/// What a sandbox needs to behave like the image it came from.
#[derive(Debug, Default, Clone, serde::Serialize, Deserialize)]
pub struct ImageEnvironment {
    /// `KEY=value`, as the image declared them.
    pub env: Vec<String>,
    pub working_dir: String,
}

impl ImageEnvironment {
    pub fn as_map(&self) -> HashMap<String, String> {
        self.env
            .iter()
            .filter_map(|entry| entry.split_once('='))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    /// Bundles the image points its own tooling at, which installing the
    /// inspection CA into the system store alone would miss.
    ///
    /// An image that ships a bundle and names it here never reads
    /// `/etc/ssl/certs`, so every inspected request from it fails verification
    /// against a CA that was installed correctly. `curlimages/curl` sets
    /// `CURL_CA_BUNDLE=/cacert.pem`.
    pub fn trust_bundles(&self) -> Vec<burrow_proto::agent::v1::TrustBundle> {
        let map = self.as_map();
        let mut bundles: Vec<burrow_proto::agent::v1::TrustBundle> = Vec::new();
        for (variable, create_if_missing) in TRUST_BUNDLE_VARIABLES {
            let Some(path) = map.get(variable) else {
                continue;
            };
            if !usable_bundle_path(path) {
                tracing::warn!(
                    variable,
                    path,
                    "ignoring a trust bundle an image named: not an absolute path free of .."
                );
                continue;
            }
            // Two variables commonly name the same file; appending twice is
            // harmless but the warning it would log is not.
            if bundles.iter().any(|bundle| bundle.path == *path) {
                continue;
            }
            bundles.push(burrow_proto::agent::v1::TrustBundle {
                path: path.clone(),
                create_if_missing,
            });
        }
        bundles
    }
}

/// The environment an imported image declared, if this template came from one.
///
/// Templates built the old way simply have none, and so does a template whose
/// record cannot be parsed: the environment is a convenience, and refusing to
/// start a sandbox over it would be worse than starting one without it.
pub async fn image_environment(data_dir: &Path, template: &str) -> ImageEnvironment {
    let path = data_dir.join("images").join(template).join("image.json");
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => ImageEnvironment::default(),
    }
}

/// Environment variables whose value names a trust bundle, and whether a file
/// that is not there yet may be created.
///
/// `NODE_EXTRA_CA_CERTS` differs in kind from the rest: it names a file of
/// *additional* CAs rather than a complete bundle, so a missing one means no
/// extra CAs yet and writing just the inspection CA is the whole answer.
const TRUST_BUNDLE_VARIABLES: [(&str, bool); 4] = [
    ("CURL_CA_BUNDLE", false),
    ("SSL_CERT_FILE", false),
    ("REQUESTS_CA_BUNDLE", false),
    ("NODE_EXTRA_CA_CERTS", true),
];

/// Whether a path an image declared may be written to.
///
/// The value is the image's, not the operator's, so it is held to the same
/// bar as any other untrusted path: absolute, and with no component that
/// walks back out of wherever it appears to lead.
pub fn usable_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && !path.contains('\0')
        && !std::path::Path::new(path)
            .components()
            .any(|component| component == std::path::Component::ParentDir)
}

/// Token services that legitimately live on a different host from the registry
/// they mint tokens for.
///
/// Docker Hub is the only one burrow ships with. Everything else has to name a
/// realm on its own host, because the realm is where the operator's registry
/// password is presented. See [`Registry::fetch_token`].
const KNOWN_TOKEN_SERVICES: &[(&str, &str)] = &[(DEFAULT_REGISTRY, "auth.docker.io")];

/// A registry client that carries its bearer token between requests.
struct Registry {
    http: reqwest::Client,
    token: Option<String>,
    /// The host being pulled from, as written in the reference.
    host: String,
    /// Credentials for the registry being pulled from, if any are configured.
    credential: Option<auth::Credential>,
    /// Hosts permitted to be plain HTTP.
    insecure: Vec<String>,
}

impl Registry {
    fn new(
        host: String,
        credential: Option<auth::Credential>,
        insecure: Vec<String>,
    ) -> Result<Self, Status> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("burrow/", env!("CARGO_PKG_VERSION")))
            // Layers are large and registries can be slow, but a stalled pull
            // must not hang a build forever. The read timeout is per chunk
            // rather than for the whole response, so a large layer arriving
            // steadily is fine and a registry that stops sending is not.
            .connect_timeout(std::time::Duration::from_secs(15))
            .read_timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|err| Status::internal(format!("http client: {err}")))?;
        Ok(Self {
            http,
            token: None,
            host,
            credential,
            insecure,
        })
    }

    /// Whether this registry was excused from TLS.
    fn is_insecure(&self) -> bool {
        self.insecure.iter().any(|host| host == &self.host)
    }

    /// Performs a GET, acquiring a token if the registry asks for one.
    ///
    /// Registries answer an unauthenticated request with a 401 naming the
    /// realm and scope to get a token from, even for public images, so this is
    /// the normal path rather than an error path.
    async fn get(&mut self, url: &str, accept: Option<&str>) -> Result<reqwest::Response, Status> {
        let response = self.send(url, accept).await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return check(response, url).await;
        }

        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| {
                Status::permission_denied(format!("{url} requires auth but did not say how"))
            })?;

        // Some registries skip the token dance entirely and want the
        // credential on the request itself.
        if challenge
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("basic")
        {
            let Some(credential) = self.credential.clone() else {
                return Err(Status::permission_denied(format!(
                    "{url} needs credentials; none configured for this registry"
                )));
            };
            // An identity token is redeemed at a token service, so there is
            // nothing to put in a Basic header. Said plainly rather than sent
            // as a password, which would only fail as a wrong one.
            if credential.is_identity_token() {
                return Err(Status::permission_denied(format!(
                    "{url} asked for basic auth, but the credential for {} is an identity token, \
                     which only a token service can redeem",
                    self.host
                )));
            }
            let retried = self
                .http
                .get(url)
                .header(reqwest::header::ACCEPT, accept.unwrap_or("*/*"))
                .basic_auth(&credential.username, Some(&credential.password))
                .send()
                .await
                .map_err(|err| Status::unavailable(format!("GET {url}: {err}")))?;
            return check(retried, url).await;
        }

        self.token = Some(self.fetch_token(&challenge).await?);

        let retried = self.send(url, accept).await?;
        check(retried, url).await
    }

    async fn send(&self, url: &str, accept: Option<&str>) -> Result<reqwest::Response, Status> {
        let mut request = self.http.get(url);
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("GET {url}: {err}")))
    }

    /// Exchanges a `Bearer realm=…,service=…,scope=…` challenge for a token.
    async fn fetch_token(&self, challenge: &str) -> Result<String, Status> {
        let params = parse_challenge(challenge);
        let realm = params.get("realm").ok_or_else(|| {
            Status::permission_denied(format!("auth challenge has no realm: {challenge}"))
        })?;
        // The realm is chosen by the registry and is where the operator's
        // password is sent, so one that could name any realm could harvest it.
        // The realm has to be the registry itself, or a token service burrow
        // already knows mints tokens for it, over TLS unless excused.
        check_realm(realm, &self.host, self.is_insecure())?;

        // An identity token is not a password: it is redeemed by POSTing a
        // refresh-token grant to the same realm, which is what a credential
        // helper answering `<token>` expects to happen with its secret.
        let identity = self
            .credential
            .as_ref()
            .filter(|credential| credential.is_identity_token());
        let mut request = if let Some(credential) = identity {
            let mut form = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", credential.password.as_str()),
                ("client_id", "burrow"),
            ];
            for key in ["service", "scope"] {
                if let Some(value) = params.get(key) {
                    form.push((key, value.as_str()));
                }
            }
            self.http.post(realm).form(&form)
        } else {
            let mut request = self.http.get(realm);
            for key in ["service", "scope"] {
                if let Some(value) = params.get(key) {
                    request = request.query(&[(key, value)]);
                }
            }
            request
        };
        // The token service is where credentials are presented: it mints a
        // bearer token whose scope reflects what this account may pull. Without
        // them the token comes back with public scope only, which is why a
        // private image 404s rather than 401s.
        if let Some(credential) = self.credential.as_ref().filter(|c| !c.is_identity_token()) {
            request = request.basic_auth(&credential.username, Some(&credential.password));
        }
        let response = request
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("token request: {err}")))?;
        let response = check(response, realm).await?;

        #[derive(Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            token: Option<String>,
            // Some registries name it this instead.
            #[serde(default)]
            access_token: Option<String>,
        }
        let body: TokenResponse = response
            .json()
            .await
            .map_err(|err| Status::internal(format!("token response: {err}")))?;
        body.token
            .or(body.access_token)
            .ok_or_else(|| Status::permission_denied("registry returned no token"))
    }
}

/// Refuses a token realm that is not the registry being pulled from.
fn check_realm(realm: &str, registry: &str, insecure: bool) -> Result<(), Status> {
    let url = reqwest::Url::parse(realm)
        .map_err(|err| Status::permission_denied(format!("auth realm {realm:?}: {err}")))?;
    if url.scheme() != "https" && !insecure {
        return Err(Status::permission_denied(format!(
            "auth realm {realm:?} is not https; refusing to send credentials in the clear"
        )));
    }
    let host = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => {
            return Err(Status::permission_denied(format!(
                "auth realm {realm:?} names no host"
            )));
        }
    };

    let permitted = host.eq_ignore_ascii_case(registry)
        || KNOWN_TOKEN_SERVICES.iter().any(|(reg, service)| {
            registry.eq_ignore_ascii_case(reg) && host.eq_ignore_ascii_case(service)
        });
    if !permitted {
        return Err(Status::permission_denied(format!(
            "{registry} pointed its auth realm at {host}; refusing to send credentials elsewhere"
        )));
    }
    Ok(())
}

/// Verifies raw bytes against a `sha256:…` digest before anything parses them.
///
/// Without this, pinning an image by digest buys nothing: the layers are
/// content-addressed and checked on arrival, but the manifest that names them
/// and the config that describes the image are taken on trust.
fn verify_digest(what: &str, bytes: &[u8], expected: &str) -> Result<(), Status> {
    use sha2::Digest as _;

    let Some(hex) = expected.strip_prefix("sha256:") else {
        return Err(Status::unimplemented(format!(
            "{what} is addressed by {expected}, which burrow cannot verify"
        )));
    };
    let actual: String = sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !actual.eq_ignore_ascii_case(hex) {
        return Err(Status::data_loss(format!(
            "{what} does not match its digest: asked for {expected}, received sha256:{actual}"
        )));
    }
    Ok(())
}

async fn check(response: reqwest::Response, url: &str) -> Result<reqwest::Response, Status> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    // The body usually names the actual problem ("manifest unknown"), which is
    // far more useful than the status alone. Only a registry's own error
    // document is quoted back, though: the caller chooses the registry, so
    // echoing arbitrary response bodies would turn a pull into a read oracle
    // for whatever the node can reach and the caller cannot. A body that is
    // not registry-shaped becomes the status alone.
    let body = response.text().await.unwrap_or_default();
    let detail = registry_error_detail(&body)
        .map(|detail| format!(": {detail}"))
        .unwrap_or_default();
    Err(match status {
        reqwest::StatusCode::NOT_FOUND => Status::not_found(format!("{url} not found{detail}")),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            Status::permission_denied(format!("{url} denied{detail}"))
        }
        other => Status::unavailable(format!("{url} returned {other}{detail}")),
    })
}

/// The `errors` array an OCI registry returns, rendered for a human.
///
/// Returns `None` for anything that is not that document, which is what keeps
/// the bytes of an unrelated HTTP server off the caller's error path. Only the
/// registry's own `code` and `message` fields travel, never the whole body,
/// and the result is capped so a hostile registry cannot use it as a channel
/// of its own.
fn registry_error_detail(body: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Errors {
        errors: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        #[serde(default)]
        code: String,
        #[serde(default)]
        message: String,
    }

    let parsed: Errors = serde_json::from_str(body).ok()?;
    let rendered = parsed
        .errors
        .iter()
        .map(|entry| match (entry.code.trim(), entry.message.trim()) {
            ("", message) => message.to_string(),
            (code, "") => code.to_string(),
            (code, message) => format!("{code}: {message}"),
        })
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    (!rendered.is_empty()).then(|| rendered.chars().take(200).collect())
}

/// Splits `Bearer realm="x",service="y"` into its parameters.
fn parse_challenge(challenge: &str) -> HashMap<String, String> {
    challenge
        .trim()
        .strip_prefix("Bearer ")
        .unwrap_or(challenge)
        .split(',')
        .filter_map(|part| part.split_once('='))
        .map(|(key, value)| {
            (
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            )
        })
        .collect()
}

/// The architecture this node can run guests for.
fn host_architecture() -> &'static str {
    // OCI's names, which differ from Rust's.
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// An image pulled and staged on this node.
pub struct PulledImage {
    /// Layer blobs in application order.
    pub layers: Vec<PathBuf>,
    pub environment: ImageEnvironment,
}

/// Fetches an image's layers and config, storing layers in the blob store.
///
/// Layers are content-addressed by the registry using the same sha256 the blob
/// store uses, so a layer shared between two images (a common base) is fetched
/// once and verified on arrival for free.
pub async fn pull(
    reference: &Reference,
    data_dir: &Path,
    credentials: &auth::Store,
    insecure: &[String],
    progress: &mut impl FnMut(String),
) -> Result<PulledImage, Status> {
    let credential = credentials.resolve(&reference.registry).await;
    if credential.is_some() {
        progress(format!("authenticating to {}", reference.registry));
    }
    let mut registry = Registry::new(reference.registry.clone(), credential, insecure.to_vec())?;
    let store = BlobStore::new(data_dir);

    progress(format!(
        "resolving {}/{}:{}",
        reference.registry, reference.repository, reference.reference
    ));
    let manifest = resolve_manifest(&mut registry, reference).await?;

    // The config is small and describes how the image expects to run.
    let config_bytes = registry
        .get(&reference.blob_url(&manifest.config.digest, insecure), None)
        .await?
        .bytes()
        .await
        .map_err(|err| Status::unavailable(format!("image config: {err}")))?;
    verify_digest("image config", &config_bytes, &manifest.config.digest)?;
    let envelope: ImageConfigEnvelope = serde_json::from_slice(&config_bytes)
        .map_err(|err| Status::internal(format!("image config: {err}")))?;

    let mut layers = Vec::new();
    for (index, layer) in manifest.layers.iter().enumerate() {
        if !is_supported_layer(&layer.media_type) {
            return Err(Status::unimplemented(format!(
                "layer {} uses {}, which burrow cannot unpack yet",
                index + 1,
                layer.media_type
            )));
        }
        let digest = layer_digest(&layer.digest)?;

        if store.has(&digest).await {
            progress(format!(
                "layer {}/{} already present",
                index + 1,
                manifest.layers.len()
            ));
        } else {
            progress(format!(
                "pulling layer {}/{} ({})",
                index + 1,
                manifest.layers.len(),
                human_size(layer.size)
            ));
            download(
                &mut registry,
                reference,
                &layer.digest,
                &store,
                &digest,
                layer.size,
            )
            .await?;
        }
        layers.push(store.path(&digest));
    }

    Ok(PulledImage {
        layers,
        environment: ImageEnvironment {
            env: envelope.config.env,
            working_dir: envelope.config.working_dir,
        },
    })
}

/// Follows an index to the manifest for this node's platform.
async fn resolve_manifest(
    registry: &mut Registry,
    reference: &Reference,
) -> Result<Manifest, Status> {
    let response = registry
        .get(
            &reference.manifest_url(&registry.insecure.clone()),
            Some(MANIFEST_ACCEPT),
        )
        .await?;
    // A reference that already names a digest is checked against it; a tag is
    // checked against whatever the registry claims it resolved to, which at
    // least ties the bytes to the name the registry itself used.
    let claimed = if reference.reference.starts_with("sha256:") {
        Some(reference.reference.clone())
    } else {
        response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    let body = response
        .bytes()
        .await
        .map_err(|err| Status::unavailable(format!("manifest: {err}")))?;
    if let Some(claimed) = &claimed {
        verify_digest("manifest", &body, claimed)?;
    }

    // A manifest and an index are told apart by shape rather than by the
    // content-type header, which registries are inconsistent about.
    if let Ok(manifest) = serde_json::from_slice::<Manifest>(&body) {
        return Ok(manifest);
    }
    let index: Index = serde_json::from_slice(&body)
        .map_err(|err| Status::internal(format!("manifest is neither image nor index: {err}")))?;

    let want = host_architecture();
    let entry = index
        .manifests
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|p| {
                p.os == "linux"
                    && p.architecture == want
                    // A variant, when present, must not contradict; `v8` and
                    // absent both mean the baseline arm64 this runs on.
                    && p.variant.as_deref().is_none_or(|v| v == "v8" || v.is_empty())
            })
        })
        .ok_or_else(|| {
            let available: Vec<String> = index
                .manifests
                .iter()
                .filter_map(|e| e.platform.as_ref())
                .map(|p| format!("{}/{}", p.os, p.architecture))
                .collect();
            Status::not_found(format!(
                "image has no linux/{want} manifest; it offers {}",
                available.join(", ")
            ))
        })?;

    let by_digest = Reference {
        reference: entry.digest.clone(),
        ..reference.clone()
    };
    let body = registry
        .get(
            &by_digest.manifest_url(&registry.insecure.clone()),
            Some(MANIFEST_ACCEPT),
        )
        .await?
        .bytes()
        .await
        .map_err(|err| Status::unavailable(format!("platform manifest: {err}")))?;
    // This one is addressed by digest, so there is no excuse for not checking:
    // the index just told us exactly what these bytes must hash to.
    verify_digest("platform manifest", &body, &entry.digest)?;
    serde_json::from_slice(&body)
        .map_err(|err| Status::internal(format!("platform manifest: {err}")))
}

fn is_supported_layer(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.docker.image.rootfs.diff.tar"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.zstd"
            // Some registries omit it; assume the common case rather than fail.
            | ""
    )
}

fn layer_digest(digest: &str) -> Result<Digest, Status> {
    digest
        .strip_prefix("sha256:")
        .and_then(Digest::parse)
        .ok_or_else(|| Status::unimplemented(format!("unsupported layer digest {digest}")))
}

/// Ceiling on a single layer's compressed body, for the case where the
/// manifest declares no size at all.
const MAX_LAYER_COMPRESSED: u64 = 8 * 1024 * 1024 * 1024;

/// Streams a blob into the store, verified against its digest as it arrives.
async fn download(
    registry: &mut Registry,
    reference: &Reference,
    raw_digest: &str,
    store: &BlobStore,
    digest: &Digest,
    declared_size: u64,
) -> Result<(), Status> {
    use futures::StreamExt;

    let insecure = registry.insecure.clone();
    let response = registry
        .get(&reference.blob_url(raw_digest, &insecure), None)
        .await?;
    let mut writer = store
        .receive(digest.clone())
        .await
        .map_err(|err| Status::internal(format!("staging layer: {err}")))?;

    // The manifest said how large this layer is. A registry that keeps sending
    // past that is either broken or trying to fill the node's disk, and either
    // way the digest at the end can no longer match, so stop now rather than
    // write terabytes to find that out.
    let limit = if declared_size == 0 {
        MAX_LAYER_COMPRESSED
    } else {
        declared_size.min(MAX_LAYER_COMPRESSED)
    };
    let mut received: u64 = 0;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| Status::unavailable(format!("layer body: {err}")))?;
        received += chunk.len() as u64;
        if received > limit {
            return Err(Status::out_of_range(format!(
                "layer {raw_digest} is larger than the {limit} bytes its manifest declared"
            )));
        }
        writer
            .write(&chunk)
            .await
            .map_err(|err| Status::internal(format!("writing layer: {err}")))?;
    }
    // The registry named this blob by its hash; if the bytes disagree, the
    // image is not the one that was asked for.
    writer
        .finish()
        .await
        .map_err(|err| Status::data_loss(format!("layer verification: {err}")))?;
    Ok(())
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.0}{}", UNITS[unit])
}

/// Marks a path as deleted by a later layer.
const WHITEOUT_PREFIX: &str = ".wh.";
/// Marks a directory's *existing* contents as deleted by a later layer.
const OPAQUE_MARKER: &str = ".wh..wh..opq";

/// Ceiling on what one layer may expand to.
///
/// A gzip layer of a few megabytes can decompress to terabytes of zeroes, and
/// the only thing standing between that and a full node disk is a budget on
/// the decompressed stream.
const MAX_LAYER_UNPACKED: u64 = 32 * 1024 * 1024 * 1024;
/// Ceiling on entries in one layer, so a layer of empty files is bounded too.
const MAX_LAYER_ENTRIES: usize = 1_000_000;

/// Applies layers in order into `dest`.
///
/// Whiteouts are the part that cannot be skipped: a layer deletes a file from
/// the layers below it by adding a `.wh.<name>` entry, and an image that
/// removes a setuid binary or a credential in a later layer would otherwise
/// have it silently restored.
pub fn unpack_layers(layers: &[PathBuf], dest: &Path) -> std::io::Result<()> {
    for layer in layers {
        unpack_layer(layer, dest)?;
    }
    Ok(())
}

/// How a layer's bytes are packed, decided by its magic number.
///
/// Sniffed rather than taken from the media type, which registries sometimes
/// omit and occasionally get wrong. The bytes cannot be wrong about themselves.
#[derive(Debug, PartialEq, Eq)]
enum Compression {
    None,
    Gzip,
    Zstd,
}

fn sniff(layer: &Path) -> std::io::Result<Compression> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let mut probe = std::fs::File::open(layer)?;
    if probe.read_exact(&mut magic).is_err() {
        return Ok(Compression::None);
    }
    Ok(match magic {
        [0x1f, 0x8b, ..] => Compression::Gzip,
        // zstd frame magic, little-endian 0xFD2FB528.
        [0x28, 0xb5, 0x2f, 0xfd] => Compression::Zstd,
        _ => Compression::None,
    })
}

fn unpack_layer(layer: &Path, dest: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(layer)?;
    match sniff(layer)? {
        Compression::Gzip => apply_entries(
            tar::Archive::new(Budgeted::new(flate2::read::GzDecoder::new(file))),
            dest,
        ),
        // A pure-Rust decoder, so the cross-compiled node build needs no C
        // toolchain for a format most registries do not use yet.
        Compression::Zstd => {
            let decoder = ruzstd::StreamingDecoder::new(file)
                .map_err(|err| std::io::Error::other(format!("zstd layer: {err}")))?;
            apply_entries(tar::Archive::new(Budgeted::new(decoder)), dest)
        }
        Compression::None => apply_entries(tar::Archive::new(Budgeted::new(file)), dest),
    }
}

/// A reader that refuses to produce more than [`MAX_LAYER_UNPACKED`] bytes.
///
/// The cap is on the *decompressed* stream, which is the only place it means
/// anything: the compressed body is bounded at download time and says nothing
/// about what it expands to.
struct Budgeted<R> {
    inner: R,
    remaining: u64,
}

impl<R: std::io::Read> Budgeted<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            remaining: MAX_LAYER_UNPACKED,
        }
    }
}

impl<R: std::io::Read> std::io::Read for Budgeted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other(format!(
                "layer expands past the {MAX_LAYER_UNPACKED} byte limit"
            )));
        }
        let cap = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let want = buf.len().min(cap);
        let read = self.inner.read(&mut buf[..want])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn apply_entries<R: std::io::Read>(
    mut archive: tar::Archive<R>,
    dest: &Path,
) -> std::io::Result<()> {
    let mut seen = 0usize;
    for entry in archive.entries()? {
        seen += 1;
        if seen > MAX_LAYER_ENTRIES {
            return Err(std::io::Error::other(format!(
                "layer has more than {MAX_LAYER_ENTRIES} entries"
            )));
        }
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if name == OPAQUE_MARKER {
            if let Some(parent) = path.parent() {
                clear_directory(&safe_dir(dest, parent)?)?;
            }
            continue;
        }
        if let Some(removed) = name.strip_prefix(WHITEOUT_PREFIX) {
            // A bare `.wh.` names nothing; deleting its parent because of it
            // would be an image's most convenient accident.
            if removed.is_empty() {
                continue;
            }
            let target = path.parent().unwrap_or(Path::new("")).join(removed);
            remove_any(&safe_join(dest, &target)?)?;
            continue;
        }

        // A layer may replace a path whose type changed, a directory becoming a
        // symlink say, which extraction alone will not do.
        let target = safe_join(dest, &path)?;
        if entry.header().entry_type() != tar::EntryType::Directory
            && std::fs::symlink_metadata(&target).is_ok()
        {
            remove_any(&target)?;
        }
        // `unpack_in` refuses paths that escape `dest`, which is what stops a
        // hostile image writing outside the staging directory.
        entry.unpack_in(dest)?;
    }
    Ok(())
}

/// Resolves a tar entry's path inside the staging directory, or refuses it.
///
/// Extraction goes through `unpack_in`, which is escape-safe; the deletion
/// paths are not, and they run as root. `dest.join(raw)` with an absolute `raw`
/// *discards* `dest`, so `/etc/.wh.passwd` becomes a request to unlink the
/// host's `/etc/passwd`; `..` walks out the same way; and a symlink planted by
/// an earlier entry (`x -> /etc`, then a whiteout of `x/passwd`) escapes
/// without either. So only plain components are accepted, and no intermediate
/// component may be a symlink.
fn safe_join(dest: &Path, raw: &Path) -> std::io::Result<PathBuf> {
    use std::path::Component;

    let mut resolved = dest.to_path_buf();
    let mut components = raw.components().peekable();
    while let Some(component) = components.next() {
        let name = match component {
            Component::Normal(name) => name,
            Component::CurDir => continue,
            // RootDir, ParentDir, Prefix. A real image has no use for any of
            // them, so this is a hostile layer, not a quirk to work around.
            _ => {
                return Err(std::io::Error::other(format!(
                    "layer entry {} escapes the staging directory",
                    raw.display()
                )));
            }
        };
        resolved.push(name);
        if components.peek().is_some()
            && std::fs::symlink_metadata(&resolved).is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(std::io::Error::other(format!(
                "layer entry {} resolves through a symlink",
                raw.display()
            )));
        }
    }
    Ok(resolved)
}

/// As [`safe_join`], for a path that is about to be *read* as a directory.
///
/// `safe_join` lets the last component be anything, because the deletion it
/// feeds never follows a symlink. `read_dir` does, so an opaque marker under a
/// symlinked directory would otherwise clear whatever it points at.
fn safe_dir(dest: &Path, raw: &Path) -> std::io::Result<PathBuf> {
    let resolved = safe_join(dest, raw)?;
    if resolved != dest
        && std::fs::symlink_metadata(&resolved).is_ok_and(|meta| meta.file_type().is_symlink())
    {
        return Err(std::io::Error::other(format!(
            "layer entry {} resolves through a symlink",
            raw.display()
        )));
    }
    Ok(resolved)
}

fn clear_directory(dir: &Path) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        remove_any(&entry.path())?;
    }
    Ok(())
}

fn remove_any(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registry_error_document_is_quoted_back() {
        let detail = registry_error_detail(
            r#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}"#,
        );
        assert_eq!(
            detail.as_deref(),
            Some("MANIFEST_UNKNOWN: manifest unknown")
        );
    }

    /// The caller picks the URL a pull dials, so a body echoed back verbatim
    /// would read out whatever the node can reach and the caller cannot.
    #[test]
    fn a_body_that_is_not_a_registry_error_is_not_echoed() {
        for body in [
            "<html><body>internal admin console</body></html>",
            r#"{"instance-id":"i-0123456789","iam":{"role":"admin"}}"#,
            "",
            "{}",
            r#"{"errors":[]}"#,
            r#"{"errors":[{"code":"","message":"  "}]}"#,
        ] {
            assert_eq!(registry_error_detail(body), None, "{body:?} was echoed");
        }
    }

    /// The registry controls this field, so it is capped.
    #[test]
    fn a_registry_error_is_capped() {
        let body = format!(r#"{{"errors":[{{"message":"{}"}}]}}"#, "x".repeat(5000));
        assert_eq!(registry_error_detail(&body).unwrap().chars().count(), 200);
    }

    #[test]
    fn a_bare_name_is_an_official_docker_hub_image() {
        let r = Reference::parse("alpine").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn a_tag_is_honoured() {
        let r = Reference::parse("python:3.12-slim").unwrap();
        assert_eq!(r.repository, "library/python");
        assert_eq!(r.reference, "3.12-slim");
    }

    /// `alpine/git` is a Docker Hub org, not a registry called `alpine`: the
    /// first segment only names a host when it looks like one.
    #[test]
    fn a_namespaced_name_is_not_mistaken_for_a_registry() {
        let r = Reference::parse("alpine/git:v2").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "alpine/git");
        assert_eq!(r.reference, "v2");
    }

    #[test]
    fn an_explicit_registry_is_used_verbatim() {
        let r = Reference::parse("ghcr.io/astral-sh/uv:latest").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "astral-sh/uv");
        // No implicit `library/` outside Docker Hub.
        assert!(!r.repository.starts_with("library/"));
    }

    #[test]
    fn a_registry_with_a_port_is_recognised() {
        let r = Reference::parse("localhost:5000/mine:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "mine");
        assert_eq!(r.reference, "dev");
    }

    #[test]
    fn a_digest_reference_is_kept_whole() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let r = Reference::parse(&format!("alpine@{digest}")).unwrap();
        assert_eq!(r.reference, digest);
    }

    #[test]
    fn a_malformed_digest_is_refused_rather_than_requested() {
        assert!(Reference::parse("alpine@sha256:nothex").is_err());
        assert!(Reference::parse("alpine@md5:abc").is_err());
        assert!(Reference::parse("").is_err());
    }

    #[test]
    fn an_auth_challenge_is_split_into_its_parameters() {
        let params = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        );
        assert_eq!(params["realm"], "https://auth.docker.io/token");
        assert_eq!(params["service"], "registry.docker.io");
        assert_eq!(params["scope"], "repository:library/alpine:pull");
    }

    #[test]
    fn image_env_becomes_a_map() {
        let env = ImageEnvironment {
            env: vec![
                "PATH=/usr/bin".into(),
                "LANG=C.UTF-8".into(),
                "BROKEN".into(),
            ],
            working_dir: "/app".into(),
        };
        let map = env.as_map();
        assert_eq!(map["PATH"], "/usr/bin");
        assert_eq!(map["LANG"], "C.UTF-8");
        assert!(
            !map.contains_key("BROKEN"),
            "an entry with no = is not a variable"
        );
    }

    #[test]
    fn an_image_naming_its_own_bundle_gets_it_installed_into() {
        let env = ImageEnvironment {
            env: vec![
                "CURL_CA_BUNDLE=/cacert.pem".into(),
                "NODE_EXTRA_CA_CERTS=/opt/node/extra.pem".into(),
            ],
            working_dir: String::new(),
        };
        let bundles = env.trust_bundles();
        assert_eq!(bundles.len(), 2);
        assert_eq!(bundles[0].path, "/cacert.pem");
        assert!(
            !bundles[0].create_if_missing,
            "a full bundle that is absent is not invented"
        );
        assert_eq!(bundles[1].path, "/opt/node/extra.pem");
        assert!(
            bundles[1].create_if_missing,
            "no extra ca file yet simply means no extra cas yet"
        );
    }

    #[test]
    fn an_image_naming_nothing_changes_nothing() {
        let env = ImageEnvironment {
            env: vec!["PATH=/usr/bin".into()],
            working_dir: String::new(),
        };
        assert!(env.trust_bundles().is_empty());
    }

    #[test]
    fn a_bundle_path_an_image_chose_is_held_to_the_untrusted_path_rules() {
        assert!(usable_bundle_path("/cacert.pem"));
        assert!(!usable_bundle_path(""));
        assert!(!usable_bundle_path("cacert.pem"));
        assert!(!usable_bundle_path("../../etc/shadow"));
        assert!(!usable_bundle_path(
            "/etc/ssl/../../root/.ssh/authorized_keys"
        ));
        assert!(!usable_bundle_path("/etc/ssl/\0certs"));

        let env = ImageEnvironment {
            env: vec![
                "SSL_CERT_FILE=certs/ca.pem".into(),
                "REQUESTS_CA_BUNDLE=/etc/../root/ca.pem".into(),
            ],
            working_dir: String::new(),
        };
        assert!(env.trust_bundles().is_empty());
    }

    #[test]
    fn two_variables_naming_one_file_produce_one_bundle() {
        let env = ImageEnvironment {
            env: vec![
                "CURL_CA_BUNDLE=/cacert.pem".into(),
                "SSL_CERT_FILE=/cacert.pem".into(),
            ],
            working_dir: String::new(),
        };
        assert_eq!(env.trust_bundles().len(), 1);
    }

    /// A later layer deleting a file must actually delete it. Getting this
    /// wrong silently restores things an image removed on purpose.
    #[test]
    fn a_whiteout_deletes_a_file_from_a_lower_layer() {
        let dir = scratch("whiteout");
        let lower = build_tar(&[("secret.txt", b"leaked".as_slice())]);
        let upper = build_tar(&[(".wh.secret.txt", b"".as_slice())]);

        unpack_layers(&[lower, upper], &dir).unwrap();
        assert!(!dir.join("secret.txt").exists(), "whiteout did not delete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_opaque_marker_clears_the_directory_beneath_it() {
        let dir = scratch("opaque");
        let lower = build_tar(&[
            ("etc/a.conf", b"a".as_slice()),
            ("etc/b.conf", b"b".as_slice()),
        ]);
        let upper = build_tar(&[
            ("etc/.wh..wh..opq", b"".as_slice()),
            ("etc/c.conf", b"c".as_slice()),
        ]);

        unpack_layers(&[lower, upper], &dir).unwrap();
        assert!(!dir.join("etc/a.conf").exists());
        assert!(!dir.join("etc/b.conf").exists());
        assert!(
            dir.join("etc/c.conf").exists(),
            "the new entry must survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_later_layer_replaces_a_file() {
        let dir = scratch("replace");
        let lower = build_tar(&[("app/version", b"1".as_slice())]);
        let upper = build_tar(&[("app/version", b"2".as_slice())]);
        unpack_layers(&[lower, upper], &dir).unwrap();
        assert_eq!(std::fs::read(dir.join("app/version")).unwrap(), b"2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hostile layer must not be able to write outside the staging tree.
    ///
    /// The header is written by hand because the `tar` crate refuses to *build*
    /// an archive containing `..`, and a test that cannot express the attack
    /// proves nothing.
    #[test]
    fn a_layer_cannot_escape_the_staging_directory() {
        let dir = scratch("escape");
        let outside = dir.parent().unwrap().join("escaped-marker");
        let _ = std::fs::remove_file(&outside);

        for name in ["../escaped-marker", "/tmp/escaped-marker"] {
            let layer = raw_tar(name, b"pwned");
            // Refused outright or contained; both are fine. Escaping is not.
            let _ = unpack_layers(&[layer], &dir);
        }

        assert!(!outside.exists(), "a layer escaped via ..");
        assert!(
            !std::path::Path::new("/tmp/escaped-marker").exists(),
            "a layer escaped via an absolute path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whiteouts and opaque markers do not go through `unpack_in`, so they need
    /// their own containment. They also run as root, which makes an escape here
    /// an arbitrary unlink on the host.
    #[test]
    fn a_whiteout_cannot_delete_outside_the_staging_directory() {
        let dir = scratch("whiteout-escape");
        let victim = dir.parent().unwrap().join("burrow-victim.txt");
        std::fs::write(&victim, b"do not delete me").unwrap();

        for name in [
            // Absolute: `dest.join("/…")` would discard dest entirely.
            "/burrow-victim.txt/.wh.x",
            &format!(
                "{}/.wh.burrow-victim.txt",
                victim.parent().unwrap().display()
            ),
            // Traversal.
            "../.wh.burrow-victim.txt",
            "a/../../.wh.burrow-victim.txt",
        ] {
            let layer = raw_tar(name, b"");
            let _ = unpack_layers(&[layer], &dir);
            assert!(
                victim.exists(),
                "{name} deleted a file outside the staging tree"
            );
        }

        // An opaque marker at the filesystem root would clear `/`.
        let layer = raw_tar("/.wh..wh..opq", b"");
        let _ = unpack_layers(&[layer], &dir);
        assert!(victim.exists(), "an absolute opaque marker escaped");

        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A layer can plant a symlink and then whiteout a path "inside" it; the
    /// deletion must not follow the link out of the staging tree.
    #[test]
    fn a_whiteout_does_not_follow_a_symlinked_parent() {
        let dir = scratch("whiteout-symlink");
        let outside = dir.parent().unwrap().join("burrow-symlink-victim");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("passwd"), b"root:x:0:0").unwrap();

        // Layer one plants `escape -> <outside>`; layer two whites out
        // `escape/passwd`, which naively resolves to the host's file.
        std::os::unix::fs::symlink(&outside, dir.join("escape")).unwrap();
        let layer = raw_tar("escape/.wh.passwd", b"");
        let _ = unpack_layers(&[layer], &dir);

        assert!(
            outside.join("passwd").exists(),
            "a whiteout deleted through a symlinked parent"
        );
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_realm_must_belong_to_the_registry_it_mints_tokens_for() {
        // The host's own token endpoint, and the one service burrow knows
        // legitimately differs.
        assert!(check_realm("https://ghcr.io/token", "ghcr.io", false).is_ok());
        assert!(check_realm("https://auth.docker.io/token", DEFAULT_REGISTRY, false).is_ok());

        // Somewhere else entirely: this is where the password would go.
        assert!(check_realm("https://evil.example/token", "ghcr.io", false).is_err());
        // auth.docker.io is only excused for the hub.
        assert!(check_realm("https://auth.docker.io/token", "ghcr.io", false).is_err());
        // Plain HTTP, for a registry that was not excused.
        assert!(check_realm("http://ghcr.io/token", "ghcr.io", false).is_err());
        assert!(check_realm("http://ghcr.io/token", "ghcr.io", true).is_ok());
        assert!(check_realm("not a url", "ghcr.io", false).is_err());
    }

    #[test]
    fn bytes_are_checked_against_the_digest_that_named_them() {
        // sha256("abc")
        let expected = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_digest("manifest", b"abc", expected).is_ok());
        assert!(verify_digest("manifest", b"abd", expected).is_err());
        assert!(verify_digest("manifest", b"abc", "md5:whatever").is_err());
    }

    /// A small layer that decompresses to a great deal must not be allowed to
    /// fill the node's disk.
    #[test]
    fn an_oversized_layer_is_refused_rather_than_written() {
        use std::io::Read as _;

        let mut reader = Budgeted {
            inner: std::io::repeat(0),
            remaining: 8,
        };
        let mut sink = [0u8; 16];
        assert_eq!(reader.read(&mut sink).unwrap(), 8);
        assert!(
            reader.read(&mut sink).is_err(),
            "the budget was not enforced"
        );
    }

    #[test]
    fn gzipped_and_plain_layers_are_both_handled() {
        let dir = scratch("gzip");
        let plain = build_tar(&[("plain.txt", b"p".as_slice())]);
        let zipped = gzip_of(&plain);
        unpack_layers(&[plain, zipped], &dir).unwrap();
        assert!(dir.join("plain.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_layer_types_are_accepted_and_others_named() {
        for good in [
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "",
        ] {
            assert!(is_supported_layer(good), "{good} should be supported");
        }
        assert!(!is_supported_layer(
            "application/vnd.oci.image.layer.v1.tar+brotli"
        ));
    }

    /// The media type is advisory; the bytes are not.
    #[test]
    fn compression_is_sniffed_from_the_bytes() {
        let dir = scratch("sniff");
        let plain = build_tar(&[("a.txt", b"a".as_slice())]);
        assert_eq!(sniff(&plain).unwrap(), Compression::None);
        assert_eq!(sniff(&gzip_of(&plain)).unwrap(), Compression::Gzip);

        let zstd = dir.join("layer.tar.zst");
        std::fs::write(&zstd, [0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]).unwrap();
        assert_eq!(sniff(&zstd).unwrap(), Compression::Zstd);

        // Too short to have a magic number is simply uncompressed.
        let tiny = dir.join("tiny");
        std::fs::write(&tiny, b"ab").unwrap();
        assert_eq!(sniff(&tiny).unwrap(), Compression::None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_zstd_layer_unpacks() {
        let dir = scratch("zstd");
        let plain = build_tar(&[("zstd-file.txt", b"from a zstd layer".as_slice())]);
        let compressed = zstd_of(&plain, &dir.join("layer.tar.zst"));

        unpack_layers(&[compressed], &dir).unwrap();
        assert_eq!(
            std::fs::read(dir.join("zstd-file.txt")).unwrap(),
            b"from a zstd layer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    pub(super) fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow-oci-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_tar(entries: &[(&str, &[u8])]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "burrow-layer-{}-{}.tar",
            std::process::id(),
            entries.len() * 31 + entries.first().map_or(0, |e| e.0.len())
        ));
        let file = std::fs::File::create(&path).unwrap();
        let mut builder = tar::Builder::new(file);
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *body).unwrap();
        }
        builder.finish().unwrap();
        path
    }

    /// A one-entry tar written byte by byte, so the name can be anything,
    /// including the traversal a tar writer would refuse to produce.
    fn raw_tar(name: &str, body: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "burrow-raw-{}-{}.tar",
            std::process::id(),
            name.len()
        ));
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"000644 \0"); // mode
        header[108..116].copy_from_slice(b"000000 \0"); // uid
        header[116..124].copy_from_slice(b"000000 \0"); // gid
        let size = format!("{:011o} ", body.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[136..148].copy_from_slice(b"00000000000 "); // mtime
        header[156] = b'0'; // regular file
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // The checksum is computed with its own field read as spaces.
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());

        let mut archive = header.to_vec();
        archive.extend_from_slice(body);
        archive.resize(archive.len().div_ceil(512) * 512, 0);
        // Two zero blocks end the archive.
        archive.extend_from_slice(&[0u8; 1024]);
        std::fs::write(&path, archive).unwrap();
        path
    }

    /// Compresses with a hand-built zstd frame containing one raw block, which
    /// is enough to exercise the decoder without a compressor dependency.
    fn zstd_of(source: &Path, out: &Path) -> PathBuf {
        let data = std::fs::read(source).unwrap();
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd];
        // Frame header descriptor: content-size flag 0b10 (4-byte size),
        // single-segment, no dictionary, no checksum. The flag and the number
        // of bytes written after it have to agree, or the decoder reads the
        // block header from the wrong offset.
        frame.push(0b1010_0000);
        frame.extend_from_slice(&(data.len() as u32).to_le_bytes());
        // One raw block, marked as the last.
        let header = (data.len() as u32) << 3 | 0b001;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(&data);
        std::fs::write(out, frame).unwrap();
        out.to_path_buf()
    }

    fn gzip_of(source: &Path) -> PathBuf {
        use std::io::Write;
        let out = source.with_extension("tar.gz");
        let mut encoder = flate2::write::GzEncoder::new(
            std::fs::File::create(&out).unwrap(),
            flate2::Compression::fast(),
        );
        encoder.write_all(&std::fs::read(source).unwrap()).unwrap();
        encoder.finish().unwrap();
        out
    }
}

/// Credentials for registries that need them.
///
/// The file is Docker's `config.json` shape, so an existing
/// `~/.docker/config.json` works unchanged.
///
/// That shape includes credential helpers, which is how most real configs store
/// a secret: `credsStore` names one helper for everything, `credHelpers` names
/// one per registry, and the secret lives in a keychain rather than in the
/// file. Reading only the inline `auths` would leave those registries pulling
/// anonymously.
pub mod auth {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::Duration;

    use base64::Engine as _;
    use serde::Deserialize;

    /// Docker's marker in the `Username` field for "the secret is an identity
    /// token, not a password". See [`Credential::is_identity_token`].
    const IDENTITY_TOKEN_USER: &str = "<token>";

    /// How long a helper has to answer.
    ///
    /// A helper talks to a local keychain or a metadata endpoint, so seconds is
    /// generous. The ceiling matters more than the value: a helper waiting on a
    /// locked keyring would otherwise wedge every pull behind it.
    const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
    /// Ceiling on what is read back from a helper. The answer is one small JSON
    /// object; whatever a helper is producing past this, it is not that.
    const MAX_HELPER_OUTPUT: u64 = 64 * 1024;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Credential {
        pub username: String,
        pub password: String,
    }

    impl Credential {
        /// Whether the secret is an OAuth2 identity token rather than a
        /// password.
        ///
        /// Helpers for registries that mint refresh tokens (ECR's public
        /// endpoint, ACR, and docker's own desktop store after a `docker login`
        /// with SSO) answer with the literal `<token>` as the username. The two
        /// are not interchangeable: an identity token is presented to the token
        /// service as a refresh-token grant, not as a basic-auth password.
        pub fn is_identity_token(&self) -> bool {
            self.username == IDENTITY_TOKEN_USER
        }
    }

    #[derive(Debug, Default, Deserialize)]
    struct DockerConfig {
        #[serde(default)]
        auths: HashMap<String, AuthEntry>,
        /// One helper for every registry that has no more specific one.
        #[serde(rename = "credsStore", default)]
        creds_store: Option<String>,
        /// Helper per registry, which beats `credsStore`.
        #[serde(rename = "credHelpers", default)]
        cred_helpers: HashMap<String, String>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct AuthEntry {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        /// base64 of `username:password`, which is how docker stores it.
        #[serde(default)]
        auth: Option<String>,
    }

    /// A helper to ask for one registry's credentials.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Helper {
        /// The bare name, without the `docker-credential-` prefix.
        name: String,
        /// The server url to hand it, spelled as the config spelled it.
        ///
        /// Helpers key their store by this exact string, so a per-registry
        /// helper is asked with the key it was configured under rather than
        /// with burrow's normalised host.
        server: Option<String>,
    }

    /// Credentials per registry host, and the helpers to ask for the rest.
    #[derive(Debug, Default, Clone)]
    pub struct Store {
        by_registry: HashMap<String, Credential>,
        /// Keyed by normalised host, from `credHelpers`.
        helpers: HashMap<String, Helper>,
        /// `credsStore`: the helper for every registry without its own.
        default_helper: Option<String>,
    }

    impl Store {
        /// Reads a docker-style config. A missing file is not an error:
        /// anonymous pulls are the common case.
        pub async fn load(path: &Path) -> Self {
            let Ok(text) = tokio::fs::read_to_string(path).await else {
                return Self::default();
            };
            match Self::parse(&text) {
                Ok(store) => {
                    tracing::info!(
                        path = %path.display(),
                        registries = store.by_registry.len(),
                        helpers = store.helpers.len() + usize::from(store.default_helper.is_some()),
                        "loaded registry credentials"
                    );
                    store
                }
                Err(err) => {
                    // Loud: a caller who wrote a credentials file expects it to
                    // be used, and silently pulling anonymously would look like
                    // an unrelated permissions failure later.
                    tracing::error!(path = %path.display(), %err, "ignoring unreadable registry credentials");
                    Self::default()
                }
            }
        }

        pub fn parse(text: &str) -> Result<Self, String> {
            let config: DockerConfig = serde_json::from_str(text).map_err(|err| err.to_string())?;
            let mut by_registry = HashMap::new();

            for (host, entry) in config.auths {
                let credential = match (&entry.username, &entry.password, &entry.auth) {
                    (Some(username), Some(password), _) => Credential {
                        username: username.clone(),
                        password: password.clone(),
                    },
                    (_, _, Some(encoded)) => {
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(encoded.trim())
                            .map_err(|err| format!("auth for {host}: {err}"))?;
                        let decoded = String::from_utf8(decoded)
                            .map_err(|err| format!("auth for {host}: {err}"))?;
                        let (username, password) = decoded
                            .split_once(':')
                            .ok_or_else(|| format!("auth for {host} is not user:password"))?;
                        Credential {
                            username: username.to_string(),
                            password: password.to_string(),
                        }
                    }
                    // An entry with no usable credential is skipped rather than
                    // rejected: docker writes bare entries for credential
                    // helpers it manages elsewhere.
                    _ => continue,
                };
                by_registry.insert(normalise(&host), credential);
            }

            // A helper name is checked here rather than at use, so a typo is
            // reported once at load instead of once per pull. An unusable name
            // drops the entry: the registry falls back to whatever the file
            // holds inline, or to anonymous.
            let mut helpers = HashMap::new();
            for (host, name) in config.cred_helpers {
                if let Err(err) = validate_helper_name(&name) {
                    tracing::warn!(registry = %host, helper = %name, %err, "ignoring credential helper");
                    continue;
                }
                helpers.insert(
                    normalise(&host),
                    Helper {
                        name,
                        server: Some(host),
                    },
                );
            }
            let default_helper =
                config
                    .creds_store
                    .filter(|name| match validate_helper_name(name) {
                        Ok(()) => true,
                        Err(err) => {
                            tracing::warn!(helper = %name, %err, "ignoring credsStore");
                            false
                        }
                    });

            Ok(Self {
                by_registry,
                helpers,
                default_helper,
            })
        }

        /// The credential to pull `registry` with, asking a helper if one is
        /// configured for it.
        ///
        /// Precedence follows docker: `credHelpers[registry]` beats
        /// `credsStore`, which beats an inline `auths` entry.
        ///
        /// A helper that fails, times out or answers with something
        /// unrecognisable is a warning and nothing more: the pull falls through
        /// to an inline entry, or to an anonymous pull, because a broken
        /// keychain must not turn a public image into an outage.
        pub async fn resolve(&self, registry: &str) -> Option<Credential> {
            let key = normalise(registry);
            if let Some(helper) = self.helper_for(&key) {
                let server = helper
                    .server
                    .clone()
                    .unwrap_or_else(|| helper_server(registry));
                match ask_helper(&helper.name, &server).await {
                    Ok(Some(credential)) => return Some(credential),
                    Ok(None) => tracing::info!(
                        registry,
                        helper = %helper.name,
                        "credential helper holds nothing for this registry"
                    ),
                    Err(err) => tracing::warn!(
                        registry,
                        helper = %helper.name,
                        %err,
                        "credential helper failed; continuing without it"
                    ),
                }
            }
            self.by_registry.get(&key).cloned()
        }

        /// The helper for an already-normalised host, per-registry first.
        fn helper_for(&self, key: &str) -> Option<Helper> {
            self.helpers.get(key).cloned().or_else(|| {
                self.default_helper.as_ref().map(|name| Helper {
                    name: name.clone(),
                    server: None,
                })
            })
        }

        /// The inline `auths` entry alone, without consulting a helper.
        #[cfg(test)]
        pub fn for_registry(&self, registry: &str) -> Option<&Credential> {
            self.by_registry.get(&normalise(registry))
        }

        #[cfg(test)]
        pub fn is_empty(&self) -> bool {
            self.by_registry.is_empty() && self.helpers.is_empty() && self.default_helper.is_none()
        }
    }

    /// The server url a helper is asked about, when the config did not spell
    /// one itself.
    ///
    /// Docker Hub is the exception every helper store shares: `docker login`
    /// files it under its v1 url, so asking for the host burrow actually dials
    /// would find nothing.
    fn helper_server(registry: &str) -> String {
        if normalise(registry) == super::DEFAULT_REGISTRY {
            "https://index.docker.io/v1/".to_string()
        } else {
            registry.to_string()
        }
    }

    /// Checks a helper name before it becomes part of a program to execute.
    ///
    /// The name comes from an operator's config file rather than from a caller,
    /// but it is still a string that turns into a binary run as root on the
    /// node, so it is held to the narrow shape docker's own names have. The
    /// character set is the check: it admits no separator, no `.` and therefore
    /// no `..`, so the name cannot escape into a path at all.
    fn validate_helper_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("helper name is empty".to_string());
        }
        if name.len() > 64 {
            return Err("helper name is longer than 64 characters".to_string());
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "helper name {name:?} is not [A-Za-z0-9_-]+; a helper is named, not a path"
            ));
        }
        Ok(())
    }

    /// Finds `docker-credential-<name>` on a search path.
    ///
    /// Resolved here rather than left to `execvp` so the config can only ever
    /// select between binaries an operator already put on the node's PATH. An
    /// empty PATH entry means the working directory to a shell; it is skipped,
    /// because whatever the daemon's working directory happens to be is not a
    /// place to find a binary to run as root.
    fn find_helper(name: &str, path: &str) -> Option<PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;

        let program = format!("docker-credential-{name}");
        path.split(':')
            .filter(|dir| !dir.is_empty())
            .map(|dir| Path::new(dir).join(&program))
            .find(|candidate| {
                std::fs::metadata(candidate)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
    }

    /// Runs a helper and reads back what it holds for `server`.
    ///
    /// The protocol is docker's: `docker-credential-<name> get`, the server url
    /// on stdin, a JSON object on stdout. argv and stdin throughout, with no
    /// shell involved, so neither the server url nor the helper's answer is
    /// ever parsed as a command.
    async fn ask_helper(name: &str, server: &str) -> Result<Option<Credential>, String> {
        validate_helper_name(name)?;
        let path = std::env::var("PATH").unwrap_or_default();
        let program = find_helper(name, &path)
            .ok_or_else(|| format!("docker-credential-{name} is not on PATH"))?;
        let output = run_helper(&program, server).await?;
        parse_helper_output(&output)
    }

    async fn run_helper(program: &Path, server: &str) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut child = tokio::process::Command::new(program)
            .arg("get")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // A helper's diagnostics are its own business, and they are one
            // careless line away from carrying the secret.
            .stderr(Stdio::null())
            // A helper that outruns the timeout has nothing left to say, and a
            // finished pull must not leave one behind.
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| format!("running {}: {err}", program.display()))?;

        let exchange = async {
            let mut stdin = child.stdin.take().ok_or("helper stdin was not piped")?;
            // Inside the timeout: a helper that never reads its stdin would
            // otherwise block the write rather than the wait.
            stdin
                .write_all(server.as_bytes())
                .await
                .map_err(|err| format!("writing to the helper: {err}"))?;
            // EOF is how the helper knows the url ended.
            drop(stdin);

            let stdout = child.stdout.take().ok_or("helper stdout was not piped")?;
            let mut output = Vec::new();
            stdout
                .take(MAX_HELPER_OUTPUT)
                .read_to_end(&mut output)
                .await
                .map_err(|err| format!("reading from the helper: {err}"))?;
            let status = child
                .wait()
                .await
                .map_err(|err| format!("waiting for the helper: {err}"))?;
            Ok::<_, String>((status, output))
        };

        let (status, output) = tokio::time::timeout(HELPER_TIMEOUT, exchange)
            .await
            .map_err(|_| {
                format!(
                    "{} did not answer within {}s",
                    program.display(),
                    HELPER_TIMEOUT.as_secs()
                )
            })??;

        if !status.success() {
            // A helper with nothing stored for the registry says so by exiting
            // non-zero with "credentials not found" on stderr, which is the
            // same shape as a helper that is simply broken. Both mean the same
            // thing here: pull without it.
            return Err(format!("{} exited with {status}", program.display()));
        }
        Ok(output)
    }

    /// Reads a helper's `{"ServerURL":..,"Username":..,"Secret":..}`.
    ///
    /// Fields are pulled out of a parsed value rather than deserialised into a
    /// struct on purpose: serde's type errors quote the offending value, and
    /// the offending value here could be the secret. A field of the wrong type
    /// is therefore treated as absent, which lands on the same anonymous
    /// fallback as a helper that holds nothing.
    fn parse_helper_output(bytes: &[u8]) -> Result<Option<Credential>, String> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|err| format!("helper output is not JSON: {err}"))?;
        if !value.is_object() {
            return Err("helper output is not a JSON object".to_string());
        }
        let field = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (username, secret) = (field("Username"), field("Secret"));
        if username.is_empty() || secret.is_empty() {
            // How a helper reports "nothing stored here" without failing.
            return Ok(None);
        }
        Ok(Some(Credential {
            username,
            password: secret,
        }))
    }

    /// Reduces the many spellings of a registry to one key.
    ///
    /// Docker writes Hub as a full v1 URL, and people write it as `docker.io`;
    /// all of them mean the host burrow actually dials.
    fn normalise(host: &str) -> String {
        let host = host
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let host = host.split('/').next().unwrap_or(host);
        match host {
            "index.docker.io" | "docker.io" | "registry.docker.io" => {
                super::DEFAULT_REGISTRY.to_string()
            }
            other => other.to_ascii_lowercase(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn explicit_username_and_password_are_read() {
            let store =
                Store::parse(r#"{"auths":{"ghcr.io":{"username":"me","password":"secret"}}}"#)
                    .unwrap();
            let c = store.for_registry("ghcr.io").unwrap();
            assert_eq!(c.username, "me");
            assert_eq!(c.password, "secret");
        }

        #[test]
        fn dockers_base64_auth_field_is_decoded() {
            // base64("me:secret")
            let store = Store::parse(r#"{"auths":{"ghcr.io":{"auth":"bWU6c2VjcmV0"}}}"#).unwrap();
            let c = store.for_registry("ghcr.io").unwrap();
            assert_eq!(c.username, "me");
            assert_eq!(c.password, "secret");
        }

        /// A password may itself contain a colon; only the first splits.
        #[test]
        fn a_password_containing_a_colon_survives() {
            let encoded = base64::engine::general_purpose::STANDARD.encode("me:a:b:c");
            let store =
                Store::parse(&format!(r#"{{"auths":{{"r.io":{{"auth":"{encoded}"}}}}}}"#)).unwrap();
            assert_eq!(store.for_registry("r.io").unwrap().password, "a:b:c");
        }

        /// Docker Hub is spelled several ways; all of them mean the host
        /// burrow dials.
        #[test]
        fn docker_hub_spellings_all_resolve() {
            for spelling in [
                "https://index.docker.io/v1/",
                "index.docker.io",
                "docker.io",
                "registry-1.docker.io",
            ] {
                let store = Store::parse(&format!(
                    r#"{{"auths":{{"{spelling}":{{"auth":"bWU6cw=="}}}}}}"#
                ))
                .unwrap();
                assert!(
                    store.for_registry(super::super::DEFAULT_REGISTRY).is_some(),
                    "{spelling} should map to the hub"
                );
            }
        }

        #[test]
        fn entries_without_credentials_are_skipped_not_rejected() {
            let store = Store::parse(r#"{"auths":{"helper.io":{},"ghcr.io":{"auth":"bWU6cw=="}}}"#)
                .unwrap();
            assert!(store.for_registry("helper.io").is_none());
            assert!(store.for_registry("ghcr.io").is_some());
        }

        #[test]
        fn an_unknown_registry_has_no_credential() {
            let store = Store::parse(r#"{"auths":{"ghcr.io":{"auth":"bWU6cw=="}}}"#).unwrap();
            assert!(store.for_registry("quay.io").is_none());
        }

        #[test]
        fn malformed_config_is_an_error_rather_than_silently_empty() {
            assert!(Store::parse("not json").is_err());
            assert!(Store::parse(r#"{"auths":{"r.io":{"auth":"!!!not base64"}}}"#).is_err());
        }

        #[test]
        fn an_absent_auths_block_is_simply_empty() {
            assert!(Store::parse("{}").unwrap().is_empty());
        }

        /// The name becomes a binary run as root, so anything that could reach
        /// outside a plain PATH lookup is refused.
        #[test]
        fn only_a_plain_helper_name_is_accepted() {
            for good in [
                "osxkeychain",
                "ecr-login",
                "secretservice",
                "gcloud",
                "Desktop_1",
            ] {
                assert!(
                    validate_helper_name(good).is_ok(),
                    "{good} should be a name"
                );
            }
            for bad in [
                "",
                "../../bin/sh",
                "/usr/bin/sh",
                "..",
                ".",
                "foo/bar",
                "foo\\bar",
                "foo bar",
                "foo;id",
                "foo$(id)",
                "helper\n",
                "héro",
                &"a".repeat(65),
            ] {
                assert!(
                    validate_helper_name(bad).is_err(),
                    "{bad:?} should be refused"
                );
            }
        }

        /// PATH lookup must not admit the working directory, which an empty
        /// entry means to a shell.
        #[test]
        fn a_helper_is_found_only_in_a_named_directory() {
            let dir = super::super::tests::scratch("helper-path");
            let program = dir.join("docker-credential-findme");
            write_script(&program, "#!/bin/sh\nexit 0\n");
            // Present but not executable: not a helper.
            std::fs::write(dir.join("docker-credential-inert"), "x").unwrap();

            let path = format!("{}:/nonexistent", dir.display());
            assert_eq!(find_helper("findme", &path), Some(program));
            assert!(find_helper("inert", &path).is_none());
            assert!(find_helper("findme", "/nonexistent").is_none());
            assert!(find_helper("findme", "::").is_none(), "empty PATH entries");
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn a_helpers_answer_is_read() {
            let credential = parse_helper_output(
                br#"{"ServerURL":"ghcr.io","Username":"me","Secret":"s3cret"}"#,
            )
            .unwrap()
            .unwrap();
            assert_eq!(credential.username, "me");
            assert_eq!(credential.password, "s3cret");
            assert!(!credential.is_identity_token());
        }

        /// `<token>` means the secret is redeemed at the token service rather
        /// than sent as a password.
        #[test]
        fn an_identity_token_is_recognised_as_one() {
            let credential =
                parse_helper_output(br#"{"Username":"<token>","Secret":"refresh-me"}"#)
                    .unwrap()
                    .unwrap();
            assert!(credential.is_identity_token());
            assert_eq!(credential.password, "refresh-me");
        }

        /// Nothing a helper can answer with may fail a pull that would have
        /// worked anonymously: either it is a credential or it is not.
        #[test]
        fn a_malformed_answer_yields_no_credential_rather_than_a_guess() {
            // Not JSON at all, and JSON that is not an object.
            assert!(parse_helper_output(b"credentials not found").is_err());
            assert!(parse_helper_output(b"").is_err());
            assert!(parse_helper_output(br#"["me","secret"]"#).is_err());
            assert!(parse_helper_output(br#"{"Username":"me","Secret":"#).is_err());

            // Well-formed, but holding nothing: docker's own "no credentials
            // for this server" answer.
            assert_eq!(parse_helper_output(br#"{}"#).unwrap(), None);
            assert_eq!(
                parse_helper_output(br#"{"ServerURL":"ghcr.io","Username":"","Secret":""}"#)
                    .unwrap(),
                None
            );
            // A field of the wrong type is treated as absent rather than
            // quoted back in an error, since the value could be the secret.
            assert_eq!(
                parse_helper_output(br#"{"Username":"me","Secret":12345}"#).unwrap(),
                None
            );
            // Lowercase keys are another tool's protocol, not this one.
            assert_eq!(
                parse_helper_output(br#"{"username":"me","secret":"s"}"#).unwrap(),
                None
            );
        }

        /// docker resolves `credHelpers[registry]` first, then `credsStore`,
        /// then the inline `auths` entry.
        #[test]
        fn a_per_registry_helper_beats_the_global_one_which_beats_an_inline_entry() {
            let store = Store::parse(
                r#"{
                    "auths": {
                        "ghcr.io": {"auth": "bWU6cw=="},
                        "quay.io": {"auth": "bWU6cw=="}
                    },
                    "credsStore": "everything",
                    "credHelpers": {"ghcr.io": "ghcr-only"}
                }"#,
            )
            .unwrap();

            assert_eq!(
                store.helper_for("ghcr.io").unwrap().name,
                "ghcr-only",
                "a per-registry helper must win"
            );
            assert_eq!(
                store.helper_for("quay.io").unwrap().name,
                "everything",
                "credsStore covers registries without their own helper"
            );
            // An inline entry is still there, and is what a failing helper
            // falls back to rather than the pull failing.
            assert!(store.for_registry("ghcr.io").is_some());

            // With no helpers at all, the inline entry is simply used.
            let inline = Store::parse(r#"{"auths":{"ghcr.io":{"auth":"bWU6cw=="}}}"#).unwrap();
            assert!(inline.helper_for("ghcr.io").is_none());
        }

        /// A per-registry helper is asked with the key it was configured
        /// under, because that is how its store is keyed.
        #[test]
        fn a_helper_is_asked_about_the_server_the_config_named() {
            let store = Store::parse(
                r#"{"credHelpers":{"https://index.docker.io/v1/":"desktop"},"credsStore":"osxkeychain"}"#,
            )
            .unwrap();
            let hub = store
                .helper_for(&normalise("registry-1.docker.io"))
                .unwrap();
            assert_eq!(hub.name, "desktop");
            assert_eq!(hub.server.as_deref(), Some("https://index.docker.io/v1/"));

            // Falling back to credsStore, burrow supplies the url itself, and
            // the hub is the spelling every helper store files it under.
            assert_eq!(
                helper_server("registry-1.docker.io"),
                "https://index.docker.io/v1/"
            );
            assert_eq!(helper_server("ghcr.io"), "ghcr.io");
            assert_eq!(helper_server("localhost:5000"), "localhost:5000");
        }

        /// An unusable name never reaches a spawn.
        #[test]
        fn a_helper_named_as_a_path_is_dropped_at_load() {
            let store = Store::parse(
                r#"{"credsStore":"../../bin/sh","credHelpers":{"ghcr.io":"/usr/bin/env"}}"#,
            )
            .unwrap();
            assert!(store.helper_for("ghcr.io").is_none());
        }

        /// The whole protocol, against a real helper process.
        #[tokio::test]
        async fn a_helper_process_is_asked_on_stdin_and_read_on_stdout() {
            let dir = super::super::tests::scratch("helper-run");
            let program = dir.join("docker-credential-echo");
            // Echoes the server url back, so the test also proves the url
            // reached the helper on stdin rather than as an argument.
            write_script(
                &program,
                "#!/bin/sh\nread -r server\nprintf '{\"ServerURL\":\"%s\",\"Username\":\"me\",\"Secret\":\"s3cret\"}' \"$server\"\n",
            );

            let credential = run_helper(&program, "test-registry:5000")
                .await
                .map(|output| parse_helper_output(&output).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(credential.username, "me");
            assert_eq!(credential.password, "s3cret");

            let output = run_helper(&program, "test-registry:5000").await.unwrap();
            assert!(
                String::from_utf8_lossy(&output).contains("test-registry:5000"),
                "the server url did not reach the helper's stdin"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A helper that fails, hangs or floods is a warning, never a pull
        /// that breaks.
        #[tokio::test]
        async fn a_helper_that_misbehaves_is_refused_rather_than_waited_on() {
            let dir = super::super::tests::scratch("helper-bad");

            let failing = dir.join("docker-credential-failing");
            write_script(
                &failing,
                "#!/bin/sh\necho 'credentials not found' >&2\nexit 1\n",
            );
            assert!(run_helper(&failing, "ghcr.io").await.is_err());

            let hanging = dir.join("docker-credential-hanging");
            write_script(&hanging, "#!/bin/sh\nsleep 120\n");
            let started = std::time::Instant::now();
            assert!(
                run_helper(&hanging, "ghcr.io").await.is_err(),
                "a hung helper must not be waited on forever"
            );
            assert!(
                started.elapsed() < HELPER_TIMEOUT * 3,
                "the timeout did not fire"
            );

            // Output is capped, so a helper that never stops writing cannot
            // grow the daemon's memory.
            let flooding = dir.join("docker-credential-flooding");
            write_script(&flooding, "#!/bin/sh\nyes aaaaaaaaaaaaaaaaaaaaaaaa\n");
            if let Ok(output) = run_helper(&flooding, "ghcr.io").await {
                assert!(output.len() as u64 <= MAX_HELPER_OUTPUT);
            }

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A helper that is not installed leaves the pull where it was.
        #[tokio::test]
        async fn a_missing_helper_is_an_error_and_not_a_panic() {
            let err = ask_helper("burrow-no-such-helper", "ghcr.io")
                .await
                .unwrap_err();
            assert!(err.contains("not on PATH"), "{err}");
            // And a name that never should have been spawned is refused before
            // PATH is even consulted.
            assert!(ask_helper("../../bin/sh", "ghcr.io").await.is_err());
        }

        fn write_script(path: &Path, body: &str) {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::write(path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
