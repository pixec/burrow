//! The fleet's object store, spoken to as S3 through the AWS SDK.
//!
//! Whole objects only: put, get, head, delete and a prefix listing. The SDK is
//! built on the node's own TLS stack, rustls on ring, so the musl cross build
//! stays free of a second one. Credentials come from the environment,
//! `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, the way every S3 tool
//! reads them; the endpoint is always addressed path-style, which every
//! self-hosted store supports and which a bucket name with a dot needs.
//!
//! Every request is retried on throttling (S3's `503 SlowDown`) and on
//! transient failures, with exponential backoff and jitter. Standard mode
//! rather than adaptive: adaptive's rate limiter, measuring a node that has
//! sent little, held a cold upload to a request every several seconds after
//! one throttle. The bounds on chunk uploads keep the pressure down instead.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::retry::{RetryConfig, RetryPartition, TokenBucket};
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::create_bucket::CreateBucketError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{BucketLocationConstraint, CreateBucketConfiguration};
use aws_smithy_http_client::tls;
use tonic::Status;

#[derive(Clone)]
pub struct ObjectStore {
    client: Client,
    endpoint: String,
    bucket: String,
    /// Key prefix inside the bucket, empty or ending in `/`.
    prefix: String,
    /// Chunk puts in flight on this node, across every upload.
    uploads: Arc<tokio::sync::Semaphore>,
    /// Chunk puts one upload keeps in flight.
    upload_parallelism: usize,
    /// The first wait before an upload that failed whole is tried again.
    requeue_after: Duration,
}

/// Where the store is, from the flags: `s3://bucket/prefix` and an endpoint,
/// and how hard to push it.
pub struct Options {
    pub url: String,
    pub endpoint: String,
    pub region: String,
    /// Tries per request before it fails.
    pub attempts: u32,
    /// Chunk puts in flight on this node.
    pub uploads: usize,
    /// Chunk puts in flight per upload, which is per sandbox.
    pub uploads_per_sandbox: usize,
}

/// The SDK's backoff between tries: full jitter over a cap that starts here
/// and doubles up to [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(20);

/// Between tries of an upload that failed whole, doubling up to the cap.
const REQUEUE_AFTER: Duration = Duration::from_secs(30);
const MAX_REQUEUE_AFTER: Duration = Duration::from_secs(600);

impl ObjectStore {
    pub fn open(options: &Options) -> anyhow::Result<Self> {
        let rest = options
            .url
            .strip_prefix("s3://")
            .ok_or_else(|| anyhow::anyhow!("--object-store must be s3://bucket[/prefix]"))?;
        let (bucket, prefix) = match rest.split_once('/') {
            Some((bucket, prefix)) => (bucket, prefix.trim_matches('/')),
            None => (rest, ""),
        };
        if bucket.is_empty() {
            anyhow::bail!("--object-store names no bucket");
        }
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
        if access_key.is_empty() || secret_key.is_empty() {
            anyhow::bail!("--object-store needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
        }
        Ok(Self::with_credentials(
            options,
            bucket,
            prefix,
            Credentials::new(access_key, secret_key, None, None, "burrow-flags"),
        ))
    }

    fn with_credentials(
        options: &Options,
        bucket: &str,
        prefix: &str,
        credentials: Credentials,
    ) -> Self {
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(options.region.clone()))
            .endpoint_url(options.endpoint.trim_end_matches('/'))
            .credentials_provider(credentials)
            .force_path_style(true)
            // No trailing checksum on puts: a memory image is streamed with a
            // known length, and the self-hosted stores this targets either
            // ignore the trailer or pay for parsing it.
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .http_client(http)
            .retry_config(
                RetryConfig::standard()
                    .with_max_attempts(options.attempts.max(1))
                    .with_initial_backoff(INITIAL_BACKOFF)
                    .with_max_backoff(MAX_BACKOFF),
            )
            // Without a retry quota: the default one runs dry in a burst of
            // throttled chunk puts, which is when retries are needed most.
            // Attempts and the upload bounds limit them instead.
            .retry_partition(
                RetryPartition::custom(format!("burrow {}", options.endpoint))
                    .token_bucket(TokenBucket::unlimited())
                    .build(),
            )
            .sleep_impl(aws_sdk_s3::config::SharedAsyncSleep::new(
                aws_smithy_async::rt::sleep::TokioSleep::new(),
            ))
            .build();
        Self {
            client: Client::from_conf(config),
            endpoint: options.endpoint.trim_end_matches('/').to_string(),
            bucket: bucket.to_string(),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
            uploads: Arc::new(tokio::sync::Semaphore::new(options.uploads.max(1))),
            upload_parallelism: options.uploads_per_sandbox.max(1),
            requeue_after: REQUEUE_AFTER,
        }
    }

    /// Chunk puts one upload keeps in flight.
    pub fn upload_parallelism(&self) -> usize {
        self.upload_parallelism
    }

    /// How long to wait before the `attempt`th retry of an upload that failed
    /// whole: doubling from the first, capped, with jitter.
    pub fn requeue_delay(&self, attempt: u32) -> Duration {
        let cap = self
            .requeue_after
            .saturating_mul(1 << attempt.saturating_sub(1).min(16))
            .min(MAX_REQUEUE_AFTER.max(self.requeue_after));
        let jitter = (uuid::Uuid::new_v4().as_u128() % 1000) as f64 / 2000.0;
        cap.mul_f64(0.5 + jitter)
    }

    /// Puts a chunk, holding one of the node's upload slots while it is sent
    /// and retried.
    pub async fn put_chunk(&self, key: &str, bytes: Vec<u8>) -> Result<(), Status> {
        let _slot = self
            .uploads
            .acquire()
            .await
            .expect("the upload semaphore is never closed");
        self.put_bytes(key, bytes).await
    }

    /// Creates the bucket if the store does not have it. Self-hosted stores
    /// start empty, and a node that can create its own tables should not
    /// need an operator to make its bucket by hand. A bucket that is already
    /// there is only looked at, so a pre-created one needs no
    /// `s3:CreateBucket`.
    pub async fn ensure_bucket(&self) -> Result<(), Status> {
        match self.client.head_bucket().bucket(&self.bucket).send().await {
            Ok(_) => return Ok(()),
            Err(SdkError::ServiceError(err)) if err.err().is_not_found() => {}
            Err(err) => return Err(unavailable("head bucket", &self.bucket, err)),
        }
        // S3 refuses a create without the bucket's region everywhere but
        // us-east-1, where it refuses one with it.
        let region = self.client.config().region().map(Region::as_ref);
        let configuration = region
            .filter(|region| !region.is_empty() && *region != "us-east-1")
            .map(|region| {
                CreateBucketConfiguration::builder()
                    .location_constraint(BucketLocationConstraint::from(region))
                    .build()
            });
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .set_create_bucket_configuration(configuration)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError(err))
                if matches!(
                    err.err(),
                    CreateBucketError::BucketAlreadyOwnedByYou(_)
                        | CreateBucketError::BucketAlreadyExists(_)
                ) =>
            {
                Ok(())
            }
            Err(err) => Err(unavailable("create bucket", &self.bucket, err)),
        }
    }

    pub fn describe(&self) -> String {
        format!("s3://{}/{} at {}", self.bucket, self.prefix, self.endpoint)
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    pub async fn put_file(&self, key: &str, path: &Path) -> Result<(), Status> {
        let body = ByteStream::from_path(path).await.map_err(|err| {
            Status::internal(format!("opening {} to upload: {err}", path.display()))
        })?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .body(body)
            .send()
            .await
            .map(drop)
            .map_err(|err| unavailable("put", key, err))
    }

    pub async fn put_bytes(&self, key: &str, bytes: Vec<u8>) -> Result<(), Status> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map(drop)
            .map_err(|err| unavailable("put", key, err))
    }

    /// Writes an object only if the store holds the version `expect` names,
    /// `None` meaning no object at all. `Ok(None)` when it holds another; the
    /// new version's ETag otherwise.
    ///
    /// The check and the write are one request, so of two writers that read
    /// the same version only one lands. A store that ignores the headers
    /// would land both, which [`Self::probe_conditional_writes`] catches.
    pub async fn put_bytes_if(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expect: Option<&str>,
    ) -> Result<Option<String>, Status> {
        let put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .body(ByteStream::from(bytes));
        let put = match expect {
            Some(etag) => put.if_match(etag),
            None => put.if_none_match("*"),
        };
        match put.send().await {
            Ok(out) => out
                .e_tag()
                .map(|etag| Some(etag.to_string()))
                .ok_or_else(|| Status::unavailable(format!("object store put {key}: no ETag"))),
            // 412 is the precondition failing, 404 an `If-Match` on an object
            // that is gone, and 409 S3 refusing one of two conditional writes
            // racing each other: all mean another version is there.
            Err(SdkError::ServiceError(err))
                if matches!(err.raw().status().as_u16(), 404 | 409 | 412) =>
            {
                Ok(None)
            }
            Err(err) => Err(unavailable("put", key, err)),
        }
    }

    /// Whether the store refuses a conditional write it should. Some
    /// self-hosted ones ignore `If-Match` and `If-None-Match` and write
    /// anyway, which would turn every lease built on them into a race.
    pub async fn probe_conditional_writes(&self) -> Result<bool, Status> {
        let key = format!("probes/conditional-{}", uuid::Uuid::new_v4().simple());
        self.delete(&key).await?;
        let created = self.put_bytes_if(&key, b"1".to_vec(), None).await?;
        let recreated = self.put_bytes_if(&key, b"2".to_vec(), None).await?;
        let mismatched = self
            .put_bytes_if(&key, b"3".to_vec(), Some("\"burrow-probe\""))
            .await?;
        self.delete(&key).await?;
        Ok(created.is_some() && recreated.is_none() && mismatched.is_none())
    }

    async fn get(&self, key: &str) -> Result<Option<ByteStream>, Status> {
        Ok(self.get_versioned(key).await?.map(|(body, _)| body))
    }

    async fn get_versioned(&self, key: &str) -> Result<Option<(ByteStream, String)>, Status> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .send()
            .await
        {
            Ok(resp) => {
                let etag = resp.e_tag().unwrap_or_default().to_string();
                Ok(Some((resp.body, etag)))
            }
            Err(SdkError::ServiceError(err))
                if matches!(err.err(), GetObjectError::NoSuchKey(_)) =>
            {
                Ok(None)
            }
            Err(err) => Err(unavailable("get", key, err)),
        }
    }

    /// Streams an object into a file, created fresh. `None` when it does not
    /// exist.
    pub async fn get_to_file(&self, key: &str, path: &Path) -> Result<Option<()>, Status> {
        let Some(body) = self.get(key).await? else {
            return Ok(None);
        };
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|err| Status::internal(format!("creating {}: {err}", path.display())))?;
        tokio::io::copy(&mut body.into_async_read(), &mut file)
            .await
            .map_err(|err| Status::unavailable(format!("object store read {key}: {err}")))?;
        Ok(Some(()))
    }

    pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Status> {
        let Some(body) = self.get(key).await? else {
            return Ok(None);
        };
        body.collect()
            .await
            .map(|data| Some(data.into_bytes().to_vec()))
            .map_err(|err| Status::unavailable(format!("object store read {key}: {err}")))
    }

    /// An object with the ETag it was read at, for a write conditional on it.
    pub async fn get_bytes_versioned(
        &self,
        key: &str,
    ) -> Result<Option<(Vec<u8>, String)>, Status> {
        let Some((body, etag)) = self.get_versioned(key).await? else {
            return Ok(None);
        };
        let data = body
            .collect()
            .await
            .map_err(|err| Status::unavailable(format!("object store read {key}: {err}")))?;
        Ok(Some((data.into_bytes().to_vec(), etag)))
    }

    pub async fn exists(&self, key: &str) -> Result<bool, Status> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(err))
                if matches!(err.err(), HeadObjectError::NotFound(_)) =>
            {
                Ok(false)
            }
            Err(err) => Err(unavailable("head", key, err)),
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), Status> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .send()
            .await
            .map(drop)
            .map_err(|err| unavailable("delete", key, err))
    }

    /// Keys under `prefix`, relative to the store's own prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Status> {
        let mut keys = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(self.key(prefix))
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|err| unavailable("list", prefix, err))?;
            for object in page.contents() {
                if let Some(rest) = object.key().and_then(|k| k.strip_prefix(&self.prefix)) {
                    keys.push(rest.to_string());
                }
            }
        }
        Ok(keys)
    }
}

impl ObjectStore {
    /// Keys under `prefix` with when each was last written, for collecting
    /// what nothing references any more.
    pub async fn list_aged(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, Option<std::time::SystemTime>)>, Status> {
        let mut keys = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(self.key(prefix))
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|err| unavailable("list", prefix, err))?;
            for object in page.contents() {
                if let Some(rest) = object.key().and_then(|k| k.strip_prefix(&self.prefix)) {
                    let modified = object
                        .last_modified()
                        .and_then(|at| std::time::SystemTime::try_from(*at).ok());
                    keys.push((rest.to_string(), modified));
                }
            }
        }
        Ok(keys)
    }
}

fn unavailable<E: std::error::Error + 'static, R: std::fmt::Debug>(
    what: &str,
    key: &str,
    err: SdkError<E, R>,
) -> Status {
    // The service error carries the message; the SDK's Display for the
    // wrapper says only that a service error happened.
    let detail = match &err {
        SdkError::ServiceError(inner) => inner.err().to_string(),
        other => other.to_string(),
    };
    Status::unavailable(format!("object store {what} {key}: {detail}"))
}

#[cfg(test)]
pub(crate) mod fake {
    //! An S3 server of objects in a map, enough of one for the SDK: get,
    //! head, put (conditional or not), delete, a one-page listing and head
    //! and create of a bucket, over HTTP/1.1. Puts can be throttled, as S3 throttles them with `SlowDown`.

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

    use super::{ObjectStore, Options};

    #[derive(Default)]
    pub struct Objects {
        by_key: HashMap<String, (Vec<u8>, String)>,
        versions: u64,
        /// Each bucket by name, with the body of the create that made it.
        pub buckets: HashMap<String, String>,
    }

    /// What the store does to puts.
    #[derive(Default)]
    pub struct Faults {
        /// Puts still to be refused with `503 SlowDown`.
        pub slow_downs: AtomicUsize,
        /// How long each put is held, so puts overlap.
        pub put_delay_ms: AtomicUsize,
        in_flight: AtomicUsize,
        /// The most puts that were ever in flight at once.
        pub most_in_flight: AtomicUsize,
    }

    /// A store on a loopback port. `honours_conditions` false is a store that
    /// ignores `If-Match` and `If-None-Match`, as versitygw 1.0.14 does.
    pub async fn store(honours_conditions: bool) -> ObjectStore {
        let objects = Arc::new(Mutex::new(Objects::default()));
        objects
            .lock()
            .unwrap()
            .buckets
            .insert("test".into(), String::new());
        serving(
            honours_conditions,
            Arc::default(),
            objects,
            options(10, 32, 8),
        )
        .await
    }

    /// A store signing for `region` that has no bucket yet, and its contents.
    pub async fn bucketless(region: &str) -> (ObjectStore, Arc<Mutex<Objects>>) {
        let objects = Arc::new(Mutex::new(Objects::default()));
        let mut options = options(10, 32, 8);
        options.region = region.into();
        let store = serving(true, Arc::default(), Arc::clone(&objects), options).await;
        (store, objects)
    }

    /// A store whose puts fail as `faults` says, with `options` for the client.
    pub async fn faulty(options: Options) -> (ObjectStore, Arc<Faults>) {
        let faults = Arc::new(Faults::default());
        let mut store = serving(true, Arc::clone(&faults), Arc::default(), options).await;
        store.requeue_after = std::time::Duration::from_millis(20);
        (store, faults)
    }

    pub fn options(attempts: u32, uploads: usize, uploads_per_sandbox: usize) -> Options {
        Options {
            url: "s3://test".into(),
            endpoint: String::new(),
            region: "us-east-1".into(),
            attempts,
            uploads,
            uploads_per_sandbox,
        }
    }

    async fn serving(
        honours_conditions: bool,
        faults: Arc<Faults>,
        objects: Arc<Mutex<Objects>>,
        mut options: Options,
    ) -> ObjectStore {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        options.endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let objects = Arc::clone(&objects);
                tokio::spawn(serve(
                    stream,
                    objects,
                    honours_conditions,
                    Arc::clone(&faults),
                ));
            }
        });
        ObjectStore::with_credentials(
            &options,
            "test",
            "",
            aws_sdk_s3::config::Credentials::new("test", "test", None, None, "test"),
        )
    }

    async fn serve(
        stream: tokio::net::TcpStream,
        objects: Arc<Mutex<Objects>>,
        honours_conditions: bool,
        faults: Arc<Faults>,
    ) {
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        loop {
            let mut line = String::new();
            if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let target = parts.next().unwrap_or_default();
            let (key, query) = target.split_once('?').unwrap_or((target, ""));
            let key = match query.is_empty() {
                true => key,
                false => key.trim_end_matches('/'),
            }
            .to_string();
            let listing = query.split('&').any(|pair| pair == "list-type=2").then(|| {
                let prefix = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("prefix="))
                    .unwrap_or_default();
                format!("{key}/{}", decode(prefix))
            });
            let mut headers = HashMap::new();
            loop {
                let mut header = String::new();
                read.read_line(&mut header).await.unwrap();
                let header = header.trim_end();
                if header.is_empty() {
                    break;
                }
                if let Some((name, value)) = header.split_once(':') {
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                }
            }
            let length = headers
                .get("content-length")
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0; length];
            read.read_exact(&mut body).await.unwrap();

            let bucket = key.trim_matches('/');
            let bucket = (listing.is_none() && !bucket.contains('/')).then(|| bucket.to_string());
            let throttled = method == "PUT"
                && bucket.is_none()
                && faults
                    .slow_downs
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .is_ok();
            if method == "PUT" {
                let now = faults.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                faults.most_in_flight.fetch_max(now, Ordering::Relaxed);
                let delay = faults.put_delay_ms.load(Ordering::Relaxed) as u64;
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                faults.in_flight.fetch_sub(1, Ordering::Relaxed);
            }
            let (status, etag, payload) = if throttled {
                (503, None, error("SlowDown"))
            } else {
                let mut objects = objects.lock().unwrap();
                let current = objects.by_key.get(&key).map(|(_, etag)| etag.clone());
                match method.as_str() {
                    "HEAD" if bucket.is_some() => {
                        match objects.buckets.contains_key(bucket.as_ref().unwrap()) {
                            true => (200, None, Vec::new()),
                            false => (404, None, Vec::new()),
                        }
                    }
                    "PUT" if bucket.is_some() => match objects.buckets.entry(bucket.unwrap()) {
                        std::collections::hash_map::Entry::Occupied(_) => {
                            (400, None, error("IllegalLocationConstraintException"))
                        }
                        std::collections::hash_map::Entry::Vacant(slot) => {
                            slot.insert(String::from_utf8(body).unwrap());
                            (200, None, Vec::new())
                        }
                    },
                    "GET" if listing.is_some() => {
                        let prefix = listing.unwrap();
                        let bucket = format!("{key}/");
                        let contents: String = objects
                            .by_key
                            .keys()
                            .filter(|stored| stored.starts_with(&prefix))
                            .map(|stored| {
                                format!(
                                    "<Contents><Key>{}</Key></Contents>",
                                    &stored[bucket.len()..]
                                )
                            })
                            .collect();
                        let body = format!(
                            "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>"
                        );
                        (200, None, body.into_bytes())
                    }
                    "GET" | "HEAD" => match objects.by_key.get(&key) {
                        Some((bytes, etag)) => (200, Some(etag.clone()), bytes.clone()),
                        None => (404, None, error("NoSuchKey")),
                    },
                    "DELETE" => {
                        objects.by_key.remove(&key);
                        (204, None, Vec::new())
                    }
                    "PUT" => {
                        let refused = honours_conditions
                            && (headers.contains_key("if-none-match") && current.is_some()
                                || headers
                                    .get("if-match")
                                    .is_some_and(|want| current.as_ref() != Some(want)));
                        if refused {
                            (412, None, error("PreconditionFailed"))
                        } else {
                            objects.versions += 1;
                            let etag = format!("\"{}\"", objects.versions);
                            objects.by_key.insert(key, (body, etag.clone()));
                            (200, Some(etag), Vec::new())
                        }
                    }
                    _ => (405, None, error("MethodNotAllowed")),
                }
            };
            let mut response = format!("HTTP/1.1 {status} X\r\n");
            if let Some(etag) = etag {
                response.push_str(&format!("ETag: {etag}\r\n"));
            }
            let sent = if method == "HEAD" { 0 } else { payload.len() };
            response.push_str(&format!("Content-Length: {}\r\n\r\n", payload.len()));
            let mut bytes = response.into_bytes();
            bytes.extend_from_slice(&payload[..sent]);
            if write.write_all(&bytes).await.is_err() {
                return;
            }
        }
    }

    fn decode(escaped: &str) -> String {
        let mut out = Vec::new();
        let mut rest = escaped.as_bytes();
        while let Some((&byte, tail)) = rest.split_first() {
            let hex = std::str::from_utf8(tail.get(..2).unwrap_or_default()).unwrap_or_default();
            match u8::from_str_radix(hex, 16) {
                Ok(decoded) if byte == b'%' => {
                    out.push(decoded);
                    rest = &tail[2..];
                }
                _ => {
                    out.push(byte);
                    rest = tail;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn error(code: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{code}</Message></Error>"
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    /// S3 throttles a burst at one prefix with `503 SlowDown`. A put that
    /// meets it is tried again until it lands.
    #[tokio::test]
    async fn a_throttled_put_is_retried_until_it_lands() {
        let (store, faults) = super::fake::faulty(super::fake::options(10, 32, 8)).await;
        faults.slow_downs.store(3, Ordering::Relaxed);
        store.put_bytes("chunks/a", b"a".to_vec()).await.unwrap();
        assert_eq!(faults.slow_downs.load(Ordering::Relaxed), 0);
        assert_eq!(store.get_bytes("chunks/a").await.unwrap().unwrap(), b"a");
    }

    /// A memory image's chunks go up through a run of throttling, and never
    /// more at once than the node allows.
    #[tokio::test]
    async fn an_image_uploads_through_slow_downs_within_the_node_bound() {
        let (store, faults) = super::fake::faulty(super::fake::options(10, 2, 8)).await;
        faults.slow_downs.store(5, Ordering::Relaxed);
        faults.put_delay_ms.store(20, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "burrow-throttled-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let chunk = crate::chunks::CHUNK_SIZE as usize;
        let image: Vec<u8> = (0..4 * chunk).map(|i| (i / chunk + 1) as u8).collect();
        std::fs::write(dir.join("snapshot.mem"), &image).unwrap();

        let index = crate::chunks::put_image(
            &store,
            &dir,
            &["snapshot.mem".to_string()],
            None,
            &Default::default(),
        )
        .await
        .unwrap();

        assert_eq!(index.chunks.len(), 4);
        for digest in index.digests() {
            assert!(
                store
                    .exists(&crate::chunks::chunk_key(digest))
                    .await
                    .unwrap()
            );
        }
        assert_eq!(faults.slow_downs.load(Ordering::Relaxed), 0);
        assert!(faults.most_in_flight.load(Ordering::Relaxed) <= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requeues_back_off_to_a_cap() {
        let mut options = super::fake::options(1, 1, 1);
        options.endpoint = "http://127.0.0.1:1".into();
        let store = super::ObjectStore::with_credentials(
            &options,
            "test",
            "",
            aws_sdk_s3::config::Credentials::new("test", "test", None, None, "test"),
        );
        let first = store.requeue_delay(1);
        assert!(first >= super::REQUEUE_AFTER / 2 && first <= super::REQUEUE_AFTER);
        assert!(store.requeue_delay(40) <= super::MAX_REQUEUE_AFTER);
        assert!(store.requeue_delay(40) >= super::MAX_REQUEUE_AFTER / 2);
    }

    /// A pre-created bucket is only looked at: AWS refuses a create of an
    /// existing bucket outside us-east-1 before it says who owns it.
    #[tokio::test]
    async fn an_existing_bucket_is_not_created_again() {
        let store = super::fake::store(true).await;
        store.ensure_bucket().await.unwrap();
    }

    #[tokio::test]
    async fn a_missing_bucket_is_created_in_the_store_region() {
        let (store, objects) = super::fake::bucketless("ap-southeast-5").await;
        store.ensure_bucket().await.unwrap();
        let created = objects.lock().unwrap().buckets["test"].clone();
        assert!(
            created.contains("<LocationConstraint>ap-southeast-5</LocationConstraint>"),
            "{created}"
        );
        store.ensure_bucket().await.unwrap();

        let (store, objects) = super::fake::bucketless("us-east-1").await;
        store.ensure_bucket().await.unwrap();
        assert!(!objects.lock().unwrap().buckets["test"].contains("LocationConstraint"));
    }

    #[tokio::test]
    async fn a_store_that_ignores_conditional_writes_is_found_out() {
        assert!(
            super::fake::store(true)
                .await
                .probe_conditional_writes()
                .await
                .unwrap()
        );
        assert!(
            !super::fake::store(false)
                .await
                .probe_conditional_writes()
                .await
                .unwrap()
        );
    }
}
