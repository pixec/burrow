//! The fleet's object store, spoken to as S3 through the AWS SDK.
//!
//! Whole objects only: put, get, head, delete and a prefix listing. The SDK is
//! built on the node's own TLS stack, rustls on ring, so the musl cross build
//! stays free of a second one. Credentials come from the environment,
//! `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, the way every S3 tool
//! reads them; the endpoint is always addressed path-style, which every
//! self-hosted store supports and which a bucket name with a dot needs.

use std::path::Path;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::create_bucket::CreateBucketError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_http_client::tls;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tonic::Status;

#[derive(Clone)]
pub struct ObjectStore {
    client: Client,
    endpoint: String,
    bucket: String,
    /// Key prefix inside the bucket, empty or ending in `/`.
    prefix: String,
}

/// Where the store is, from the flags: `s3://bucket/prefix` and an endpoint.
pub struct Options {
    pub url: String,
    pub endpoint: String,
    pub region: String,
}

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
        }
    }

    /// Creates the bucket if the store does not have it. Self-hosted stores
    /// start empty, and a node that can create its own tables should not
    /// need an operator to make its bucket by hand.
    pub async fn ensure_bucket(&self) -> Result<(), Status> {
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
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

/// Sparse files, as snapshots were stored before they were chunked.
///
/// Each was one object of its data extents, each prefixed by where it sits,
/// under a key with a `.sparse` suffix. Kept so a snapshot uploaded in that
/// form still restores; nothing is written this way any more.
///
/// Format, all little-endian: `BRSPARSE` + u64 apparent length, then
/// (u64 offset, u64 length, bytes) per extent in ascending order.
const SPARSE_MAGIC: &[u8; 8] = b"BRSPARSE";

pub fn sparse_key(key: &str) -> String {
    format!("{key}.sparse")
}

impl ObjectStore {
    /// Rebuilds a sparse file from the store. `None` when the key is absent.
    pub async fn get_sparse_file(&self, key: &str, path: &Path) -> Result<Option<()>, Status> {
        let sparse = sparse_key(key);
        let Some(body) = self.get(&sparse).await? else {
            return Ok(None);
        };
        let mut reader = body.into_async_read();
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|err| Status::internal(format!("creating {}: {err}", path.display())))?;
        let read_err =
            |err: std::io::Error| Status::unavailable(format!("object store read {sparse}: {err}"));
        let write_err =
            |err: std::io::Error| Status::internal(format!("writing {}: {err}", path.display()));
        let corrupt = || Status::data_loss(format!("object {sparse} is not a sparse image"));

        let mut header = [0u8; 16];
        reader.read_exact(&mut header).await.map_err(read_err)?;
        if &header[..8] != SPARSE_MAGIC {
            return Err(corrupt());
        }
        let apparent = u64::from_le_bytes(header[8..].try_into().unwrap());
        file.set_len(apparent).await.map_err(write_err)?;

        let mut extent = [0u8; 16];
        loop {
            match reader.read_exact(&mut extent).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(read_err(err)),
            }
            let start = u64::from_le_bytes(extent[..8].try_into().unwrap());
            let len = u64::from_le_bytes(extent[8..].try_into().unwrap());
            if start.checked_add(len).is_none_or(|end| end > apparent) {
                return Err(corrupt());
            }
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(write_err)?;
            let copied = tokio::io::copy(&mut (&mut reader).take(len), &mut file)
                .await
                .map_err(read_err)?;
            if copied != len {
                return Err(corrupt());
            }
        }
        file.flush().await.map_err(write_err)?;
        Ok(Some(()))
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! An S3 server of objects in a map, enough of one for the SDK: get,
    //! head, put (conditional or not) and delete, over HTTP/1.1.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

    use super::{ObjectStore, Options};

    #[derive(Default)]
    struct Objects {
        by_key: HashMap<String, (Vec<u8>, String)>,
        versions: u64,
    }

    /// A store on a loopback port. `honours_conditions` false is a store that
    /// ignores `If-Match` and `If-None-Match`, as versitygw 1.0.14 does.
    pub async fn store(honours_conditions: bool) -> ObjectStore {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let objects = Arc::new(Mutex::new(Objects::default()));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let objects = Arc::clone(&objects);
                tokio::spawn(serve(stream, objects, honours_conditions));
            }
        });
        let options = Options {
            url: "s3://test".into(),
            endpoint,
            region: "us-east-1".into(),
        };
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
            let key = target.split('?').next().unwrap_or_default().to_string();
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

            let (status, etag, payload) = {
                let mut objects = objects.lock().unwrap();
                let current = objects.by_key.get(&key).map(|(_, etag)| etag.clone());
                match method.as_str() {
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

    fn error(code: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{code}</Message></Error>"
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
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
