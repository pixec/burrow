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
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(options.region.clone()))
            .endpoint_url(options.endpoint.trim_end_matches('/'))
            .credentials_provider(Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "burrow-flags",
            ))
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
        Ok(Self {
            client: Client::from_conf(config),
            endpoint: options.endpoint.trim_end_matches('/').to_string(),
            bucket: bucket.to_string(),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
        })
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

    async fn get(&self, key: &str) -> Result<Option<ByteStream>, Status> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .send()
            .await
        {
            Ok(resp) => Ok(Some(resp.body)),
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
