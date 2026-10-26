//! The fleet's object store, spoken to as S3.
//!
//! Just enough of the protocol for whole objects: put, get, head, delete and a
//! prefix listing, signed with SigV4 and an unsigned payload so a multi-gigabyte
//! memory image streams from disk without being hashed first. Written here
//! rather than taken from a crate because every S3 crate pulls its own TLS and
//! HTTP stacks, and the node already has reqwest on rustls.
//!
//! Credentials come from the environment, `AWS_ACCESS_KEY_ID` and
//! `AWS_SECRET_ACCESS_KEY`, the way every S3 tool reads them.

use std::path::Path;

use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use tonic::Status;

type HmacSha256 = Hmac<Sha256>;

const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

#[derive(Clone)]
pub struct ObjectStore {
    http: reqwest::Client,
    /// Scheme and host of the endpoint, no trailing slash.
    endpoint: String,
    bucket: String,
    /// Key prefix inside the bucket, empty or ending in `/`.
    prefix: String,
    region: String,
    access_key: String,
    secret_key: String,
    /// `endpoint/bucket/key` rather than `bucket.endpoint/key`. Always, since
    /// every self-hosted store supports it and a bucket name with a dot
    /// breaks the other form's TLS.
    host: String,
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
        let endpoint = options.endpoint.trim_end_matches('/').to_string();
        let host = reqwest::Url::parse(&endpoint)
            .ok()
            .and_then(|url| {
                url.host_str().map(|h| match url.port() {
                    Some(port) => format!("{h}:{port}"),
                    None => h.to_string(),
                })
            })
            .ok_or_else(|| anyhow::anyhow!("--object-store-endpoint is not a URL"))?;
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
        if access_key.is_empty() || secret_key.is_empty() {
            anyhow::bail!("--object-store needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()?,
            endpoint,
            bucket: bucket.to_string(),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
            region: options.region.clone(),
            access_key,
            secret_key,
            host,
        })
    }

    /// Creates the bucket if the store does not have it. Self-hosted stores
    /// start empty, and a node that can create its own tables should not
    /// need an operator to make its bucket by hand.
    pub async fn ensure_bucket(&self) -> Result<(), Status> {
        let resp = self
            .signed(reqwest::Method::PUT, "", &[])
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store: {err}")))?;
        match resp.status().as_u16() {
            200 | 409 => Ok(()),
            _ => ok(resp, "").await.map(drop),
        }
    }

    pub fn describe(&self) -> String {
        format!("s3://{}/{} at {}", self.bucket, self.prefix, self.endpoint)
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    fn url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.endpoint,
            self.bucket,
            uri_encode(&self.key(key), false)
        )
    }

    /// Signs a request against the object at `key`, or the bucket when `key`
    /// is empty, with `query` already in canonical order.
    fn signed(
        &self,
        method: reqwest::Method,
        key: &str,
        query: &[(&str, &str)],
    ) -> reqwest::RequestBuilder {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (date, stamp) = amz_date(now);
        let canonical_uri = if key.is_empty() {
            format!("/{}", self.bucket)
        } else {
            format!("/{}/{}", self.bucket, uri_encode(&self.key(key), false))
        };
        let canonical_query = query
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
            .collect::<Vec<_>>()
            .join("&");
        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{UNSIGNED}\nx-amz-date:{stamp}\n",
            self.host
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!(
            "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{UNSIGNED}",
            method.as_str()
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let key_date = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let key_region = hmac(&key_date, self.region.as_bytes());
        let key_service = hmac(&key_region, b"s3");
        let key_signing = hmac(&key_service, b"aws4_request");
        let signature = hex::encode(hmac(&key_signing, to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );
        let url = if key.is_empty() {
            format!("{}/{}", self.endpoint, self.bucket)
        } else {
            self.url(key)
        };
        let url = if canonical_query.is_empty() {
            url
        } else {
            format!("{url}?{canonical_query}")
        };
        self.http
            .request(method, url)
            .header("x-amz-date", stamp)
            .header("x-amz-content-sha256", UNSIGNED)
            .header("authorization", authorization)
    }

    pub async fn put_file(&self, key: &str, path: &Path) -> Result<(), Status> {
        let file = tokio::fs::File::open(path).await.map_err(|err| {
            Status::internal(format!("opening {} to upload: {err}", path.display()))
        })?;
        let len = file
            .metadata()
            .await
            .map_err(|err| Status::internal(format!("sizing {}: {err}", path.display())))?
            .len();
        let stream = tokio_util::io::ReaderStream::new(file);
        let resp = self
            .signed(reqwest::Method::PUT, key, &[])
            .header("content-length", len)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store put {key}: {err}")))?;
        ok(resp, key).await.map(drop)
    }

    pub async fn put_bytes(&self, key: &str, bytes: Vec<u8>) -> Result<(), Status> {
        let resp = self
            .signed(reqwest::Method::PUT, key, &[])
            .body(bytes)
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store put {key}: {err}")))?;
        ok(resp, key).await.map(drop)
    }

    /// Streams an object into a file, created fresh. `None` when it does not
    /// exist.
    pub async fn get_to_file(&self, key: &str, path: &Path) -> Result<Option<()>, Status> {
        use tokio::io::AsyncWriteExt as _;
        let resp = self
            .signed(reqwest::Method::GET, key, &[])
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store get {key}: {err}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let mut resp = ok(resp, key).await?;
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|err| Status::internal(format!("creating {}: {err}", path.display())))?;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|err| Status::unavailable(format!("object store read {key}: {err}")))?
        {
            file.write_all(&chunk)
                .await
                .map_err(|err| Status::internal(format!("writing {}: {err}", path.display())))?;
        }
        file.flush()
            .await
            .map_err(|err| Status::internal(format!("writing {}: {err}", path.display())))?;
        Ok(Some(()))
    }

    pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Status> {
        let resp = self
            .signed(reqwest::Method::GET, key, &[])
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store get {key}: {err}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = ok(resp, key).await?;
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|err| Status::unavailable(format!("object store read {key}: {err}")))
    }

    pub async fn exists(&self, key: &str) -> Result<bool, Status> {
        let resp = self
            .signed(reqwest::Method::HEAD, key, &[])
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store head {key}: {err}")))?;
        match resp.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(false),
            status if status.is_success() => Ok(true),
            status => Err(Status::unavailable(format!(
                "object store head {key}: {status}"
            ))),
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), Status> {
        let resp = self
            .signed(reqwest::Method::DELETE, key, &[])
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store delete {key}: {err}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        ok(resp, key).await.map(drop)
    }

    /// Keys under `prefix`, relative to the store's own prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Status> {
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        let full_prefix = self.key(prefix);
        loop {
            let mut query: Vec<(&str, &str)> = Vec::new();
            if let Some(token) = &token {
                query.push(("continuation-token", token));
            }
            query.push(("list-type", "2"));
            query.push(("prefix", &full_prefix));
            query.sort();
            let resp = self
                .signed(reqwest::Method::GET, "", &query)
                .send()
                .await
                .map_err(|err| Status::unavailable(format!("object store list: {err}")))?;
            let body = ok(resp, "")
                .await?
                .text()
                .await
                .map_err(|err| Status::unavailable(format!("object store list: {err}")))?;
            for key in between_all(&body, "<Key>", "</Key>") {
                if let Some(rest) = key.strip_prefix(&self.prefix) {
                    keys.push(rest.to_string());
                }
            }
            match between_all(&body, "<NextContinuationToken>", "</NextContinuationToken>").pop() {
                Some(next) if body.contains("<IsTruncated>true</IsTruncated>") => {
                    token = Some(next)
                }
                _ => return Ok(keys),
            }
        }
    }
}

async fn ok(resp: reqwest::Response, key: &str) -> Result<reqwest::Response, Status> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let detail = between_all(&body, "<Message>", "</Message>")
        .pop()
        .unwrap_or_else(|| body.chars().take(200).collect());
    Err(Status::unavailable(format!(
        "object store {key}: {status} {detail}"
    )))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SigV4's URI encoding: unreserved characters pass, `/` passes in a path and
/// is encoded in a query value, everything else is percent-encoded.
fn uri_encode(text: &str, is_query: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b'/' if !is_query => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// `YYYYMMDD` and `YYYYMMDDTHHMMSSZ` for a unix time.
fn amz_date(secs: u64) -> (String, String) {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    let date = format!("{year:04}{month:02}{d:02}");
    (date.clone(), format!("{date}T{h:02}{m:02}{s:02}Z"))
}

fn between_all(text: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(close) else { break };
        out.push(after[..end].to_string());
        rest = &after[end + close.len()..];
    }
    out
}

/// Sparse files over the wire.
///
/// A memory image and a scratch disk are mostly holes: a snapshot that occupies
/// 40 MiB on disk has a 512 MiB memory file and a scratch disk the size of the
/// guest's allowance. Sent as bytes they cost the apparent size on every
/// upload and fetch, and arrive dense. So they go as their data extents, each
/// prefixed by where it sits, under a key with a `.sparse` suffix, and the
/// fetch writes them back at those offsets into a file truncated to the
/// apparent length, so the holes come back as holes.
///
/// Format, all little-endian: `BRSPARSE` + u64 apparent length, then
/// (u64 offset, u64 length, bytes) per extent in ascending order.
const SPARSE_MAGIC: &[u8; 8] = b"BRSPARSE";
const SPARSE_CHUNK: usize = 1 << 20;

pub fn sparse_key(key: &str) -> String {
    format!("{key}.sparse")
}

impl ObjectStore {
    pub async fn put_sparse_file(&self, key: &str, path: &Path) -> Result<(), Status> {
        use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
        let std_file = std::fs::File::open(path)
            .map_err(|err| Status::internal(format!("opening {}: {err}", path.display())))?;
        let apparent = std_file
            .metadata()
            .map_err(|err| Status::internal(format!("sizing {}: {err}", path.display())))?
            .len();
        let extents = data_extents(&std_file, apparent)
            .map_err(|err| Status::internal(format!("walking {}: {err}", path.display())))?;
        let content_length = 16 + extents.iter().map(|(s, e)| 16 + (e - s)).sum::<u64>();
        let mut file = tokio::fs::File::from_std(std_file);
        let stream = async_stream::stream! {
            let mut header = Vec::with_capacity(16);
            header.extend_from_slice(SPARSE_MAGIC);
            header.extend_from_slice(&apparent.to_le_bytes());
            yield Ok::<_, std::io::Error>(bytes::Bytes::from(header));
            for (start, end) in extents {
                let mut extent = Vec::with_capacity(16);
                extent.extend_from_slice(&start.to_le_bytes());
                extent.extend_from_slice(&(end - start).to_le_bytes());
                yield Ok(bytes::Bytes::from(extent));
                if let Err(err) = file.seek(std::io::SeekFrom::Start(start)).await {
                    yield Err(err);
                    return;
                }
                let mut left = end - start;
                while left > 0 {
                    let want = left.min(SPARSE_CHUNK as u64) as usize;
                    let mut buf = vec![0u8; want];
                    if let Err(err) = file.read_exact(&mut buf).await {
                        yield Err(err);
                        return;
                    }
                    left -= want as u64;
                    yield Ok(bytes::Bytes::from(buf));
                }
            }
        };
        let resp = self
            .signed(reqwest::Method::PUT, &sparse_key(key), &[])
            .header("content-length", content_length)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store put {key}: {err}")))?;
        ok(resp, key).await.map(drop)
    }

    /// Rebuilds a sparse file from the store. `None` when the key is absent.
    pub async fn get_sparse_file(&self, key: &str, path: &Path) -> Result<Option<()>, Status> {
        use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};
        let sparse = sparse_key(key);
        let resp = self
            .signed(reqwest::Method::GET, &sparse, &[])
            .send()
            .await
            .map_err(|err| Status::unavailable(format!("object store get {sparse}: {err}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let mut resp = ok(resp, &sparse).await?;
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|err| Status::internal(format!("creating {}: {err}", path.display())))?;
        let corrupt = || Status::data_loss(format!("object {sparse} is not a sparse image"));

        let mut buf: Vec<u8> = Vec::new();
        let mut extent_left: u64 = 0;
        let mut is_header_read = false;
        loop {
            // Drain what the buffer can satisfy before reading more.
            loop {
                if extent_left > 0 {
                    if buf.is_empty() {
                        break;
                    }
                    let take = buf.len().min(extent_left as usize);
                    file.write_all(&buf[..take]).await.map_err(|err| {
                        Status::internal(format!("writing {}: {err}", path.display()))
                    })?;
                    buf.drain(..take);
                    extent_left -= take as u64;
                    continue;
                }
                if buf.len() < 16 {
                    break;
                }
                if !is_header_read {
                    if &buf[..8] != SPARSE_MAGIC {
                        return Err(corrupt());
                    }
                    let apparent = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    file.set_len(apparent).await.map_err(|err| {
                        Status::internal(format!("sizing {}: {err}", path.display()))
                    })?;
                    is_header_read = true;
                } else {
                    let start = u64::from_le_bytes(buf[..8].try_into().unwrap());
                    extent_left = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    file.seek(std::io::SeekFrom::Start(start))
                        .await
                        .map_err(|err| {
                            Status::internal(format!("seeking {}: {err}", path.display()))
                        })?;
                }
                buf.drain(..16);
            }
            match resp
                .chunk()
                .await
                .map_err(|err| Status::unavailable(format!("object store read {sparse}: {err}")))?
            {
                Some(chunk) => buf.extend_from_slice(&chunk),
                None => break,
            }
        }
        if !is_header_read || extent_left > 0 || !buf.is_empty() {
            return Err(corrupt());
        }
        file.flush()
            .await
            .map_err(|err| Status::internal(format!("writing {}: {err}", path.display())))?;
        Ok(Some(()))
    }
}

#[cfg(target_os = "linux")]
fn data_extents(file: &std::fs::File, _apparent: u64) -> std::io::Result<Vec<(u64, u64)>> {
    burrow_vmm::data_extents(file)
}

/// Without SEEK_DATA the whole file is one extent, which is correct and dense.
#[cfg(not(target_os = "linux"))]
fn data_extents(_file: &std::fs::File, apparent: u64) -> std::io::Result<Vec<(u64, u64)>> {
    Ok(if apparent == 0 {
        Vec::new()
    } else {
        vec![(0, apparent)]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_render_as_sigv4_expects() {
        assert_eq!(amz_date(0).1, "19700101T000000Z");
        assert_eq!(amz_date(1_700_000_000).1, "20231114T221320Z");
        assert_eq!(amz_date(1_709_164_800).0, "20240229");
    }

    #[test]
    fn encoding_keeps_slashes_in_paths_only() {
        assert_eq!(uri_encode("a/b c", false), "a/b%20c");
        assert_eq!(uri_encode("a/b c", true), "a%2Fb%20c");
    }

    #[test]
    fn listing_bodies_are_parsed_without_an_xml_crate() {
        let body = "<R><Contents><Key>p/a</Key></Contents><Contents><Key>p/b</Key></Contents></R>";
        assert_eq!(between_all(body, "<Key>", "</Key>"), ["p/a", "p/b"]);
    }
}
