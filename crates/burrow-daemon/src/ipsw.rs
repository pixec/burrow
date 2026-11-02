//! macOS restore images for vz template builds: what `latest` means, read
//! from Apple's catalogue, and a verified copy of it kept in the data
//! directory for the next build.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tonic::Status;

/// Apple's list of the restore images Macs may install.
pub const CATALOGUE: &str =
    "https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml";

/// One restore image the catalogue lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restore {
    pub url: String,
    /// e.g. `26B123`.
    pub build: String,
    /// e.g. `27.2`.
    pub version: String,
    /// Lowercase hex, when any of the image's entries carries one.
    pub sha1: Option<String>,
}

/// Every restore image in the catalogue, once per URL. The catalogue lists
/// the one universal image under each Mac model, and only some entries carry
/// its checksum, so an image takes the first checksum any entry gives it.
pub fn restores(xml: &str) -> Vec<Restore> {
    let mut out: Vec<Restore> = Vec::new();
    for block in xml.split("<key>Restore</key>").skip(1) {
        let Some(body) = block.trim_start().strip_prefix("<dict>") else {
            continue;
        };
        let fields = fields(body.split("</dict>").next().unwrap_or_default());
        let get = |name: &str| {
            fields
                .iter()
                .find(|(key, value)| key == name && !value.is_empty())
                .map(|(_, value)| value.clone())
        };
        let (Some(url), Some(build), Some(version)) = (
            get("FirmwareURL"),
            get("BuildVersion"),
            get("ProductVersion"),
        ) else {
            continue;
        };
        let sha1 = get("FirmwareSHA1").map(|sha1| sha1.to_ascii_lowercase());
        match out.iter_mut().find(|known| known.url == url) {
            Some(known) => {
                if known.sha1.is_none() {
                    known.sha1 = sha1;
                }
            }
            None => out.push(Restore {
                url,
                build,
                version,
                sha1,
            }),
        }
    }
    out
}

/// The newest restore image the catalogue lists.
pub fn latest(xml: &str) -> Option<Restore> {
    restores(xml).into_iter().max_by_key(|restore| {
        let version: Vec<u32> = restore
            .version
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect();
        (version, restore.build.clone())
    })
}

/// The key/string pairs of a flat plist dict.
fn fields(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<key>") {
        rest = &rest[start + "<key>".len()..];
        let Some(end) = rest.find("</key>") else {
            break;
        };
        let key = unescape(&rest[..end]);
        rest = rest[end + "</key>".len()..].trim_start();
        if let Some(after) = rest.strip_prefix("<string/>") {
            rest = after;
            out.push((key, String::new()));
        } else if let Some(after) = rest.strip_prefix("<string>") {
            let Some(end) = after.find("</string>") else {
                break;
            };
            out.push((key, unescape(&after[..end])));
            rest = &after[end + "</string>".len()..];
        }
    }
    out
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The file an image is kept under: the last segment of its URL.
fn file_name(url: &str) -> Result<&str, Status> {
    url.rsplit('/')
        .next()
        .filter(|name| name.ends_with(".ipsw") && !name.starts_with('.'))
        .ok_or_else(|| Status::unavailable(format!("the catalogue's image {url} is not an .ipsw")))
}

/// One download at a time: two `latest` builds would otherwise write the
/// same partial file.
static FETCHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The newest restore image Apple lists, as a file under `data_dir`:
/// downloaded, resuming whatever an earlier attempt left, and checked against
/// its size and the catalogue's checksum before it takes its name. An image
/// already there was checked when it got it, and is used as it is.
pub async fn fetch_latest(data_dir: &Path, progress: impl Fn(String)) -> Result<PathBuf, Status> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(120))
        .build()
        .map_err(|err| Status::internal(format!("http client: {err}")))?;
    let unavailable = |err: reqwest::Error| {
        Status::unavailable(format!("reading Apple's restore image catalogue: {err}"))
    };
    let xml = client
        .get(CATALOGUE)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(unavailable)?
        .text()
        .await
        .map_err(unavailable)?;
    let restore = latest(&xml)
        .ok_or_else(|| Status::unavailable("Apple's restore image catalogue lists no image"))?;
    let dir = data_dir.join("ipsw");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|err| Status::internal(format!("{}: {err}", dir.display())))?;
    let name = file_name(&restore.url)?;
    let path = dir.join(name);
    let _one = FETCHING.lock().await;
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        progress(format!(
            "using macOS {} ({}), downloaded before",
            restore.version, restore.build
        ));
        return Ok(path);
    }
    progress(format!(
        "downloading macOS {} ({}) from {}",
        restore.version, restore.build, restore.url
    ));
    let partial = dir.join(format!("{name}.part"));
    download(&client, &restore.url, &partial, &progress).await?;
    match &restore.sha1 {
        Some(expected) => {
            progress("verifying the download".into());
            let actual = sha1_file(&partial).await?;
            if actual != *expected {
                let _ = tokio::fs::remove_file(&partial).await;
                return Err(Status::data_loss(format!(
                    "{name} has SHA-1 {actual}, not the catalogue's {expected}; removed it"
                )));
            }
        }
        None => tracing::warn!(
            image = name,
            "the catalogue lists no checksum for this image; only its size was checked"
        ),
    }
    tokio::fs::rename(&partial, &path)
        .await
        .map_err(|err| Status::internal(format!("keeping {name}: {err}")))?;
    Ok(path)
}

/// Downloads `url` into `partial`, from where it left off.
async fn download(
    client: &reqwest::Client,
    url: &str,
    partial: &Path,
    progress: &impl Fn(String),
) -> Result<(), Status> {
    use futures::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;

    let failed =
        |err: &dyn std::fmt::Display| Status::unavailable(format!("downloading {url}: {err}"));
    let written = |err: std::io::Error| Status::internal(format!("{}: {err}", partial.display()));
    let have = tokio::fs::metadata(partial)
        .await
        .map_or(0, |meta| meta.len());
    let mut request = client.get(url);
    if have > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={have}-"));
    }
    let response = request.send().await.map_err(|err| failed(&err))?;
    // "bytes 100-199/200", or "bytes */200" when nothing is left to send.
    let range_total = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit('/').next())
        .and_then(|total| total.parse::<u64>().ok());
    let (mut file, mut done, total) = match response.status() {
        reqwest::StatusCode::PARTIAL_CONTENT => {
            progress(format!("resuming at {:.1} GiB", gib(have)));
            let file = tokio::fs::OpenOptions::new()
                .append(true)
                .open(partial)
                .await
                .map_err(written)?;
            (file, have, range_total)
        }
        reqwest::StatusCode::RANGE_NOT_SATISFIABLE if range_total == Some(have) => return Ok(()),
        status if status.is_success() => {
            let file = tokio::fs::File::create(partial).await.map_err(written)?;
            (file, 0, response.content_length())
        }
        status => {
            // A partial file the server will not continue is not worth
            // keeping for the next attempt.
            if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                let _ = tokio::fs::remove_file(partial).await;
            }
            return Err(failed(&status));
        }
    };
    let mut stream = response.bytes_stream();
    let mut reported = Instant::now();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| failed(&err))?;
        file.write_all(&chunk).await.map_err(written)?;
        done += chunk.len() as u64;
        if reported.elapsed() >= Duration::from_secs(15) {
            reported = Instant::now();
            progress(match total {
                Some(total) => format!("downloaded {:.1} of {:.1} GiB", gib(done), gib(total)),
                None => format!("downloaded {:.1} GiB", gib(done)),
            });
        }
    }
    file.flush().await.map_err(written)?;
    if let Some(total) = total
        && done != total
    {
        return Err(failed(&format!(
            "ended at {done} of {total} bytes; the next build resumes it"
        )));
    }
    Ok(())
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / f64::from(1u32 << 30)
}

async fn sha1_file(path: &Path) -> Result<String, Status> {
    use sha1::Digest as _;
    use std::io::Read as _;

    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = sha1::Sha1::new();
        let mut buffer = vec![0u8; 4 << 20];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        std::io::Result::Ok(hex::encode(hasher.finalize()))
    })
    .await
    .map_err(|err| Status::internal(format!("hashing did not run: {err}")))?
    .map_err(|err| Status::internal(format!("hashing the download: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../testdata/macos-ipsw-catalogue.xml");

    #[test]
    fn the_catalogue_lists_one_image_with_the_checksum_some_entries_carry() {
        let restores = restores(SAMPLE);
        assert_eq!(
            restores,
            vec![Restore {
                url: "https://updates.cdn-apple.com/2026FallFCS/c9671975-52db-4fb5-9af2-00217169ba8d/UniversalMac_27.2_26B123_Restore.ipsw".into(),
                build: "26B123".into(),
                version: "27.2".into(),
                sha1: Some("617360e5619dbb424ed3774b98732bb3cfeacc0b".into()),
            }]
        );
        assert_eq!(
            file_name(&restores[0].url).unwrap(),
            "UniversalMac_27.2_26B123_Restore.ipsw"
        );
    }

    #[test]
    fn latest_is_the_highest_version_then_build() {
        let entry = |version: &str, build: &str| {
            format!(
                "<key>Restore</key>\n<dict>\n<key>BuildVersion</key>\n<string>{build}</string>\n\
                 <key>FirmwareURL</key>\n<string>https://example.invalid/UniversalMac_{version}_{build}_Restore.ipsw</string>\n\
                 <key>ProductVersion</key>\n<string>{version}</string>\n</dict>\n"
            )
        };
        let xml = format!(
            "{}{}{}{SAMPLE}",
            entry("27.10", "26X1"),
            entry("27.9.1", "26W9"),
            entry("27.10", "26X2"),
        );
        let newest = latest(&xml).unwrap();
        assert_eq!(
            (newest.version.as_str(), newest.build.as_str()),
            ("27.10", "26X2")
        );
        assert_eq!(newest.sha1, None);
        assert_eq!(latest(SAMPLE).unwrap().build, "26B123");
        assert_eq!(latest("<plist><dict></dict></plist>"), None);
    }

    #[test]
    fn an_entry_missing_its_url_or_version_is_skipped() {
        let xml = "<key>Restore</key><dict><key>BuildVersion</key><string>1A1</string>\
                   <key>FirmwareURL</key><string/></dict>";
        assert!(restores(xml).is_empty());
        assert!(file_name("https://example.invalid/restore.zip").is_err());
    }
}
