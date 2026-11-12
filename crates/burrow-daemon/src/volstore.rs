//! Volumes kept in the object store, so they outlive their node.
//!
//! A volume's image goes to the store as a chunk index, the way a root disk
//! does: content-addressed chunks, only the new ones sent. What is uploaded is
//! always a reflink clone taken while nothing writes the image, either because
//! no writer is attached or because the writer's guest has the filesystem
//! frozen for the instant the clone takes. The clone is kept as the base of
//! the next upload, so a chunk still sharing device blocks with it is not
//! read again.
//!
//! The manifest names the node holding the volume, and every write to it is
//! conditional on the version read, as a stored sandbox's is: a node takes a
//! volume only from the holder the orchestrator wrote off, or from none, and
//! a node writing as the holder checks the manifest still names it. A node
//! that finds another holder has lost the volume and stops serving its copy.
//!
//! Layout, under the store's prefix:
//!
//! ```text
//! volumes/<name>/manifest.json
//! volumes/<name>/<generation>.index.json
//! chunks/<sha256>
//! ```

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::chunks::ImageIndex;
use crate::durable::Stamp;
use crate::objstore::ObjectStore;

const FORMAT: u32 = 1;
/// What this node last uploaded, beside the volume's image.
pub const LOCAL: &str = "durable.json";
/// A clone of the image as it was last uploaded, the next upload's base.
pub const BASE: &str = "uploaded.img";
/// The clone an upload reads, taken while nothing writes the image.
pub const CAPTURE: &str = ".capture.img";

pub const STATE_HELD: &str = "held";
/// Let go of for a move: the next node to adopt it takes it.
pub const STATE_RELEASED: &str = "released";
pub const STATE_DELETING: &str = "deleting";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub name: String,
    /// Unix milliseconds of the upload, raised past the previous one if the
    /// clock disagrees. Names the index.
    pub generation: u64,
    /// The node holding the volume; empty once released.
    pub node_id: String,
    pub state: String,
    pub size_mib: u64,
    pub created_at_ms: i64,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub guest_os: String,
    pub uploaded_at_ms: i64,
}

fn prefix(name: &str) -> String {
    format!("volumes/{name}/")
}

fn manifest_key(name: &str) -> String {
    format!("volumes/{name}/manifest.json")
}

fn index_key(name: &str, generation: u64) -> String {
    format!("volumes/{name}/{generation}.index.json")
}

/// A volume's manifest as the store holds it, with the ETag it was read at.
#[derive(Debug)]
pub struct Held {
    pub manifest: Manifest,
    etag: String,
}

pub async fn read(store: &ObjectStore, name: &str) -> Result<Option<Held>, Status> {
    let Some((bytes, etag)) = store.get_bytes_versioned(&manifest_key(name)).await? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|err| Status::data_loss(format!("volume {name}'s stored manifest: {err}")))?;
    if manifest.format != FORMAT {
        return Err(Status::failed_precondition(format!(
            "volume {name} was stored by another build of burrowd"
        )));
    }
    Ok(Some(Held { manifest, etag }))
}

async fn replace(
    store: &ObjectStore,
    held: Option<&Held>,
    next: &Manifest,
) -> Result<Held, Status> {
    let json = serde_json::to_vec_pretty(next)
        .map_err(|err| Status::internal(format!("encoding the manifest: {err}")))?;
    match store
        .put_bytes_if(
            &manifest_key(&next.name),
            json,
            held.map(|held| held.etag.as_str()),
        )
        .await?
    {
        Some(etag) => Ok(Held {
            manifest: next.clone(),
            etag,
        }),
        None => Err(lost(&next.name, read(store, &next.name).await?.as_ref())),
    }
}

/// Writes `next` for a volume the store must record as held by `holder`, or,
/// when `may_create`, have nothing for yet.
async fn write_held(
    store: &ObjectStore,
    holder: &str,
    next: &Manifest,
    may_create: bool,
) -> Result<Held, Status> {
    let current = read(store, &next.name).await?;
    match &current {
        Some(held) if held.manifest.node_id == holder && held.manifest.state == STATE_HELD => {
            replace(store, Some(held), next).await
        }
        None if may_create => replace(store, None, next).await,
        _ => Err(lost(&next.name, current.as_ref())),
    }
}

fn lost(name: &str, current: Option<&Held>) -> Status {
    match current {
        Some(held) => Status::aborted(format!(
            "volume {name} is {} by node {:?} in the object store; this node lost it",
            held.manifest.state, held.manifest.node_id
        )),
        None => Status::aborted(format!(
            "volume {name} is no longer in the object store; this node lost it"
        )),
    }
}

/// What this node last uploaded of a volume, or adopted of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Local {
    pub manifest: Manifest,
    pub index: ImageIndex,
    /// The image as it was when the upload's clone was taken.
    pub stamp: Stamp,
    pub is_published: bool,
}

pub async fn load_local(dir: &Path) -> Option<Local> {
    let bytes = tokio::fs::read(dir.join(LOCAL)).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn save_local(dir: &Path, local: &Local) -> Result<(), Status> {
    let json = serde_json::to_vec(local)
        .map_err(|err| Status::internal(format!("encoding the durable state: {err}")))?;
    crate::fsync::replace(&dir.join(LOCAL), &dir.join(format!(".{LOCAL}.tmp")), json)
        .await
        .map_err(|err| Status::internal(format!("writing the durable state: {err}")))
}

/// Uploads `capture`, a clone of the volume's image, returning what was
/// stored. Unchanged chunks keep their digests and nothing is published when
/// no chunk changed. Refused, as `Aborted`, when another node holds the
/// volume now.
pub async fn upload(
    store: &ObjectStore,
    dir: &Path,
    capture: &Path,
    stamp: Stamp,
    draft: Manifest,
    previous: Option<&Local>,
) -> Result<Local, Status> {
    let started = std::time::Instant::now();
    let base = dir.join(BASE);
    let base = match previous {
        Some(previous) if tokio::fs::try_exists(&base).await.unwrap_or(false) => {
            Some((base.as_path(), &previous.index))
        }
        _ => None,
    };
    let known: HashSet<String> = previous
        .map(|p| p.index.digests().map(str::to_string).collect())
        .unwrap_or_default();
    let index = crate::chunks::put_disk_since(store, capture, base, &known).await?;
    if let Some(previous) = previous
        && previous.is_published
        && previous.index.chunks == index.chunks
        && previous.index.size == index.size
    {
        let _ = tokio::fs::rename(capture, dir.join(BASE)).await;
        let local = Local {
            stamp,
            ..previous.clone()
        };
        save_local(dir, &local).await?;
        return Ok(local);
    }
    let now = burrow_common::unix_now_ms();
    let generation = (now as u64).max(previous.map_or(0, |p| p.manifest.generation + 1));
    let json = serde_json::to_vec(&index)
        .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
    store
        .put_bytes(&index_key(&draft.name, generation), json)
        .await?;
    let mut local = Local {
        manifest: Manifest {
            format: FORMAT,
            generation,
            state: STATE_HELD.to_string(),
            uploaded_at_ms: now,
            ..draft
        },
        index,
        stamp,
        is_published: false,
    };
    save_local(dir, &local).await?;
    let may_create = previous.is_none_or(|previous| !previous.is_published);
    write_held(store, &local.manifest.node_id, &local.manifest, may_create).await?;
    local.is_published = true;
    save_local(dir, &local).await?;
    let _ = tokio::fs::rename(capture, dir.join(BASE)).await;
    if let Some(previous) = previous
        && previous.manifest.generation != generation
    {
        let _ = store
            .delete(&index_key(
                &local.manifest.name,
                previous.manifest.generation,
            ))
            .await;
    }
    tracing::info!(
        volume = local.manifest.name,
        generation,
        stored_bytes = local.index.stored_bytes(),
        took_ms = started.elapsed().as_millis() as u64,
        "volume is in the object store"
    );
    Ok(local)
}

/// Takes a stored volume onto this node: fetches its image into `image`, then
/// claims it, conditional on the manifest it fetched. `from` is the holder the
/// orchestrator wrote off; a volume held by any other node is refused.
pub async fn adopt(
    store: &ObjectStore,
    name: &str,
    node_id: &str,
    from: &str,
    image: &Path,
) -> Result<Local, Status> {
    let held = read(store, name)
        .await?
        .ok_or_else(|| Status::not_found(format!("volume {name} is not in the object store")))?;
    let manifest = &held.manifest;
    let is_takeable = match manifest.state.as_str() {
        STATE_RELEASED => true,
        STATE_HELD => manifest.node_id == from || manifest.node_id == node_id,
        _ => false,
    };
    if !is_takeable {
        return Err(Status::aborted(format!(
            "volume {name} is {} by node {:?} in the object store, not node {from:?}; it is not \
             taken from here",
            manifest.state, manifest.node_id
        )));
    }
    let index = crate::snapshot::read_index(store, &index_key(name, manifest.generation))
        .await?
        .ok_or_else(|| {
            Status::data_loss(format!(
                "volume {name}'s stored generation {} has no index",
                manifest.generation
            ))
        })?;
    let started = std::time::Instant::now();
    crate::chunks::get_image(store, &index, image).await?;
    let claimed = Manifest {
        node_id: node_id.to_string(),
        state: STATE_HELD.to_string(),
        ..manifest.clone()
    };
    if let Err(err) = replace(store, Some(&held), &claimed).await {
        let _ = tokio::fs::remove_file(image).await;
        return Err(err);
    }
    tracing::info!(
        volume = name,
        from = manifest.node_id,
        bytes = index.stored_bytes(),
        took_ms = started.elapsed().as_millis() as u64,
        "volume adopted from the object store"
    );
    Ok(Local {
        manifest: claimed,
        index,
        stamp: Stamp::default(),
        is_published: true,
    })
}

/// Records the adopted volume beside its image, with a clone of it as the
/// next upload's base.
pub async fn settle_adopted(dir: &Path, image: &Path, mut local: Local) -> Result<Local, Status> {
    if crate::rootdisk::is_clonable(image, dir) {
        let _ = crate::rootdisk::clone(image, &dir.join(BASE)).await;
    }
    local.stamp = Stamp::of(image).unwrap_or_default();
    save_local(dir, &local).await?;
    Ok(local)
}

/// Lets go of a volume for a move, as its holder. Its last upload is what the
/// next node takes.
pub async fn release(store: &ObjectStore, holder: &str, local: &Local) -> Result<(), Status> {
    let released = Manifest {
        node_id: String::new(),
        state: STATE_RELEASED.to_string(),
        ..local.manifest.clone()
    };
    write_held(store, holder, &released, false).await.map(drop)
}

/// Removes everything stored for a volume, as `holder` or, with `None`, for
/// one whose holder the orchestrator wrote off.
pub async fn purge(store: &ObjectStore, name: &str, holder: Option<&str>) -> Result<(), Status> {
    if let Some(held) = read(store, name).await? {
        if let Some(holder) = holder
            && held.manifest.node_id != holder
            && held.manifest.state == STATE_HELD
        {
            return Err(lost(name, Some(&held)));
        }
        let deleting = Manifest {
            state: STATE_DELETING.to_string(),
            ..held.manifest.clone()
        };
        replace(store, Some(&held), &deleting).await?;
    }
    store.delete(&manifest_key(name)).await?;
    for key in store.list(&prefix(name)).await? {
        store.delete(&key).await?;
    }
    Ok(())
}

/// Every volume manifest the store holds.
pub async fn list(store: &ObjectStore) -> Result<Vec<Manifest>, Status> {
    let mut out = Vec::new();
    for key in store.list("volumes/").await? {
        let Some(name) = key
            .strip_prefix("volumes/")
            .and_then(|rest| rest.strip_suffix("/manifest.json"))
        else {
            continue;
        };
        if let Some(held) = read(store, name).await?
            && held.manifest.state != STATE_DELETING
        {
            out.push(held.manifest);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Adds the chunks every stored volume's current generation names to
/// `referenced`, and deletes indexes of older generations past `grace`.
pub async fn collect_refs(
    store: &ObjectStore,
    grace: std::time::Duration,
    referenced: &mut HashSet<String>,
) -> Result<usize, Status> {
    let objects = store.list_aged("volumes/").await?;
    let mut current: HashMap<String, u64> = HashMap::new();
    for (key, _) in &objects {
        let Some(name) = key
            .strip_prefix("volumes/")
            .and_then(|rest| rest.strip_suffix("/manifest.json"))
        else {
            continue;
        };
        let Some(held) = read(store, name).await? else {
            continue;
        };
        let key = index_key(name, held.manifest.generation);
        if let Some(index) = crate::snapshot::read_index(store, &key).await? {
            referenced.extend(index.digests().map(str::to_string));
        }
        current.insert(name.to_string(), held.manifest.generation);
    }
    let cutoff = std::time::SystemTime::now() - grace;
    let mut stale = 0;
    for (key, modified) in &objects {
        let Some((name, generation)) = key
            .strip_prefix("volumes/")
            .and_then(|rest| rest.split_once('/'))
            .and_then(|(name, file)| {
                file.strip_suffix(".index.json")
                    .and_then(|g| g.parse::<u64>().ok())
                    .map(|g| (name, g))
            })
        else {
            continue;
        };
        if current.get(name) == Some(&generation) || modified.is_none_or(|at| at > cutoff) {
            continue;
        }
        if store.delete(key).await.is_ok() {
            stale += 1;
        }
    }
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-volstore-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn draft(name: &str, node_id: &str) -> Manifest {
        Manifest {
            format: FORMAT,
            name: name.into(),
            generation: 0,
            node_id: node_id.into(),
            state: String::new(),
            size_mib: 4,
            created_at_ms: 1,
            labels: HashMap::new(),
            guest_os: "linux".into(),
            uploaded_at_ms: 0,
        }
    }

    fn write_image(path: &Path, fill: &[(u64, u8)]) {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .unwrap();
        file.set_len(4 << 20).unwrap();
        for (at, byte) in fill {
            file.write_all_at(&[*byte; 4096], *at).unwrap();
        }
    }

    async fn capture(dir: &Path, image: &Path) -> (std::path::PathBuf, Stamp) {
        let capture = dir.join(CAPTURE);
        crate::rootdisk::clone(image, &capture).await.unwrap();
        (capture, Stamp::of(image).unwrap())
    }

    /// A volume uploaded on one node and adopted on another arrives byte for
    /// byte, and a second upload sends only what changed.
    #[tokio::test]
    async fn a_volume_survives_its_node_and_uploads_only_what_changed() {
        let store = crate::objstore::fake::store(true).await;
        let a = scratch("a");
        let image = a.join("volume.ext4");
        write_image(&image, &[(0, 1), (2 << 20, 2)]);

        let (clone, stamp) = capture(&a, &image).await;
        let first = upload(&store, &a, &clone, stamp, draft("data", "node-a"), None)
            .await
            .unwrap();
        assert!(first.is_published);
        assert_eq!(first.index.chunks.len(), 2);
        assert!(tokio::fs::try_exists(a.join(BASE)).await.unwrap());

        let (clone, stamp) = capture(&a, &image).await;
        let same = upload(
            &store,
            &a,
            &clone,
            stamp,
            draft("data", "node-a"),
            Some(&first),
        )
        .await
        .unwrap();
        assert_eq!(same.manifest.generation, first.manifest.generation);

        write_image(&image, &[(3 << 20, 3)]);
        let (clone, stamp) = capture(&a, &image).await;
        let second = upload(
            &store,
            &a,
            &clone,
            stamp,
            draft("data", "node-a"),
            Some(&first),
        )
        .await
        .unwrap();
        assert!(second.manifest.generation > first.manifest.generation);
        assert_eq!(second.index.chunks.len(), 3);
        assert_eq!(second.index.chunks[&0], first.index.chunks[&0]);

        let b = scratch("b");
        let fetched = b.join("volume.ext4");
        let adopted = adopt(&store, "data", "node-b", "node-a", &fetched)
            .await
            .unwrap();
        assert_eq!(adopted.manifest.node_id, "node-b");
        assert_eq!(
            std::fs::read(&fetched).unwrap(),
            std::fs::read(&image).unwrap()
        );

        // The node it was taken from has lost it.
        write_image(&image, &[(1 << 20, 9)]);
        let (clone, stamp) = capture(&a, &image).await;
        let refused = upload(
            &store,
            &a,
            &clone,
            stamp,
            draft("data", "node-a"),
            Some(&second),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Aborted);
        assert!(
            refused.message().contains("node-b"),
            "{}",
            refused.message()
        );
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// Two nodes told to take one volume from a dead holder: one gets it.
    #[tokio::test]
    async fn of_two_nodes_adopting_one_volume_only_one_takes_it() {
        let store = crate::objstore::fake::store(true).await;
        let a = scratch("race");
        let image = a.join("volume.ext4");
        write_image(&image, &[(0, 7)]);
        let (clone, stamp) = capture(&a, &image).await;
        upload(&store, &a, &clone, stamp, draft("race", "node-a"), None)
            .await
            .unwrap();
        let (b, c) = (scratch("rb"), scratch("rc"));
        let (to_b, to_c) = (b.join("v"), c.join("v"));
        let (got_b, got_c) = tokio::join!(
            adopt(&store, "race", "node-b", "node-a", &to_b),
            adopt(&store, "race", "node-c", "node-a", &to_c),
        );
        assert!(got_b.is_ok() != got_c.is_ok(), "exactly one adopt lands");
        let holder = read(&store, "race")
            .await
            .unwrap()
            .unwrap()
            .manifest
            .node_id;
        assert!(holder == "node-b" || holder == "node-c");
        // Nor can a node that was not the written-off holder take it.
        let refused = adopt(&store, "race", "node-d", "node-a", &a.join("d"))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Aborted);
        for dir in [a, b, c] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A released volume is anyone's to take, and the releasing node no
    /// longer writes as its holder.
    #[tokio::test]
    async fn a_released_volume_is_taken_by_the_next_node() {
        let store = crate::objstore::fake::store(true).await;
        let a = scratch("rel");
        let image = a.join("volume.ext4");
        write_image(&image, &[(0, 5)]);
        let (clone, stamp) = capture(&a, &image).await;
        let local = upload(&store, &a, &clone, stamp, draft("moving", "node-a"), None)
            .await
            .unwrap();
        release(&store, "node-a", &local).await.unwrap();
        let b = scratch("relb");
        adopt(&store, "moving", "node-b", "", &b.join("v"))
            .await
            .unwrap();
        assert_eq!(
            release(&store, "node-a", &local).await.unwrap_err().code(),
            tonic::Code::Aborted
        );
        purge(&store, "moving", Some("node-b")).await.unwrap();
        assert!(read(&store, "moving").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}
