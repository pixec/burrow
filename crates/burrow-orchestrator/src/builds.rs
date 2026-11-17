//! Templates as builds, in the store: resolving what a caller names to one
//! build, recording builds as nodes make them, listing them, and dropping
//! the ones nothing keeps.
//!
//! A build is immutable and named by its manifest's digest. A tag resolves
//! to its newest assignment whose build is ready, so a build in progress or
//! one that failed never moves it. Nodes report the builds they hold; that
//! is kept as a cache for placement and display, never as the truth about a
//! build.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use tonic::Status;

use burrow_common::build::{Digest, Manifest, TemplateRef};
use burrow_proto::api::v1 as api;
use burrow_proto::common::v1 as common;
use burrow_store::{BuildRow, Finished, Store, StoreError, TagRow};

use crate::OrchestratorState;

fn store_error(err: StoreError) -> Status {
    Status::unavailable(format!("the template store: {err}"))
}

pub fn store(state: &OrchestratorState) -> Result<&Arc<Store>, Status> {
    state.store.as_ref().ok_or_else(|| {
        Status::unavailable("templates are kept in the orchestrator's store, which is not open")
    })
}

/// The ready build `text` names: `name`, `name:tag`, `name@sha256:<hex>` or
/// `sha256:<hex>`.
pub async fn resolve(store: &Store, text: &str) -> Result<String, Status> {
    let reference = TemplateRef::parse(text).map_err(Status::invalid_argument)?;
    match &reference {
        TemplateRef::Tag { name, tag } => store
            .resolve_tag(name, tag)
            .await
            .map_err(store_error)?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "no ready build of template {reference}; import one with `burrow pull` or \
                     build one"
                ))
            }),
        TemplateRef::Build { name, digest } => {
            let digest = digest.to_string();
            let build = store
                .get_build(&digest)
                .await
                .map_err(store_error)?
                .filter(|build| build.status == burrow_store::READY)
                .ok_or_else(|| Status::not_found(format!("no ready build {digest}")))?;
            if let Some(name) = name
                && &build.template != name
                && !store
                    .list_tags(Some(name))
                    .await
                    .map_err(store_error)?
                    .iter()
                    .any(|tag| tag.digest == digest)
            {
                return Err(Status::not_found(format!(
                    "{digest} is not a build of template {name}"
                )));
            }
            Ok(digest)
        }
    }
}

/// A ready build's manifest.
pub async fn manifest(store: &Store, digest: &str) -> Result<Manifest, Status> {
    let build = store
        .get_build(digest)
        .await
        .map_err(store_error)?
        .ok_or_else(|| Status::not_found(format!("no build {digest}")))?;
    serde_json::from_str(&build.manifest)
        .map_err(|err| Status::internal(format!("build {digest}'s manifest: {err}")))
}

/// The hypervisor a build runs under: the one it records, or its guest's
/// default where it names none.
pub fn hypervisor_of(manifest: &Manifest) -> String {
    match manifest.config["hypervisor"].as_str() {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => guest_os_of(manifest).default_hypervisor().to_string(),
    }
}

fn guest_os_of(manifest: &Manifest) -> burrow_common::hypervisor::GuestOs {
    burrow_common::hypervisor::GuestOs::from_record(
        manifest.config["guest_os"].as_str().unwrap_or_default(),
    )
    .unwrap_or_default()
}

/// What a build is tagged under: `name` or `name:tag`.
pub fn target(text: &str) -> Result<(String, String), Status> {
    match TemplateRef::parse(text).map_err(Status::invalid_argument)? {
        TemplateRef::Tag { name, tag } => Ok((name, tag)),
        TemplateRef::Build { .. } => Err(Status::invalid_argument(
            "a build is published under name or name:tag, not a digest",
        )),
    }
}

/// The digest a node's report of a build claims, checked against its
/// manifest.
fn verified(done: &api::BuildDone) -> Result<String, Status> {
    let digest = Digest::parse(&done.digest)
        .ok_or_else(|| Status::data_loss(format!("{:?} is not a build digest", done.digest)))?;
    Manifest::verified(&done.manifest, &digest).map_err(Status::data_loss)?;
    Ok(digest.to_string())
}

/// One build as its node's log goes by: a row while it builds, a ready row
/// for each step it keeps, and the tag once it is ready.
pub struct Recorder {
    store: Arc<Store>,
    id: String,
    name: String,
    tag: String,
    node_id: String,
    parent: String,
    is_begun: bool,
    is_finished: bool,
}

impl Recorder {
    /// Starts recording. A build whose name is not known yet, a Kit set named
    /// from its digests, gets its row when it finishes.
    pub async fn begin(
        store: Arc<Store>,
        name: String,
        tag: String,
        node_id: String,
        parent: String,
    ) -> Result<Self, Status> {
        let mut recorder = Self {
            store,
            id: format!("bld_{}", uuid::Uuid::new_v4().simple()),
            name,
            tag,
            node_id,
            parent,
            is_begun: false,
            is_finished: false,
        };
        if !recorder.name.is_empty() {
            recorder.start().await?;
        }
        Ok(recorder)
    }

    async fn start(&mut self) -> Result<(), Status> {
        self.store
            .begin_build(&BuildRow {
                id: self.id.clone(),
                template: self.name.clone(),
                parent_digest: self.parent.clone(),
                node_id: self.node_id.clone(),
                created_at_ms: burrow_common::unix_now_ms(),
                ..Default::default()
            })
            .await
            .map_err(store_error)?;
        self.is_begun = true;
        Ok(())
    }

    /// Records what `log` says about the build.
    pub async fn observe(&mut self, log: &api::BuildLog) -> Result<(), Status> {
        match &log.event {
            Some(api::build_log::Event::Layer(layer)) => {
                let digest = verified(layer)?;
                let template = match self.name.is_empty() {
                    true => layer.template.clone(),
                    false => self.name.clone(),
                };
                self.store
                    .put_ready_build(&BuildRow {
                        id: format!("bld_{}", uuid::Uuid::new_v4().simple()),
                        digest,
                        template,
                        manifest: layer.manifest.clone(),
                        parent_digest: layer.parent_digest.clone(),
                        node_id: self.node_id.clone(),
                        created_at_ms: burrow_common::unix_now_ms(),
                        ..Default::default()
                    })
                    .await
                    .map_err(store_error)
            }
            Some(api::build_log::Event::Done(done)) => {
                let digest = verified(done)?;
                if !self.is_begun {
                    self.name = done.template.clone();
                    self.parent = done.parent_digest.clone();
                    self.start().await?;
                }
                let finished = self
                    .store
                    .finish_build(
                        &self.id,
                        &digest,
                        &done.manifest,
                        std::slice::from_ref(&self.tag),
                        burrow_common::unix_now_ms(),
                    )
                    .await
                    .map_err(store_error)?;
                self.is_finished = true;
                match finished {
                    Finished::Ready | Finished::Existing => {
                        tracing::info!(
                            template = self.name,
                            tag = self.tag,
                            build = digest,
                            node_id = self.node_id,
                            "build ready"
                        );
                        Ok(())
                    }
                    Finished::NotBuilding => Err(Status::aborted(format!(
                        "build {} of {} was marked failed before it finished",
                        self.id, self.name
                    ))),
                }
            }
            _ => Ok(()),
        }
    }

    /// The template and tag the build is published under, as a caller
    /// names them.
    pub fn reference(&self) -> String {
        TemplateRef::Tag {
            name: self.name.clone(),
            tag: self.tag.clone(),
        }
        .to_string()
    }

    /// Records the build failed, unless it finished.
    pub async fn fail(&mut self, why: &str) {
        if !self.is_begun || self.is_finished {
            return;
        }
        self.is_finished = true;
        if let Err(err) = self
            .store
            .fail_build(&self.id, why, burrow_common::unix_now_ms())
            .await
        {
            tracing::warn!(build = self.id, %err, "could not record a failed build");
        }
    }
}

/// The builds tags resolve to, read from the store at most every
/// [`TAGGED_FOR`].
#[derive(Default)]
pub struct Tagged(std::sync::Mutex<Option<(std::time::Instant, Vec<String>)>>);

const TAGGED_FOR: std::time::Duration = std::time::Duration::from_secs(10);

/// The builds tags resolve to now, for nodes to keep warm. The last list
/// read stands while the store cannot be read.
pub async fn tagged(state: &OrchestratorState) -> Vec<String> {
    if let Some((at, digests)) = &*state.tagged.0.lock().unwrap()
        && at.elapsed() < TAGGED_FOR
    {
        return digests.clone();
    }
    let Some(store) = &state.store else {
        return Vec::new();
    };
    let read = async {
        let live: HashSet<String> = store
            .list_templates()
            .await?
            .into_iter()
            .filter(|template| template.deleted_at_ms == 0)
            .map(|template| template.name)
            .collect();
        let builds = store.list_builds(None).await?;
        let tags = store.list_tags(None).await?;
        let ready: HashSet<&str> = builds
            .iter()
            .filter(|build| build.status == burrow_store::READY)
            .map(|build| build.digest.as_str())
            .collect();
        let mut digests: Vec<String> = current(&tags, &ready)
            .into_iter()
            .filter(|((template, _), _)| live.contains(*template))
            .map(|(_, tag)| tag.digest.clone())
            .collect();
        digests.sort();
        digests.dedup();
        Ok::<_, StoreError>(digests)
    };
    match read.await {
        Ok(digests) => {
            *state.tagged.0.lock().unwrap() = Some((std::time::Instant::now(), digests.clone()));
            digests
        }
        Err(err) => {
            tracing::warn!(%err, "could not read which builds are tagged");
            state
                .tagged
                .0
                .lock()
                .unwrap()
                .as_ref()
                .map(|(_, digests)| digests.clone())
                .unwrap_or_default()
        }
    }
}

/// Every node's last status, by node id.
fn statuses(state: &OrchestratorState) -> Vec<(String, common::NodeStatus)> {
    state.nodes.statuses()
}

/// Which build each tag resolves to: its newest assignment whose build is
/// ready, by (template, tag).
fn current<'a>(
    tags: &'a [TagRow],
    ready: &HashSet<&str>,
) -> BTreeMap<(&'a str, &'a str), &'a TagRow> {
    let mut out = BTreeMap::new();
    for tag in tags {
        if ready.contains(tag.digest.as_str()) {
            out.insert((tag.template.as_str(), tag.tag.as_str()), tag);
        }
    }
    out
}

fn info(build: &BuildRow, statuses: &[(String, common::NodeStatus)]) -> api::TemplateInfo {
    let manifest: Manifest = serde_json::from_str(&build.manifest).unwrap_or_default();
    let warm_shapes = warm_shapes(&build.digest, &build.template, statuses);
    api::TemplateInfo {
        name: build.template.clone(),
        size_bytes: manifest.rootfs.bytes,
        is_warm: !warm_shapes.is_empty(),
        is_kit: !manifest.config["kit"].is_null(),
        is_systemd: manifest.config["systemd"].as_bool().unwrap_or(false),
        guest_os: match build.digest.is_empty() {
            true => String::new(),
            false => guest_os_of(&manifest).as_str().to_string(),
        },
        hypervisor: match build.digest.is_empty() {
            true => String::new(),
            false => hypervisor_of(&manifest),
        },
        warm_shapes,
        kernel: statuses
            .iter()
            .find_map(|(_, status)| status.build_kernels.get(&build.digest))
            .cloned(),
        tag: String::new(),
        digest: build.digest.clone(),
        status: build.status.clone(),
        created_at_unix_ms: build.created_at_ms,
    }
}

fn warm_shapes(
    digest: &str,
    template: &str,
    statuses: &[(String, common::NodeStatus)],
) -> Vec<common::WarmShape> {
    statuses
        .iter()
        .flat_map(|(node_id, status)| {
            status
                .warm_shapes
                .iter()
                .filter(|shape| shape.build_digest == digest)
                .map(|shape| common::WarmShape {
                    node_id: node_id.clone(),
                    template: template.to_string(),
                    ..shape.clone()
                })
        })
        .collect()
}

/// One row per tag, at the build it resolves to, and each template's newest
/// build when it is building or failed after its newest ready one.
pub async fn list(state: &OrchestratorState) -> Result<Vec<api::TemplateInfo>, Status> {
    let store = store(state)?;
    let live: HashSet<String> = store
        .list_templates()
        .await
        .map_err(store_error)?
        .into_iter()
        .filter(|template| template.deleted_at_ms == 0)
        .map(|template| template.name)
        .collect();
    let builds = store.list_builds(None).await.map_err(store_error)?;
    let tags = store.list_tags(None).await.map_err(store_error)?;
    let ready: HashSet<&str> = builds
        .iter()
        .filter(|build| build.status == burrow_store::READY)
        .map(|build| build.digest.as_str())
        .collect();
    let by_digest: std::collections::HashMap<&str, &BuildRow> = builds
        .iter()
        .filter(|build| !build.digest.is_empty())
        .map(|build| (build.digest.as_str(), build))
        .collect();
    let statuses = statuses(state);
    let mut out = Vec::new();
    for ((template, tag), assignment) in current(&tags, &ready) {
        if !live.contains(template) {
            continue;
        }
        let Some(build) = by_digest.get(assignment.digest.as_str()) else {
            continue;
        };
        out.push(api::TemplateInfo {
            name: template.to_string(),
            tag: tag.to_string(),
            ..info(build, &statuses)
        });
    }
    for template in &live {
        let newest_ready = builds
            .iter()
            .filter(|build| &build.template == template && build.status == burrow_store::READY)
            .map(|build| build.created_at_ms)
            .max()
            .unwrap_or(i64::MIN);
        if let Some(pending) = builds
            .iter()
            .filter(|build| {
                &build.template == template
                    && matches!(
                        build.status.as_str(),
                        burrow_store::BUILDING | burrow_store::FAILED
                    )
                    && build.created_at_ms > newest_ready
            })
            .max_by_key(|build| build.created_at_ms)
        {
            out.push(info(pending, &statuses));
        }
    }
    out.sort_by(|a, b| (&a.name, &a.tag).cmp(&(&b.name, &b.tag)));
    Ok(out)
}

/// One template's builds, its tag history and where each build is.
pub async fn detail(state: &OrchestratorState, name: &str) -> Result<api::TemplateDetail, Status> {
    let store = store(state)?;
    burrow_common::build::validate_name(name).map_err(Status::invalid_argument)?;
    let exists = store
        .list_templates()
        .await
        .map_err(store_error)?
        .into_iter()
        .any(|template| template.name == name && template.deleted_at_ms == 0);
    if !exists {
        return Err(Status::not_found(format!("no template {name}")));
    }
    let tags = store.list_tags(Some(name)).await.map_err(store_error)?;
    let mut builds = store.list_builds(Some(name)).await.map_err(store_error)?;
    // A tag can point at another template's build; it is listed too.
    for tag in &tags {
        if !builds.iter().any(|build| build.digest == tag.digest)
            && let Some(build) = store.get_build(&tag.digest).await.map_err(store_error)?
        {
            builds.push(build);
        }
    }
    let ready: HashSet<&str> = builds
        .iter()
        .filter(|build| build.status == burrow_store::READY)
        .map(|build| build.digest.as_str())
        .collect();
    let resolved = current(&tags, &ready);
    let holders = store.list_node_builds().await.map_err(store_error)?;
    let statuses = statuses(state);
    let builds = builds
        .iter()
        .map(|build| {
            let manifest: Manifest = serde_json::from_str(&build.manifest).unwrap_or_default();
            api::TemplateBuild {
                digest: build.digest.clone(),
                status: build.status.clone(),
                parent_digest: build.parent_digest.clone(),
                created_at_unix_ms: build.created_at_ms,
                finished_at_unix_ms: build.finished_at_ms,
                size_bytes: manifest.rootfs.bytes,
                hypervisor: match build.digest.is_empty() {
                    true => String::new(),
                    false => hypervisor_of(&manifest),
                },
                guest_os: match build.digest.is_empty() {
                    true => String::new(),
                    false => guest_os_of(&manifest).as_str().to_string(),
                },
                tags: resolved
                    .iter()
                    .filter(|(_, tag)| !build.digest.is_empty() && tag.digest == build.digest)
                    .map(|((_, tag), _)| tag.to_string())
                    .collect(),
                node_ids: holders
                    .iter()
                    .filter(|(_, digest)| !build.digest.is_empty() && digest == &build.digest)
                    .map(|(node_id, _)| node_id.clone())
                    .collect(),
                error: build.error.clone(),
                warm_shapes: warm_shapes(&build.digest, name, &statuses),
                built_on: build.node_id.clone(),
            }
        })
        .collect();
    Ok(api::TemplateDetail {
        name: name.to_string(),
        builds,
        tag_history: tags
            .into_iter()
            .map(|tag| api::TagAssignment {
                tag: tag.tag,
                digest: tag.digest,
                assigned_at_unix_ms: tag.assigned_at_ms,
            })
            .collect(),
    })
}

/// Deletes a template, or one tag of it. Its builds stay until retention
/// drops them, which it does once nothing uses them.
pub async fn delete(state: &OrchestratorState, text: &str) -> Result<(), Status> {
    let store = store(state)?;
    let (name, tag) = match text.split_once(':') {
        Some((name, tag)) => (name, Some(tag)),
        None => (text, None),
    };
    burrow_common::build::validate_name(name).map_err(Status::invalid_argument)?;
    let removed = match tag {
        Some(tag) => {
            store
                .delete_tag(name, tag, burrow_common::unix_now_ms())
                .await
                .map_err(store_error)?
                > 0
        }
        None => store
            .delete_template(name, burrow_common::unix_now_ms())
            .await
            .map_err(store_error)?,
    };
    match removed {
        true => Ok(()),
        false => Err(Status::not_found(format!("no template {text}"))),
    }
}

/// Records which builds `node_id` holds when its report changes them.
pub async fn note_builds(state: &OrchestratorState, node_id: &str, status: &common::NodeStatus) {
    let Some(store) = &state.store else {
        return;
    };
    let mut reported = status.builds.clone();
    reported.sort();
    let held = state.nodes.builds_of(node_id).map(|mut held| {
        held.sort();
        held
    });
    if held.as_ref() == Some(&reported) {
        return;
    }
    if let Err(err) = store
        .replace_node_builds(node_id, &reported, burrow_common::unix_now_ms())
        .await
    {
        tracing::warn!(node_id, %err, "could not record the builds a node holds");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_builds_hypervisor_is_read_from_its_config() {
        let manifest = |config: serde_json::Value| Manifest {
            config,
            ..Default::default()
        };
        assert_eq!(
            hypervisor_of(&manifest(
                serde_json::json!({"hypervisor": "cloud-hypervisor"})
            )),
            "cloud-hypervisor"
        );
        assert_eq!(
            hypervisor_of(&manifest(serde_json::json!({}))),
            "firecracker"
        );
        assert_eq!(
            hypervisor_of(&manifest(serde_json::json!({"guest_os": "windows"}))),
            "cloud-hypervisor"
        );
    }

    #[tokio::test]
    async fn a_reference_resolves_to_a_ready_build() {
        let store = Store::open_in_memory().await.unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            resolve(&store, "py").await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        store
            .put_ready_build(&BuildRow {
                id: "b1".into(),
                digest: digest.clone(),
                template: "py".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store.assign_tag("py", "3.12", &digest, 1).await.unwrap();
        assert_eq!(resolve(&store, "py:3.12").await.unwrap(), digest);
        assert!(resolve(&store, "py").await.is_err());
        assert_eq!(
            resolve(&store, &format!("py@{digest}")).await.unwrap(),
            digest
        );
        assert_eq!(resolve(&store, &digest).await.unwrap(), digest);
        assert!(resolve(&store, &format!("other@{digest}")).await.is_err());
        assert_eq!(
            resolve(&store, "py@sha256:zz").await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}
