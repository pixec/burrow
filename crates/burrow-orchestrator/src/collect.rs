//! Collects what the object store holds that no row references: the stored
//! state of deleted sandboxes, snapshots and volumes whose node was not
//! there to delete it, or was not told in time.
//!
//! A delete removes the row and succeeds at once. Whatever a reachable node
//! was holding it deletes then, and an absent node at its next heartbeat;
//! what is in the object store is left to this, which any node with the
//! store reaches. Nothing is ever kept for a row that is gone, so nothing
//! can come back. Rows are written before any node makes what they name, so
//! nothing in flight is taken.

use std::collections::HashSet;
use std::time::Duration;

use burrow_proto::node::v1 as nodepb;

use crate::OrchestratorState;

/// How often the leader collects.
pub const INTERVAL: Duration = Duration::from_secs(600);

/// What one pass removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Collected {
    pub sandboxes: usize,
    pub snapshots: usize,
    pub volumes: usize,
}

/// One pass through the first healthy node with the object store. `None`
/// when no node could be asked, or the object store's holdings from before
/// snapshots and volumes had rows are not recorded yet.
pub async fn once(state: &OrchestratorState) -> Option<Collected> {
    let store = state.sandboxes.store();
    if !store.is_stored_inventory_recorded().await.ok()? {
        return None;
    }
    for node_id in state.nodes.healthy_ids() {
        let Some(endpoint) = state.nodes.endpoint(&node_id) else {
            continue;
        };
        let Ok(mut client) = crate::api::connect_node(endpoint, state.node_token.as_deref()).await
        else {
            continue;
        };
        let stored = match client
            .list_stored_sandboxes(nodepb::NodeListStoredRequest {})
            .await
        {
            Ok(stored) => stored.into_inner().sandbox_ids,
            Err(err) if err.code() == tonic::Code::FailedPrecondition => continue,
            Err(err) => {
                tracing::warn!(node_id, %err, "could not list stored sandboxes to collect");
                return None;
            }
        };
        let snapshots = client
            .list_durable_snapshots(nodepb::NodeListSnapshotsRequest {
                sandbox_id: String::new(),
            })
            .await
            .ok()?
            .into_inner()
            .snapshots;
        let volumes = client
            .list_durable_volumes(burrow_proto::api::v1::ListVolumesRequest {
                node_id: String::new(),
            })
            .await
            .ok()?
            .into_inner()
            .volumes;

        // Read after the listings: a row written since is for something a
        // node has not made yet, and one deleted since is collected next time.
        let placed: HashSet<String> = store
            .list_placements()
            .await
            .ok()?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let named_snapshots = store.snapshot_ids().await.ok()?;
        let named_volumes = store.volume_names().await.ok()?;

        let mut collected = Collected::default();
        for id in stored.iter().filter(|id| !placed.contains(*id)) {
            match client
                .purge_sandbox(nodepb::NodeSandboxRef {
                    sandbox_id: id.clone(),
                })
                .await
            {
                Ok(_) => collected.sandboxes += 1,
                Err(err) => tracing::warn!(sandbox = id, %err, "could not collect stored state"),
            }
        }
        for snapshot in snapshots
            .iter()
            .filter(|snapshot| !named_snapshots.contains(&snapshot.id))
        {
            match client
                .delete_snapshot(burrow_proto::api::v1::SnapshotRef {
                    id: snapshot.id.clone(),
                })
                .await
            {
                Ok(_) => collected.snapshots += 1,
                Err(err) if err.code() == tonic::Code::NotFound => {}
                Err(err) => {
                    tracing::warn!(snapshot = snapshot.id, %err, "could not collect a stored snapshot")
                }
            }
        }
        for volume in volumes.iter().filter(|volume| {
            // A Kit's volume belongs to its sandbox, and goes with it.
            let owner = volume.labels.get(burrow_common::kit::VOLUME_OWNER_LABEL);
            match owner {
                Some(sandbox) => !placed.contains(sandbox),
                None => !named_volumes.contains(&volume.name),
            }
        }) {
            match client
                .purge_volume(burrow_proto::api::v1::VolumeRef {
                    name: volume.name.clone(),
                })
                .await
            {
                Ok(_) => collected.volumes += 1,
                Err(err) => {
                    tracing::warn!(volume = volume.name, %err, "could not collect a stored volume")
                }
            }
        }
        if collected != Collected::default() {
            tracing::info!(
                node_id,
                sandboxes = collected.sandboxes,
                snapshots = collected.snapshots,
                volumes = collected.volumes,
                "collected stored state no row references"
            );
        }
        return Some(collected);
    }
    None
}

/// Collects every [`INTERVAL`], on the leader only.
pub async fn run(state: std::sync::Arc<OrchestratorState>) {
    let mut ticker = tokio::time::interval(INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if state.leader.is_leader() {
            once(&state).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use burrow_proto::api::v1 as api;
    use burrow_proto::common::v1 as common;
    use tonic::codegen::{BoxFuture, Service, http};
    use tonic::{Request, Response, Status};

    use super::*;

    /// A node with the object store, holding what it is built with, and
    /// recording what it is asked to remove.
    #[derive(Clone, Default)]
    struct Stored {
        sandboxes: Vec<String>,
        snapshots: Vec<String>,
        volumes: Vec<(String, Option<String>)>,
        removed: Arc<Mutex<Vec<String>>>,
    }

    impl tonic::server::NamedService for Stored {
        const NAME: &'static str = "burrow.node.v1.NodeService";
    }

    macro_rules! unary {
        ($name:ident, $req:ty, $resp:ty, |$node:ident, $request:ident| $body:expr) => {
            struct $name(Stored);
            impl tonic::server::UnaryService<$req> for $name {
                type Response = $resp;
                type Future = BoxFuture<Response<$resp>, Status>;
                fn call(&mut self, $request: Request<$req>) -> Self::Future {
                    let $node = self.0.clone();
                    Box::pin(async move { Ok(Response::new($body)) })
                }
            }
        };
    }

    unary!(
        ListStored,
        nodepb::NodeListStoredRequest,
        nodepb::NodeListStoredResponse,
        |node, _r| {
            nodepb::NodeListStoredResponse {
                sandbox_ids: node.sandboxes,
            }
        }
    );
    unary!(
        ListSnapshots,
        nodepb::NodeListSnapshotsRequest,
        api::ListSnapshotsResponse,
        |node, _r| {
            api::ListSnapshotsResponse {
                snapshots: node
                    .snapshots
                    .iter()
                    .map(|id| common::Snapshot {
                        id: id.clone(),
                        is_durable: true,
                        ..Default::default()
                    })
                    .collect(),
            }
        }
    );
    unary!(
        ListVolumes,
        api::ListVolumesRequest,
        api::ListVolumesResponse,
        |node, _r| {
            api::ListVolumesResponse {
                volumes: node
                    .volumes
                    .iter()
                    .map(|(name, owner)| common::Volume {
                        name: name.clone(),
                        is_durable: true,
                        labels: owner
                            .iter()
                            .map(|owner| {
                                (
                                    burrow_common::kit::VOLUME_OWNER_LABEL.to_string(),
                                    owner.clone(),
                                )
                            })
                            .collect(),
                        ..Default::default()
                    })
                    .collect(),
            }
        }
    );
    unary!(
        PurgeSandbox,
        nodepb::NodeSandboxRef,
        nodepb::NodeDeleteResponse,
        |node, request| {
            node.removed
                .lock()
                .unwrap()
                .push(request.into_inner().sandbox_id);
            nodepb::NodeDeleteResponse {}
        }
    );
    unary!(
        DeleteSnapshot,
        api::SnapshotRef,
        api::DeleteSnapshotResponse,
        |node, request| {
            node.removed.lock().unwrap().push(request.into_inner().id);
            api::DeleteSnapshotResponse {}
        }
    );
    unary!(
        PurgeVolume,
        api::VolumeRef,
        api::DeleteVolumeResponse,
        |node, request| {
            node.removed.lock().unwrap().push(request.into_inner().name);
            api::DeleteVolumeResponse {}
        }
    );

    impl Service<http::Request<tonic::body::Body>> for Stored {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
            let node = self.clone();
            Box::pin(async move {
                macro_rules! serve {
                    ($service:expr) => {
                        tonic::server::Grpc::new(tonic::codec::ProstCodec::default())
                            .unary($service, req)
                            .await
                    };
                }
                let method = req.uri().path().rsplit('/').next().unwrap_or_default();
                Ok(match method {
                    "ListStoredSandboxes" => serve!(ListStored(node)),
                    "ListDurableSnapshots" => serve!(ListSnapshots(node)),
                    "ListDurableVolumes" => serve!(ListVolumes(node)),
                    "PurgeSandbox" => serve!(PurgeSandbox(node)),
                    "DeleteSnapshot" => serve!(DeleteSnapshot(node)),
                    _ => serve!(PurgeVolume(node)),
                })
            })
        }
    }

    /// Deleted while their nodes were away, a sandbox, a snapshot and a
    /// volume left state in the object store. The collector removes exactly
    /// that, and only once what the store held before rows is recorded.
    #[tokio::test]
    async fn stored_state_no_row_references_is_collected() {
        let node = Stored {
            sandboxes: vec!["sbx_kept".into(), "sbx_deleted".into()],
            snapshots: vec!["snap_kept".into(), "snap_deleted".into()],
            volumes: vec![
                ("vol_kept".into(), None),
                ("vol_deleted".into(), None),
                ("kit-kept".into(), Some("sbx_kept".into())),
                ("kit-deleted".into(), Some("sbx_deleted".into())),
            ],
            ..Default::default()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(node.clone())
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
        );
        let api = crate::api::tests::replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        api.0
            .nodes
            .register(
                common::NodeInfo {
                    id: "n1".into(),
                    address: address.to_string(),
                    ..Default::default()
                },
                String::new(),
                String::new(),
                None,
            )
            .unwrap();
        api.0
            .nodes
            .heartbeat("n1", common::NodeStatus::default(), None);
        let store = api.0.sandboxes.store();
        api.0
            .sandboxes
            .put(common::Sandbox {
                id: "sbx_kept".into(),
                ..Default::default()
            })
            .await;
        assert_eq!(once(&api.0).await, None);
        store
            .record_stored_inventory(&["snap_kept".into()], &["vol_kept".into()], 1)
            .await
            .unwrap();

        let collected = once(&api.0).await.unwrap();
        assert_eq!(
            collected,
            Collected {
                sandboxes: 1,
                snapshots: 1,
                volumes: 2,
            }
        );
        let mut removed = node.removed.lock().unwrap().clone();
        removed.sort();
        assert_eq!(
            removed,
            ["kit-deleted", "sbx_deleted", "snap_deleted", "vol_deleted"]
        );
    }
}
