//! The Access service: exec and files for sandboxes on this node, called by
//! clients directly with a token from the orchestrator's IssueAccess.
//!
//! The traffic skips the orchestrator, but nothing else does. Each call is
//! checked against the token here, and then runs through the same handler
//! the orchestrator's relay reaches, so the sandbox's exec and file policies
//! hold either way. The node token never enters into it: an Access token
//! reaches these five calls and nothing else the node serves.
//!
//! Revocation works like a lock: RevokeAccess stamps the sandbox, every token
//! issued at or before the stamp is refused from then on, and the sessions
//! such tokens opened here are ended on the spot. A node that has stopped
//! hearing from the orchestrator cannot know whether a revoke is waiting for
//! it, so it refuses every token until it hears again.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use burrow_common::access::{Claims, OP_EXEC, OP_FILES_READ, OP_FILES_WRITE, Verifier};
use burrow_proto::api::v1 as api;
use burrow_proto::api::v1::access_server::Access;
use burrow_proto::node::v1::node_service_server::NodeService;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::nodeapi::{BoxStream, NodeApi};

/// How long the node goes on accepting tokens without hearing from the
/// orchestrator. Six heartbeats: long enough to ride out one slow beat, short
/// enough that a revoke the node never received stops mattering soon.
const STALE_AFTER: Duration = Duration::from_secs(30);

/// The orchestrator's keys, and when it last confirmed them.
#[derive(Default)]
pub struct Keys {
    verifier: Verifier,
    heard: Option<Instant>,
}

pub type SharedKeys = Arc<RwLock<Keys>>;

/// Puts the orchestrator's announced keys in force, and notes that it was
/// heard from. Called on every registration and every heartbeat.
pub fn apply_keys(keys: &RwLock<Keys>, announced: &[burrow_proto::node::v1::AccessKey]) {
    let fresh = Verifier::new(
        announced
            .iter()
            .map(|key| (key.kid.clone(), key.public_key.clone())),
    );
    let mut held = keys.write().unwrap();
    if !held.verifier.same_keys(&fresh) {
        tracing::info!(keys = announced.len(), "access keys updated");
        held.verifier = fresh;
    }
    held.heard = Some(Instant::now());
}

/// Direct sessions open on this node, by sandbox, so a revoke can end them.
#[derive(Default)]
pub struct Sessions {
    open: Mutex<HashMap<String, Vec<Arc<Session>>>>,
}

pub struct Session {
    ended: CancellationToken,
    /// The command an exec session started, once the guest has named it.
    command: Mutex<Option<String>>,
}

/// Holds a session open for as long as the call it belongs to runs.
struct Held {
    sessions: Arc<Sessions>,
    sandbox: String,
    session: Arc<Session>,
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut open = self.sessions.open.lock().unwrap();
        if let Some(list) = open.get_mut(&self.sandbox) {
            list.retain(|held| !Arc::ptr_eq(held, &self.session));
            if list.is_empty() {
                open.remove(&self.sandbox);
            }
        }
    }
}

impl Sessions {
    fn open(self: &Arc<Self>, sandbox: &str) -> Held {
        let session = Arc::new(Session {
            ended: CancellationToken::new(),
            command: Mutex::new(None),
        });
        self.open
            .lock()
            .unwrap()
            .entry(sandbox.to_string())
            .or_default()
            .push(Arc::clone(&session));
        Held {
            sessions: Arc::clone(self),
            sandbox: sandbox.to_string(),
            session,
        }
    }

    /// Ends every session open on `sandbox`, returning how many there were.
    pub fn end_all(&self, sandbox: &str) -> usize {
        let ended = self
            .open
            .lock()
            .unwrap()
            .remove(sandbox)
            .unwrap_or_default();
        for session in &ended {
            session.ended.cancel();
        }
        ended.len()
    }
}

fn revoked() -> Status {
    Status::unauthenticated("this access token was revoked")
}

pub struct AccessApi {
    pub api: Arc<NodeApi>,
    pub keys: SharedKeys,
    pub sessions: Arc<Sessions>,
}

impl AccessApi {
    fn claims<T>(&self, req: &Request<T>) -> Result<Claims, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("expected a Bearer access token"))?;
        let keys = self.keys.read().unwrap();
        if keys.verifier.is_empty() {
            return Err(Status::unavailable(
                "this node has not been given the orchestrator's access keys yet",
            ));
        }
        if keys.heard.is_none_or(|at| at.elapsed() > STALE_AFTER) {
            return Err(Status::unavailable(format!(
                "this node has not heard from the orchestrator in {}s, so it cannot tell \
                 which access tokens are revoked",
                STALE_AFTER.as_secs()
            )));
        }
        keys.verifier
            .verify(token, &self.api.node_id())
            .map_err(|err| Status::unauthenticated(err.to_string()))
    }

    /// Checks a call against its token and opens a session for it.
    ///
    /// The session is registered before the revocation stamp is read. A revoke
    /// writes the stamp before ending sessions, so a call racing one either
    /// sees the stamp or is already registered to be ended.
    async fn admit(&self, claims: &Claims, sandbox_id: &str, op: &str) -> Result<Held, Status> {
        permit(claims, sandbox_id, op)?;
        let held = self.sessions.open(sandbox_id);
        let sandbox = self.api.sandboxes.get(sandbox_id).await?;
        if claims.iat as i64 <= sandbox.record().access_revoked_at {
            return Err(revoked());
        }
        tracing::info!(
            sandbox = sandbox_id,
            op,
            jti = claims.jti,
            user = claims.user,
            "direct access"
        );
        Ok(held)
    }
}

fn permit(claims: &Claims, sandbox_id: &str, op: &str) -> Result<(), Status> {
    if claims.sub != sandbox_id {
        return Err(Status::permission_denied(
            "this access token is for another sandbox",
        ));
    }
    if !claims.allows(op) {
        return Err(Status::permission_denied(format!(
            "this access token does not allow {op}"
        )));
    }
    Ok(())
}

/// Passes `stream` on until its session is ended, then fails it.
fn until_ended<T: Send + 'static>(
    stream: impl Stream<Item = Result<T, Status>> + Send + 'static,
    held: Held,
) -> impl Stream<Item = Result<T, Status>> + Send + 'static {
    async_stream::stream! {
        let ended = held.session.ended.clone();
        tokio::pin!(stream);
        loop {
            tokio::select! {
                _ = ended.cancelled() => {
                    yield Err(revoked());
                    break;
                }
                item = stream.next() => match item {
                    Some(item) => yield item,
                    None => break,
                },
            }
        }
        drop(held);
    }
}

#[tonic::async_trait]
impl Access for AccessApi {
    type ExecStream = BoxStream<api::ExecOutput>;

    async fn exec(
        &self,
        req: Request<tonic::Streaming<api::ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let claims = self.claims(&req)?;
        let mut inbound = req.into_inner();
        let mut first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("Exec stream closed before Start"))?;
        let Some(api::exec_input::Input::Start(start)) = first.input.as_mut() else {
            return Err(Status::invalid_argument("first Exec message must be Start"));
        };
        // A token naming a user confines every command to it. One that names
        // none is root's, and root may run a command as anyone.
        if !claims.user.is_empty() {
            if start.user.is_empty() {
                start.user = claims.user.clone();
            } else if start.user != claims.user {
                return Err(Status::permission_denied(format!(
                    "this access token runs commands as {}",
                    claims.user
                )));
            }
        }
        let sandbox_id = start.sandbox_id.clone();
        let held = self.admit(&claims, &sandbox_id, OP_EXEC).await?;
        let inbound = tokio_stream::once(Ok(first)).chain(inbound);
        let output = self.api.exec_stream(Box::pin(inbound)).await?;

        // A command outlives the stream that started it, so ending the
        // session alone would leave whatever the revoked token ran still
        // running. It is killed too.
        let session = Arc::clone(&held.session);
        let api = Arc::clone(&self.api);
        let killer = held.session.ended.clone();
        tokio::spawn(async move {
            killer.cancelled().await;
            let command = session.command.lock().unwrap().take();
            if let Some(command_id) = command {
                let req = Request::new(api::SignalCommandRequest {
                    sandbox_id,
                    command_id,
                    signal: 0,
                });
                if let Err(err) = NodeService::signal_command(&*api, req).await {
                    tracing::warn!(%err, "could not kill a command started under a revoked token");
                }
            }
        });
        let session = Arc::clone(&held.session);
        let output = output.map(move |msg| {
            if let Ok(api::ExecOutput {
                output: Some(api::exec_output::Output::CommandId(id)),
            }) = &msg
            {
                *session.command.lock().unwrap() = Some(id.clone());
            }
            msg
        });
        Ok(Response::new(Box::pin(until_ended(output, held))))
    }

    type AttachStream = BoxStream<api::ExecOutput>;

    async fn attach(
        &self,
        req: Request<tonic::Streaming<api::AttachInput>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        let claims = self.claims(&req)?;
        let mut inbound = req.into_inner();
        let first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("Attach stream closed before Start"))?;
        let Some(api::attach_input::Input::Start(start)) = first.input.as_ref() else {
            return Err(Status::invalid_argument(
                "first Attach message must be Start",
            ));
        };
        let sandbox_id = start.sandbox_id.clone();
        let held = self.admit(&claims, &sandbox_id, OP_EXEC).await?;
        let inbound = tokio_stream::once(Ok(first)).chain(inbound);
        let output = self
            .api
            .attach_stream(Box::pin(inbound), claims.user)
            .await?;
        Ok(Response::new(Box::pin(until_ended(output, held))))
    }

    async fn upload_file(
        &self,
        req: Request<tonic::Streaming<api::FileChunk>>,
    ) -> Result<Response<api::UploadResult>, Status> {
        let claims = self.claims(&req)?;
        let mut inbound = req.into_inner();
        let first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("upload stream was empty"))?;
        let sandbox_id = first.sandbox_id.clone();
        let held = self.admit(&claims, &sandbox_id, OP_FILES_WRITE).await?;
        // Failing the inbound stream is what makes the upload end as cut
        // short, with the partial file removed, rather than as complete.
        let inbound = until_ended(tokio_stream::once(Ok(first)).chain(inbound), held);
        self.api
            .upload_stream(Box::pin(inbound), claims.user)
            .await
            .map(Response::new)
    }

    type DownloadFileStream = BoxStream<api::FileChunk>;

    async fn download_file(
        &self,
        req: Request<api::DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let claims = self.claims(&req)?;
        let req = req.into_inner();
        let held = self.admit(&claims, &req.sandbox_id, OP_FILES_READ).await?;
        let stream = self.api.download_as(req, claims.user).await?;
        Ok(Response::new(Box::pin(until_ended(stream, held))))
    }

    async fn list_dir(
        &self,
        req: Request<api::ListDirRequest>,
    ) -> Result<Response<api::ListDirResponse>, Status> {
        let claims = self.claims(&req)?;
        let req = req.into_inner();
        let _held = self.admit(&claims, &req.sandbox_id, OP_FILES_READ).await?;
        self.api
            .list_dir_as(req, claims.user)
            .await
            .map(Response::new)
    }

    type WatchStream = BoxStream<api::WatchEvent>;

    async fn watch(
        &self,
        req: Request<api::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let claims = self.claims(&req)?;
        let req = req.into_inner();
        let held = self.admit(&claims, &req.sandbox_id, OP_FILES_READ).await?;
        let stream = self.api.watch_as(req, claims.user).await?;
        Ok(Response::new(Box::pin(until_ended(stream, held))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(ops: &[&str]) -> Claims {
        Claims::new(
            "node_a",
            "sbx_a",
            ops.iter().map(|op| op.to_string()).collect(),
            String::new(),
            300,
        )
    }

    #[test]
    fn a_token_reaches_its_own_sandbox_only() {
        let held = claims(&[OP_EXEC]);
        assert!(permit(&held, "sbx_a", OP_EXEC).is_ok());
        assert_eq!(
            permit(&held, "sbx_b", OP_EXEC).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn a_token_does_only_what_it_names() {
        let held = claims(&[OP_FILES_READ]);
        assert!(permit(&held, "sbx_a", OP_FILES_READ).is_ok());
        assert!(permit(&held, "sbx_a", OP_FILES_WRITE).is_err());
        assert!(permit(&held, "sbx_a", OP_EXEC).is_err());
    }

    #[tokio::test]
    async fn ending_a_sandbox_s_sessions_fails_their_streams() {
        let sessions = Arc::new(Sessions::default());
        let held = sessions.open("sbx_a");
        let other = sessions.open("sbx_b");
        let pending = tokio_stream::pending::<Result<u32, Status>>();
        let mut stream = Box::pin(until_ended(pending, held));
        assert_eq!(sessions.end_all("sbx_a"), 1);
        let item = stream.next().await.unwrap();
        assert_eq!(item.unwrap_err().code(), tonic::Code::Unauthenticated);
        assert!(stream.next().await.is_none());
        assert!(!other.session.ended.is_cancelled());
    }

    #[tokio::test]
    async fn a_finished_session_leaves_the_registry() {
        let sessions = Arc::new(Sessions::default());
        drop(sessions.open("sbx_a"));
        assert_eq!(sessions.end_all("sbx_a"), 0);
    }
}
