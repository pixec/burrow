//! The `Guest` service, as every platform serves it.
//!
//! What a call means is the same on Linux and Windows; how it is done is the
//! platform's, in `crate::os`. The command registry, attach and the output
//! feed are the same code everywhere.

#![allow(clippy::result_large_err)]

use tonic::{Request, Response, Status};

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::guest_server::{Guest, GuestServer};

use crate::commands;
use crate::os;

#[derive(Default)]
struct AgentService;

/// The service, for a platform's listener to serve.
pub fn service() -> GuestServer<impl Guest> {
    GuestServer::new(AgentService)
}

#[tonic::async_trait]
impl Guest for AgentService {
    async fn handshake(
        &self,
        req: Request<guestpb::HandshakeRequest>,
    ) -> Result<Response<guestpb::HandshakeResponse>, Status> {
        let arrival = req.extensions().get::<os::Arrival>().copied();
        Ok(Response::new(
            os::handshake(arrival, req.into_inner()).await?,
        ))
    }

    /// Replaces this agent with the binary streamed in. Refused while a
    /// command is running, because its pipes and terminal live in this
    /// process.
    async fn upgrade(
        &self,
        req: Request<tonic::Streaming<guestpb::UpgradeChunk>>,
    ) -> Result<Response<guestpb::UpgradeResponse>, Status> {
        if commands::has_running() {
            return Err(Status::failed_precondition(
                "a command is running; the agent upgrades once it is idle",
            ));
        }
        Ok(Response::new(os::upgrade(req.into_inner()).await?))
    }

    async fn health(
        &self,
        _req: Request<guestpb::GuestHealthRequest>,
    ) -> Result<Response<guestpb::GuestHealthResponse>, Status> {
        Ok(Response::new(guestpb::GuestHealthResponse {
            features: os::features(),
        }))
    }

    type ExecStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::ExecOutput, Status>>;

    async fn exec(
        &self,
        req: Request<tonic::Streaming<guestpb::ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let rx = os::exec::run(req.into_inner()).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn upload_file(
        &self,
        req: Request<tonic::Streaming<guestpb::FileChunk>>,
    ) -> Result<Response<guestpb::UploadResult>, Status> {
        Ok(Response::new(os::files::upload(req.into_inner()).await?))
    }

    type DownloadFileStream =
        tokio_stream::wrappers::ReceiverStream<Result<guestpb::FileChunk, Status>>;

    async fn download_file(
        &self,
        req: Request<guestpb::DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let req = req.into_inner();
        let rx = os::files::download(req.path, &req.user).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::WatchEvent, Status>>;

    async fn watch(
        &self,
        req: Request<guestpb::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = req.into_inner();
        let interval = std::time::Duration::from_millis(if req.interval_ms == 0 {
            500
        } else {
            req.interval_ms.max(50) as u64
        });
        let rx = os::files::watch(req.path, req.is_recursive, interval, &req.user).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn list_dir(
        &self,
        req: Request<guestpb::ListDirRequest>,
    ) -> Result<Response<guestpb::ListDirResponse>, Status> {
        let req = req.into_inner();
        Ok(Response::new(
            os::files::list_dir(&req.path, &req.user).await?,
        ))
    }

    async fn fs(
        &self,
        req: Request<guestpb::FsRequest>,
    ) -> Result<Response<guestpb::FsResponse>, Status> {
        Ok(Response::new(os::fs::handle(req.into_inner()).await?))
    }

    async fn list_commands(
        &self,
        _req: Request<guestpb::ListCommandsRequest>,
    ) -> Result<Response<guestpb::ListCommandsResponse>, Status> {
        Ok(Response::new(commands::list()))
    }

    async fn get_command(
        &self,
        req: Request<guestpb::GetCommandRequest>,
    ) -> Result<Response<guestpb::CommandInfo>, Status> {
        Ok(Response::new(commands::get(&req.into_inner().command_id)?))
    }

    type AttachCommandStream =
        tokio_stream::wrappers::ReceiverStream<Result<guestpb::ExecOutput, Status>>;

    async fn attach_command(
        &self,
        req: Request<guestpb::AttachCommandRequest>,
    ) -> Result<Response<Self::AttachCommandStream>, Status> {
        let rx = commands::attach(&req.into_inner().command_id)?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type AttachStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::ExecOutput, Status>>;

    async fn attach(
        &self,
        req: Request<tonic::Streaming<guestpb::AttachInput>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        use guestpb::attach_input::Input as Attach;
        use guestpb::exec_input::Input as Exec;
        use tokio_stream::StreamExt as _;

        let mut inbound = req.into_inner();
        let Some(Attach::Start(start)) = inbound.next().await.transpose()?.and_then(|m| m.input)
        else {
            return Err(Status::invalid_argument(
                "first Attach message must be Start",
            ));
        };
        let rx = commands::attach(&start.command_id)?;
        // Looked up on the first input rather than now: following a command
        // that has finished is fine, and only feeding it is not.
        let id = start.command_id;
        tokio::spawn(async move {
            let mut input = None;
            while let Some(Ok(msg)) = inbound.next().await {
                let translated = match msg.input {
                    Some(Attach::Stdin(bytes)) => Exec::Stdin(bytes),
                    Some(Attach::Resize(size)) => Exec::Resize(size),
                    Some(Attach::Signal(signal)) => Exec::Signal(signal),
                    Some(Attach::IsStdinEof(eof)) => Exec::IsStdinEof(eof),
                    Some(Attach::Start(_)) | None => continue,
                };
                if input.is_none() {
                    match commands::input(&id) {
                        Ok(tx) => input = Some(tx),
                        Err(err) => {
                            tracing::debug!(%err, "input for a command that takes none");
                            return;
                        }
                    }
                }
                let msg = guestpb::ExecInput {
                    input: Some(translated),
                };
                // Waits for room rather than dropping: this task carries only
                // input, so a slow child holds up nobody's output.
                if let Some(tx) = &input
                    && tx.send(msg).await.is_err()
                {
                    return;
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn prune_commands(
        &self,
        _req: Request<guestpb::PruneCommandsRequest>,
    ) -> Result<Response<guestpb::PruneCommandsResponse>, Status> {
        Ok(Response::new(commands::prune()))
    }

    type FeedStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::FeedFrame, Status>>;

    async fn feed(
        &self,
        req: Request<tonic::Streaming<guestpb::FeedAck>>,
    ) -> Result<Response<Self::FeedStream>, Status> {
        let rx = commands::feed(req.into_inner()).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn signal_command(
        &self,
        req: Request<guestpb::SignalCommandRequest>,
    ) -> Result<Response<guestpb::SignalCommandResponse>, Status> {
        let req = req.into_inner();
        commands::signal(&req.command_id, req.signal)?;
        Ok(Response::new(guestpb::SignalCommandResponse {}))
    }

    async fn create_user(
        &self,
        req: Request<guestpb::CreateUserRequest>,
    ) -> Result<Response<guestpb::CreateUserResponse>, Status> {
        Ok(Response::new(
            os::users::create_user(&req.into_inner().name).await?,
        ))
    }

    async fn create_group(
        &self,
        req: Request<guestpb::CreateGroupRequest>,
    ) -> Result<Response<guestpb::CreateGroupResponse>, Status> {
        Ok(Response::new(
            os::users::create_group(&req.into_inner().name).await?,
        ))
    }

    async fn add_user_to_group(
        &self,
        req: Request<guestpb::GroupMembership>,
    ) -> Result<Response<guestpb::GroupMembershipResponse>, Status> {
        let req = req.into_inner();
        os::users::add_to_group(&req.user, &req.group).await?;
        Ok(Response::new(guestpb::GroupMembershipResponse {}))
    }

    async fn remove_user_from_group(
        &self,
        req: Request<guestpb::GroupMembership>,
    ) -> Result<Response<guestpb::GroupMembershipResponse>, Status> {
        let req = req.into_inner();
        os::users::remove_from_group(&req.user, &req.group).await?;
        Ok(Response::new(guestpb::GroupMembershipResponse {}))
    }
}
