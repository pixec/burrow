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
        .max_decoding_message_size(burrow_proto::MAX_MESSAGE_BYTES)
        .max_encoding_message_size(burrow_proto::MAX_MESSAGE_BYTES)
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

    async fn set_public_addresses(
        &self,
        req: Request<guestpb::NetworkConfig>,
    ) -> Result<Response<guestpb::SetPublicAddressesResponse>, Status> {
        os::set_public_addresses(req.into_inner()).await?;
        Ok(Response::new(guestpb::SetPublicAddressesResponse {}))
    }

    async fn clear_network(
        &self,
        _req: Request<guestpb::ClearNetworkRequest>,
    ) -> Result<Response<guestpb::ClearNetworkResponse>, Status> {
        os::clear_network().await?;
        Ok(Response::new(guestpb::ClearNetworkResponse {}))
    }

    async fn root_disk(
        &self,
        req: Request<guestpb::RootDiskRequest>,
    ) -> Result<Response<guestpb::RootDiskResponse>, Status> {
        Ok(Response::new(os::root_disk(req.into_inner()).await?))
    }

    async fn sync_clock(
        &self,
        req: Request<guestpb::SyncClockRequest>,
    ) -> Result<Response<guestpb::SyncClockResponse>, Status> {
        Ok(Response::new(crate::clock::sync(req.into_inner())?))
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

    async fn delete_user(
        &self,
        req: Request<guestpb::DeleteUserRequest>,
    ) -> Result<Response<guestpb::DeleteUserResponse>, Status> {
        let req = req.into_inner();
        let running = commands::list().commands.into_iter().any(|command| {
            command.state == guestpb::CommandState::Running as i32
                && command
                    .user
                    .split(':')
                    .next()
                    .is_some_and(|user| user.eq_ignore_ascii_case(&req.name))
        });
        if running {
            return Err(Status::failed_precondition(format!(
                "user {} has running commands; end them first",
                req.name
            )));
        }
        Ok(Response::new(
            os::users::delete_user(&req.name, req.is_home_removed).await?,
        ))
    }

    async fn delete_group(
        &self,
        req: Request<guestpb::DeleteGroupRequest>,
    ) -> Result<Response<guestpb::DeleteGroupResponse>, Status> {
        let req = req.into_inner();
        Ok(Response::new(
            os::users::delete_group(&req.name, req.is_shared_dir_removed).await?,
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use burrow_proto::guest::v1::guest_client::GuestClient;
    use burrow_proto::{MAX_FILE_CHUNK, MAX_MESSAGE_BYTES};
    use guestpb::fs_request::Op;
    use guestpb::fs_response::Result as Outcome;
    use tokio_stream::StreamExt;

    use super::*;

    /// The agent over a real connection, with the client the node builds.
    async fn agent() -> GuestClient<tonic::transport::Channel> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service())
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
        );
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        GuestClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }

    async fn fs(agent: &mut GuestClient<tonic::transport::Channel>, op: Op) -> Outcome {
        agent
            .fs(guestpb::FsRequest {
                op: Some(op),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow-agent-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A full chunk, which gRPC's 4 MiB default refused once the fields
    /// around it were counted, is written and read back in one call each.
    #[tokio::test]
    async fn a_full_chunk_is_written_and_read_in_one_call() {
        let mut agent = agent().await;
        let dir = scratch("fs");
        let path = dir.join("f").to_str().unwrap().to_string();
        let data: Vec<u8> = (0..MAX_FILE_CHUNK).map(|i| i as u8).collect();
        // O_RDWR | O_CREAT | O_TRUNC, in the guest's Linux numbering.
        let Outcome::Handle(handle) = fs(
            &mut agent,
            Op::Open(guestpb::FsOpen {
                path,
                flags: 0o2 | 0o100 | 0o1000,
                mode: 0,
            }),
        )
        .await
        else {
            panic!("open failed");
        };
        let written = fs(
            &mut agent,
            Op::Write(guestpb::FsWrite {
                handle,
                position: 0,
                data: data.clone(),
            }),
        )
        .await;
        assert_eq!(written, Outcome::Written(MAX_FILE_CHUNK as u64));
        let read = fs(
            &mut agent,
            Op::Read(guestpb::FsRead {
                handle,
                position: 0,
                length: MAX_FILE_CHUNK as u32,
            }),
        )
        .await;
        assert!(read == Outcome::Data(data), "read back something else");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An upload whose chunk is a full one lands whole, and comes back.
    #[tokio::test]
    async fn a_full_upload_chunk_is_accepted() {
        let mut agent = agent().await;
        let dir = scratch("upload");
        let path = dir.join("f").to_str().unwrap().to_string();
        let data = vec![7u8; MAX_FILE_CHUNK];
        let chunks = vec![
            guestpb::FileChunk {
                path: path.clone(),
                ..Default::default()
            },
            guestpb::FileChunk {
                data: data.clone(),
                ..Default::default()
            },
        ];
        let result = agent
            .upload_file(tokio_stream::iter(chunks))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.bytes_written, MAX_FILE_CHUNK as u64);
        let mut stream = agent
            .download_file(guestpb::DownloadRequest {
                path,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let mut back = Vec::new();
        while let Some(chunk) = stream.next().await {
            back.extend(chunk.unwrap().data);
        }
        assert!(back == data, "downloaded something else");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A message past the limit, from a client that does not hold itself to
    /// it, is refused saying so.
    #[tokio::test]
    async fn a_message_past_the_limit_is_refused() {
        let mut agent = agent().await.max_encoding_message_size(usize::MAX);
        let err = agent
            .fs(guestpb::FsRequest {
                op: Some(Op::Write(guestpb::FsWrite {
                    data: vec![0; MAX_MESSAGE_BYTES],
                    ..Default::default()
                })),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err}");
        assert!(err.message().contains("too large"), "{err}");
    }
}
