//! Drives a guest agent end to end through a Firecracker-style vsock UDS, the
//! way burrowd reaches one: `CONNECT 1024\n`, `OK ...\n`, then gRPC.
//!
//! ```sh
//! cargo run -p burrow-guest --example guest_probe -- <dir>/vsock.sock [ca.pem] [upgrade-binary]
//! ```
//!
//! Every check prints `ok` or `FAIL` with what it saw, and the exit code is
//! the number that failed. It creates `/tmp/probe`, a user `probeuNNNN` and a
//! group `probegNNNN` in the guest, so run it against a scratch machine. Paths
//! and expectations are a macOS guest's (`sw_vers`, `/Users`); most hold on
//! Linux too.

#[cfg(unix)]
mod probe {
    use std::collections::HashMap;

    use burrow_proto::guest::v1 as pb;
    use burrow_proto::guest::v1::guest_client::GuestClient;
    use hyper_util::rt::TokioIo;
    use pb::exec_input::Input;
    use pb::exec_output::Output;
    use pb::fs_request::Op;
    use pb::fs_response::Result as Outcome;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio_stream::StreamExt as _;
    use tonic::transport::{Channel, Endpoint, Uri};

    type Client = GuestClient<Channel>;

    const O_WRONLY: u32 = 0o1;
    const O_RDWR: u32 = 0o2;
    const O_CREAT: u32 = 0o100;
    const O_TRUNC: u32 = 0o1000;
    const S_IFMT: u32 = 0o170000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFREG: u32 = 0o100000;

    struct Checks {
        failed: u32,
    }

    impl Checks {
        fn check(&mut self, what: &str, ok: bool, seen: impl std::fmt::Debug) {
            if ok {
                println!("ok    {what}");
            } else {
                self.failed += 1;
                println!("FAIL  {what}: {seen:?}");
            }
        }
    }

    async fn connect(uds: String) -> anyhow::Result<Client> {
        let channel = Endpoint::try_from("http://vsock.invalid")?
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let uds = uds.clone();
                async move {
                    let mut stream = tokio::net::UnixStream::connect(&uds).await?;
                    stream.write_all(b"CONNECT 1024\n").await?;
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).await?;
                    if !line.starts_with("OK") {
                        return Err(std::io::Error::other(format!("vsock said {line:?}")));
                    }
                    Ok::<_, std::io::Error>(TokioIo::new(reader.into_inner()))
                }
            }))
            .await?;
        Ok(GuestClient::new(channel).max_decoding_message_size(64 << 20))
    }

    /// What a command printed and how it ended.
    #[derive(Debug, Default)]
    struct Ran {
        id: String,
        stdout: String,
        stderr: String,
        code: Option<i32>,
        signal: i32,
    }

    async fn exec(client: &mut Client, start: pb::ExecStart, input: Vec<Input>) -> Ran {
        let mut messages = vec![pb::ExecInput {
            input: Some(Input::Start(start)),
        }];
        messages.extend(
            input
                .into_iter()
                .map(|input| pb::ExecInput { input: Some(input) }),
        );
        let mut ran = Ran::default();
        let mut stream = match client.exec(tokio_stream::iter(messages)).await {
            Ok(response) => response.into_inner(),
            Err(status) => {
                ran.stderr = status.to_string();
                return ran;
            }
        };
        while let Some(Ok(out)) = stream.next().await {
            match out.output {
                Some(Output::CommandId(id)) => ran.id = id,
                Some(Output::Stdout(bytes)) => ran.stdout += &String::from_utf8_lossy(&bytes),
                Some(Output::Stderr(bytes)) => ran.stderr += &String::from_utf8_lossy(&bytes),
                Some(Output::ExitSignal(signal)) => ran.signal = signal,
                Some(Output::ExitCode(code)) => {
                    ran.code = Some(code);
                    break;
                }
                _ => {}
            }
        }
        ran
    }

    fn argv(args: &[&str]) -> pb::ExecStart {
        pb::ExecStart {
            cmd: args.iter().map(|arg| arg.to_string()).collect(),
            ..Default::default()
        }
    }

    async fn sh(client: &mut Client, script: &str) -> Ran {
        exec(client, argv(&["/bin/sh", "-c", script]), vec![]).await
    }

    async fn fs(client: &mut Client, user: &str, scopes: &[&str], op: Op) -> Outcome {
        let request = pb::FsRequest {
            user: user.into(),
            path_scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            max_write_bytes: 0,
            op: Some(op),
        };
        match client.fs(request).await {
            Ok(response) => response.into_inner().result.expect("a result"),
            Err(status) => Outcome::Error(pb::FsError {
                code: format!("grpc {status}"),
                ..Default::default()
            }),
        }
    }

    fn code(outcome: &Outcome) -> &str {
        match outcome {
            Outcome::Error(err) => &err.code,
            _ => "",
        }
    }

    fn stat(path: &str, is_nofollow: bool) -> Op {
        Op::Stat(pb::FsStat {
            path: path.into(),
            is_nofollow,
        })
    }

    fn open(path: &str, flags: u32) -> Op {
        Op::Open(pb::FsOpen {
            path: path.into(),
            flags,
            mode: 0,
        })
    }

    async fn upload(
        client: &mut Client,
        path: &str,
        user: &str,
        data: &[u8],
    ) -> Result<u64, String> {
        let chunks = vec![
            pb::FileChunk {
                path: path.into(),
                user: user.into(),
                ..Default::default()
            },
            pb::FileChunk {
                data: data.to_vec(),
                ..Default::default()
            },
        ];
        client
            .upload_file(tokio_stream::iter(chunks))
            .await
            .map(|response| response.into_inner().bytes_written)
            .map_err(|status| status.message().to_string())
    }

    async fn download(client: &mut Client, path: &str, user: &str) -> Result<Vec<u8>, String> {
        let request = pb::DownloadRequest {
            path: path.into(),
            user: user.into(),
        };
        let mut stream = client
            .download_file(request)
            .await
            .map_err(|status| status.message().to_string())?
            .into_inner();
        let mut data = Vec::new();
        while let Some(chunk) = stream.next().await {
            data.extend(chunk.map_err(|status| status.message().to_string())?.data);
        }
        Ok(data)
    }

    pub async fn run(
        uds: String,
        ca: Option<String>,
        upgrade_binary: Option<String>,
    ) -> anyhow::Result<u32> {
        let mut client = connect(uds.clone()).await?;
        let mut c = Checks { failed: 0 };

        let health = client.health(pb::GuestHealthRequest {}).await?.into_inner();
        c.check(
            "health lists fs-scoped and files-as-user",
            health.features.iter().any(|f| f == "fs-scoped")
                && health.features.iter().any(|f| f == "files-as-user"),
            &health.features,
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as i64;
        let pem = match &ca {
            Some(path) => std::fs::read_to_string(path)?,
            None => String::new(),
        };
        let handshake = client
            .handshake(pb::HandshakeRequest {
                entropy: vec![7; 64],
                host_time_unix_nanos: now,
                is_restored: false,
                network: Some(pb::NetworkConfig {
                    ip: "192.168.64.6".into(),
                    prefix_len: 24,
                    gateway: "192.168.64.1".into(),
                    ..Default::default()
                }),
                inspection_ca_pem: pem.clone(),
                extra_trust_bundles: vec![pb::TrustBundle {
                    path: "/tmp/probe-extra-ca.pem".into(),
                    is_created_if_missing: true,
                }],
                volumes: vec![],
            })
            .await;
        let digest = match &handshake {
            Ok(response) => response.get_ref().agent_digest.clone(),
            Err(_) => String::new(),
        };
        c.check(
            "handshake answers with a version and digest",
            handshake
                .as_ref()
                .is_ok_and(|r| !r.get_ref().agent_version.is_empty() && digest.len() == 64),
            &handshake,
        );
        let clock = sh(&mut client, "date +%s").await;
        let guest_now: i64 = clock.stdout.trim().parse().unwrap_or_default();
        c.check(
            "the guest clock is the host's",
            (guest_now - now / 1_000_000_000).abs() <= 2,
            &clock,
        );
        if !pem.is_empty() {
            let trust = sh(
                &mut client,
                "grep -c 'BEGIN CERTIFICATE' /private/etc/ssl/certs/burrow-inspection-ca.pem; \
                 grep -c \"$(sed -n 2p /private/etc/ssl/certs/burrow-inspection-ca.pem)\" /etc/ssl/cert.pem; \
                 grep -c 'BEGIN CERTIFICATE' /tmp/probe-extra-ca.pem",
            )
            .await;
            c.check(
                "the ca is in its own file, the system bundle and the extra bundle",
                trust.stdout.split_whitespace().collect::<Vec<_>>() == ["1", "1", "1"],
                &trust,
            );
            let again = client
                .handshake(pb::HandshakeRequest {
                    inspection_ca_pem: pem.clone(),
                    ..Default::default()
                })
                .await;
            c.check(
                "a second handshake with the same ca succeeds",
                again.is_ok(),
                &again,
            );
        }
        let volumes = client
            .handshake(pb::HandshakeRequest {
                volumes: vec![pb::VolumeMount {
                    path: "/mnt/x".into(),
                    is_tmpfs: true,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .await;
        c.check(
            "a handshake with volumes is refused as unimplemented",
            volumes
                .as_ref()
                .is_err_and(|status| status.code() == tonic::Code::Unimplemented),
            &volumes,
        );

        let sw = exec(&mut client, argv(&["sw_vers"]), vec![]).await;
        c.check(
            "exec sw_vers",
            sw.code == Some(0) && sw.stdout.contains("ProductVersion"),
            &sw,
        );
        let both = sh(&mut client, "echo out; echo err >&2; exit 7").await;
        c.check(
            "exec keeps stdout and stderr apart and reports the code",
            both.stdout == "out\n" && both.stderr == "err\n" && both.code == Some(7),
            &both,
        );
        let stdin = exec(
            &mut client,
            argv(&["/bin/cat"]),
            vec![Input::Stdin(b"fed in".to_vec()), Input::IsStdinEof(true)],
        )
        .await;
        c.check("exec feeds stdin", stdin.stdout == "fed in", &stdin);

        let mut pty = argv(&[
            "/bin/sh",
            "-c",
            "tty; stty size; test -t 0 && echo interactive",
        ]);
        pty.is_pty = true;
        pty.rows = 30;
        pty.cols = 100;
        let pty = exec(&mut client, pty, vec![]).await;
        c.check(
            "a pty exec gets a terminal of the size asked",
            pty.code == Some(0)
                && pty.stdout.contains("/dev/ttys")
                && pty.stdout.contains("30 100")
                && pty.stdout.contains("interactive"),
            &pty,
        );
        let mut resized = argv(&["/bin/sh", "-c", "read x; stty size"]);
        resized.is_pty = true;
        let resized = exec(
            &mut client,
            resized,
            vec![
                Input::Resize(pb::ExecResize {
                    rows: 50,
                    cols: 132,
                }),
                Input::Stdin(b"go\n".to_vec()),
            ],
        )
        .await;
        c.check("a pty resizes", resized.stdout.contains("50 132"), &resized);

        // Signals go by Linux number: 10 is SIGUSR1, 30 on macOS.
        let mut other = client.clone();
        let trap = "trap 'echo got usr1; exit 3' USR1; while :; do sleep 0.1; done";
        let usr1 =
            tokio::spawn(
                async move { exec(&mut other, argv(&["/bin/sh", "-c", trap]), vec![]).await },
            );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let listed = client
            .list_commands(pb::ListCommandsRequest {})
            .await?
            .into_inner();
        let running = listed
            .commands
            .iter()
            .find(|cmd| cmd.state == "running" && cmd.cmd.iter().any(|arg| arg.contains("usr1")))
            .map(|cmd| cmd.command_id.clone());
        c.check(
            "list_commands shows the running command",
            running.is_some(),
            &listed,
        );
        if let Some(id) = &running {
            let sent = client
                .signal_command(pb::SignalCommandRequest {
                    command_id: id.clone(),
                    signal: 10,
                })
                .await;
            c.check(
                "signal_command with SIGUSR1 by its Linux number",
                sent.is_ok(),
                &sent,
            );
        }
        let usr1 = usr1.await?;
        c.check(
            "the trap saw SIGUSR1",
            usr1.stdout.contains("got usr1") && usr1.code == Some(3),
            &usr1,
        );
        let term = sh(&mut client, "kill -USR2 $$; sleep 5").await;
        c.check(
            "a command killed by SIGUSR2 reports Linux's 12, and 140",
            term.signal == 12 && term.code == Some(140),
            &term,
        );

        // The feed: everything so far is on it, unacknowledged.
        let (ack_tx, ack_rx) = tokio::sync::mpsc::channel(4);
        ack_tx
            .send(pb::FeedAck {
                seq: 0,
                positions: vec![],
            })
            .await?;
        let mut feed = client
            .feed(tokio_stream::wrappers::ReceiverStream::new(ack_rx))
            .await?
            .into_inner();
        let mut fed: HashMap<String, (String, Option<i32>)> = HashMap::new();
        let mut last = 0;
        while let Ok(Some(Ok(frame))) =
            tokio::time::timeout(std::time::Duration::from_millis(500), feed.next()).await
        {
            last = frame.seq;
            let entry = fed.entry(frame.command_id).or_default();
            match frame.output {
                Some(pb::feed_frame::Output::Stdout(bytes)) => {
                    entry.0 += &String::from_utf8_lossy(&bytes)
                }
                Some(pb::feed_frame::Output::Exit(exit)) => entry.1 = Some(exit.code),
                _ => {}
            }
        }
        c.check(
            "the feed carries sw_vers' output and exit",
            fed.get(&sw.id)
                .is_some_and(|(out, code)| out.contains("ProductVersion") && *code == Some(0)),
            fed.get(&sw.id),
        );
        let _ = ack_tx
            .send(pb::FeedAck {
                seq: last,
                positions: vec![],
            })
            .await;
        drop(feed);

        // Fs, with and without scopes, through /tmp, which macOS reads as
        // /private/tmp.
        let setup = sh(
            &mut client,
            "rm -rf /tmp/probe && mkdir -p /tmp/probe/scope/sub /tmp/probe/scopex /tmp/probe/outside && \
             echo secret > /tmp/probe/outside/secret && echo mine > /tmp/probe/scope/mine && \
             ln -s /tmp/probe/outside/secret /tmp/probe/scope/escape && \
             ln -s /tmp/probe/outside /tmp/probe/scope/dirlink && \
             ln -s mine /tmp/probe/scope/inside && chmod 777 /tmp/probe/scope",
        )
        .await;
        c.check("fs fixture", setup.code == Some(0), &setup);
        let scope = ["/tmp/probe/scope"];

        let opened = fs(
            &mut client,
            "",
            &scope,
            open("/tmp/probe/scope/f", O_RDWR | O_CREAT),
        )
        .await;
        let handle = match opened {
            Outcome::Handle(handle) => handle,
            _ => 0,
        };
        c.check("open O_RDWR|O_CREAT in scope", handle != 0, &opened);
        let wrote = fs(
            &mut client,
            "",
            &[],
            Op::Write(pb::FsWrite {
                handle,
                position: -1,
                data: b"hello fs".to_vec(),
            }),
        )
        .await;
        c.check("write", wrote == Outcome::Written(8), &wrote);
        let read = fs(
            &mut client,
            "",
            &[],
            Op::Read(pb::FsRead {
                handle,
                position: 6,
                length: 10,
            }),
        )
        .await;
        c.check("pread", read == Outcome::Data(b"fs".to_vec()), &read);
        let fstat = fs(&mut client, "", &[], Op::Fstat(pb::FsHandle { handle })).await;
        c.check(
            "fstat has size and a birth time",
            matches!(&fstat, Outcome::Stat(s) if s.size == 8 && s.birthtime_ns > 0),
            &fstat,
        );
        let closed = fs(&mut client, "", &[], Op::Close(pb::FsHandle { handle })).await;
        c.check("close", closed == Outcome::IsDone(true), &closed);

        let st = fs(&mut client, "", &scope, stat("/tmp/probe/scope/f", false)).await;
        c.check(
            "stat in scope",
            matches!(&st, Outcome::Stat(s) if s.mode & S_IFMT == S_IFREG),
            &st,
        );
        let inside = fs(
            &mut client,
            "",
            &scope,
            stat("/tmp/probe/scope/inside", false),
        )
        .await;
        c.check(
            "stat through a link that stays inside",
            matches!(inside, Outcome::Stat(_)),
            &inside,
        );
        for (what, op) in [
            (
                "stat through a link out of scope",
                stat("/tmp/probe/scope/escape", false),
            ),
            (
                "open through a link out of scope",
                open("/tmp/probe/scope/escape", 0),
            ),
            (
                "create through a directory link out of scope",
                open("/tmp/probe/scope/dirlink/new", O_WRONLY | O_CREAT),
            ),
            (
                "readdir through a directory link out of scope",
                Op::ReadDir(pb::FsReadDir {
                    path: "/tmp/probe/scope/dirlink".into(),
                }),
            ),
            (
                "chmod through a link out of scope",
                Op::Chmod(pb::FsChmod {
                    path: "/tmp/probe/scope/escape".into(),
                    mode: 0o777,
                }),
            ),
            (
                "truncate through a link out of scope",
                Op::Truncate(pb::FsTruncate {
                    path: "/tmp/probe/scope/escape".into(),
                    length: 0,
                }),
            ),
            (
                "realpath through a link out of scope",
                Op::Realpath(pb::FsRealpath {
                    path: "/tmp/probe/scope/escape".into(),
                }),
            ),
            (
                "utimes through a link out of scope",
                Op::Utimes(pb::FsUtimes {
                    path: "/tmp/probe/scope/escape".into(),
                    atime_ns: 0,
                    mtime_ns: 0,
                    is_nofollow: false,
                }),
            ),
            (
                "access through a link out of scope",
                Op::Access(pb::FsAccess {
                    path: "/tmp/probe/scope/escape".into(),
                    mode: 4,
                }),
            ),
            (
                "chown through a link out of scope",
                Op::Chown(pb::FsChown {
                    path: "/tmp/probe/scope/escape".into(),
                    uid: 0,
                    gid: 0,
                    is_nofollow: false,
                }),
            ),
            ("a sibling of the scope", stat("/tmp/probe/scopex", false)),
            (
                "a parent reference out of scope",
                stat("/tmp/probe/scope/../outside/secret", false),
            ),
        ] {
            let outcome = fs(&mut client, "", &scope, op).await;
            c.check(what, code(&outcome) == "EACCES", &outcome);
        }
        let secret = sh(&mut client, "cat /tmp/probe/outside/secret; ls /tmp/probe/outside; stat -f %p /tmp/probe/outside/secret").await;
        c.check(
            "nothing outside the scope changed",
            secret.stdout == "secret\nsecret\n100644\n",
            &secret,
        );
        let lstat = fs(
            &mut client,
            "",
            &scope,
            stat("/tmp/probe/scope/escape", true),
        )
        .await;
        c.check(
            "lstat of the link itself is in scope",
            matches!(&lstat, Outcome::Stat(s) if s.mode & S_IFMT == S_IFLNK),
            &lstat,
        );
        let unscoped = fs(&mut client, "", &[], stat("/tmp/probe/scope/escape", false)).await;
        c.check(
            "without scopes the link is followed",
            matches!(unscoped, Outcome::Stat(_)),
            &unscoped,
        );
        let listed = fs(
            &mut client,
            "",
            &scope,
            Op::ReadDir(pb::FsReadDir {
                path: "/tmp/probe/scope".into(),
            }),
        )
        .await;
        let names = match &listed {
            Outcome::Entries(entries) => {
                let mut names: Vec<_> = entries
                    .entries
                    .iter()
                    .map(|e| format!("{}:{}", e.name, e.r#type))
                    .collect();
                names.sort();
                names
            }
            _ => vec![],
        };
        c.check(
            "readdir in scope",
            names
                == [
                    "dirlink:symlink",
                    "escape:symlink",
                    "f:file",
                    "inside:symlink",
                    "mine:file",
                    "sub:dir",
                ],
            &listed,
        );
        let real = fs(
            &mut client,
            "",
            &[],
            Op::Realpath(pb::FsRealpath {
                path: "/tmp/probe/scope/inside".into(),
            }),
        )
        .await;
        c.check(
            "realpath resolves /tmp into /private",
            real == Outcome::Path("/private/tmp/probe/scope/mine".into()),
            &real,
        );
        let made = fs(
            &mut client,
            "",
            &scope,
            Op::Mkdir(pb::FsMkdir {
                path: "/tmp/probe/scope/a/b".into(),
                mode: 0,
                is_recursive: true,
            }),
        )
        .await;
        c.check(
            "mkdir -p reports the first directory made",
            made == Outcome::Path("/tmp/probe/scope/a".into()),
            &made,
        );
        let renamed = fs(
            &mut client,
            "",
            &scope,
            Op::Rename(pb::FsRename {
                src: "/tmp/probe/scope/f".into(),
                dst: "/tmp/probe/scope/a/b/g".into(),
            }),
        )
        .await;
        c.check(
            "rename in scope",
            renamed == Outcome::IsDone(true),
            &renamed,
        );
        let unlinked = fs(
            &mut client,
            "",
            &scope,
            Op::Remove(pb::FsRemove {
                path: "/tmp/probe/scope/a".into(),
                ..Default::default()
            }),
        )
        .await;
        c.check(
            "unlink of a directory is EISDIR",
            code(&unlinked) == "EISDIR",
            &unlinked,
        );
        let removed = fs(
            &mut client,
            "",
            &scope,
            Op::Remove(pb::FsRemove {
                path: "/tmp/probe/scope/a".into(),
                is_recursive: true,
                ..Default::default()
            }),
        )
        .await;
        c.check("rm -r in scope", removed == Outcome::IsDone(true), &removed);
        let looped = fs(&mut client, "", &[], open("/tmp/probe/scope/sub", O_WRONLY)).await;
        c.check(
            "an errno is named and numbered as Linux's",
            matches!(&looped, Outcome::Error(e) if e.code == "EISDIR" && e.errno == 21),
            &looped,
        );
        let elooped = sh(&mut client, "ln -sf loop /tmp/probe/scope/loop").await;
        let elooped_open = fs(&mut client, "", &[], open("/tmp/probe/scope/loop", 0)).await;
        c.check(
            "ELOOP carries Linux's 40",
            elooped.code == Some(0)
                && matches!(&elooped_open, Outcome::Error(e) if e.code == "ELOOP" && e.errno == 40),
            &elooped_open,
        );

        // Upload and download, which refuse every link.
        let up = upload(
            &mut client,
            "/tmp/probe/up/nested/file.txt",
            "",
            b"uploaded",
        )
        .await;
        c.check("upload creates parents under /tmp", up == Ok(8), &up);
        let down = download(&mut client, "/tmp/probe/up/nested/file.txt", "").await;
        c.check(
            "download",
            down.as_deref() == Ok(b"uploaded".as_slice()),
            &down,
        );
        let through = upload(&mut client, "/tmp/probe/scope/dirlink/planted", "", b"x").await;
        c.check(
            "upload through a link is refused",
            through.is_err(),
            &through,
        );
        let leaked = download(&mut client, "/tmp/probe/scope/escape", "").await;
        c.check(
            "download through a link is refused",
            leaked.is_err(),
            &leaked,
        );
        let planted = sh(
            &mut client,
            "test -e /tmp/probe/outside/planted && echo planted",
        )
        .await;
        c.check(
            "nothing was planted outside",
            planted.stdout.is_empty(),
            &planted,
        );
        let ls = client
            .list_dir(pb::ListDirRequest {
                path: "/tmp/probe/up/nested".into(),
                user: String::new(),
            })
            .await
            .map(|r| r.into_inner().entries.len());
        c.check("list_dir", ls.as_ref().is_ok_and(|n| *n == 1), &ls);

        // Users.
        // Named afresh each run: the agent's directory lookups are cached in
        // its process, and an account deleted behind its back stays found.
        let tag = std::process::id() % 100_000;
        let (name, group_name) = (format!("probeu{tag}"), format!("probeg{tag}"));
        let home = format!("/Users/{name}");
        let shared_dir = format!("/Users/Shared/{group_name}");
        let user = client
            .create_user(pb::CreateUserRequest { name: name.clone() })
            .await
            .map(|r| r.into_inner());
        c.check(
            "create_user",
            user.as_ref().is_ok_and(|u| u.uid >= 501 && u.home == home),
            &user,
        );
        let (uid, gid) = user.as_ref().map_or((0, 0), |u| (u.uid, u.gid));
        let mut as_user = argv(&["/bin/sh", "-c", "id -u; id -g; pwd; echo $HOME $USER"]);
        as_user.user = name.clone();
        let as_user = exec(&mut client, as_user, vec![]).await;
        c.check(
            "exec as the user",
            as_user.stdout == format!("{uid}\n{gid}\n{home}\n{home} {name}\n"),
            &as_user,
        );
        let mut pty_user = argv(&["/bin/sh", "-c", "stat -f %Su $(tty)"]);
        pty_user.user = name.clone();
        pty_user.is_pty = true;
        let pty_user = exec(&mut client, pty_user, vec![]).await;
        c.check(
            "a pty as the user is the user's",
            pty_user.stdout.trim() == name,
            &pty_user,
        );
        let _ = sh(
            &mut client,
            "echo root > /tmp/probe/rootonly && chmod 600 /tmp/probe/rootonly",
        )
        .await;
        let denied = fs(&mut client, &name, &[], open("/tmp/probe/rootonly", 0)).await;
        c.check(
            "fs as the user is held to the user's permissions",
            code(&denied) == "EACCES",
            &denied,
        );
        let created = fs(
            &mut client,
            &name,
            &[],
            open(&format!("{home}/mine"), O_WRONLY | O_CREAT | O_TRUNC),
        )
        .await;
        c.check(
            "fs as the user creates in their home",
            matches!(created, Outcome::Handle(_)),
            &created,
        );
        let owned = fs(&mut client, "", &[], stat(&format!("{home}/mine"), false)).await;
        c.check(
            "what the user created is theirs",
            matches!(&owned, Outcome::Stat(s) if s.uid == uid),
            &owned,
        );
        let access = fs(
            &mut client,
            &name,
            &[],
            Op::Access(pb::FsAccess {
                path: "/tmp/probe/rootonly".into(),
                mode: 4,
            }),
        )
        .await;
        c.check(
            "access as the user checks the user",
            code(&access) == "EACCES",
            &access,
        );
        let up_user = upload(&mut client, &format!("{home}/up.txt"), &name, b"by user").await;
        let up_owner = sh(&mut client, &format!("stat -f %Su {home}/up.txt")).await;
        c.check(
            "upload as the user is the user's",
            up_user == Ok(7) && up_owner.stdout.trim() == name,
            (&up_user, &up_owner),
        );
        let down_denied = download(&mut client, "/tmp/probe/rootonly", &name).await;
        c.check(
            "download as the user is refused a root-only file",
            down_denied.is_err(),
            &down_denied,
        );
        let still_root = sh(&mut client, "id -u").await;
        c.check(
            "the agent is still root",
            still_root.stdout == "0\n",
            &still_root,
        );

        let group = client
            .create_group(pb::CreateGroupRequest {
                name: group_name.clone(),
            })
            .await
            .map(|r| r.into_inner());
        c.check(
            "create_group",
            group.as_ref().is_ok_and(|g| g.shared_dir == shared_dir),
            &group,
        );
        let joined = client
            .add_user_to_group(pb::GroupMembership {
                user: name.clone(),
                group: group_name.clone(),
            })
            .await;
        c.check("add_user_to_group", joined.is_ok(), &joined);
        let mut groups = argv(&["/usr/bin/id", "-Gn"]);
        groups.user = name.clone();
        let groups = exec(&mut client, groups, vec![]).await;
        c.check(
            "exec as the user has the group",
            groups.stdout.contains(&group_name),
            &groups,
        );
        let shared = fs(
            &mut client,
            &name,
            &[],
            open(&format!("{shared_dir}/shared"), O_WRONLY | O_CREAT),
        )
        .await;
        c.check(
            "fs as the user writes in the group's directory",
            matches!(shared, Outcome::Handle(_)),
            &shared,
        );
        let left = client
            .remove_user_from_group(pb::GroupMembership {
                user: name.clone(),
                group: group_name.clone(),
            })
            .await;
        let shut_out = fs(
            &mut client,
            &name,
            &[],
            open(&format!("{shared_dir}/other"), O_WRONLY | O_CREAT),
        )
        .await;
        c.check(
            "after leaving the group the user is shut out",
            left.is_ok() && code(&shut_out) == "EACCES",
            (&left, &shut_out),
        );

        if let Some(binary) = upgrade_binary {
            use sha2::Digest as _;
            let bytes = std::fs::read(&binary)?;
            let new_digest: String = sha2::Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let opened = fs(&mut client, "", &[], open("/tmp/probe/scope/mine", 0)).await;
            let kept = match opened {
                Outcome::Handle(handle) => handle,
                _ => 0,
            };
            let chunks: Vec<_> = bytes
                .chunks(64 << 10)
                .enumerate()
                .map(|(i, data)| pb::UpgradeChunk {
                    data: data.to_vec(),
                    digest: if i == 0 {
                        new_digest.clone()
                    } else {
                        String::new()
                    },
                })
                .collect();
            let upgraded = client.upgrade(tokio_stream::iter(chunks)).await;
            c.check(
                "upgrade restarts into a different binary",
                upgraded.as_ref().is_ok_and(|r| r.get_ref().is_restarting),
                &upgraded,
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let mut client = connect(uds).await?;
            let after = client.handshake(pb::HandshakeRequest::default()).await;
            c.check(
                "the agent came back as the new binary",
                after
                    .as_ref()
                    .is_ok_and(|r| r.get_ref().agent_digest == new_digest && new_digest != digest),
                &after,
            );
            let read = fs(
                &mut client,
                "",
                &[],
                Op::Read(pb::FsRead {
                    handle: kept,
                    position: 0,
                    length: 4,
                }),
            )
            .await;
            c.check(
                "an open handle survived the upgrade",
                read == Outcome::Data(b"mine".to_vec()),
                &read,
            );
            let history = client
                .get_command(pb::GetCommandRequest {
                    command_id: sw.id.clone(),
                })
                .await;
            c.check(
                "the command table survived the upgrade",
                history.is_ok(),
                &history,
            );
        }

        Ok(c.failed)
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(uds) = args.next() else {
        anyhow::bail!("usage: guest_probe <vsock.sock> [ca.pem] [upgrade-binary]");
    };
    let failed = probe::run(uds, args.next(), args.next()).await?;
    println!("{failed} failed");
    std::process::exit(failed as i32);
}

#[cfg(not(unix))]
fn main() {
    eprintln!("guest_probe dials a vsock UDS, which needs a Unix host");
}
