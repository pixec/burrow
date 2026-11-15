//! Starting a reader and asking it things.

use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::process::Stdio;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::protocol::{Entry, MAX_FRAME, Request, Stat, Tag, TarSummary};

/// What a reader may use of the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub memory_mib: u64,
    /// CPU time over the reader's whole life.
    pub cpu_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_mib: 512,
            cpu_secs: 600,
        }
    }
}

impl Limits {
    fn to_args(self) -> [String; 2] {
        [self.memory_mib.to_string(), self.cpu_secs.to_string()]
    }

    pub(crate) fn from_args(args: &[String]) -> std::io::Result<Self> {
        let number = |at: usize| {
            args.get(at)
                .and_then(|arg| arg.parse().ok())
                .ok_or_else(|| std::io::Error::other("usage: disk-reader <memory-mib> <cpu-secs>"))
        };
        Ok(Self {
            memory_mib: number(0)?,
            cpu_secs: number(1)?,
        })
    }
}

/// A running reader, which goes when this is dropped.
pub struct Reader {
    child: tokio::process::Child,
    requests: tokio::process::ChildStdin,
    answers: tokio::io::BufReader<tokio::process::ChildStdout>,
}

impl Reader {
    /// Starts `exe` as a reader of the image at `image`, which it is handed
    /// open read-only.
    pub fn spawn(exe: &Path, image: &Path, limits: Limits) -> std::io::Result<Self> {
        let image = std::fs::File::open(image)?;
        let fd = image.as_raw_fd();
        let mut command = tokio::process::Command::new(exe);
        command
            .arg(crate::SUBCOMMAND)
            .args(limits.to_args())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                let target = crate::server::IMAGE_FD;
                let rc = match fd == target {
                    true => libc::fcntl(fd, libc::F_SETFD, 0),
                    false => libc::dup2(fd, target),
                };
                match rc < 0 {
                    true => Err(std::io::Error::last_os_error()),
                    false => Ok(()),
                }
            });
        }
        let mut child = command.spawn()?;
        drop(image);
        let requests = child.stdin.take().expect("stdin is piped");
        let answers = tokio::io::BufReader::new(child.stdout.take().expect("stdout is piped"));
        Ok(Self {
            child,
            requests,
            answers,
        })
    }

    /// The reader's process id, while it runs.
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    pub async fn list(&mut self, path: &str) -> Result<Vec<Entry>, String> {
        self.ask(Request::ListDir { path: path.into() }).await?;
        self.reply().await
    }

    pub async fn stat(&mut self, path: &str) -> Result<Stat, String> {
        self.ask(Request::Stat { path: path.into() }).await?;
        self.reply().await
    }

    /// Up to `len` bytes of the file at `path` from `offset`.
    pub async fn read(&mut self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        self.ask(Request::Read {
            path: path.into(),
            offset,
            len,
        })
        .await?;
        let mut bytes = Vec::new();
        loop {
            let (tag, payload) = self.frame().await?;
            match tag {
                Tag::Data => bytes.extend_from_slice(&payload),
                Tag::End => return Ok(bytes),
                _ => return Err(unexpected(tag, &payload)),
            }
        }
    }

    /// Streams the tree at `path` as a tar archive into `chunks`.
    pub async fn tar(
        &mut self,
        path: &str,
        max_bytes: u64,
        max_entries: u64,
        chunks: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<TarSummary, String> {
        self.ask(Request::Tar {
            path: path.into(),
            max_bytes,
            max_entries,
        })
        .await?;
        loop {
            let (tag, payload) = self.frame().await?;
            match tag {
                Tag::Data => chunks
                    .send(payload)
                    .await
                    .map_err(|_| crate::RECEIVER_GONE.to_string())?,
                Tag::End => return serde_json::from_slice(&payload).map_err(|err| err.to_string()),
                _ => return Err(unexpected(tag, &payload)),
            }
        }
    }

    async fn ask(&mut self, request: Request) -> Result<(), String> {
        let payload = serde_json::to_vec(&request).map_err(|err| err.to_string())?;
        let mut frame = vec![Tag::Request as u8];
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        if self.requests.write_all(&frame).await.is_err() {
            return Err(self.died().await);
        }
        Ok(())
    }

    async fn reply<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, String> {
        let (tag, payload) = self.frame().await?;
        match tag {
            Tag::Reply => serde_json::from_slice(&payload).map_err(|err| err.to_string()),
            _ => Err(unexpected(tag, &payload)),
        }
    }

    async fn frame(&mut self) -> Result<(Tag, Vec<u8>), String> {
        let mut header = [0; 5];
        if self.answers.read_exact(&mut header).await.is_err() {
            return Err(self.died().await);
        }
        let tag = match header[0] {
            1 => Tag::Reply,
            2 => Tag::Data,
            3 => Tag::End,
            4 => Tag::Error,
            _ => return Err("the disk reader sent something it should not".into()),
        };
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len > MAX_FRAME {
            return Err("the disk reader sent something it should not".into());
        }
        let mut payload = vec![0; len];
        if self.answers.read_exact(&mut payload).await.is_err() {
            return Err(self.died().await);
        }
        Ok((tag, payload))
    }

    /// Why the reader stopped answering, from how it exited and what it
    /// said last.
    async fn died(&mut self) -> String {
        let mut said = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let mut bytes = Vec::new();
            let _ = (&mut stderr).take(4096).read_to_end(&mut bytes).await;
            said = String::from_utf8_lossy(&bytes).trim().to_string();
        }
        let status = match self.child.wait().await {
            Ok(status) => describe(status),
            Err(err) => err.to_string(),
        };
        match said.is_empty() {
            true => format!("the disk reader {status}"),
            false => format!("the disk reader {status}: {said}"),
        }
    }
}

fn describe(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt as _;
    match (status.code(), status.signal()) {
        (_, Some(libc::SIGSYS)) => "was killed for a system call it may not make".into(),
        (_, Some(libc::SIGXCPU)) => "ran out of CPU time".into(),
        (_, Some(signal)) => format!("was killed by signal {signal}"),
        (Some(code), _) => format!("exited with {code}"),
        (None, None) => "stopped".into(),
    }
}

fn unexpected(tag: Tag, payload: &[u8]) -> String {
    match tag {
        Tag::Error => String::from_utf8_lossy(payload).into_owned(),
        _ => "the disk reader answered out of turn".into(),
    }
}
