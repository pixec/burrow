//! A guest's serial console, captured to a bounded log in its working
//! directory.
//!
//! The VMM's output is copied rather than written straight to a file, so the
//! log can roll over: a guest printing to its console for weeks holds at most
//! twice [`MAX_BYTES`] on the node. Each VMM start begins the log afresh.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

pub const LOG: &str = "console.log";
/// Where the log rolls over to once it passes [`MAX_BYTES`].
pub const ROTATED: &str = "console.log.1";
pub const MAX_BYTES: u64 = 1 << 20;

/// The tasks copying a VMM's output into its console log.
pub struct Capture {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Capture {
    /// Stops copying, for a source that never closes on its own.
    pub fn abort(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }

    #[cfg(test)]
    async fn finished(self) {
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Starts the log in `workdir` over and copies each of `sources` into it
/// until they all close, rolling it over at [`MAX_BYTES`].
pub fn capture<R>(workdir: &Path, sources: Vec<R>) -> std::io::Result<Capture>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let path = workdir.join(LOG);
    let rotated = workdir.join(ROTATED);
    let _ = std::fs::remove_file(&rotated);
    let file = std::fs::File::create(&path)?;
    let (chunks, mut received) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let mut tasks = Vec::new();
    for mut source in sources {
        let chunks = chunks.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0; 8192];
            while let Ok(n @ 1..) = source.read(&mut buf).await {
                if chunks.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        }));
    }
    drop(chunks);
    tasks.push(tokio::spawn(async move {
        let mut file = tokio::fs::File::from_std(file);
        let mut size = 0u64;
        while let Some(chunk) = received.recv().await {
            if size > 0 && size + chunk.len() as u64 > MAX_BYTES {
                let _ = file.flush().await;
                match roll_over(&path, &rotated).await {
                    Ok(fresh) => (file, size) = (fresh, 0),
                    Err(err) => {
                        tracing::warn!(path = %path.display(), %err, "could not roll the console log over");
                        return;
                    }
                }
            }
            // Flushed as it goes, so a reader of the log sees what the guest
            // just printed.
            if file.write_all(&chunk).await.is_err() || file.flush().await.is_err() {
                return;
            }
            size += chunk.len() as u64;
        }
    }));
    Ok(Capture { tasks })
}

async fn roll_over(path: &PathBuf, rotated: &PathBuf) -> std::io::Result<tokio::fs::File> {
    tokio::fs::rename(path, rotated).await?;
    tokio::fs::File::create(path).await
}

/// The last `max_bytes` the guest wrote to its console, across a rollover,
/// and whether there was more before them.
pub async fn tail_bytes(workdir: &Path, max_bytes: u64) -> (String, bool) {
    let current = read_tail(&workdir.join(LOG), max_bytes).await;
    let mut bytes = current.0;
    let mut is_truncated = current.1;
    if !is_truncated && (bytes.len() as u64) < max_bytes {
        let (earlier, earlier_truncated) =
            read_tail(&workdir.join(ROTATED), max_bytes - bytes.len() as u64).await;
        if !earlier.is_empty() {
            is_truncated = earlier_truncated;
            bytes = [earlier, bytes].concat();
        }
    }
    (String::from_utf8_lossy(&bytes).into_owned(), is_truncated)
}

/// The last `lines` lines of the console; `usize::MAX` reads all of it.
pub async fn tail(workdir: &Path, lines: usize) -> String {
    let max_bytes = match lines {
        usize::MAX => 2 * MAX_BYTES,
        _ => 64 * 1024,
    };
    let (text, _) = tail_bytes(workdir, max_bytes).await;
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

async fn read_tail(path: &Path, max_bytes: u64) -> (Vec<u8>, bool) {
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return (Vec::new(), false);
    };
    let len = file.metadata().await.map_or(0, |meta| meta.len());
    let start = len.saturating_sub(max_bytes);
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return (Vec::new(), false);
    }
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes).await;
    (bytes, start > 0)
}

/// The line a panicking guest kernel printed, if the console holds one.
pub fn kernel_panic(console: &str) -> Option<&str> {
    console
        .lines()
        .find(|line| line.contains("Kernel panic - not syncing"))
        .map(str::trim)
}

/// The line a guest kernel reported a crash on, if the console holds one: an
/// oops, a `BUG:` other than a lockup report it recovers from, or a panic.
/// Only kernel lines count, which carry the kernel's timestamp.
pub fn kernel_crash(console: &str) -> Option<&str> {
    console.lines().find_map(|line| {
        let message = line.trim_start().strip_prefix('[')?.split_once(']')?;
        message.0.trim().parse::<f64>().ok()?;
        let message = message.1.trim_start();
        let is_crash = message.starts_with("Oops")
            || message.starts_with("Internal error: Oops")
            || message.starts_with("Kernel panic - not syncing")
            || (message.starts_with("BUG: ") && !message.contains("lockup"));
        is_crash.then(|| line.trim())
    })
}

/// How often [`wait_for_kernel_crash`] reads what the guest wrote.
const CRASH_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Waits until the console in `workdir` shows a [`kernel_crash`], and returns
/// its line. Never returns for a guest that does not crash.
pub async fn wait_for_kernel_crash(workdir: &Path) -> String {
    let path = workdir.join(LOG);
    let (mut read, mut pending) = (0u64, Vec::new());
    loop {
        if let Ok(mut file) = tokio::fs::File::open(&path).await {
            let len = file.metadata().await.map_or(0, |meta| meta.len());
            if len < read {
                (read, pending) = (0, Vec::new());
            }
            if len > read && file.seek(std::io::SeekFrom::Start(read)).await.is_ok() {
                let before = pending.len();
                let _ = file.read_to_end(&mut pending).await;
                read += (pending.len() - before) as u64;
                if let Some(end) = pending.iter().rposition(|byte| *byte == b'\n') {
                    let lines = String::from_utf8_lossy(&pending[..end]).into_owned();
                    if let Some(line) = kernel_crash(&lines) {
                        return line.to_string();
                    }
                    pending.drain(..=end);
                }
            }
        }
        tokio::time::sleep(CRASH_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("burrow-console-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A guest that never stops printing holds at most twice the cap, and
    /// the tail still ends at what it printed last.
    #[tokio::test]
    async fn a_chatty_console_rolls_over_and_stays_bounded() {
        let dir = workdir("chatty");
        let line = vec![b'x'; 1023];
        let mut output = Vec::new();
        for i in 0..3000 {
            output.extend_from_slice(&line);
            output.push(b'\n');
            if i == 2999 {
                output.extend_from_slice(b"last line\n");
            }
        }
        capture(&dir, vec![std::io::Cursor::new(output)])
            .unwrap()
            .finished()
            .await;
        let held = std::fs::metadata(dir.join(LOG)).unwrap().len()
            + std::fs::metadata(dir.join(ROTATED)).unwrap().len();
        assert!(held <= 2 * MAX_BYTES, "{held}");
        assert_eq!(tail(&dir, 1).await, "last line");
        let (text, is_truncated) = tail_bytes(&dir, 4096).await;
        assert!(is_truncated);
        assert!(text.ends_with("last line\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Both of the VMM's streams land in the one log.
    #[tokio::test]
    async fn every_source_reaches_the_log() {
        let dir = workdir("sources");
        capture(
            &dir,
            vec![
                std::io::Cursor::new(b"from the guest\n".to_vec()),
                std::io::Cursor::new(b"from the vmm\n".to_vec()),
            ],
        )
        .unwrap()
        .finished()
        .await;
        let text = std::fs::read_to_string(dir.join(LOG)).unwrap();
        assert!(text.contains("from the guest") && text.contains("from the vmm"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kernel_panic_is_found_on_the_console() {
        let console = "[    0.5] VFS: Cannot open root device\n[    0.5] Kernel panic - not syncing: VFS: Unable to mount root fs\n";
        assert_eq!(
            kernel_panic(console),
            Some("[    0.5] Kernel panic - not syncing: VFS: Unable to mount root fs")
        );
        assert_eq!(kernel_panic("all fine"), None);
    }

    /// The oops a warm guest restored hours after its snapshot printed, and
    /// the reports a guest survives, which do not count.
    #[test]
    fn a_kernel_crash_is_found_on_the_console() {
        let oops = "[13230.230000] BUG: kernel NULL pointer dereference, address: 0000000000000059\n\
                    [13230.231000] #PF: supervisor read access in kernel mode\n\
                    [13230.232000] Oops: Oops: 0000 [#1] SMP NOPTI\n";
        assert_eq!(
            kernel_crash(oops),
            Some("[13230.230000] BUG: kernel NULL pointer dereference, address: 0000000000000059")
        );
        let arm = "[    7.1] Unable to handle kernel NULL pointer dereference\n\
                   [    7.1] Internal error: Oops: 0000000096000004 [#1] SMP\n";
        assert_eq!(
            kernel_crash(arm),
            Some("[    7.1] Internal error: Oops: 0000000096000004 [#1] SMP")
        );
        let panic = "[    0.5] Kernel panic - not syncing: VFS: Unable to mount root fs\n";
        assert!(kernel_crash(panic).is_some());

        let survived = "[   30.0] BUG: soft lockup - CPU#0 stuck for 22s! [init:1]\n\
                        [   31.0] BUG: workqueue lockup - pool cpus=0\n\
                        [   32.0] WARNING: at __enqueue_entity+0x384/0x3b8\n\
                        [   32.1] ---[ end trace 0000000000000000 ]---\n\
                        BUG: printed by a program\n";
        assert_eq!(kernel_crash(survived), None);
    }

    /// The wait reads only whole lines, so a lockup report is not taken for a
    /// crash before the end of its line arrives.
    #[tokio::test]
    async fn the_wait_ends_at_a_crash_and_not_before() {
        let dir = workdir("crash");
        std::fs::write(dir.join(LOG), "[    1.0] booting\n[    2.0] BUG: soft lo").unwrap();
        let waiting = tokio::spawn({
            let dir = dir.clone();
            async move { wait_for_kernel_crash(&dir).await }
        });
        tokio::time::sleep(CRASH_POLL * 2).await;
        assert!(!waiting.is_finished());
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(LOG))
            .unwrap();
        std::io::Write::write_all(&mut log, b"ckup - CPU#0 stuck\n[    3.0] Oops: 0000 [#1]\n")
            .unwrap();
        let line = tokio::time::timeout(CRASH_POLL * 10, waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(line, "[    3.0] Oops: 0000 [#1]");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
