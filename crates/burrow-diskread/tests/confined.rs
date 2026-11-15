//! A reader started as burrowd starts one: this test binary is the reader
//! too, as burrowd is, and checks what the child can do.

fn main() {
    burrow_diskread::run_if_reader();
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read as _;
    use std::path::{Path, PathBuf};

    use burrow_diskread::{Limits, Reader};

    fn fixture(name: &str) -> PathBuf {
        let out =
            std::env::temp_dir().join(format!("burrow-confined-{}-{name}", std::process::id()));
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(
            std::fs::File::open(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures")
                    .join(format!("{name}.gz")),
            )
            .unwrap(),
        )
        .read_to_end(&mut bytes)
        .unwrap();
        std::fs::write(&out, bytes).unwrap();
        out
    }

    fn status_of(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap()
    }

    fn field<'a>(status: &'a str, name: &str) -> &'a str {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
    }

    pub fn run() {
        let exe = std::env::current_exe().unwrap();
        let image = fixture("root.ext4");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut reader = Reader::spawn(&exe, &image, Limits::default()).unwrap();
            let notes = reader.stat("/home/me/notes.txt").await.unwrap();
            assert_eq!((notes.uid, notes.gid), (1000, 1001));

            let status = status_of(reader.id().unwrap());
            assert_eq!(field(&status, "Seccomp:"), "2");
            assert_eq!(field(&status, "NoNewPrivs:"), "1");
            if unsafe { libc::geteuid() } == 0 {
                assert!(field(&status, "Uid:").starts_with("65534"), "{status}");
                let net = |pid: &str| std::fs::read_link(format!("/proc/{pid}/ns/net")).unwrap();
                assert_ne!(net("self"), net(&reader.id().unwrap().to_string()));
            }

            let root = reader.list("/").await.unwrap();
            assert!(root.iter().any(|entry| entry.name == b"home"));
            assert_eq!(
                reader.read("/home/me/notes.txt", 0, 64).await.unwrap(),
                b"hello\n"
            );
            let err = reader.stat("/nope").await.unwrap_err();
            assert!(err.contains("no such file"), "{err}");

            let (chunks, mut received) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
            let collect = async move {
                let mut archive = Vec::new();
                while let Some(chunk) = received.recv().await {
                    archive.extend_from_slice(&chunk);
                }
                archive
            };
            let (summary, archive) = tokio::join!(
                reader.tar("/var/lib/app", u64::MAX, u64::MAX, chunks),
                collect
            );
            assert_eq!(summary.unwrap().entries, 3005);
            assert_eq!(
                tar::Archive::new(&archive[..]).entries().unwrap().count(),
                3005
            );
            let err = reader
                .tar("/var/lib/app", u64::MAX, 5, tokio::sync::mpsc::channel(4).0)
                .await
                .unwrap_err();
            assert!(
                err.contains("more than 5 files") || err == burrow_diskread::RECEIVER_GONE,
                "{err}"
            );

            let junk = image.with_extension("junk");
            std::fs::write(&junk, vec![0x5a; 1 << 16]).unwrap();
            let mut confused = Reader::spawn(&exe, &junk, Limits::default()).unwrap();
            let err = confused.list("/").await.unwrap_err();
            assert!(err.contains("not a readable ext4 filesystem"), "{err}");
            let err = confused.list("/").await.unwrap_err();
            assert!(err.contains("not a readable ext4 filesystem"), "{err}");

            let starved = Limits {
                memory_mib: 1,
                cpu_secs: 10,
            };
            let mut starved = Reader::spawn(&exe, &image, starved).unwrap();
            let err = starved.list("/").await.unwrap_err();
            assert!(err.contains("the disk reader"), "{err}");
            let _ = std::fs::remove_file(junk);
        });
        let _ = std::fs::remove_file(image);
        println!("confined reader: ok");
    }
}
