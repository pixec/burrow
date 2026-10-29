//! Dev driver for the Virtualization.framework backend, over [`burrow_vmm::Vm`].
//!
//! The binary needs the virtualization entitlement: `deploy/macos/sign.sh`
//! builds it and signs a copy. See deploy/macos/README.md.
//!
//! ```text
//! vz install <ipsw> <template> --disk-gib N   build a template from a restore image
//! vz new <template> <dir> [--keep-identity]   a sandbox's machine from a template
//! vz run <dir> [--provision] [--capture] [--mac M]
//!                                             boot, or restore a saved state, headless
//! vz gui <dir> [--provision]                  boot with a window, for Setup Assistant
//! ```
//!
//! `install`, `run` and `gui` take `--cpus N` and `--memory-mib N`, a
//! sandbox's resources; each defaults to the minimum the restore image
//! declares, and values outside that minimum and the host's maximum are
//! refused.
//! `--provision` creates the account in `BURROW_VZ_USER` and
//! `BURROW_VZ_PASSWORD` (default `burrow`/`burrow`) with Remote Login on, in
//! place of Setup Assistant; only the first boot after an install honours it.
//! `--capture` gives the guest a datagram socket pair instead of NAT and
//! prints the frames it sends, to show where a userspace network stack would
//! sit; the guest gets no address.
//! As in Apple's sample, a boot restores `snapshot.vzsave` when there is one
//! and deletes it either way, since the disk no longer matches it once the
//! guest runs on.
//!
//! `run` serves the guest's vsock ports on `<dir>/vsock.sock` (the backend's
//! bridge, as Firecracker's socket is) and takes one command per line on
//! `<dir>/ctl.sock`: `pause`, `resume`, `snapshot`, `stop`, and `suspend`
//! (pause, snapshot, stop, exit).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    return macos::main();
    #[cfg(not(target_os = "macos"))]
    Err("Virtualization.framework is macOS only".into())
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;
    use std::path::Path;
    use std::time::Instant;

    use burrow_vmm::vz::{self, VzConfig};
    use burrow_vmm::{Backend, Boot, GuestOs, Layout, NetSpec, Vm, VmSpec};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    pub fn main() -> Result<()> {
        let mut positional = Vec::new();
        let mut flags = HashMap::new();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--cpus" | "--memory-mib" | "--disk-gib" | "--mac" => {
                    let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
                    flags.insert(arg, value);
                }
                _ if arg.starts_with("--") => {
                    flags.insert(arg, String::new());
                }
                _ => positional.push(arg),
            }
        }
        let arg = |i: usize| positional.get(i).map(String::as_str);
        let has = |flag: &str| flags.contains_key(flag);
        let number = |flag: &str| flags.get(flag).map(|v| v.parse::<u32>()).transpose();
        let (cpus, mem_mib) = (number("--cpus")?, number("--memory-mib")?);
        let mut node = VzConfig {
            provisioning: has("--provision").then(provisioning),
            ..VzConfig::default()
        };
        match (arg(0), arg(1), arg(2)) {
            (Some("install"), Some(ipsw), Some(template)) => {
                let spec = vz::InstallSpec {
                    template: template.into(),
                    vcpus: cpus,
                    mem_mib,
                    disk_bytes: u64::from(number("--disk-gib")?.ok_or("install needs --disk-gib")?)
                        << 30,
                };
                runtime()?.block_on(install(Path::new(ipsw), &spec))
            }
            (Some("new"), Some(template), Some(dir)) => {
                let started = Instant::now();
                vz::clone_machine(Path::new(template), Path::new(dir), has("--keep-identity"))?;
                println!("cloned in {:?}", started.elapsed());
                Ok(())
            }
            (Some("run"), Some(dir), _) => {
                if has("--capture") {
                    node.network = capture()?;
                }
                let spec = spec(dir, node, cpus, mem_mib, flags.get("--mac").cloned())?;
                runtime()?.block_on(run(spec))
            }
            (Some("gui"), Some(dir), _) => gui::run(&spec(dir, node, cpus, mem_mib, None)?),
            _ => Err("usage: vz install|new|run|gui (see examples/vz.rs)".into()),
        }
    }

    /// The sandbox spec for the machine in `dir`, as the daemon would build
    /// it: the sandbox's resources, or the smallest the installed macOS
    /// supports where none are given.
    fn spec(
        dir: &str,
        node: VzConfig,
        cpus: Option<u32>,
        mem_mib: Option<u32>,
        mac: Option<String>,
    ) -> Result<VmSpec> {
        let boot = vz::MacOsBoot::read(Path::new(dir))?;
        let mut spec = VmSpec::new(
            dir.rsplit('/').next().unwrap_or(dir),
            dir,
            Backend::Vz(node),
        );
        spec.guest_os = GuestOs::MacOs;
        spec.vcpus = cpus.unwrap_or(boot.requirements.min_vcpus);
        spec.mem_mib = mem_mib.unwrap_or(boot.requirements.min_mem_mib);
        spec.boot = Boot::MacOs(boot);
        spec.drives = vec![vz::root_drive()];
        spec.net = Some(NetSpec {
            tap: String::new(),
            guest_mac: Some(mac.map_or_else(|| derived_mac(dir), Ok)?),
        });
        spec.is_vsock_enabled = true;
        Ok(spec)
    }

    fn provisioning() -> vz::Provisioning {
        let var = |name: &str| std::env::var(name).unwrap_or_else(|_| "burrow".into());
        vz::Provisioning {
            full_name: "Burrow".into(),
            username: var("BURROW_VZ_USER"),
            password: var("BURROW_VZ_PASSWORD"),
            is_auto_login: true,
            is_remote_login_enabled: true,
        }
    }

    /// A MAC derived from the machine identifier, so each machine keeps its
    /// DHCP lease (and address) across boots and its clones get their own.
    fn derived_mac(dir: &str) -> Result<String> {
        let id = std::fs::read(Path::new(dir).join(vz::MACHINE_ID_FILE))?;
        let hash = id.iter().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        });
        let b = hash.to_be_bytes();
        // 0x02: locally administered, unicast.
        Ok(format!(
            "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4]
        ))
    }

    /// A datagram socket pair for the guest's NIC, with the far end read on
    /// a thread that summarises each frame.
    fn capture() -> Result<vz::Network> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let mut fds = [0; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let (guest, host) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // Apple's guidance for this attachment: a send buffer of at least
        // the MTU and a receive buffer several times that.
        for (fd, opt, size) in [
            (guest.as_raw_fd(), libc::SO_SNDBUF, 1 << 20),
            (guest.as_raw_fd(), libc::SO_RCVBUF, 4 << 20),
        ] {
            let size: libc::c_int = size;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    (&size as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
        }
        std::thread::spawn(move || {
            let mut frame = [0u8; 65536];
            for n in 0u64.. {
                let len = unsafe {
                    libc::recv(host.as_raw_fd(), frame.as_mut_ptr().cast(), frame.len(), 0)
                };
                if len < 14 {
                    return;
                }
                let f = &frame[..len as usize];
                let ethertype = u16::from_be_bytes([f[12], f[13]]);
                let what = match ethertype {
                    0x0800 if f.len() >= 38 => {
                        let ihl = usize::from(f[14] & 0x0f) * 4;
                        let ports = f.get(14 + ihl..14 + ihl + 4).map(|p| {
                            (
                                u16::from_be_bytes([p[0], p[1]]),
                                u16::from_be_bytes([p[2], p[3]]),
                            )
                        });
                        format!(
                            "ipv4 proto {} {}.{}.{}.{} -> {}.{}.{}.{} ports {ports:?}",
                            f[23], f[26], f[27], f[28], f[29], f[30], f[31], f[32], f[33]
                        )
                    }
                    0x0806 => "arp".into(),
                    0x86dd => format!("ipv6 next header {}", f.get(20).copied().unwrap_or(0)),
                    other => format!("ethertype {other:#06x}"),
                };
                if n < 40 || n % 100 == 0 {
                    println!("frame {n}: {len} bytes from {:02x?}: {what}", &f[6..12]);
                }
            }
        });
        Ok(vz::Network::Datagram(std::sync::Arc::new(guest)))
    }

    fn runtime() -> Result<tokio::runtime::Runtime> {
        Ok(tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?)
    }

    async fn install(ipsw: &Path, spec: &vz::InstallSpec) -> Result<()> {
        let started = Instant::now();
        let image = vz::install(ipsw, spec, |fraction| {
            println!(
                "install {:.0}% after {:?}",
                fraction * 100.0,
                started.elapsed()
            );
        })
        .await?;
        println!(
            "installed macOS {} ({}) in {:?} with {} vCPUs and {} MiB; minimum {} vCPUs, {} MiB",
            image.version,
            image.build,
            started.elapsed(),
            image.vcpus,
            image.mem_mib,
            image.requirements.min_vcpus,
            image.requirements.min_mem_mib,
        );
        Ok(())
    }

    async fn run(spec: VmSpec) -> Result<()> {
        let layout: Layout = spec.layout();
        let save = spec.workdir.join(layout.state);
        println!(
            "{} vCPUs, {} MiB, mac {}",
            spec.vcpus,
            spec.mem_mib,
            spec.net
                .as_ref()
                .and_then(|n| n.guest_mac.as_deref())
                .unwrap_or("random")
        );
        let vm = if save.exists() {
            let restored = Vm::restore(spec.clone(), true).await;
            std::fs::remove_file(&save)?;
            match restored {
                Ok(vm) => {
                    println!("restored and resumed in {:?}", vm.boot_latency());
                    vm
                }
                Err(err) => {
                    println!("restore failed ({err}), booting instead");
                    let vm = Vm::boot(spec.clone()).await?;
                    println!("started in {:?}", vm.boot_latency());
                    vm
                }
            }
        } else {
            let vm = Vm::boot(spec.clone()).await?;
            println!("started in {:?}", vm.boot_latency());
            vm
        };
        println!("vsock at {}", vm.guest().socket_path().display());

        let ctl = spec.workdir.join("ctl.sock");
        let _ = std::fs::remove_file(&ctl);
        let listener = UnixListener::bind(&ctl)?;
        loop {
            let (stream, _) = tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    vm.kill().await?;
                    return Ok(());
                }
                accepted = listener.accept() => accepted?,
            };
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            while let Some(line) = lines.next_line().await? {
                let started = Instant::now();
                let (result, is_last) = match line.trim() {
                    "pause" => (vm.pause().await, false),
                    "resume" => (vm.resume().await, false),
                    "snapshot" => (vm.snapshot().await, false),
                    "suspend" => (
                        async {
                            vm.pause().await?;
                            vm.snapshot().await
                        }
                        .await,
                        true,
                    ),
                    "stop" => (Ok(()), true),
                    other => {
                        write
                            .write_all(format!("err unknown command {other:?}\n").as_bytes())
                            .await?;
                        continue;
                    }
                };
                let reply = match &result {
                    Ok(()) if line.trim() == "suspend" => format!(
                        "ok {:?}, {} MiB",
                        started.elapsed(),
                        std::fs::metadata(&save).map_or(0, |m| m.len() >> 20)
                    ),
                    Ok(()) => format!("ok {:?}", started.elapsed()),
                    Err(err) => format!("err {err}"),
                };
                println!("{} -> {reply}", line.trim());
                if is_last && result.is_ok() {
                    vm.kill().await?;
                    write.write_all(format!("{reply}\n").as_bytes()).await?;
                    return Ok(());
                }
                write.write_all(format!("{reply}\n").as_bytes()).await?;
            }
        }
    }

    /// The one-time Setup Assistant boot, where provisioning is unavailable.
    /// A view can only show a machine driven from the main queue, so this
    /// path builds the machine itself from the spec's configuration rather
    /// than through [`Vm`], which gives each machine its own queue.
    mod gui {
        use objc2::rc::Retained;
        use objc2::{AllocAnyThread, MainThreadMarker, MainThreadOnly};
        use objc2_app_kit::{
            NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSWindow,
            NSWindowStyleMask,
        };
        use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
        use objc2_virtualization::{VZVirtualMachine, VZVirtualMachineState, VZVirtualMachineView};

        use burrow_vmm::{Backend, VmSpec, vz};

        use super::Result;

        pub fn run(spec: &VmSpec) -> Result<()> {
            let Backend::Vz(node) = &spec.backend else {
                return Err("not a vz spec".into());
            };
            let mtm = MainThreadMarker::new().ok_or("gui must run on the main thread")?;
            let config = vz::configuration(spec, node)?;
            let vm = unsafe {
                VZVirtualMachine::initWithConfiguration(VZVirtualMachine::alloc(), &config)
            };
            let app = NSApplication::sharedApplication(mtm);
            app.setActivationPolicy(NSApplicationActivationPolicy::Regular);
            let window = unsafe {
                NSWindow::initWithContentRect_styleMask_backing_defer(
                    NSWindow::alloc(mtm),
                    NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1440.0, 900.0)),
                    NSWindowStyleMask::Titled
                        | NSWindowStyleMask::Closable
                        | NSWindowStyleMask::Resizable
                        | NSWindowStyleMask::Miniaturizable,
                    NSBackingStoreType::Buffered,
                    false,
                )
            };
            unsafe {
                let view = VZVirtualMachineView::new(mtm);
                window.setReleasedWhenClosed(false);
                view.setVirtualMachine(Some(&vm));
                view.setCapturesSystemKeys(true);
                view.setAutomaticallyReconfiguresDisplay(true);
                window.setContentView(Some(&view));
            }
            window.setTitle(&NSString::from_str(&format!(
                "burrow vz: {}",
                spec.workdir.display()
            )));
            window.center();
            window.makeKeyAndOrderFront(None);

            let started = block2::RcBlock::new(|err: *mut NSError| match unsafe { err.as_ref() } {
                None => println!("started"),
                Some(err) => {
                    eprintln!("start failed: {}", err.localizedDescription());
                    std::process::exit(1);
                }
            });
            let options = vz::start_options(node.provisioning.as_ref())?;
            unsafe { vm.startWithOptions_completionHandler(&options, &started) };
            watch(vm);
            #[allow(deprecated)]
            app.activateIgnoringOtherApps(true);
            app.run();
            Ok(())
        }

        /// Exits once the guest has shut itself down, which is how the
        /// Setup Assistant boot is meant to end.
        fn watch(vm: Retained<VZVirtualMachine>) {
            struct MainQueue(Retained<VZVirtualMachine>);
            // SAFETY: only messaged from closures run on the main queue.
            unsafe impl Send for MainQueue {}
            unsafe impl Sync for MainQueue {}
            impl MainQueue {
                fn get(&self) -> &VZVirtualMachine {
                    &self.0
                }
            }
            let vm = MainQueue(vm);
            let check = move || {
                let state = unsafe { vm.get().state() };
                if state == VZVirtualMachineState::Stopped || state == VZVirtualMachineState::Error
                {
                    println!("guest stopped ({})", state.0);
                    std::process::exit(0);
                }
            };
            std::thread::spawn(move || {
                let check = std::sync::Arc::new(check);
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let check = check.clone();
                    dispatch2::DispatchQueue::main().exec_async(move || check());
                }
            });
        }
    }
}
