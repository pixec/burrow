//! `burrowd vm`: a development harness for the VMM layer.
//!
//! Boots microVMs from local images, times how long they take to reach
//! userspace, and tears them down. The real lifecycle, driven by the
//! orchestrator over the node API, reuses `burrow_vmm` the same way.

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;

use burrow_vmm::{DriveSpec, MicroVm, MicroVmSpec, SnapshotType};

#[derive(Args, Clone)]
pub struct VmBootArgs {
    /// Directory holding the kernel and rootfs; also the VM's working dir.
    #[arg(long, default_value = "/var/lib/burrow/images/dev")]
    pub workdir: PathBuf,
    /// Kernel filename, relative to --workdir.
    #[arg(long, default_value = "vmlinux")]
    pub kernel: String,
    /// Root filesystem image, relative to --workdir.
    #[arg(long, default_value = "rootfs.squashfs")]
    pub rootfs: String,
    #[arg(long, default_value = "/usr/local/bin/firecracker")]
    pub firecracker: PathBuf,
    #[arg(long, default_value_t = 1)]
    pub vcpus: u32,
    #[arg(long, default_value_t = 512)]
    pub mem_mib: u32,
    /// Console string that means the guest reached userspace.
    #[arg(long, default_value = "login:")]
    pub ready_marker: String,
    /// Seconds to wait for the ready marker.
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,
    /// Boot this many times in sequence and report latencies.
    #[arg(long, default_value_t = 1)]
    pub repeat: u32,
    /// Extra kernel command line, e.g. "quiet loglevel=0".
    #[arg(long, default_value = "")]
    pub extra_boot_args: String,
}

impl VmBootArgs {
    fn spec(&self, vm_id: impl Into<String>) -> MicroVmSpec {
        let mut spec = MicroVmSpec::new(vm_id, &self.workdir);
        spec.firecracker_bin = self.firecracker.clone();
        spec.kernel = self.kernel.clone();
        spec.vcpus = self.vcpus;
        spec.mem_mib = self.mem_mib;
        spec.drives = vec![DriveSpec::root_ro(&self.rootfs)];
        // Squashfs and ext4 roots both come up on /dev/vda as the first drive.
        spec.boot_args = format!(
            "{} root=/dev/vda ro {}",
            burrow_vmm::DEFAULT_BOOT_ARGS,
            self.extra_boot_args
        );
        spec
    }
}

/// Guest-reported time (seconds since kernel start) at which the kernel handed
/// off to userspace. The gap between this and the ready marker is entirely
/// distro init cost, which is what tells us whether a slow boot is the VMM's
/// fault or the image's.
fn kernel_handoff_secs(console: &str) -> Option<f64> {
    let line = console.lines().find(|l| l.contains("as init process"))?;
    let ts = line.split_once('[')?.1.split_once(']')?.0;
    ts.trim().parse().ok()
}

pub async fn run(args: VmBootArgs) -> anyhow::Result<()> {
    let mut boot_ms = Vec::new();
    let mut ready_ms = Vec::new();

    for iteration in 1..=args.repeat {
        let vm = MicroVm::boot(args.spec(format!("devvm-{iteration}"))).await?;
        let info = vm.instance_info().await?;

        match vm
            .wait_for_console(&args.ready_marker, Duration::from_secs(args.timeout))
            .await
        {
            Ok(elapsed) => {
                boot_ms.push(vm.boot_latency().as_millis() as u64);
                ready_ms.push(elapsed.as_millis() as u64);
                let handoff = kernel_handoff_secs(&vm.console_tail(usize::MAX).await)
                    .map(|s| format!(" kernel->init={:.0}ms", s * 1000.0))
                    .unwrap_or_default();
                println!(
                    "boot {iteration}/{}: vmm={} start={}ms ready={}ms{} (fc {})",
                    args.repeat,
                    info.state,
                    vm.boot_latency().as_millis(),
                    elapsed.as_millis(),
                    handoff,
                    info.vmm_version,
                );
            }
            Err(err) => {
                eprintln!("boot {iteration} failed: {err}");
                eprintln!("--- console tail ---\n{}", vm.console_tail(25).await);
                vm.kill().await?;
                anyhow::bail!("guest did not reach {:?}", args.ready_marker);
            }
        }
        vm.kill().await?;
    }

    if args.repeat > 1 {
        println!(
            "\n{} boots: start p50={}ms max={}ms | ready p50={}ms max={}ms",
            args.repeat,
            median(&mut boot_ms),
            boot_ms.iter().max().copied().unwrap_or(0),
            median(&mut ready_ms),
            ready_ms.iter().max().copied().unwrap_or(0),
        );
    }
    Ok(())
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or(0)
}

/// Boots the minimal agent rootfs and talks to the guest agent over vsock:
/// proves the agent comes up as PID 1, that the hybrid-vsock handshake works,
/// and that gRPC rides over it.
pub async fn agent_boot(args: VmBootArgs) -> anyhow::Result<()> {
    let mut spec = args.spec("agenttest");
    spec.drives = vec![DriveSpec::root_ro(&args.rootfs)];
    spec.vsock = true;
    spec.boot_args = format!(
        "{} root=/dev/vda ro init=/usr/bin/burrow-agent {}",
        burrow_vmm::DEFAULT_BOOT_ARGS,
        args.extra_boot_args
    );

    let start = std::time::Instant::now();
    let vm = MicroVm::boot(spec).await?;

    let ready = match vm
        .wait_for_vsock(
            crate::agentconn::AGENT_PORT,
            Duration::from_secs(args.timeout),
        )
        .await
    {
        Ok(elapsed) => elapsed,
        Err(err) => {
            eprintln!("agent never came up: {err}");
            eprintln!("--- console tail ---\n{}", vm.console_tail(30).await);
            vm.kill().await?;
            anyhow::bail!("agent unreachable over vsock");
        }
    };

    let mut client = crate::agentconn::connect(vm.vsock_uds_path()).await?;
    let handshake = client
        .handshake(crate::agentconn::handshake_request(false))
        .await?
        .into_inner();
    client
        .health(burrow_proto::agent::v1::AgentHealthRequest {})
        .await?;

    println!("vmm start:        {}ms", vm.boot_latency().as_millis());
    println!("agent reachable:  {}ms after spawn", ready.as_millis());
    println!(
        "handshake+health: ok in {}ms total",
        start.elapsed().as_millis()
    );
    println!("agent version:    {}", handshake.agent_version);

    vm.kill().await?;
    Ok(())
}

/// Runs a command in a freshly booted agent sandbox and streams the result.
pub async fn agent_exec(args: VmBootArgs, cmd: Vec<String>) -> anyhow::Result<()> {
    let vm = boot_agent_vm(&args, "exectest").await?;
    let mut client = crate::agentconn::connect(vm.vsock_uds_path()).await?;
    client
        .handshake(crate::agentconn::handshake_request(false))
        .await?;

    let code = exec_capture(&mut client, &cmd, |line| print!("{line}")).await?;
    vm.kill().await?;
    if code != 0 {
        anyhow::bail!("command exited with {code}");
    }
    Ok(())
}

/// Boots a VM running the agent rootfs and waits for the agent to accept.
async fn boot_agent_vm(args: &VmBootArgs, id: &str) -> anyhow::Result<MicroVm> {
    let mut spec = args.spec(id);
    spec.vsock = true;
    spec.boot_args = format!(
        "{} root=/dev/vda ro init=/usr/bin/burrow-agent {}",
        burrow_vmm::DEFAULT_BOOT_ARGS,
        args.extra_boot_args
    );
    let vm = MicroVm::boot(spec).await?;
    if let Err(err) = vm
        .wait_for_vsock(
            crate::agentconn::AGENT_PORT,
            Duration::from_secs(args.timeout),
        )
        .await
    {
        eprintln!("--- console tail ---\n{}", vm.console_tail(30).await);
        vm.kill().await?;
        return Err(err.into());
    }
    Ok(vm)
}

/// Drives one Exec stream to completion, handing each output chunk to `sink`,
/// and returns the exit code.
async fn exec_capture(
    client: &mut burrow_proto::agent::v1::agent_client::AgentClient<tonic::transport::Channel>,
    cmd: &[String],
    mut sink: impl FnMut(&str),
) -> anyhow::Result<i32> {
    use burrow_proto::agent::v1 as agentpb;
    use tokio_stream::StreamExt;

    let start = agentpb::ExecInput {
        input: Some(agentpb::exec_input::Input::Start(agentpb::ExecStart {
            cmd: cmd.to_vec(),
            env: Default::default(),
            cwd: String::new(),
            pty: false,
            rows: 0,
            cols: 0,
            // The node's own housekeeping, which is root's.
            user: String::new(),
        })),
    };
    // The command takes no stdin, so close the request stream immediately;
    // otherwise the agent would wait on a stream that never ends.
    let outbound = tokio_stream::iter(vec![start]);

    let mut stream = client.exec(outbound).await?.into_inner();
    let mut code = 0;
    while let Some(msg) = stream.next().await {
        match msg?.output {
            Some(agentpb::exec_output::Output::Stdout(b))
            | Some(agentpb::exec_output::Output::Stderr(b)) => {
                sink(&String::from_utf8_lossy(&b));
            }
            Some(agentpb::exec_output::Output::ExitCode(c)) => code = c,
            // The id is for coming back to a command later; this one is
            // collected here and now.
            Some(agentpb::exec_output::Output::CommandId(_)) | None => {}
        }
    }
    Ok(code)
}

/// Reads 16 random bytes in the guest as a hex string.
const RNG_PROBE: &str = "head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \\n'";

/// Restores two sandboxes from one snapshot and checks whether they produce
/// the same randomness.
///
/// Clones start with byte-identical memory, so without a reseed they share an
/// RNG state, which is the sharpest hazard in snapshot-based sandboxing. Also
/// answers whether clones can share one memory file, which warm snapshots rely on.
pub async fn clone_divergence(args: VmBootArgs) -> anyhow::Result<()> {
    let base = boot_agent_vm(&args, "clonebase").await?;
    let mut client = crate::agentconn::connect(base.vsock_uds_path()).await?;
    client
        .handshake(crate::agentconn::handshake_request(false))
        .await?;
    base.pause().await?;
    base.snapshot(SnapshotType::Full).await?;
    base.kill().await?;
    println!("snapshot taken from a running agent sandbox\n");

    // Warm snapshots are restored by many sandboxes from one memory file, so
    // the file must come back unmodified after being restored from.
    let mem_path = args.workdir.join(burrow_vmm::SNAPSHOT_MEM_FILE);
    let mem_before = file_digest(&mem_path).await?;

    let mut before = Vec::new();
    let mut after = Vec::new();

    for name in ["clone-a", "clone-b"] {
        let dir = args.workdir.join(name);
        link_clone(&args.workdir, &dir, &args.rootfs).await?;

        let mut spec = args.spec(name);
        spec.workdir = dir;
        spec.vsock = true;
        let vm = MicroVm::restore(spec, true).await?;
        vm.wait_for_vsock(
            crate::agentconn::AGENT_PORT,
            Duration::from_secs(args.timeout),
        )
        .await?;

        let mut client = crate::agentconn::connect(vm.vsock_uds_path()).await?;

        // Before the handshake the clone still carries the snapshot's RNG.
        let mut pre = String::new();
        exec_capture(&mut client, &sh(RNG_PROBE), |s| pre.push_str(s)).await?;

        client
            .handshake(crate::agentconn::handshake_request(true))
            .await?;

        let mut post = String::new();
        exec_capture(&mut client, &sh(RNG_PROBE), |s| post.push_str(s)).await?;

        println!("{name}: restored in {}ms", vm.boot_latency().as_millis());
        println!("  rng before reseed: {}", pre.trim());
        println!("  rng after  reseed: {}", post.trim());
        before.push(pre.trim().to_string());
        after.push(post.trim().to_string());
        vm.kill().await?;
    }

    let mem_after = file_digest(&mem_path).await?;

    println!();
    let diverged_after = after[0] != after[1];
    let diverged_before = before[0] != before[1];
    println!("clones diverge after our reseed:  {diverged_after}");
    println!(
        "clones diverge before it:         {diverged_before} \
         (true means the guest kernel self-reseeded via vmgenid/sysgenid)"
    );
    println!(
        "shared memory file unmodified:    {} (warm restores can share one mem file)",
        mem_before == mem_after
    );

    if !diverged_after {
        anyhow::bail!("clones produced identical randomness; snapshot cloning is unsafe");
    }
    if mem_before != mem_after {
        anyhow::bail!(
            "restoring modified the snapshot memory file; clones cannot share it \
             and warm restores need per-clone copies"
        );
    }
    println!("\nOK: clones are independent and the base snapshot is reusable");
    Ok(())
}

/// Cheap content fingerprint: length plus a rolling hash over the file. Enough
/// to catch a restore mutating the snapshot, without pulling in a hash crate.
async fn file_digest(path: &std::path::Path) -> anyhow::Result<(u64, u64)> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; 1 << 20];
    let (mut len, mut hash) = (0u64, 0xcbf29ce484222325u64);
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        len += n as u64;
        for byte in &buf[..n] {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Ok((len, hash))
}

fn sh(script: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), script.into()]
}

/// Builds a clone workdir that hard-links the base snapshot and rootfs.
///
/// Hard links (rather than copies) are what warm restores need: many sandboxes
/// restoring from one memory file. Firecracker maps the memory file
/// `MAP_PRIVATE`, so guest writes stay per-process and the shared file is not
/// modified.
async fn link_clone(
    base: &std::path::Path,
    clone: &std::path::Path,
    rootfs: &str,
) -> anyhow::Result<()> {
    if tokio::fs::try_exists(clone).await.unwrap_or(false) {
        tokio::fs::remove_dir_all(clone).await?;
    }
    tokio::fs::create_dir_all(clone).await?;
    for file in [
        burrow_vmm::SNAPSHOT_FILE,
        burrow_vmm::SNAPSHOT_MEM_FILE,
        rootfs,
    ] {
        tokio::fs::hard_link(base.join(file), clone.join(file)).await?;
    }
    Ok(())
}

/// Measures the floor: boot straight into a shell as PID 1 (no distro init)
/// and time until it actually responds. This is what a minimal rootfs running
/// the burrow agent as init will see; anything above it is image cost, not
/// hypervisor cost.
pub async fn boot_floor(args: VmBootArgs) -> anyhow::Result<()> {
    let mut spec = args.spec("floortest");
    spec.boot_args = format!(
        "{} root=/dev/vda ro init=/bin/sh {}",
        burrow_vmm::DEFAULT_BOOT_ARGS,
        args.extra_boot_args
    );

    let start = std::time::Instant::now();
    let mut vm = MicroVm::boot(spec).await?;
    let vmm_ms = vm.boot_latency().as_millis();

    // PID 1 shell prints no prompt, so probe it: poke the serial line until it
    // echoes back. First response = userspace is live and executing.
    let deadline = std::time::Instant::now() + Duration::from_secs(args.timeout);
    let mut responded = None;
    while std::time::Instant::now() < deadline {
        vm.console_write("echo BURROW_READY\n").await?;
        // Poll finely: at ~1s totals, coarse polling dominates the result.
        if vm
            .wait_for_console("BURROW_READY", Duration::from_millis(25))
            .await
            .is_ok()
        {
            responded = Some(start.elapsed());
            break;
        }
    }
    let console = vm.console_tail(usize::MAX).await;
    vm.kill().await?;

    let Some(elapsed) = responded else {
        anyhow::bail!("shell never responded within {}s", args.timeout);
    };

    let handoff = kernel_handoff_secs(&console);
    println!("vmm start:        {vmm_ms}ms");
    match handoff {
        Some(s) => println!(
            "kernel -> init:   {:.0}ms (guest-reported)\nuserspace live:   {}ms wall",
            s * 1000.0,
            elapsed.as_millis()
        ),
        None => println!("userspace live:   {}ms wall", elapsed.as_millis()),
    }
    Ok(())
}

/// Boot → run a command in the guest → snapshot → kill → restore → run
/// another command. Proves the restored guest continues with live state,
/// which is the property the whole pause/resume design rests on.
pub async fn snapshot_roundtrip(args: VmBootArgs) -> anyhow::Result<()> {
    let mut vm = MicroVm::boot(args.spec("snaptest")).await?;
    let ready = vm
        .wait_for_console(&args.ready_marker, Duration::from_secs(args.timeout))
        .await?;
    println!(
        "booted in {}ms (guest reached {:?})",
        ready.as_millis(),
        args.ready_marker
    );

    // Leave a value in the shell's memory; if the restore is real, the
    // restored guest still has it.
    vm.console_write("SECRET=burrow-$$-alive\n").await?;
    vm.console_write("echo PRE:$SECRET\n").await?;
    vm.wait_for_console("PRE:burrow-", Duration::from_secs(10))
        .await?;
    let pre = extract_marker(&vm.console_tail(60).await, "PRE:").unwrap_or_default();
    println!("pre-snapshot guest state: {pre}");

    vm.pause().await?;
    let snap_start = std::time::Instant::now();
    vm.snapshot(SnapshotType::Full).await?;
    println!("snapshot written in {}ms", snap_start.elapsed().as_millis());
    vm.kill().await?;

    let restore_start = std::time::Instant::now();
    let mut vm = MicroVm::restore(args.spec("snaptest"), true).await?;
    println!("restored in {}ms", restore_start.elapsed().as_millis());

    // The restored shell should still hold $SECRET from before the snapshot.
    vm.console_write("echo POST:$SECRET\n").await?;
    vm.wait_for_console("POST:burrow-", Duration::from_secs(10))
        .await?;
    let post = extract_marker(&vm.console_tail(60).await, "POST:").unwrap_or_default();
    println!("post-restore guest state: {post}");
    vm.kill().await?;

    if pre.is_empty() || pre != post {
        anyhow::bail!("guest state did not survive the snapshot ({pre:?} != {post:?})");
    }
    println!(
        "\nOK: guest resumed with identical in-memory state ({}ms restore)",
        restore_start.elapsed().as_millis()
    );
    Ok(())
}

/// Pulls the value following `prefix` out of console output, ignoring the
/// echoed command line itself (which contains a `$` sigil).
fn extract_marker(console: &str, prefix: &str) -> Option<String> {
    console
        .lines()
        .filter_map(|line| {
            line.split_once(prefix)
                .map(|(_, rest)| rest.trim().to_string())
        })
        .find(|value| !value.contains('$') && !value.is_empty())
}
