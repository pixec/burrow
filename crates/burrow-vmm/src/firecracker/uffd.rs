//! Lazy guest memory on restore, via userfaultfd.
//!
//! Restoring a snapshot with the `File` memory backend makes the kernel
//! responsible for the guest's memory: every page the guest touches faults, and
//! Firecracker's mapping is private, so each sandbox ends up with its own
//! anonymous copy of everything it reads. A 512 MiB guest that uses 60 MiB
//! still costs a page-in per touched page, and nothing is shared between
//! sandboxes restored from the same snapshot.
//!
//! The `Uffd` backend moves that decision into this process. Firecracker
//! creates the userfaultfd, registers the guest's memory regions with it, and
//! hands us the descriptor plus the region layout over a Unix socket. From then
//! on we serve faults ourselves out of a read-only private mapping of the
//! snapshot's memory file.
//!
//! Two things follow, and they are the whole point:
//!
//! - **Only touched pages are ever populated.** Memory a guest never reads
//!   costs nothing, so a node's memory commitment tracks what sandboxes
//!   actually use rather than what they were promised.
//! - **The backing file is shared.** Warm snapshots are hard-linked into each
//!   sandbox's working directory, so every sandbox restored from one template
//!   maps the *same inode*. Reads come from one page cache copy no matter how
//!   many sandboxes are running.
//!
//! The handler runs on a dedicated OS thread, not the tokio runtime: a fault is
//! a stalled vCPU, so it must never queue behind unrelated async work.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::memfile;

/// Socket Firecracker connects to, relative to the VM working directory.
pub const UFFD_SOCK: &str = "uffd.sock";

/// How long to wait for Firecracker to connect after `load_snapshot` is issued.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// One guest memory region, as Firecracker describes it.
///
/// Field names are Firecracker's wire format, not ours; they must match its
/// `GuestRegionUffdMapping` exactly or the handler will populate the wrong
/// addresses.
#[derive(Debug, Clone, Deserialize)]
struct RegionMapping {
    /// Where this region lives in Firecracker's address space.
    base_host_virt_addr: u64,
    size: usize,
    /// Where the region's contents start in the memory file.
    offset: u64,
    page_size: usize,
}

impl RegionMapping {
    fn is_in_region(&self, addr: u64) -> bool {
        addr >= self.base_host_virt_addr && addr < self.base_host_virt_addr + self.size as u64
    }
}
//
// Bound by hand rather than through a crate. Firecracker creates the fd,
// performs the API handshake, and registers the regions, so the handler only
// ever needs to resolve a fault: `COPY` for a page that has contents in the
// memory file, `ZEROPAGE` for one the balloon removed. Two ioctls and two
// structs is less surface than a bindgen dependency in a cross-compiled build.

const UFFDIO: u32 = 0xAA;
const IOC_READ_WRITE: u32 = 3;

const fn iowr(nr: u32, size: u32) -> u32 {
    (IOC_READ_WRITE << 30) | (size << 16) | (UFFDIO << 8) | nr
}

const UFFDIO_COPY: u32 = iowr(0x03, std::mem::size_of::<UffdioCopy>() as u32);
const UFFDIO_ZEROPAGE: u32 = iowr(0x04, std::mem::size_of::<UffdioZeropage>() as u32);

#[repr(C)]
#[derive(Default)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    /// Bytes copied, or `-errno` when the ioctl reports failure this way.
    copy: i64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

/// `struct uffd_msg` is 32 bytes: an 8-byte header and a 24-byte union.
const UFFD_MSG_SIZE: usize = 32;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_EVENT_REMOVE: u8 = 0x15;

/// A message read off the userfaultfd.
enum Event {
    /// A vCPU touched an unpopulated page and is stalled until we fill it.
    PageFault {
        address: u64,
    },
    /// The balloon returned memory to the host. The range stays registered, so
    /// a later fault there must be answered with zeroes rather than file
    /// contents: the guest already considers it discarded.
    Remove {
        start: u64,
        end: u64,
    },
    Other,
}

fn parse_event(buf: &[u8; UFFD_MSG_SIZE]) -> Event {
    let arg = &buf[8..];
    let u64_at = |offset: usize| {
        u64::from_ne_bytes(
            arg[offset..offset + 8]
                .try_into()
                .expect("fixed-size slice"),
        )
    };
    match buf[0] {
        // struct { __u64 flags; __u64 address; __u32 ptid; }
        UFFD_EVENT_PAGEFAULT => Event::PageFault { address: u64_at(8) },
        // struct { __u64 start; __u64 end; }
        UFFD_EVENT_REMOVE => Event::Remove {
            start: u64_at(0),
            end: u64_at(8),
        },
        _ => Event::Other,
    }
}

/// A read-only private mapping of one memory file.
///
/// `MAP_POPULATE` is deliberately not used: faulting the backing pages in on
/// demand is what keeps reads coming from the shared page cache instead of
/// pulling the whole file into this process up front.
struct Backing {
    addr: *const u8,
    len: usize,
}

// SAFETY: the mapping is read-only and never unmapped while the handler thread
// holds it, so sharing the pointer across the thread boundary is sound.
unsafe impl Send for Backing {}

impl Backing {
    fn map(path: &Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Err(io::Error::other("snapshot memory file is empty"));
        }
        // SAFETY: `file` is open and `len` is its real size.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr.cast(),
            len,
        })
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: this mapping was created by `map` and is dropped once.
        unsafe { libc::munmap(self.addr as *mut libc::c_void, self.len) };
    }
}

/// One memory file in a snapshot chain, with the pages it defines.
///
/// A hole and a page of genuine zeroes are identical through a mapping, so a
/// diff's pages come from the map written beside it ([`crate::memfile`]).
/// Without that a diff would appear to define every page and the layers
/// beneath it would never be consulted.
struct Layer {
    backing: Backing,
    pages: memfile::Layer,
    /// Set when the file is still arriving: every page is asked for before it
    /// is read.
    source: Option<Arc<dyn super::PageSource>>,
}

impl Layer {
    fn open(
        path: &Path,
        index: usize,
        source: Option<Arc<dyn super::PageSource>>,
    ) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let pages = match &source {
            Some(source) => memfile::Layer::full(file.metadata()?.len(), source.extents()),
            None => memfile::open_layer(path, &file, index)?,
        };
        Ok(Self {
            backing: Backing::map(path)?,
            pages,
            source,
        })
    }
}

impl AsRef<memfile::Layer> for Layer {
    fn as_ref(&self) -> &memfile::Layer {
        &self.pages
    }
}

/// Every page the handler has filled, by file offset.
///
/// Firecracker writes a diff of a VM restored through this handler from
/// `mincore`, which reports exactly the pages that are present, and a page of
/// an anonymous mapping registered with a userfaultfd is only ever made
/// present here. So this is a superset of what a diff holds, and the pages it
/// adds are ones the balloon took back, which read as zeroes from the diff and
/// are zeroes to the guest.
type Served = Mutex<memfile::PageMap>;

/// Tells the handler thread to stop, waking it out of any poll at once.
struct Stop {
    flag: AtomicBool,
    wake: OwnedFd,
}

impl Stop {
    fn new() -> io::Result<Self> {
        // SAFETY: eventfd takes no pointers.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            flag: AtomicBool::new(false),
            // SAFETY: the descriptor was just created and is named nowhere else.
            wake: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn signal(&self) {
        self.flag.store(true, Ordering::Relaxed);
        let one = 1u64;
        // SAFETY: `one` is eight readable bytes, what an eventfd write takes.
        unsafe { libc::write(self.wake.as_raw_fd(), (&raw const one).cast(), 8) };
    }

    fn is_set(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Waits until `fd` is readable or the stop is signalled, returning
    /// whether `fd` is readable. `timeout_ms` of -1 waits indefinitely.
    fn wait(&self, fd: RawFd, timeout_ms: libc::c_int) -> io::Result<bool> {
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is two valid entries for the duration of the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) } < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(err)
            };
        }
        Ok(fds[0].revents != 0)
    }
}

fn mark(served: &Served, offset: u64, len: u64) {
    served.lock().unwrap().insert_bytes(offset, offset + len);
}

/// How guest memory should be served for one restored VM.
#[derive(Default, Clone)]
pub struct MemoryPlan {
    /// Memory files oldest first: a full base, then diffs layered over it.
    pub chain: Vec<PathBuf>,
    /// Hands the socket to a jailed firecracker's uid/gid.
    pub owner: Option<(u32, u32)>,
    /// Pages to populate before the guest runs, recorded from an earlier
    /// restore of the same snapshot.
    pub prefetch: Option<PathBuf>,
    /// Where to write the offsets this VM faults on, to become a future
    /// prefetch plan.
    pub record_to: Option<PathBuf>,
    /// Where the oldest layer is still being filled in from.
    pub base_source: Option<Arc<dyn super::PageSource>>,
}

impl std::fmt::Debug for MemoryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryPlan")
            .field("chain", &self.chain)
            .field("prefetch", &self.prefetch)
            .field("is_base_arriving", &self.base_source.is_some())
            .finish()
    }
}

/// Reads a prefetch plan: little-endian `u64` file offsets, nothing else.
///
/// A plan that cannot be read is not an error. It is an optimisation, and a
/// guest that faults its own pages in is merely slower.
fn read_plan(path: &Path) -> Vec<u64> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
        .collect()
}

fn write_plan(path: &Path, offsets: &[u64]) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(offsets.len() * 8);
    for offset in offsets {
        bytes.extend_from_slice(&offset.to_le_bytes());
    }
    // Written via a temporary: a truncated plan would populate the wrong
    // pages, which is worse than having none.
    let temp = path.with_extension("recording");
    std::fs::write(&temp, bytes)?;
    std::fs::rename(&temp, path)
}

/// Populates the pages a plan names, before the guest is running.
///
/// This is the whole point of recording: a restored guest otherwise takes
/// thousands of individual faults, each one a stalled vCPU and a round trip
/// into this process. Filling them in one pass turns that into a sequential
/// copy.
fn prefetch(
    fd: RawFd,
    regions: &[RegionMapping],
    layers: &[Layer],
    served: &Served,
    offsets: &[u64],
) -> usize {
    // A base still arriving is asked for the whole plan in one go, so its
    // pages come in parallel rather than one blocking fetch per offset below.
    if let (Some(source), Some(region)) = (
        layers.first().and_then(|layer| layer.source.as_ref()),
        regions.first(),
    ) && let Err(err) = source.ensure_all(offsets, region.page_size as u64)
    {
        tracing::warn!(%err, "could not fetch the prefetch plan's pages ahead of the guest");
    }
    let mut filled = 0;
    for &offset in offsets {
        // The plan stores file offsets; the address to populate depends on
        // which region covers that offset in *this* restore.
        let Some(region) = regions
            .iter()
            .find(|r| offset >= r.offset && offset < r.offset + r.size as u64)
        else {
            continue;
        };
        let page = region.base_host_virt_addr + (offset - region.offset);
        // A page already populated returns EEXIST, which copy_page treats as
        // success; a missing one is simply skipped.
        match copy_page(fd, region, page, layers, served) {
            Ok(()) => filled += 1,
            // Nothing was filled, so a diff will not hold it either.
            Err(_) => served
                .lock()
                .unwrap()
                .remove_bytes(offset, offset + region.page_size as u64),
        }
    }
    filled
}

/// Serves page faults for one restored VM.
///
/// Owned by the [`MicroVm`](crate::MicroVm) it belongs to. Dropping it stops
/// the handler, which is only safe once the VMM is gone: a live guest whose
/// faults stop being answered hangs rather than fails.
pub struct UffdBackend {
    socket_path: PathBuf,
    stop: Arc<Stop>,
    served: Arc<Served>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl UffdBackend {
    /// Binds the socket and starts the handler thread.
    ///
    /// Must be called *before* `load_snapshot`, because Firecracker connects as
    /// part of handling that request and fails outright if nothing is
    /// listening.
    /// `chain` lists the memory files oldest first: a full base, then any diff
    /// snapshots layered over it. The newest layer that defines a page wins.
    pub fn start(workdir: &Path, plan: &MemoryPlan) -> io::Result<Self> {
        let chain = &plan.chain;
        let owner = plan.owner;
        if chain.is_empty() {
            return Err(io::Error::other("no memory files to serve"));
        }
        let socket_path = workdir.join(UFFD_SOCK);
        // A previous VM in the same working directory leaves its socket behind.
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;

        // A jailed firecracker runs unprivileged and has to be able to connect
        // to this socket, which burrowd created as root. Ownership is handed
        // over rather than the mode widened, so nothing else on the host gains
        // a path into a sandbox's guest memory.
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&socket_path, Some(uid), Some(gid))?;
            std::fs::set_permissions(
                &socket_path,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )?;
        }

        let layers: Vec<Layer> = chain
            .iter()
            .enumerate()
            .map(|(index, path)| {
                Layer::open(
                    path,
                    index,
                    (index == 0).then(|| plan.base_source.clone()).flatten(),
                )
            })
            .collect::<io::Result<_>>()?;
        let stop = Arc::new(Stop::new()?);
        let served = Arc::new(Mutex::new(memfile::PageMap::new(
            layers[0].pages.len / memfile::PAGE,
        )));

        let thread = {
            let stop = Arc::clone(&stop);
            let served = Arc::clone(&served);
            let memory_file = chain.last().cloned().unwrap_or_default();
            let plan = plan.clone();
            std::thread::Builder::new()
                .name("burrow-uffd".into())
                .spawn(move || {
                    if let Err(err) = serve(&listener, layers, &served, &stop, &plan) {
                        // A guest whose faults go unanswered stalls silently,
                        // so this is the only warning anyone will get.
                        tracing::error!(
                            memory_file = %memory_file.display(), %err,
                            "page-fault handler stopped; guest memory is no longer being served"
                        );
                    }
                })?
        };

        Ok(Self {
            socket_path,
            stop,
            served,
            thread: Some(thread),
        })
    }

    /// The pages a diff of this VM holds, at most: every page served so far.
    pub fn served_pages(&self) -> memfile::PageMap {
        self.served.lock().unwrap().clone()
    }

    /// Path Firecracker should be pointed at, relative to the working
    /// directory.
    pub fn backend_path() -> &'static str {
        UFFD_SOCK
    }
}

impl Drop for UffdBackend {
    fn drop(&mut self) {
        self.stop.signal();
        // Joining keeps the mapping alive until the thread is genuinely
        // finished with it.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Accepts Firecracker's connection, then serves faults until it exits.
fn serve(
    listener: &UnixListener,
    layers: Vec<Layer>,
    served: &Served,
    stop: &Stop,
    plan: &MemoryPlan,
) -> io::Result<()> {
    let stream = accept(listener, stop)?;
    let Some(stream) = stream else { return Ok(()) };

    let (regions, uffd) = receive_layout(&stream)?;
    if regions.is_empty() {
        return Err(io::Error::other("firecracker sent no memory regions"));
    }
    let total: usize = regions.iter().map(|r| r.size).sum();
    // The base is sized for the whole guest; diffs are the same size with
    // holes, so any layer being short means a mismatched snapshot.
    if let Some(short) = layers.iter().find(|layer| total as u64 > layer.pages.len) {
        return Err(io::Error::other(format!(
            "guest memory is {total} bytes but a snapshot layer holds {}",
            short.pages.len
        )));
    }
    tracing::debug!(
        regions = regions.len(),
        bytes = total,
        layers = layers.len(),
        "serving guest memory lazily"
    );

    // Before the guest is unpaused, not while it runs: a page filled here is
    // a fault the guest never takes.
    if let Some(path) = &plan.prefetch {
        let offsets = read_plan(path);
        if !offsets.is_empty() {
            let started = Instant::now();
            let filled = prefetch(uffd.as_raw_fd(), &regions, &layers, served, &offsets);
            tracing::debug!(
                pages = filled,
                of = offsets.len(),
                took_ms = started.elapsed().as_millis() as u64,
                "prefetched guest memory"
            );
        }
    }

    let faulted = handle_faults(&uffd, &regions, &layers, served, stop)?;

    if let Some(path) = &plan.record_to {
        let mut offsets: Vec<u64> = faulted.into_iter().collect();
        offsets.sort_unstable();
        if let Err(err) = write_plan(path, &offsets) {
            tracing::warn!(path = %path.display(), %err, "could not write the prefetch plan");
        } else {
            tracing::info!(pages = offsets.len(), path = %path.display(), "recorded a prefetch plan");
        }
    }
    Ok(())
}

/// Waits for Firecracker to connect, giving up rather than hanging forever.
fn accept(listener: &UnixListener, stop: &Stop) -> io::Result<Option<UnixStream>> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        if stop.is_set() {
            return Ok(None);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(Some(stream));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "firecracker never connected to the page-fault socket",
            ));
        }
        stop.wait(listener.as_raw_fd(), left.as_millis().max(1) as libc::c_int)?;
    }
}

/// Reads the region layout and the userfaultfd Firecracker passes with it.
///
/// The descriptor rides as `SCM_RIGHTS` ancillary data alongside the JSON body.
/// Firecracker occasionally completes the write without the ancillary payload
/// landing in the same read, so a body without a descriptor is retried rather
/// than treated as fatal.
fn receive_layout(stream: &UnixStream) -> io::Result<(Vec<RegionMapping>, OwnedFd)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    let mut last_body = String::new();
    for _ in 0..5 {
        let mut buf = vec![0u8; 8192];
        let mut cmsg = nix::cmsg_space!([RawFd; 1]);
        let mut iov = [io::IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg[..]),
            MsgFlags::empty(),
        )
        .map_err(io::Error::from)?;

        let mut received = None;
        for cmsg in msg.cmsgs().map_err(io::Error::from)? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg
                && let Some(&fd) = fds.first()
            {
                // SAFETY: the kernel just installed this descriptor in our
                // table and it is named nowhere else.
                received = Some(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) });
            }
        }
        let bytes = msg.bytes;

        last_body = String::from_utf8_lossy(&buf[..bytes]).into_owned();
        let Some(uffd) = received else {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };
        let regions: Vec<RegionMapping> = serde_json::from_str(&last_body).map_err(|err| {
            io::Error::other(format!(
                "memory layout from firecracker: {err}: {last_body}"
            ))
        })?;
        return Ok((regions, uffd));
    }
    Err(io::Error::other(format!(
        "firecracker never sent a userfaultfd (last body: {last_body})"
    )))
}

/// The fault-serving loop. Returns when Firecracker closes the descriptor.
fn handle_faults(
    uffd: &OwnedFd,
    regions: &[RegionMapping],
    layers: &[Layer],
    served: &Served,
    stop: &Stop,
) -> io::Result<std::collections::BTreeSet<u64>> {
    let fd = uffd.as_raw_fd();
    let mut buf = [0u8; UFFD_MSG_SIZE];
    let mut faulted = std::collections::BTreeSet::new();
    loop {
        if stop.is_set() {
            return Ok(faulted);
        }
        // Firecracker makes the descriptor non-blocking, so a bare read spun
        // a host core for as long as the guest ran.
        if !stop.wait(fd, -1)? {
            continue;
        }
        // SAFETY: `fd` is the userfaultfd and `buf` is exactly one message.
        let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), UFFD_MSG_SIZE) };
        if read == 0 {
            // Firecracker exited; nothing left to serve.
            return Ok(faulted);
        }
        if read < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                // The VMM died and took the descriptor with it.
                _ if err.raw_os_error() == Some(libc::EBADF) => return Ok(faulted),
                _ => return Err(err),
            }
        }

        match parse_event(&buf) {
            Event::PageFault { address } => {
                let Some(region) = regions.iter().find(|r| r.is_in_region(address)) else {
                    // Serving the wrong address would corrupt the guest, so
                    // leave it stalled and say why.
                    return Err(io::Error::other(format!(
                        "fault at {address:#x} is outside every known region"
                    )));
                };
                let page = address & !(region.page_size as u64 - 1);
                // Recorded by file offset, because the address a region lands
                // at is a property of this restore, not of the snapshot.
                faulted.insert(region.offset + (page - region.base_host_virt_addr));
                copy_page(fd, region, page, layers, served)?;
            }
            Event::Remove { start, end } => {
                if let Some(region) = regions.iter().find(|r| r.is_in_region(start)) {
                    mark(
                        served,
                        region.offset + (start - region.base_host_virt_addr),
                        end - start,
                    );
                }
                zero_range(fd, start, end)?
            }
            Event::Other => {}
        }
    }
}

/// Populates one page from the newest layer that defines it.
///
/// A page no layer defines was never written, which for a sparse snapshot
/// means it is zero, so it is filled rather than treated as an error.
fn copy_page(
    fd: RawFd,
    region: &RegionMapping,
    page: u64,
    layers: &[Layer],
    served: &Served,
) -> io::Result<()> {
    let offset = region.offset + (page - region.base_host_virt_addr);
    // Before the page can be present, so no snapshot finds it present and
    // unrecorded.
    mark(served, offset, region.page_size as u64);
    let Some(layer) = memfile::resolve(layers, offset).map(|index| &layers[index]) else {
        return zero_range(fd, page, page + region.page_size as u64);
    };
    if let Some(source) = &layer.source {
        source.ensure(offset, region.page_size as u64)?;
    }
    loop {
        let mut arg = UffdioCopy {
            dst: page,
            src: layer.backing.addr as u64 + offset,
            len: region.page_size as u64,
            mode: 0,
            copy: 0,
        };
        // SAFETY: `fd` is the userfaultfd and `arg` matches `struct uffdio_copy`.
        if unsafe { libc::ioctl(fd, UFFDIO_COPY as _, &mut arg) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Another thread faulted the same page first; the guest is
            // unblocked either way.
            Some(libc::EEXIST) => return Ok(()),
            // The address space changed under the copy, which filled nothing
            // and woke nobody. A vCPU stalled on this page stays stalled
            // until it is filled, so the copy is tried again.
            Some(libc::EAGAIN) => continue,
            _ => return Err(err),
        }
    }
}

/// Answers a ballooned-away range with zeroes.
fn zero_range(fd: RawFd, start: u64, end: u64) -> io::Result<()> {
    let mut arg = UffdioZeropage {
        range: UffdioRange {
            start,
            len: end - start,
        },
        mode: 0,
        zeropage: 0,
    };
    loop {
        // SAFETY: `fd` is the userfaultfd and `arg` matches `struct uffdio_zeropage`.
        if unsafe { libc::ioctl(fd, UFFDIO_ZEROPAGE as _, &mut arg) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EEXIST) => return Ok(()),
            // As for a copy: nothing was filled, so it is tried again.
            Some(libc::EAGAIN) => {
                arg.zeropage = 0;
                continue;
            }
            _ => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_wakes_an_idle_fault_handler_at_once() {
        let (read, _write) = nix::unistd::pipe().unwrap();
        let stop = Arc::new(Stop::new().unwrap());
        let served = Mutex::new(memfile::PageMap::new(0));
        let handler = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || handle_faults(&read, &[], &[], &served, &stop).map(drop))
        };
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        stop.signal();
        handler.join().unwrap().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(20),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn dropping_a_backend_firecracker_never_reached_returns_promptly() {
        let dir = std::env::temp_dir().join(format!("burrow-uffd-stop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mem = dir.join("snapshot.mem");
        std::fs::write(&mem, vec![0u8; 2 * memfile::PAGE as usize]).unwrap();
        let backend = UffdBackend::start(
            &dir,
            &MemoryPlan {
                chain: vec![mem],
                ..Default::default()
            },
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        drop(backend);
        assert!(
            started.elapsed() < Duration::from_millis(20),
            "took {:?}",
            started.elapsed()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ioctl_numbers_match_the_kernel_abi() {
        // Values from linux/userfaultfd.h on both x86_64 and aarch64; a
        // mismatch here means every fault fails with ENOTTY.
        assert_eq!(UFFDIO_COPY, 0xc028aa03);
        assert_eq!(UFFDIO_ZEROPAGE, 0xc020aa04);
    }

    #[test]
    fn struct_layouts_match_the_kernel_abi() {
        assert_eq!(std::mem::size_of::<UffdioCopy>(), 40);
        assert_eq!(std::mem::size_of::<UffdioZeropage>(), 32);
        assert_eq!(std::mem::size_of::<UffdioRange>(), 16);
    }

    #[test]
    fn a_pagefault_message_yields_its_address() {
        let mut buf = [0u8; UFFD_MSG_SIZE];
        buf[0] = UFFD_EVENT_PAGEFAULT;
        // arg.pagefault = { flags, address, ptid }
        buf[16..24].copy_from_slice(&0xdead_0000u64.to_ne_bytes());
        match parse_event(&buf) {
            Event::PageFault { address } => assert_eq!(address, 0xdead_0000),
            _ => panic!("expected a page fault"),
        }
    }

    #[test]
    fn a_remove_message_yields_its_range() {
        let mut buf = [0u8; UFFD_MSG_SIZE];
        buf[0] = UFFD_EVENT_REMOVE;
        buf[8..16].copy_from_slice(&0x1000u64.to_ne_bytes());
        buf[16..24].copy_from_slice(&0x3000u64.to_ne_bytes());
        match parse_event(&buf) {
            Event::Remove { start, end } => {
                assert_eq!((start, end), (0x1000, 0x3000));
            }
            _ => panic!("expected a remove"),
        }
    }

    #[test]
    fn a_fault_is_matched_to_the_region_holding_it() {
        let regions = [
            RegionMapping {
                base_host_virt_addr: 0x1000,
                size: 0x1000,
                offset: 0,
                page_size: 0x1000,
            },
            RegionMapping {
                base_host_virt_addr: 0x100000,
                size: 0x2000,
                offset: 0x1000,
                page_size: 0x1000,
            },
        ];
        assert!(regions[0].is_in_region(0x1fff));
        assert!(!regions[0].is_in_region(0x2000));
        assert!(regions[1].is_in_region(0x101000));
        // The gap between regions belongs to neither.
        assert!(!regions.iter().any(|r| r.is_in_region(0x50000)));
    }

    #[test]
    fn firecrackers_layout_wire_format_parses() {
        // Field names are Firecracker's; a rename on its side must fail here
        // rather than silently produce zero regions.
        let body = r#"[{"base_host_virt_addr":140244897726464,"size":268435456,
                        "offset":0,"page_size":4096}]"#;
        let regions: Vec<RegionMapping> = serde_json::from_str(body).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].size, 268435456);
        assert_eq!(regions[0].page_size, 4096);
    }
}
