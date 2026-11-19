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
//!
//! With huge pages on, the whole 2 MiB block around a fault is filled and
//! then collapsed into a huge page in Firecracker's address space. The
//! kernel never allocates a huge page for a range registered with a
//! userfaultfd, so served a page at a time a restored guest ran on 4 KiB
//! mappings for good: every first touch was a fault, a round trip through
//! this thread and, nested, an exit to the outer hypervisor, and touching
//! 1 GiB took 16 s against 0.3 s on Cloud Hypervisor. A block costs 2 MiB of
//! memory where one page was asked for, which is what a huge page costs
//! anyway, and a node that would rather have the density turns it off.

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

/// What a fault is answered with when huge pages are on: one huge page.
const BLOCK: u64 = 2 << 20;

/// How long collapsing is left alone once the kernel has no huge page to
/// give. Each refusal is a compaction stall with a vCPU waiting on it, and on
/// a fragmented host the next block's would fail the same way.
const COLLAPSE_PAUSE: Duration = Duration::from_secs(1);

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
        addr >= self.base_host_virt_addr && addr < self.end()
    }

    fn end(&self) -> u64 {
        self.base_host_virt_addr + self.size as u64
    }

    /// Where `addr` lies in the memory file.
    fn offset_of(&self, addr: u64) -> u64 {
        self.offset + (addr - self.base_host_virt_addr)
    }

    /// The block around `addr`, cut to this region.
    fn block_of(&self, addr: u64) -> (u64, u64) {
        let start = addr & !(BLOCK - 1);
        (
            start.max(self.base_host_virt_addr),
            (start + BLOCK).min(self.end()),
        )
    }
}
//
// Bound by hand rather than through a crate. Firecracker creates the fd,
// performs the API handshake, and registers the regions, so the handler only
// ever needs to resolve a fault: `COPY` for a page that has contents in the
// memory file, `ZEROPAGE` for one the balloon removed, `WAKE` once a block
// is in place. Three ioctls and three structs is less surface than a bindgen
// dependency in a cross-compiled build.

const UFFDIO: u32 = 0xAA;
const IOC_READ_WRITE: u32 = 3;

const fn iowr(nr: u32, size: u32) -> u32 {
    (IOC_READ_WRITE << 30) | (size << 16) | (UFFDIO << 8) | nr
}

const UFFDIO_WAKE: u32 =
    (2 << 30) | ((std::mem::size_of::<UffdioRange>() as u32) << 16) | (UFFDIO << 8) | 0x02;
const UFFDIO_COPY: u32 = iowr(0x03, std::mem::size_of::<UffdioCopy>() as u32);
const UFFDIO_ZEROPAGE: u32 = iowr(0x04, std::mem::size_of::<UffdioZeropage>() as u32);
const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1;
const MADV_COLLAPSE: libc::c_int = 25;
const SO_PEERPIDFD: libc::c_int = 77;

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
    /// A read-only anonymous block, which reads as zeroes without using any
    /// memory: the source of every page no layer defines, when it is to
    /// become part of a huge page. A page mapped from the zero page would
    /// keep its block from collapsing, and cost a write a second fault.
    fn zeroes() -> io::Result<Self> {
        let len = BLOCK as usize;
        // SAFETY: an anonymous mapping takes no descriptor.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
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

/// Tells the handler thread to stop, or that the VM is restored, waking it
/// out of any poll at once.
struct Stop {
    flag: AtomicBool,
    is_restored: AtomicBool,
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
            is_restored: AtomicBool::new(false),
            // SAFETY: the descriptor was just created and is named nowhere else.
            wake: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn signal(&self) {
        self.flag.store(true, Ordering::Relaxed);
        self.wake();
    }

    fn restored(&self) {
        self.is_restored.store(true, Ordering::Relaxed);
        self.wake();
    }

    fn wake(&self) {
        let one = 1u64;
        // SAFETY: `one` is eight readable bytes, what an eventfd write takes.
        unsafe { libc::write(self.wake.as_raw_fd(), (&raw const one).cast(), 8) };
    }

    fn is_set(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn is_restored(&self) -> bool {
        self.is_restored.load(Ordering::Relaxed)
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
        // Drained once the restore has woken it, or every poll after would
        // return at once. A stop is left readable: nothing polls after it.
        if fds[1].revents != 0 && !self.is_set() {
            let mut count = 0u64;
            // SAFETY: `count` is eight writable bytes, what an eventfd read takes.
            unsafe { libc::read(self.wake.as_raw_fd(), (&raw mut count).cast(), 8) };
        }
        Ok(fds[0].revents != 0)
    }
}

fn mark(served: &Served, offset: u64, len: u64) {
    served.lock().unwrap().insert_bytes(offset, offset + len);
}

/// Collapses filled blocks into huge pages in Firecracker's address space.
///
/// `MADV_COLLAPSE` only succeeds on a block whose every page is present, which
/// is why a fault fills the whole block first. A kernel or a VMM that refuses
/// it leaves the blocks on small pages: slower, never wrong.
struct Collapse {
    pidfd: Option<OwnedFd>,
    /// Once a block has collapsed, `EINVAL` is that block's trouble rather
    /// than a kernel without `MADV_COLLAPSE`.
    has_collapsed: bool,
    paused_until: Option<Instant>,
}

impl Collapse {
    /// The peer's pidfd, from the socket where the kernel can give one
    /// (Linux 6.5), else opened from its pid.
    fn of(stream: &UnixStream) -> Self {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let mut fd: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` and `len` describe the int the option is read into.
        let peer = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&raw mut fd).cast(),
                &mut len,
            )
        };
        let fd = if peer == 0 {
            Some(fd)
        } else {
            getsockopt(stream, PeerCredentials).ok().and_then(|cred| {
                // SAFETY: pidfd_open takes a pid and flags.
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, cred.pid(), 0) };
                (fd >= 0).then_some(fd as RawFd)
            })
        };
        Self {
            // SAFETY: the descriptor was just created and is named nowhere else.
            pidfd: fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            has_collapsed: false,
            paused_until: None,
        }
    }

    fn run(&mut self, start: u64, end: u64) {
        let Some(pidfd) = &self.pidfd else { return };
        if self
            .paused_until
            .is_some_and(|until| Instant::now() < until)
        {
            return;
        }
        let iov = libc::iovec {
            iov_base: start as *mut libc::c_void,
            iov_len: (end - start) as usize,
        };
        // SAFETY: `iov` is one valid entry; the range it names is in the
        // target's address space and only read by the kernel.
        let done = unsafe {
            libc::syscall(
                libc::SYS_process_madvise,
                pidfd.as_raw_fd(),
                &raw const iov,
                1,
                MADV_COLLAPSE,
                0,
            )
        };
        if done >= 0 {
            self.has_collapsed = true;
            return;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Out of huge pages for now is worth trying again in a while; a
            // kernel that cannot do it at all is not.
            Some(libc::ENOMEM) => self.paused_until = Some(Instant::now() + COLLAPSE_PAUSE),
            Some(libc::ENOSYS | libc::EPERM) => self.give_up(&err),
            Some(libc::EINVAL) if !self.has_collapsed => self.give_up(&err),
            _ => {}
        }
    }

    fn give_up(&mut self, err: &io::Error) {
        tracing::debug!(%err, "cannot collapse guest memory into huge pages");
        self.pidfd = None;
    }
}

/// Answers faults a block at a time, collapsing each into a huge page.
///
/// Until the VM is restored a fault is answered with its page alone, and its
/// block is filled once the restore is done and no fault is waiting. The
/// restore's few faults are Firecracker and KVM putting the VM back together,
/// one after another, and filling and collapsing a block took milliseconds
/// each on a nested host. Once restored, a block's first fault is answered
/// the same way and a second one with the whole block, so a guest walking
/// through memory does not take a fault per page.
struct Blocks {
    zeroes: Backing,
    collapse: Collapse,
    /// Blocks to fill once the handler is idle, by their start address.
    waiting: std::collections::VecDeque<u64>,
    is_waiting: std::collections::HashSet<u64>,
    /// Blocks waiting or filled, which are not filled again.
    seen: std::collections::HashSet<u64>,
}

impl Blocks {
    fn new(zeroes: Backing, collapse: Collapse) -> Self {
        Self {
            zeroes,
            collapse,
            waiting: std::collections::VecDeque::new(),
            is_waiting: std::collections::HashSet::new(),
            seen: std::collections::HashSet::new(),
        }
    }

    /// Leaves the block around `page` to be filled once idle, unless it has
    /// been already.
    fn defer(&mut self, region: &RegionMapping, page: u64) {
        let (start, _) = region.block_of(page);
        if self.seen.insert(start) {
            self.is_waiting.insert(start);
            self.waiting.push_back(start);
        }
    }

    /// Answers a fault on `page`: with the whole block when it is waiting
    /// and the VM is restored, else with the page alone.
    fn serve(
        &mut self,
        fd: RawFd,
        region: &RegionMapping,
        page: u64,
        layers: &[Layer],
        served: &Served,
        is_restored: bool,
    ) -> io::Result<()> {
        let (start, _) = region.block_of(page);
        let layer = memfile::resolve(layers, region.offset_of(page));
        let size = region.page_size as u64;
        if is_restored && self.is_waiting.remove(&start) {
            fill(
                fd,
                region,
                page,
                size,
                layer,
                layers,
                Some(&self.zeroes),
                served,
                UFFDIO_COPY_MODE_DONTWAKE,
            )?;
            return self.fill_block(fd, region, start, layers, served);
        }
        fill(
            fd,
            region,
            page,
            size,
            layer,
            layers,
            Some(&self.zeroes),
            served,
            0,
        )?;
        self.defer(region, page);
        Ok(())
    }

    /// Fills the oldest waiting block.
    fn fill_next(
        &mut self,
        fd: RawFd,
        regions: &[RegionMapping],
        layers: &[Layer],
        served: &Served,
    ) -> io::Result<()> {
        let Some(start) = self.waiting.pop_front() else {
            return Ok(());
        };
        if !self.is_waiting.remove(&start) {
            return Ok(());
        }
        match regions.iter().find(|region| region.is_in_region(start)) {
            Some(region) => self.fill_block(fd, region, start, layers, served),
            None => Ok(()),
        }
    }

    /// Fills every page of the block at `at` not served yet, collapses it
    /// and wakes it.
    ///
    /// A page that cannot be filled, its contents failing to arrive or its
    /// memory to be charged, ends the filling and leaves the block on small
    /// pages, with the rest to fault in on their own.
    fn fill_block(
        &mut self,
        fd: RawFd,
        region: &RegionMapping,
        at: u64,
        layers: &[Layer],
        served: &Served,
    ) -> io::Result<()> {
        let size = region.page_size as u64;
        let (start, end) = region.block_of(at);
        let fill = |at: u64, len: u64, layer: Option<usize>| {
            fill(
                fd,
                region,
                at,
                len,
                layer,
                layers,
                Some(&self.zeroes),
                served,
                UFFDIO_COPY_MODE_DONTWAKE,
            )
        };
        let runs = {
            let served = served.lock().unwrap();
            let is_missing = |at: u64| !served.contains(region.offset_of(at) / memfile::PAGE);
            let mut runs = Vec::new();
            let mut at = start;
            while at < end {
                if !is_missing(at) {
                    at += size;
                    continue;
                }
                let layer = memfile::resolve(layers, region.offset_of(at));
                let mut run_end = at + size;
                while run_end < end
                    && is_missing(run_end)
                    && memfile::resolve(layers, region.offset_of(run_end)) == layer
                {
                    run_end += size;
                }
                runs.push((at, run_end, layer));
                at = run_end;
            }
            runs
        };
        let is_whole = runs
            .into_iter()
            .all(|(at, run_end, layer)| fill(at, run_end - at, layer).is_ok());
        if is_whole && end - start == BLOCK {
            self.collapse.run(start, end);
        }
        wake(fd, start, end)
    }
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
    /// Answer a fault with its whole block and collapse it into a huge page,
    /// rather than with the one page asked for.
    pub is_huge_page_fill_enabled: bool,
}

impl std::fmt::Debug for MemoryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryPlan")
            .field("chain", &self.chain)
            .field("prefetch", &self.prefetch)
            .field("is_base_arriving", &self.base_source.is_some())
            .field("is_huge_page_fill_enabled", &self.is_huge_page_fill_enabled)
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
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk))
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
/// copy. With huge pages on, their blocks are filled once the handler is idle.
fn prefetch(
    fd: RawFd,
    regions: &[RegionMapping],
    layers: &[Layer],
    mut blocks: Option<&mut Blocks>,
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
    let mut at = 0;
    while at < offsets.len() {
        let offset = offsets[at];
        // The plan stores file offsets; the address to populate depends on
        // which region covers that offset in *this* restore.
        let Some(region) = regions
            .iter()
            .find(|r| offset >= r.offset && offset < r.offset + r.size as u64)
        else {
            at += 1;
            continue;
        };
        // Adjacent pages from the same layer go in one copy. The plan is
        // sorted, and a guest's pages come in runs, so this is a fraction of
        // the ioctls one per page would be.
        let page_size = region.page_size as u64;
        let layer = memfile::resolve(layers, offset);
        let mut end = at + 1;
        while end < offsets.len()
            && offsets[end] == offsets[end - 1] + page_size
            && offsets[end] < region.offset + region.size as u64
            && memfile::resolve(layers, offsets[end]) == layer
        {
            end += 1;
        }
        let start = region.base_host_virt_addr + (offset - region.offset);
        let len = (end - at) as u64 * page_size;
        let zeroes = blocks.as_deref().map(|blocks| &blocks.zeroes);
        // A missing page is simply skipped, and with it the rest of its run.
        if fill(fd, region, start, len, layer, layers, zeroes, served, 0).is_ok() {
            filled += end - at;
            if let Some(blocks) = blocks.as_deref_mut()
                && page_size == memfile::PAGE
            {
                let mut page = start & !(BLOCK - 1);
                while page < start + len {
                    blocks.defer(region, page.max(start));
                    page += BLOCK;
                }
            }
        }
        at = end;
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

    /// Tells the handler the VM is restored, so it may fill blocks.
    pub fn restored(&self) {
        self.stop.restored();
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
    // As soon as Firecracker connects, while the peer is the process that
    // did: its pid could be reused while the layout is waited for.
    let mut blocks = if plan.is_huge_page_fill_enabled {
        Some(Blocks::new(Backing::zeroes()?, Collapse::of(&stream)))
    } else {
        None
    };

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
            let filled = prefetch(
                uffd.as_raw_fd(),
                &regions,
                &layers,
                blocks.as_mut(),
                served,
                &offsets,
            );
            tracing::debug!(
                pages = filled,
                of = offsets.len(),
                took_ms = started.elapsed().as_millis() as u64,
                "prefetched guest memory"
            );
        }
    }

    let faulted = handle_faults(&uffd, &regions, &layers, served, stop, blocks.as_mut())?;

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
    mut blocks: Option<&mut Blocks>,
) -> io::Result<std::collections::BTreeSet<u64>> {
    let fd = uffd.as_raw_fd();
    let mut buf = [0u8; UFFD_MSG_SIZE];
    let mut faulted = std::collections::BTreeSet::new();
    loop {
        if stop.is_set() {
            return Ok(faulted);
        }
        // Firecracker makes the descriptor non-blocking, so a bare read spun
        // a host core for as long as the guest ran. Waiting blocks are filled
        // only while no fault is.
        let is_filling = stop.is_restored()
            && blocks
                .as_deref()
                .is_some_and(|blocks| !blocks.waiting.is_empty());
        if !stop.wait(fd, if is_filling { 0 } else { -1 })? {
            if let Some(blocks) = blocks.as_deref_mut()
                && !stop.is_set()
            {
                blocks.fill_next(fd, regions, layers, served)?;
            }
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
                faulted.insert(region.offset_of(page));
                match blocks.as_deref_mut() {
                    Some(blocks) if region.page_size as u64 == memfile::PAGE => {
                        blocks.serve(fd, region, page, layers, served, stop.is_restored())?
                    }
                    _ => copy_page(fd, region, page, layers, served)?,
                }
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
    let layer = memfile::resolve(layers, offset);
    fill(
        fd,
        region,
        page,
        region.page_size as u64,
        layer,
        layers,
        None,
        served,
        0,
    )
}

/// Populates `len` bytes of `region` from `start`, from the layer at index
/// `layer`, or with zeroes when no layer defines them: copied from `zeroes`
/// when given, else mapped from the zero page.
#[allow(clippy::too_many_arguments)]
fn fill(
    fd: RawFd,
    region: &RegionMapping,
    start: u64,
    len: u64,
    layer: Option<usize>,
    layers: &[Layer],
    zeroes: Option<&Backing>,
    served: &Served,
    mode: u64,
) -> io::Result<()> {
    let offset = region.offset_of(start);
    let layer = layer.map(|index| &layers[index]);
    // Before the pages are recorded: one that never arrives is never filled,
    // and a diff could not hold it.
    if let Some(source) = layer.and_then(|layer| layer.source.as_ref()) {
        source.ensure(offset, len)?;
    }
    // Before the pages can be present, so no snapshot finds one present and
    // unrecorded.
    mark(served, offset, len);
    // Zeroes are copied from one block of them, a block at a time.
    let (src, stride) = match layer {
        Some(layer) => (layer.backing.addr as u64 + offset, len),
        None => match zeroes {
            Some(zeroes) => (zeroes.addr as u64, zeroes.len as u64),
            // A page this did fill and no longer recorded is zeroes in every
            // layer, which is what a restore reads for it anyway.
            None => {
                return zero_range(fd, start, start + len)
                    .inspect_err(|_| served.lock().unwrap().remove_bytes(offset, offset + len));
            }
        },
    };
    let mut done = 0;
    while done < len {
        let skew = done % stride;
        let mut arg = UffdioCopy {
            dst: start + done,
            src: src + skew,
            len: (len - done).min(stride - skew),
            mode,
            copy: 0,
        };
        // SAFETY: `fd` is the userfaultfd and `arg` matches `struct uffdio_copy`.
        if unsafe { libc::ioctl(fd, UFFDIO_COPY as _, &mut arg) } == 0 {
            done += arg.len;
            continue;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Another thread faulted the next page first; the guest is
            // unblocked either way.
            Some(libc::EEXIST) => done += region.page_size as u64,
            // A copy cut short, by a page filled since or by the address
            // space changing under it, which filled what `copy` says and
            // nothing after. A vCPU stalled on the rest stays stalled until
            // it is filled, so the copy goes on from there.
            Some(libc::EAGAIN) => done += arg.copy.max(0) as u64,
            _ => {
                // Nothing past `done` was filled, so a diff will not hold it.
                served
                    .lock()
                    .unwrap()
                    .remove_bytes(offset + done, offset + len);
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Lets every vCPU stalled in `[start, end)` carry on.
fn wake(fd: RawFd, start: u64, end: u64) -> io::Result<()> {
    let mut arg = UffdioRange {
        start,
        len: end - start,
    };
    // SAFETY: `fd` is the userfaultfd and `arg` matches `struct uffdio_range`.
    if unsafe { libc::ioctl(fd, UFFDIO_WAKE as _, &mut arg) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
            std::thread::spawn(move || {
                handle_faults(&read, &[], &[], &served, &stop, None).map(drop)
            })
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
        assert_eq!(UFFDIO_WAKE, 0x8010aa02);
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
    fn a_fault_is_served_its_block_cut_to_the_region() {
        let region = RegionMapping {
            base_host_virt_addr: 0x7f00_0010_0000,
            size: 0x40_0000,
            offset: 0x1000_0000,
            page_size: 0x1000,
        };
        assert_eq!(
            region.block_of(0x7f00_0010_3000),
            (0x7f00_0010_0000, 0x7f00_0020_0000)
        );
        assert_eq!(
            region.block_of(0x7f00_0020_5000),
            (0x7f00_0020_0000, 0x7f00_0040_0000)
        );
        assert_eq!(
            region.block_of(0x7f00_004f_f000),
            (0x7f00_0040_0000, 0x7f00_0050_0000)
        );
        assert_eq!(region.offset_of(0x7f00_0020_0000), 0x1010_0000);
    }

    const PAGES: u64 = 4 * BLOCK / memfile::PAGE;

    /// Four blocks of anonymous memory registered with a userfaultfd, as
    /// Firecracker hands a guest's over, and a memory file whose every page
    /// holds its index plus one.
    struct Guest {
        uffd: OwnedFd,
        regions: [RegionMapping; 1],
        mapped: u64,
        dir: PathBuf,
    }

    impl Guest {
        fn new(name: &str) -> Self {
            const UFFDIO_API: u32 = iowr(0x3f, 24);
            const UFFDIO_REGISTER: u32 = iowr(0x00, 32);
            let len = (PAGES * memfile::PAGE) as usize;
            let dir =
                std::env::temp_dir().join(format!("burrow-uffd-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let mut contents = vec![0u8; len];
            for (index, page) in contents.chunks_mut(memfile::PAGE as usize).enumerate() {
                page[..8].copy_from_slice(&(index as u64 + 1).to_ne_bytes());
            }
            std::fs::write(dir.join("snapshot.mem"), contents).unwrap();

            // SAFETY: an anonymous mapping takes no descriptor.
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len + BLOCK as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapped, libc::MAP_FAILED);
            let base = (mapped as u64 + BLOCK - 1) & !(BLOCK - 1);
            // SAFETY: userfaultfd takes flags; user mode only needs no privilege.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_userfaultfd,
                    libc::O_CLOEXEC | libc::O_NONBLOCK | 1,
                )
            };
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            // SAFETY: the descriptor was just created and is named nowhere else.
            let uffd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
            let mut api = [0xaa_u64, 0, 0];
            let mut register = [base, len as u64, 1, 0];
            // SAFETY: both arguments match their kernel structs.
            unsafe {
                assert_eq!(libc::ioctl(fd as RawFd, UFFDIO_API as _, &mut api), 0);
                assert_eq!(
                    libc::ioctl(fd as RawFd, UFFDIO_REGISTER as _, &mut register),
                    0
                );
            }
            Self {
                uffd,
                regions: [RegionMapping {
                    base_host_virt_addr: base,
                    size: len,
                    offset: 0,
                    page_size: memfile::PAGE as usize,
                }],
                mapped: mapped as u64,
                dir,
            }
        }

        /// The memory file as a base layer defining `defined`.
        fn layer(
            &self,
            defined: Vec<(u64, u64)>,
            source: Option<Arc<dyn super::super::PageSource>>,
        ) -> Layer {
            let mem = self.dir.join("snapshot.mem");
            Layer {
                backing: Backing::map(&mem).unwrap(),
                pages: memfile::Layer::full(PAGES * memfile::PAGE, defined),
                source,
            }
        }

        fn prefetch(
            &self,
            layers: &[Layer],
            blocks: Option<&mut Blocks>,
            served: &Served,
            pages: impl Iterator<Item = u64>,
        ) -> usize {
            let plan: Vec<u64> = pages.map(|page| page * memfile::PAGE).collect();
            prefetch(
                self.uffd.as_raw_fd(),
                &self.regions,
                layers,
                blocks,
                served,
                &plan,
            )
        }

        /// Serves faults from `layers` to a restored VM while `guest` runs,
        /// then stops.
        fn serve(
            &self,
            layers: Vec<Layer>,
            blocks: Option<&mut Blocks>,
            served: &Served,
            guest: impl FnOnce(),
        ) -> std::collections::BTreeSet<u64> {
            self.serve_restoring(layers, blocks, served, |stop| {
                stop.restored();
                guest();
            })
        }

        /// As [`Self::serve`], with `guest` saying when the VM is restored.
        fn serve_restoring(
            &self,
            layers: Vec<Layer>,
            blocks: Option<&mut Blocks>,
            served: &Served,
            guest: impl FnOnce(&Stop),
        ) -> std::collections::BTreeSet<u64> {
            let stop = Stop::new().unwrap();
            std::thread::scope(|scope| {
                let handler = scope.spawn({
                    let stop = &stop;
                    move || handle_faults(&self.uffd, &self.regions, &layers, served, stop, blocks)
                });
                guest(&stop);
                stop.signal();
                handler.join().unwrap().unwrap()
            })
        }

        fn read(&self, page: u64) -> u64 {
            let at = self.regions[0].base_host_virt_addr + page * memfile::PAGE;
            // SAFETY: the page is inside the registered mapping.
            unsafe { std::ptr::read_volatile(at as *const u64) }
        }

        fn write(&self, page: u64, value: u64) {
            let at = self.regions[0].base_host_virt_addr + page * memfile::PAGE;
            // SAFETY: as for a read.
            unsafe { std::ptr::write_volatile(at as *mut u64, value) }
        }
    }

    impl Drop for Guest {
        fn drop(&mut self) {
            let len = self.regions[0].size + BLOCK as usize;
            // SAFETY: the mapping was made in `new` and nothing refers to it now.
            unsafe { libc::munmap(self.mapped as *mut libc::c_void, len) };
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn blocks() -> Blocks {
        Blocks::new(
            Backing::zeroes().unwrap(),
            Collapse {
                // SAFETY: pidfd_open takes a pid and flags.
                pidfd: match unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) } {
                    // SAFETY: the descriptor was just created and is named
                    // nowhere else.
                    fd if fd >= 0 => Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }),
                    _ => None,
                },
                has_collapsed: false,
                paused_until: None,
            },
        )
    }

    /// A base that has not arrived where `missing` says, failing whoever asks
    /// for it there.
    struct Arriving {
        missing: Mutex<Option<(u64, u64)>>,
    }

    impl super::super::PageSource for Arriving {
        fn extents(&self) -> Vec<(u64, u64)> {
            vec![(0, PAGES * memfile::PAGE)]
        }

        fn ensure(&self, offset: u64, len: u64) -> io::Result<()> {
            match *self.missing.lock().unwrap() {
                Some((start, end)) if offset < end && start < offset + len => {
                    Err(io::Error::other("not arrived"))
                }
                _ => Ok(()),
            }
        }
    }

    /// Pages 500..530 are defined by no layer. A prefetch fills 505..520 and
    /// 1000..1010 first, across a block boundary, as the plan of an earlier
    /// restore would.
    fn serve_a_guest(name: &str, mut blocks: Option<&mut Blocks>) -> memfile::PageMap {
        let guest = Guest::new(name);
        let layers = vec![guest.layer(
            vec![
                (0, 500 * memfile::PAGE),
                (530 * memfile::PAGE, PAGES * memfile::PAGE),
            ],
            None,
        )];
        let served = Mutex::new(memfile::PageMap::new(PAGES));
        assert_eq!(
            guest.prefetch(
                &layers,
                blocks.as_deref_mut(),
                &served,
                (505..520).chain(1000..1010)
            ),
            25
        );
        let mut after_one = None;
        let faulted = guest.serve(layers, blocks.take(), &served, || {
            assert_eq!(guest.read(1500), 1501);
            after_one = Some(served.lock().unwrap().clone());
            for page in 0..PAGES {
                let expected = if (500..530).contains(&page) {
                    0
                } else {
                    page + 1
                };
                assert_eq!(guest.read(page), expected, "page {page}");
            }
            guest.write(7, 42);
            assert_eq!(guest.read(7), 42);
        });
        assert!(faulted.contains(&(1500 * memfile::PAGE)));
        assert_eq!(served.lock().unwrap().count(), PAGES);
        after_one.unwrap()
    }

    #[test]
    fn a_fault_and_prefetched_pages_are_filled_with_their_blocks() {
        let after_one = serve_a_guest("blocks", Some(&mut blocks()));
        assert!(after_one.contains(1500));
    }

    /// The first fault in a block is answered with its page, and the block
    /// is filled behind it once the VM is restored.
    #[test]
    fn a_block_is_filled_behind_its_first_fault_once_restored() {
        let guest = Guest::new("behind");
        let layers = vec![guest.layer(vec![(0, PAGES * memfile::PAGE)], None)];
        let served = Mutex::new(memfile::PageMap::new(PAGES));
        let per_block = BLOCK / memfile::PAGE;
        let block = 1500 / per_block * per_block;
        let mut blocks = blocks();
        guest.serve_restoring(layers, Some(&mut blocks), &served, |restored| {
            assert_eq!(guest.read(1500), 1501);
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(served.lock().unwrap().count(), 1);
            restored.restored();
            let deadline = Instant::now() + Duration::from_secs(5);
            while served.lock().unwrap().count() < per_block {
                assert!(Instant::now() < deadline, "the block was never filled");
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let served = served.lock().unwrap();
        assert!((block..block + per_block).all(|page| served.contains(page)));
        assert_eq!(served.count(), per_block);
    }

    /// A second fault in a block still waiting fills the block before it is
    /// answered.
    #[test]
    fn a_second_fault_in_a_block_fills_it() {
        let guest = Guest::new("second");
        let layers = vec![guest.layer(vec![(0, PAGES * memfile::PAGE)], None)];
        let served = Mutex::new(memfile::PageMap::new(PAGES));
        let per_block = BLOCK / memfile::PAGE;
        let block = 1500 / per_block * per_block;
        let mut blocks = blocks();
        guest.serve(layers, Some(&mut blocks), &served, || {
            assert_eq!(guest.read(1500), 1501);
            assert_eq!(guest.read(1501), 1502);
            let served = served.lock().unwrap();
            assert!((block..block + per_block).all(|page| served.contains(page)));
        });
    }

    #[test]
    fn a_fault_fills_one_page_with_huge_pages_off() {
        let after_one = serve_a_guest("pages", None);
        assert!(after_one.contains(1500));
        assert_eq!(after_one.count(), 1 + 25);
    }

    /// A planned page whose fetch fails is left unrecorded, so no diff claims
    /// it, and is filled when the guest faults on it once it has arrived.
    #[test]
    fn a_planned_page_that_never_arrives_is_left_to_its_fault() {
        for mut blocks in [None, Some(blocks())] {
            let guest = Guest::new(&format!("arriving-{}", blocks.is_some()));
            let source = Arc::new(Arriving {
                missing: Mutex::new(Some((10 * memfile::PAGE, 20 * memfile::PAGE))),
            });
            let layers = vec![guest.layer(vec![(0, PAGES * memfile::PAGE)], Some(source.clone()))];
            let served = Mutex::new(memfile::PageMap::new(PAGES));
            assert_eq!(guest.prefetch(&layers, blocks.as_mut(), &served, 10..20), 0);
            assert_eq!(served.lock().unwrap().count(), 0);
            *source.missing.lock().unwrap() = None;
            guest.serve(layers, blocks.as_mut(), &served, || {
                assert_eq!(guest.read(15), 16);
            });
            assert!(served.lock().unwrap().contains(15));
        }
    }

    #[test]
    fn the_peers_pidfd_names_the_process_that_connected() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let pidfd = Collapse::of(&ours).pidfd.unwrap();
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).unwrap();
        assert!(
            info.lines()
                .any(|line| line == format!("Pid:\t{}", std::process::id())),
            "{info}"
        );
    }

    /// A neighbour that fails to arrive costs the block its huge page, not
    /// the guest its fault.
    #[test]
    fn a_neighbour_that_never_arrives_leaves_the_fault_answered() {
        let guest = Guest::new("neighbour");
        let source = Arc::new(Arriving {
            missing: Mutex::new(Some((1100 * memfile::PAGE, 1110 * memfile::PAGE))),
        });
        let layers = vec![guest.layer(vec![(0, PAGES * memfile::PAGE)], Some(source.clone()))];
        let served = Mutex::new(memfile::PageMap::new(PAGES));
        let mut blocks = blocks();
        guest.serve(layers, Some(&mut blocks), &served, || {
            assert_eq!(guest.read(1500), 1501);
            assert!(served.lock().unwrap().contains(1500));
            assert!(!(1100..1110).any(|page| served.lock().unwrap().contains(page)));
            *source.missing.lock().unwrap() = None;
            assert_eq!(guest.read(1105), 1106);
        });
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
