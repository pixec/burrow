//! Host tap devices, one per sandbox.
//!
//! Made with the tun ioctls and rtnetlink directly: the `ip` and `sysctl`
//! processes this once ran cost a millisecond or more each, on every create.

use crate::error::Result;
use crate::ipam::Lease;

/// Interface names are capped at 15 characters, so the name is derived from
/// the compact block index rather than the sandbox id. It is stable for the
/// lifetime of a lease, which snapshot restore depends on: Firecracker
/// requires the same host device name it was snapshotted with.
pub fn tap_name(lease: &Lease) -> String {
    format!("bt{}", lease.block)
}

/// Creates the tap and gives the host side of the /30 to it.
///
/// Any pre-existing device with the same name is removed first: a leftover
/// from an unclean shutdown would otherwise fail creation and, worse, might
/// carry stale addressing.
pub async fn create(lease: &Lease) -> Result<String> {
    create_named(&tap_name(lease), lease).await
}

/// Creates a tap under an explicit name, for interfaces that are not tied to
/// a sandbox's lease.
#[cfg(target_os = "linux")]
pub async fn create_named(name: &str, lease: &Lease) -> Result<String> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let connection = tokio::spawn(connection);
    let made = linux::configure(&handle, name, lease).await;
    connection.abort();
    made?;
    tracing::debug!(tap = name, "tap device up");
    Ok(name.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn create_named(_: &str, _: &Lease) -> Result<String> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
}

/// Removes a tap device. Absent devices are not an error: teardown runs on
/// paths where the device may never have been created.
#[cfg(target_os = "linux")]
pub async fn delete(name: &str) {
    let removed = async {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        let connection = tokio::spawn(connection);
        let removed = match linux::link_index(&handle, name).await {
            Some(index) => handle.link().del(index).execute().await.map(|()| true),
            None => Ok(false),
        };
        connection.abort();
        removed.map_err(std::io::Error::other)
    };
    match removed.await {
        Ok(true) => tracing::debug!(tap = name, "tap device removed"),
        Ok(false) => {}
        Err(err) => tracing::warn!(tap = name, %err, "could not remove a tap device"),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn delete(_: &str) {}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::IpAddr;
    use std::os::fd::AsRawFd as _;

    use rtnetlink::{Handle, LinkUnspec};

    use crate::error::Result;
    use crate::ipam::Lease;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;

    /// `struct ifreq` with its union read as the flags.
    #[repr(C)]
    struct IfReq {
        name: [u8; libc::IFNAMSIZ],
        flags: libc::c_short,
        _union: [u8; 22],
    }

    /// The index of a device that exists. Asked about a name that does
    /// not, the kernel runs modprobe for a module of that name, which cost a
    /// create 6 ms; [`link_index`] asks without.
    fn index_of(name: &str) -> Option<u32> {
        let name = std::ffi::CString::new(name).ok()?;
        // SAFETY: a NUL-terminated name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        (index != 0).then_some(index)
    }

    /// The index of the device called `name`, if there is one.
    pub(super) async fn link_index(handle: &Handle, name: &str) -> Option<u32> {
        use futures::TryStreamExt as _;
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => Some(link.header.index),
            _ => None,
        }
    }

    fn netlink(err: rtnetlink::Error) -> std::io::Error {
        std::io::Error::other(err)
    }

    /// A persistent tap called `name`, as `ip tuntap add mode tap` makes.
    fn add_tap(name: &str) -> std::io::Result<()> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(std::io::Error::other(format!(
                "tap name {name} is too long"
            )));
        }
        let tun = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TAP | IFF_NO_PI,
            _union: [0; 22],
        };
        request.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: both ioctls take the descriptor just opened, the first a
        // `struct ifreq` that outlives the call and the second an int.
        unsafe {
            if libc::ioctl(tun.as_raw_fd(), TUNSETIFF as _, &mut request) < 0
                || libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST as _, 1 as libc::c_ulong) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Turns off autoconfiguration on one tap.
    ///
    /// Best effort, and per interface rather than globally: burrow has no
    /// business changing a host-wide sysctl, and a host with IPv6 disabled
    /// outright has no such knob to write.
    fn quiet_ipv6(tap: &str) {
        for key in ["accept_ra", "autoconf", "accept_dad"] {
            let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{tap}/{key}"), "0");
        }
    }

    pub(super) async fn configure(handle: &Handle, name: &str, lease: &Lease) -> Result<()> {
        if let Some(stale) = link_index(handle, name).await {
            let _ = handle.link().del(stale).execute().await;
        }
        // Off the caller's task: registering a device is the slow part of
        // making one, and a create stages its disk and VMM alongside.
        let owned = name.to_string();
        let index = tokio::task::spawn_blocking(move || {
            add_tap(&owned)?;
            // Router advertisements are refused before the interface is up,
            // so the guest never learns an address from anything but us.
            // Burrow assigns both families itself, and a tap that
            // autoconfigured from a neighbouring router would carry an
            // address no rule names. Duplicate detection is off too: the
            // link has one other end, and the gateway address would
            // otherwise be unusable for the first second.
            quiet_ipv6(&owned);
            index_of(&owned)
                .ok_or_else(|| std::io::Error::other(format!("tap {owned} vanished once made")))
        })
        .await
        .map_err(std::io::Error::other)??;
        // The tap is persistent, so one left half made by a failure below
        // would outlive the create that made it.
        let made = address(handle, name, index, lease).await;
        if made.is_err() {
            let _ = handle.link().del(index).execute().await;
        }
        made
    }

    async fn address(handle: &Handle, name: &str, index: u32, lease: &Lease) -> Result<()> {
        handle
            .address()
            .add(index, IpAddr::V4(lease.host_ip), lease.prefix_len)
            .execute()
            .await
            .map_err(netlink)?;

        // Non-fatal: a host with IPv6 compiled out still runs sandboxes, they
        // just have no v6 link. Failing the create would take the v4 sandbox
        // with it for the sake of an address nothing yet routes.
        let host_ip6 = lease.host_ip6();
        if let Err(err) = handle
            .address()
            .add(index, IpAddr::V6(host_ip6), lease.prefix_len6())
            .execute()
            .await
        {
            tracing::warn!(tap = name, %host_ip6, %err, "tap has no IPv6 address");
        }

        handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(netlink)?;
        Ok(())
    }
}
