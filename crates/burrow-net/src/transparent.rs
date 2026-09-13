//! Reply path for share connections sourced from a non-local address.
//!
//! `--transparent-ip` binds the client's public IPv4, which the host does not
//! own. `IP_TRANSPARENT` lets the socket bind it. Guest replies are addressed
//! to that public IP, so the kernel would otherwise forward them out to the
//! internet; a prerouting mark on packets that belong to a transparent socket,
//! plus a policy rule that delivers marked packets locally, is what brings
//! them back.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use crate::error::{NetError, Result};
use crate::firewall;

/// fwmark on guest replies that belong to a transparent socket.
pub const MARK: u32 = 0x6272;
/// Routing table consulted for marked packets: `local 0.0.0.0/0` so they are
/// delivered to the socket rather than forwarded.
pub const TABLE: u32 = 187;

/// nftables script that marks those replies. Independent of the sandbox
/// policy tables, so a kernel missing `nft_socket` fails only this path.
pub fn ruleset() -> String {
    format!(
        "add table inet burrow_tproxy\n\
         flush table inet burrow_tproxy\n\
         add chain inet burrow_tproxy prerouting {{ type filter hook prerouting priority -150; policy accept; }}\n\
         add rule inet burrow_tproxy prerouting iifname \"{}*\" socket transparent 1 meta mark set {MARK:#x}\n",
        crate::firewall::TAP_PREFIX,
    )
}

/// Policy rule, local default route, and nftables mark. Idempotent.
pub async fn install() -> Result<()> {
    let table = TABLE.to_string();
    let mark = format!("{MARK:#x}");
    ip(&[
        "route",
        "replace",
        "local",
        "0.0.0.0/0",
        "dev",
        "lo",
        "table",
        &table,
    ])
    .await?;
    match ip(&[
        "rule", "add", "fwmark", &mark, "lookup", &table, "pref", "100",
    ])
    .await
    {
        Ok(()) => {}
        Err(NetError::Command { ref stderr, .. })
            if stderr.contains("File exists") || stderr.contains("exists") => {}
        Err(err) => return Err(err),
    }
    firewall::apply(&ruleset()).await
}

async fn ip(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;
    if output.status.success() {
        return Ok(());
    }
    Err(NetError::Command {
        command: format!("ip {}", args.join(" ")),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// `IP_TRANSPARENT` so the socket can bind an address the host does not own.
pub fn enable_socket(fd: impl AsFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let yes: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TRANSPARENT,
                std::ptr::from_ref(&yes).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Ok(())
    }
}

/// A UDP socket bound to `from`, with `IP_TRANSPARENT` set before bind.
pub fn bind_udp(from: Ipv4Addr) -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    enable_socket(&socket)?;
    socket.bind(&SocketAddr::from((from, 0)).into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_only_transparent_sockets_on_burrow_taps() {
        let rules = ruleset();
        assert!(rules.contains("hook prerouting priority -150; policy accept"));
        assert!(rules.contains(&format!(
            "iifname \"{}*\" socket transparent 1 meta mark set {MARK:#x}",
            crate::firewall::TAP_PREFIX
        )));
        // A base-hook drop would steal non-sandbox traffic.
        assert!(!rules.contains("policy drop"));
    }
}
