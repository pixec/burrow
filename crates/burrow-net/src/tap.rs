//! Host tap devices, one per sandbox.
//!
//! Created with the `ip` command rather than netlink bindings: it is four
//! calls per sandbox lifetime, and iproute2 is already a dependency of any
//! host that can run microVMs.

use crate::error::{NetError, Result};
use crate::ipam::Lease;

/// Interface names are capped at 15 characters, so the name is derived from
/// the compact block index rather than the sandbox id. It is stable for the
/// lifetime of a lease, which snapshot restore depends on: Firecracker
/// requires the same host device name it was snapshotted with.
pub fn tap_name(lease: &Lease) -> String {
    format!("bt{}", lease.block)
}

async fn run(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        return Err(NetError::Command {
            command: format!("ip {}", args.join(" ")),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
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
pub async fn create_named(name: &str, lease: &Lease) -> Result<String> {
    let name = name.to_string();
    delete(&name).await;

    run(&["tuntap", "add", "dev", &name, "mode", "tap"]).await?;
    let cidr = format!("{}/{}", lease.host_ip, lease.prefix_len);
    run(&["addr", "add", &cidr, "dev", &name]).await?;
    run(&["link", "set", &name, "up"]).await?;
    tracing::debug!(tap = name, %cidr, "tap device up");
    Ok(name)
}

/// Removes a tap device. Absent devices are not an error: teardown runs on
/// paths where the device may never have been created.
pub async fn delete(name: &str) {
    let output = tokio::process::Command::new("ip")
        .args(["link", "del", name])
        .output()
        .await;
    match output {
        Ok(out) if out.status.success() => tracing::debug!(tap = name, "tap device removed"),
        Ok(_) => {}
        Err(err) => tracing::warn!(tap = name, %err, "failed to run ip link del"),
    }
}
