//! The boot disk's APFS container, resized from inside.
//!
//! The host changes the disk image only while the guest is shut down, and
//! keeps the recovery container last on the disk as it does. So a grow finds
//! free space between the system container and the recovery container on the
//! next boot, which the container takes, and a shrink leaves free space there
//! for the host to cut on the next boot. The partitions before the container
//! and the recovery container after it are left as they are.

#![allow(clippy::result_large_err)]

use tonic::Status;

use super::users::run_tool;

const DISKUTIL: &str = "/usr/sbin/diskutil";
const MIB: u64 = 1 << 20;
/// What the end of the disk keeps for the backup GPT.
const GPT_TAIL: u64 = MIB;
/// APFS resizes a container in whole blocks.
const BLOCK: u64 = 4096;
/// The data volume, whose container is the one macOS boots from.
const DATA_VOLUME: &str = "/System/Volumes/Data";

/// `diskutil args`, which have to ask for a plist, as JSON.
async fn plist(args: &[&str]) -> Result<serde_json::Value, Status> {
    let mut argv = vec![
        "-c",
        "\"$0\" \"$@\" | /usr/bin/plutil -convert json -o - -",
        DISKUTIL,
    ];
    argv.extend_from_slice(args);
    let json = run_tool("/bin/sh", &argv).await?;
    serde_json::from_str(&json)
        .map_err(|err| Status::internal(format!("diskutil {}: {err}", args.join(" "))))
}

fn number(value: &serde_json::Value, key: &str) -> Result<u64, Status> {
    value[key]
        .as_u64()
        .ok_or_else(|| Status::internal(format!("diskutil reported no {key}")))
}

/// The partition the boot container lives on, e.g. `disk0s2`.
async fn store() -> Result<String, Status> {
    plist(&["info", "-plist", DATA_VOLUME]).await?["APFSPhysicalStores"][0]["APFSPhysicalStore"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| Status::failed_precondition("the data volume's container has no partition"))
}

async fn limits(store: &str) -> Result<serde_json::Value, Status> {
    plist(&["apfs", "resizeContainer", store, "limits", "-plist"]).await
}

/// What the disk holds besides the container: where the container starts,
/// plus every partition after it and the backup GPT.
async fn around(store: &str) -> Result<u64, Status> {
    let info = plist(&["info", "-plist", store]).await?;
    let offset = number(&info, "PartitionMapPartitionOffset")?;
    let whole = info["ParentWholeDisk"]
        .as_str()
        .ok_or_else(|| Status::internal(format!("diskutil named no disk for {store}")))?;
    let listed = plist(&["list", "-plist", whole]).await?;
    let mut after = 0;
    for partition in listed["AllDisksAndPartitions"][0]["Partitions"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(id) = partition["DeviceIdentifier"]
            .as_str()
            .filter(|id| *id != store)
        else {
            continue;
        };
        if number(
            &plist(&["info", "-plist", id]).await?,
            "PartitionMapPartitionOffset",
        )? > offset
        {
            after += number(partition, "Size")?;
        }
    }
    Ok(offset + after + GPT_TAIL)
}

/// Grows the boot container into the free space after it, which a grow on
/// the host left there. Returns the container's size.
///
/// A grow cut short between the partition map and APFS, by the guest being
/// stopped, leaves a partition bigger than its container, which
/// `resizeContainer` neither grows into nor resizes to the size it already
/// has. Giving the partition back to the container first lets it.
pub async fn grow() -> Result<u64, Status> {
    let store = store().await?;
    let limits = limits(&store).await?;
    let partition = number(&limits, "CurrentSize")?;
    let container = number(&limits, "ContainerCurrentSize")?;
    if container < partition {
        run_tool(
            DISKUTIL,
            &["apfs", "resizeContainer", &store, &container.to_string()],
        )
        .await?;
    } else if number(&limits, "MaximumSize")? < partition + MIB {
        return Ok(container);
    }
    run_tool(DISKUTIL, &["apfs", "resizeContainer", &store, "0"]).await?;
    number(&self::limits(&store).await?, "ContainerCurrentSize")
}

/// Shrinks the boot container, live, so the disk can be cut to `target`
/// bytes. Returns the container's size and the least the disk can be cut
/// to: APFS's own minimum for the container plus the margin a Linux root
/// gets, with the partitions around it. Below that it changes nothing.
pub async fn shrink(target: u64) -> Result<(u64, u64), Status> {
    let store = store().await?;
    let around = around(&store).await?;
    let limits = limits(&store).await?;
    let current = number(&limits, "CurrentSize")?;
    let least = crate::unix::rootdisk::minimum(number(&limits, "MinimumSizeNoGuard")?);
    let minimum = (around + least).div_ceil(MIB) * MIB;
    let wanted = target.saturating_sub(around) / BLOCK * BLOCK;
    if target < minimum || wanted >= current {
        return Ok((current, minimum));
    }
    run_tool(
        DISKUTIL,
        &["apfs", "resizeContainer", &store, &wanted.to_string()],
    )
    .await?;
    Ok((
        number(&self::limits(&store).await?, "ContainerCurrentSize")?,
        minimum,
    ))
}
