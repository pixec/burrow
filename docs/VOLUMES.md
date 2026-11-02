# Volumes

A volume is storage that outlives the sandboxes that mount it. Use one for a
package cache, a workspace an agent builds up over many runs, or a dataset you
seed once and read from many sandboxes.

```sh
burrow volume create build-cache --size-mib 20480
burrow create --template python --mount build-cache:/cache
```

Everything a sandbox writes under `/cache` is still there for the next sandbox
that mounts it.

## What a volume actually is

An ext4 image on one node, attached to the guest as a virtio block device, and
mounted by the agent at the path you named. (A Windows guest formats it NTFS
and a macOS one HFS+; see below.) That is not an implementation
detail you can ignore, because it decides the three rules below.

Firecracker offers no shared filesystem. There is no virtio-fs and no 9p, so
there is no mechanism by which two guests could share one filesystem the way
two containers share a bind mount. A block device is what there is.

### Writable mounts are exclusive

ext4 is not a cluster filesystem. Two guests writing one image corrupt it, and
no lock makes that safe, so burrow allows one writer at a time:

```sh
burrow create --template python --mount build-cache:/cache          # holds it
burrow create --template python --mount build-cache:/cache          # refused
```

The second create fails with the id of the sandbox holding it. The claim is
held by a *running* sandbox, not by whichever sandbox mounted it first, so
stopping or deleting the holder hands the volume on:

```sh
burrow stop first-job
burrow create --template python --mount build-cache:/cache          # now fine
```

Suspending releases the claims too, and resuming takes them back, so a
suspended sandbox does not sit on a volume nobody can use. A resume whose
volume has since been taken fails and leaves the sandbox suspended rather than
resuming without its data. A node restart also releases claims, which is
correct: nothing is touching an image while no VM is running.

### Read-only mounts are shared with each other, not with a writer

Any number of sandboxes can mount one volume read-only at the same time:

```sh
burrow create --template python --mount dataset:/data:ro
```

But readers and a writer are mutually exclusive. A read-only mount is refused
while a sandbox holds the volume writable, and a writer is refused while
anything is reading it. Two reasons, and the first is not a matter of taste: a
filesystem a writer has mounted has a dirty journal, and mounting that
read-only makes ext4 attempt a recovery it cannot perform on a read-only
device, so the mount fails with `EROFS`. The second is that a reader alongside
a live writer sees its own cached metadata go stale as the disk moves under it.

So the pattern for seeding is sequential: fill the volume from one sandbox, let
that sandbox go, then fan out as many readers as you like.

### A reader sees everything the last writer wrote

A reader cannot replay a journal: its disk is read-only, so the guest mounts
ext4 `norecovery` and takes the filesystem as it stands. A writer that went
without unmounting (deleted, stopped, crashed, or killed with its node) can
have left its last writes in the journal and nowhere else, and a reader would
not see them. So the node replays it first: when a read-only mount is
claimed, the node reads the image's superblock, and if a writer left it
mounted, runs `e2fsck -E journal_only` on it before anything attaches. The
claim is taken before the replay, so no writer can arrive during it, and a
second reader arriving meanwhile waits for it and finds the image clean.
Nothing has to have been recorded when the writer went, so a writer the node
never saw go, one that crashed or died with a node restart, is covered the
same way as a delete. A writer that unmounted cleanly left nothing to do, and
costs one block read.

What a writer had in memory and never wrote out is lost, as it would be on a
power cut. A delete or a stop asks a writer's guest to `sync` first, so what a
program had written by then reaches the journal and the reader sees it. A
crash keeps only what the guest had already committed, ext4's five seconds by
default.

The exception is a writer that is only suspended. Its guest still has the
filesystem mounted and resumes onto it, so the journal is its own: a reader
mounted past it sees what that writer had written back to the filesystem and
nothing it had only journaled. The node leaves the journal alone until the
suspended writer goes and no reader is mounted past it.

### A volume never moves

The image is a file on one machine. A sandbox that mounts one is placed on the
node holding it, exactly as a fork is placed on its source's node. Mounting two volumes
that live on different nodes is refused, because nothing can attach both.

Choose where a volume lands when you create it, since it is the only chance:

```sh
burrow volume create fast-cache --node-label disk=nvme
```

If that node is unreachable, creates that mount the volume fail rather than
being placed somewhere the volume is not.

## How a volume reaches a warm sandbox

Mounting a volume costs nothing in create latency: measured warm creates with a
volume attached run 26ms to 69ms on the dev harness, the same as without one.

Getting there takes a trick, because Firecracker restores a snapshot only into
the drive set it was captured with. A warm snapshot is taken once per template
and shared by every sandbox restored from it, so it has the rootfs and scratch
drives and nothing else. A third drive would make it a different machine.

So the volume is not there at restore. The node restores the warm snapshot as
usual, then **hotplugs** the volume onto the running VM, and the agent rescans
the PCI bus and mounts it during the handshake that already runs behind every
warm create. The create returns as soon as the VM is up; anything that reaches
the guest waits on the handshake, and so waits for the mount.

Two consequences worth knowing:

- Every VM runs its virtio devices on a PCI bus rather than MMIO, because
  hotplug needs PCI. A snapshot taken under one transport cannot be restored
  under the other, so enabling this invalidated every warm snapshot once and
  they rebuilt themselves.
- A create that mounts a volume never takes a pooled spare. A spare was built
  without those drives, and handing one out would give the caller a sandbox
  with none of its volumes and no error saying so.

Firecracker calls PCI device hotplug a development preview. It is exercised on
the dev harness, including across suspend and resume, but that is the status of
the feature burrow depends on here.

A cold boot needs none of this: the drives are attached before the VM starts,
and the guest finds them without a rescan.

## Managing volumes

```sh
burrow volume create <name> [--size-mib N] [--node-label k=v]
burrow volume ls [--node <node>]
burrow volume inspect <name>
burrow volume rm <name>...
```

`ls` shows the node and which sandbox, if any, holds the volume. `inspect`
reads that from the node itself rather than from the orchestrator's cache, so
it is current.

`rm` deletes the image and everything in it, and is refused while any sandbox
holds it, reader or writer. Stop them first.

| Flag | Effect | Default |
| --- | --- | --- |
| `--size-mib` | Size of the image, 1 to 1048576 | `1024` |
| `--node-label` | Labels the node holding it must carry, repeatable | none |

## Mount syntax

`--mount name:/path` mounts read-write. `--mount name:/path:ro` mounts
read-only; `:rw` is accepted and is the default. The long spellings
`:read-only` and `:read-write` work too.

`--mount tmpfs:/path` mounts a tmpfs instead of a volume: RAM-backed, empty on
every boot, and shared with nobody, so it takes no claim and counts toward no
device. `:size=512m` (or `2g`, or a bare number of MiB) caps it, and
`:mode=1777` sets the permissions on its root, which is what a world-writable
scratch directory wants. A volume mount takes `:mode=` too, applied only when
the filesystem is still empty, so a volume that already has data keeps the
permissions it has.

Mount paths must be absolute, and:

- They may not overlap. `/data` and `/data/cache` together are refused, because
  the second would be hidden by the first and you would find an empty directory
  with nothing to say why.
- They may not be inside `/proc`, `/sys`, `/dev`, `/tmp`, `/run`, `/etc`,
  `/usr` or `/bin`. Mounting over those breaks the guest in ways that look like
  anything but a bad mount point.
- One volume may not be mounted twice in one sandbox.

At most 8 volumes per sandbox, which is what the `/dev/vdc` onwards naming
allows.

## A volume belongs to one guest OS

The filesystem is the guest's: ext4 from a Linux guest, NTFS from a Windows
one, HFS+ from a macOS one, and no guest mounts the others' kind. So the first
writable mount decides which a volume is, and the node records it beside the
image (`guest_os` in `volume.json`). After that a sandbox of another OS is
refused before it boots, reader or writer:

```text
volume build-cache holds the filesystem a linux guest made (ext4), which a windows guest cannot mount
```

A read-only mount decides nothing: on a volume nothing has written, the guest
finds no filesystem and the create fails there, and the volume stays free for
a writer of either kind. A volume from before the record is judged by what is
on it: an ext4 that has ever been mounted is Linux's, HFS+ is macOS's, and the
untouched ext4 a Linux node makes at create is anyone's.

## Volumes on a Windows guest

A Windows sandbox runs under Cloud Hypervisor, and its volumes are attached
the same way as a Linux one's: the image is a virtio disk, read-only at the
hypervisor for a read-only mount. Windows numbers disks in no order the node
controls, so each volume's disk carries its identifier (`burrow-volume0`
onwards) as its virtio serial number, and the agent finds it by that.

The first writable mount initializes the blank disk GPT and formats one NTFS
partition, labelled `burrow-volume`; the ext4 a Linux node made at create is
not a partition table, so Windows sees it as blank. A mount then gives the
partition the path asked for:

- `/data` is the folder mount point `C:\data`, made if missing. It must be
  empty, as any NTFS mount point must be. `/e/data` is `E:\data`, on a drive
  that has to exist already.
- A path that is just a drive letter, `/d`, mounts the volume as `D:`. The
  system drive is refused.

A drive letter Windows hands out on its own is taken away again, so the volume
is reachable only where it was asked for. A read-only mount marks the disk
read-only before bringing it online, so NTFS mounts it read-only rather than
failing its first write.

Ownership: a fresh volume's root gives Administrators and SYSTEM full control,
as Windows formats it, and every signed-in user modify, which covers the
accounts `CreateUser` makes. `:mode=` is not applied, since Windows has no
mode bits, and there is no tmpfs: a `tmpfs:` mount fails the create.

No node can replay an NTFS log: nothing outside Windows does that properly.
A delete or a stop asks the guest to flush its NTFS volumes
(`Write-VolumeCache`) instead, which leaves a reader nothing to recover. A
Windows writer that crashed leaves its log to whichever guest mounts the
volume next; a writable mount replays it, and whether Windows mounts it
read-only cleanly without one is untested.

The Windows side has run nowhere yet: no Windows guest boots on the dev
harness (see `deploy/windows/README.md`). It is unit tested and lint clean for
Windows targets.

## Volumes on a macOS node

A Mac node has no ext4. There a volume is a raw image of the size asked for,
sparse until written, under the node's data directory (`volumes/<name>/`), made
by `burrow volume create` with `--node-label os=macos` (or any label only Mac
nodes carry). It is attached to the macOS guest as a virtio disk when the VM
starts, after the guest's own disk, and the agent formats it journaled HFS+ the
first time it is mounted writable. The rules above are unchanged: one writer,
readers exclusive with a writer, claims released on suspend and taken again on
resume, and a volume never moves off its Mac.

What differs:

- A mount point has to be on the guest's data volume, such as
  `/Users/Shared/cache`, `/opt/data` or `/Volumes/work`. The root of a macOS
  guest is the sealed system volume, so `--mount cache:/cache` fails the
  create.
- A create that mounts a volume boots cold, as everywhere; macOS guests have no
  warm pool to skip anyway. Suspend and resume keep the mount: the disk is part
  of the machine that was saved.
- A read-only mount ignores the journal (`mount_hfs -j`), as Linux mounts
  ext4 `norecovery`, and the node replays it first in the same way: HFS+
  clears a bit in its volume header while mounted, and when a reader is
  claimed on one a writer left mounted, the node attaches the image without
  mounting it and runs `fsck_hfs -p`, which replays the journal and checks
  nothing else.
- The size is the image's, so it is enforced; `ls -s` on the node shows what it
  really takes.

Not a shared directory over virtio-fs, which Virtualization.framework offers:
the guest presents one as a network volume, and macOS's privacy controls keep
the agent out of network volumes unless an MDM profile grants it. Not APFS
either: on a virtio disk the guest formats APFS with encryption keyed to that
one machine, so no other sandbox could mount it.

## Volumes, snapshots and scratch disks

Three things persist, and they are not interchangeable:

| | Lives as long as | Shared | Holds |
| --- | --- | --- | --- |
| Scratch disk | The sandbox | No | The sandbox's own writable root |
| Snapshot | Until deleted or expired | Copied by fork, not shared | A whole filesystem plus memory |
| Volume | Until deleted | Many readers or one writer | One directory |

A snapshot captures an entire sandbox so you can start more of them from it. A
volume is a directory several sandboxes take turns with. Use a snapshot to
clone an environment, a volume to accumulate data across environments.

Volumes are not captured by `burrow commit`. A snapshot holds the sandbox's own
disk, and a volume is deliberately not part of it: it belongs to the volume, not
to the sandbox that happened to have it mounted.

`burrow fork` does not copy a volume either, and does not inherit the mount. A
fork copies the source's own disk and memory; a volume has an identity of its
own, and a writable one admits a single sandbox, so a child that inherited the
mount could only ever be refused while its parent was running. Mount it on the
child explicitly once the source has let go.

## What burrow does not have

No network-backed volume mountable read-write from several nodes at once. That
needs NFS or iSCSI, which is an operational dependency burrow does not take, and
it would put shared writable state between tenants.

If you need that, run the storage as a service and allow the sandboxes through
the firewall to reach it. See [FIREWALL.md](FIREWALL.md).
