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
mounted by the agent at the path you named. That is not an implementation
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

### A volume never moves

The image is a file on one machine. A sandbox that mounts one is placed on the
node holding it, exactly as a create from a snapshot is. Mounting two volumes
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
