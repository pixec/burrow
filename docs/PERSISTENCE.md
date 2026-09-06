# Persistence and snapshots

A Burrow sandbox outlives the VM that runs it. Suspending captures the guest's
memory and disks and stops the VM; resuming boots a fresh Firecracker VM from
that state, and the processes inside carry on where they were. The sandbox id,
its name, its network lease, published ports and policy all survive the gap, so a
suspend and a resume is a pause rather than a restart.

Every command below takes the sandbox's name in place of its id.

For storage that outlives the sandbox and is shared between sandboxes rather
than copied, see [VOLUMES.md](VOLUMES.md). Snapshots clone an environment;
volumes accumulate data across environments.

## The lifecycle

| Action | Command | RPC | Result |
| --- | --- | --- | --- |
| Suspend | `burrow stop <id>` | `PauseSandbox` | Snapshot written, VM stopped, state `suspended` |
| Resume | `burrow start <id>` | `ResumeSandbox` | Snapshot restored into a new VM, processes continue |
| Snapshot | `burrow commit <id>` | `CreateSnapshot` | State kept as an object of its own, VM still running |
| Fork | `burrow fork <id>` | `ForkSandbox` | New sandbox restored from a copy of that state |

```sh
burrow stop <id>
burrow start <id>
```

Two suspends happen without you asking. `idle_suspend_secs` in `ResourcePolicy`
(`--idle-suspend-secs`, `0` to disable) parks a sandbox after that many idle
seconds. And a stopping `burrowd` suspends every running sandbox it holds, then
re-registers them from disk on start, ready to resume.

Memory is stored as a chain. The first suspend writes a full image and later ones
write only the pages touched since, and the chain is flattened back to a single
file once it grows past a small bound, so resume cost stays flat however many
times a sandbox cycles. [ARCHITECTURE.md](ARCHITECTURE.md#suspending) has the
mechanics.

## Why there is no checkpoint command

Burrow can write a running guest's memory without stopping it. `fork` and
`snapshot create` both do exactly that. It is not offered as a call of its own
because on its own it is not a restore point.

Writing memory does not write the disk. The guest keeps running and keeps writing
to `scratch.ext4`, so from the moment it touches a block the saved memory
describes a filesystem that no longer exists: page cache, open file offsets and
in-flight writes all refer to a disk that has moved on. Restoring that pair gives
you a guest whose memory and disk disagree, which is worse than having no restore
point at all.

So the write is only valid to something that consumes it immediately and copies
the disk alongside it. `fork` does, into a new sandbox. `snapshot create` does,
into a snapshot object. If you want a point to come back to, take a snapshot; if
you want to stop paying for a sandbox and pick it up later, stop it. Neither has
a window in which the two halves can drift.

Failure never leaves a sandbox in between. If the write fails, nothing reached
disk and the guest goes back to running. If the guest cannot be resumed after a
write that succeeded, the sandbox is left cleanly **suspended**, because it *is*
its state at that point, and `burrow start` brings it back.

## Sessions

A session is one VM boot inside a sandbox's life. Burrow always had the idea
implicitly, since every create, resume and restore starts a new VM; `burrow
sessions` makes it visible.

```sh
burrow sessions <id>
# SESSION      START    END         STARTED AT            ENDED AT
# ses_8dff...  resume   open        2026-09-03T09:59:23Z  -
# ses_737f...  boot     suspended   2026-09-03T09:59:22Z  2026-09-03T09:59:23Z
```

A session records how its VM started and how it stopped.

| Started | Meaning |
| --- | --- |
| `boot` | From a template, cold or from the warm pool |
| `restore` | From a fork or from a snapshot |
| `resume` | From the sandbox's own suspend state |

| Ended | Meaning |
| --- | --- |
| `suspended` | `burrow stop`, an idle-suspend, or a node shutting down |
| `deleted` | The sandbox was destroyed |
| `failed` | State was written but the guest could not be resumed |
| `unknown` | The session was open when the node died |

An `unknown` session has no end time. Nothing observed when its VM stopped, and a
guess would read as a fact. Recovery closes these on the next start rather than
leaving them open forever.

Sessions live on the node that ran the VMs, and each node keeps the 64 most
recent per sandbox and evicts the oldest, so a sandbox that cycles for weeks
cannot grow the table without bound. The list belongs to the sandbox and goes
when you delete it.

## Fork

`burrow fork <source-id> [--id <child-id>] [--name <name>]` creates a new sandbox
from another's current state. A running source's state is written first, a
suspended one is forked from the snapshot it already has, the state is copied,
and the child **restores** that copy rather than cold-booting. It arrives with
the source's processes and memory.

```sh
burrow fork <source-id> --name worker-a
```

- The child inherits the source's template, resources, network policy and tags.
  Override the egress policy with the usual `--net`, `--allow-domain` and related
  flags; name none of them and the source's policy is inherited rather than
  replaced by the default deny.
- **Resources cannot be overridden.** Firecracker takes a restored VM's machine
  configuration from the snapshot, so a fork asking for different vcpus, memory
  or scratch disk is refused rather than quietly given the source's shape.
- Filesystem and memory start as copies and nothing is shared afterwards, so both
  sides can diverge freely. The memory chain is copied whole rather than
  flattened, because the restore path reads a chain anyway.
- The child gets its own id, address lease, tap, working directory and firewall
  rules. It never comes from the warm pool: a spare holds a template with nothing
  in it, and a fork's whole content is the state copied into it.
- Fork does not stop the source, and the child lands on the source's node.
  Snapshots and disks are node-local, so there is nothing to place.

## Retention

A suspended sandbox holds disk, a memory image plus its disks, until something
deletes it. Two `ResourcePolicy` fields bound that:

| Field | Flag | Effect | Default |
| --- | --- | --- | --- |
| `max_lifetime_secs` | `--max-lifetime-secs` | Hard cap on a sandbox's total age | `0`, unlimited |
| `suspended_ttl_secs` | `--suspended-ttl-secs` | Delete a sandbox left suspended this long, releasing its disk and lease | `0`, keep indefinitely |

```sh
burrow create --template python --idle-suspend-secs 300 --suspended-ttl-secs 86400
```

All three clocks move on a running sandbox with
[`burrow config lifetime`](CLI.md#config-lifetime), so work that turns out to
need longer is not stuck with the budget it was created under. The reaper reads
the policy off the sandbox on every pass, so an extension is in force at the next
tick. The machine shape does not move: a running VM's configuration is fixed, and
a restore takes it from the snapshot.

The retention clock starts when the sandbox enters `suspended` and is reset by a
resume, so it composes with `idle_suspend_secs`. Idle parks a sandbox, and this
is how long the parked state is worth paying for. The timestamp is persisted, so
a node restart hands neither a fresh TTL to every recovered sandbox nor an
expired one to a record written before the field existed.

`burrow rm <id>` removes the suspend state in the sandbox's working directory.
That state is not a snapshot object and does not outlive the sandbox, whereas
snapshots taken with `burrow commit` are separate and survive. A forked child is
independent, so deleting the source does not affect it.

## Snapshots

A snapshot is a sandbox's state kept as an object of its own. Take one and you
can start any number of new sandboxes from it, long after the sandbox it came
from is gone. It is how you prepare an environment once and hand it out, or keep
a known-good state to return to.

```sh
burrow commit build-env
# snap_c53d56f0c90c44979070dd02e95801df (38M) in 913ms

burrow create --name from-snap --snapshot snap_c53d56f0c90c44979070dd02e95801df
burrow snapshot ls
burrow snapshot rm snap_c53d56f0c90c44979070dd02e95801df
```

`burrow snapshot create` is the same command as `burrow commit`. Unlike
`docker commit` it captures the live machine, not just a filesystem layer: the
sandbox keeps running, the guest is paused only for the write, and the disk is
copied alongside the memory. That copy is what makes a snapshot a restore point
where a bare memory write is not.

A sandbox created from a snapshot **restores** it rather than booting, so it
arrives with the processes and memory the source had, and it takes its template
and machine shape from the snapshot, so `--template`, `--vcpus` and `--mem-mib`
may not disagree with what the snapshot records.

Two things follow from how snapshots are stored:

- **They outlive their source.** The kernel and rootfs are linked in beside the
  state, so deleting the sandbox, or even the template, leaves the snapshot
  restorable.
- **They are node-local.** A snapshot encodes host cpu features and the exact
  Firecracker version, like a warm template snapshot, so it never moves between
  nodes. A create from a snapshot is placed on the node holding it, and fails
  rather than being placed elsewhere if that node is unreachable.

### Snapshot retention

Snapshots hold disk until something removes them. Three fields bound that, all
set when the sandbox is created:

| Field | Flag | Effect | Default |
| --- | --- | --- | --- |
| `snapshot_expiration_secs` | `--snapshot-expiration-secs` | Sweep a snapshot this long after it was last used | `0`, keep indefinitely |
| `keep_last_snapshots` | `--keep-last-snapshots` | Keep only this many snapshots of the sandbox, evicting the oldest | `0`, unlimited; 1 to 10 otherwise |
| `keep_evicted_snapshots` | `--keep-evicted-snapshots` | Let an evicted snapshot expire on its own instead of being deleted at once | off, evictions delete |

```sh
burrow create --template python --name build-env --keep-last-snapshots 2 --snapshot-expiration-secs 604800
burrow commit build-env --expiration-secs 3600
```

An expiration passed to `commit` wins over the sandbox's default. The clock is
measured from last use and refreshed each time a sandbox is created from the
snapshot, so one you keep using stays. Retention is applied as a snapshot lands,
which is the one moment the count grows; expiry is swept by the node's reaper.

#### Keeping what retention evicted

By default an evicted snapshot is deleted immediately. Pass
`--keep-evicted-snapshots` and it is released instead: it stops being retained,
stops counting toward `--keep-last-snapshots`, and stays restorable until its
own expiration sweeps it. Use it when the cap is about bounding how many
snapshots you actively keep rather than about reclaiming disk on the spot.

```sh
burrow create --template python --name build-env \
  --keep-last-snapshots 2 \
  --snapshot-expiration-secs 604800 \
  --keep-evicted-snapshots
```

Both other fields are required with it, and a create that omits either is
refused. Without a cap nothing is ever evicted, so the flag could not mean
anything; without an expiry a released snapshot is never reclaimed by anything,
which would turn a policy meant to bound disk into one that grows without
limit.

## Warm template snapshots

Separate from per-sandbox persistence: a node boots each template once,
snapshots the freshly booted guest, and every later create of that shape restores
from the snapshot instead of cold-booting. It is automatic and on by default. The
node warms every template that lands on it, and every shape a create asked for
and did not find, once each. See [TEMPLATES.md](TEMPLATES.md#warm-templates) for the
details and the limits, and
[ARCHITECTURE.md](ARCHITECTURE.md#snapshots-and-warm-creates) for how the pool uses
them.
