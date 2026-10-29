# Persistence and snapshots

A Burrow sandbox outlives the VM that runs it. Suspending captures the guest's
memory and disks and stops the VM; resuming boots a fresh Firecracker VM from
that state, and the processes inside carry on where they were. The sandbox id,
its name, its network lease, published ports and policy all survive the
suspension, so a suspend and a resume is a pause rather than a restart.

Every command below takes the sandbox's name in place of its id.

For storage that outlives the sandbox and is shared between sandboxes rather
than copied, see [VOLUMES.md](VOLUMES.md). Snapshots clone an environment;
volumes accumulate data across environments.

## The lifecycle

| Action | Command | RPC | Result |
| --- | --- | --- | --- |
| Suspend | `burrow stop <id>` | `PauseSandbox` | Snapshot written, VM stopped, state `suspended` |
| Resume | `burrow start <id>` | `ResumeSandbox` | Snapshot restored into a new VM, processes continue |
| Shutdown | `burrow shutdown <id>` | `StopSandbox` | VM stopped, writable disk and volumes kept, state `stopped` |
| Boot | `burrow boot <id>` | `StartSandbox` | New VM cold-booted on the kept disk, init runs again |
| Recreate | `burrow recreate <id>` | `RecreateSandbox` | Root disk replaced from the template, id and volumes kept |
| Snapshot | `burrow commit <id>` | `CreateSnapshot` | State kept as an object of its own, VM still running |
| Fork | `burrow fork <id>` | `ForkSandbox` | New sandbox restored from a copy of that state |

```sh
burrow stop <id>
burrow start <id>
```

A shutdown is what `docker stop` does: processes end and nothing in memory
survives, so a boot runs the image's init again, and a Kit template's startup
hooks with it. A suspend keeps the processes. Choose shutdown when the guest
should start clean on the data it has written, and suspend when it should carry
on where it was.

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
  or scratch disk is refused rather than silently given the source's shape.
- Filesystem and memory start as copy-on-write copies, so both sides can
  diverge freely. The memory chain is hard-linked into the child, which is safe
  because a layer is never written again once it exists. The scratch disk is
  reflink or sparse copied. A child whose chain is deeper than two layers is
  flattened behind the create, so a fork of a fork restores as fast as the
  first.
- The child gets its own id, address lease, tap, working directory and firewall
  rules. It never comes from the warm pool: a spare holds a template with nothing
  in it, and a fork's whole content is the state copied into it.
- Fork does not stop the source, and the child lands on the source's node.
  The suspend state and disks it copies are node-local, so there is nothing to
  place.

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

`burrow rm <id>` removes the suspend state in the sandbox's working directory,
and the copy in the object store if it has one. That state is not a snapshot
object and does not outlive the sandbox, whereas snapshots taken with
`burrow commit` are separate and survive. A forked child is
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
`docker commit` it captures the live machine rather than a filesystem layer: the
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
- **They live on the node that took them, and optionally in an object
  store.** A create from a snapshot is placed on the node holding it. With
  `burrowd serve --object-store s3://bucket/prefix --object-store-endpoint
  <url>` on the nodes, every snapshot is also uploaded behind the create, and
  `burrow snapshot ls` shows `+store` once that has finished. A durable
  snapshot survives its node: if the node is unreachable, or gone, the create
  is placed on any node of the same architecture running the same Firecracker.
  That node fetches the disk before the restore and takes memory as the guest
  touches it, so the create does not wait for the whole image. Without the
  store a snapshot on an unreachable node is unusable until the node returns.

### Snapshot retention

Snapshots hold disk until something removes them. Three fields bound that, all
set when the sandbox is created:

| Field | Flag | Effect | Default |
| --- | --- | --- | --- |
| `snapshot_expiration_secs` | `--snapshot-expiration-secs` | Sweep a snapshot this long after it was last used | `0`, keep indefinitely |
| `keep_last_snapshots` | `--keep-last-snapshots` | Keep only this many snapshots of the sandbox, evicting the oldest | `0`, unlimited; 1 to 10 otherwise |
| `is_evicted_snapshot_kept` | `--keep-evicted-snapshots` | Let an evicted snapshot expire on its own instead of being deleted at once | off, evictions delete |

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

## Surviving a node

With an object store on the nodes, a suspended sandbox outlives its node too.
After every suspend the node uploads the sandbox's state behind the call that
suspended it, and `burrow ps -a` shows `+store` beside the node once the copy
is current. Only what changed since the last upload is sent: the state is
stored as content-addressed chunks, and a suspend that wrote a few megabytes of
memory uploads a few megabytes.

```sh
burrow stop api
burrow ps -a
# SANDBOX      NAME   STATE       NODE             TEMPLATE  TAGS  CREATED
# sbx_2f0c...  api    suspended   node_a +store    python          2026-09-02T07:55:39Z
```

Two things use that copy.

- **`burrow move`.** The sandbox is suspended if it is running, its copy is
  brought up to date, and another node adopts it and resumes it. Its processes
  carry on where they were, with the same id, name and policy and a new
  address. Measured on the dev harness, a running sandbox moved in 2.3 to
  2.8 s and a suspended one in about 0.5 s.
- **A node that dies.** When the orchestrator writes a node off, after
  `--node-expiry-secs` of silence (a day by default; the dev harness uses two
  minutes), every sandbox that was suspended there with
  a current copy is kept with no node, and `burrow ps -a` shows its node as
  `object store`. `burrow start` places it on a node of the same architecture
  and Firecracker version and resumes it there; on the harness that took about
  0.6 s. A sandbox that was running when its node died is lost, as before: the
  copy is from its last suspend, and the guest had moved on since.

The adopting node fetches the vmstate and the scratch disk, then starts the
guest at once and serves its memory as it faults, fetching the chunk under
each fault while the rest arrives behind it.

What does not move: volumes, which are storage on a node, so a sandbox with a
volume stays where it is; published ports and shares; and the session history.
An edge hostname names the node, so it changes with the move.

Brokered credentials are never written to the store in the clear. They travel
sealed under a key every node shares, `--object-store-key-file`, which burrowd
never generates: a key each node made for itself would seal what no other node
can open. A sandbox holding credentials on a node without the key stays on its
node. Create one key for the fleet and give every node the same file.

```sh
head -c 32 /dev/urandom > store.key
burrowd serve ... --object-store s3://bucket/prefix \
  --object-store-endpoint <url> --object-store-key-file store.key
```

### One sandbox, one node

A sandbox must never run in two places, and three things make sure of it.

- **The store says where it runs.** A node records a sandbox as running in the
  store *before* it resumes the guest, and a node adopting a sandbox refuses
  one the store says is running. So a node that resumed a sandbox and then
  died leaves a copy nobody will resume in its place.
- **Taking it is one conditional write.** Every write that hands the sandbox
  to a node (an adopt, a resume, an upload after a suspend, a failed adopt
  handing it back) is conditional on the version of the manifest it was
  decided on: `If-Match` on its ETag, or `If-None-Match` for the first. Two
  nodes that both read it suspended, a move racing a start say, cannot both
  take it: one write lands, and the other is refused with `Aborted`, naming
  the node that holds it, before anything has started. A node writing as the
  holder also checks the manifest still names it, so a node the sandbox moved
  off cannot write over the one running it now. The store has to honour
  conditional writes, and burrowd checks at startup that it does: it refuses
  to start on one that ignores them (versitygw 1.0.14 does; 1.10 and AWS S3
  do not) unless `--allow-unconditional-object-store` accepts the race.
- **A node that cannot reach the orchestrator stops resuming.** Every
  heartbeat renews a lease a little shorter than the expiry after which the
  orchestrator writes a node off. Once it lapses the node resumes none of its
  stored sandboxes, edge wake-ups included, until the orchestrator confirms
  they are still its own. A restarted node starts that way too. If another node
  adopted one meanwhile, the orchestrator says so on the next heartbeat and
  the node drops its copy.

A resume of a sandbox with a stored copy reads and writes one small object in
the store first, and fails rather than resuming if the store cannot be reached
or names another node.

## Warm template snapshots

Separate from per-sandbox persistence: a node boots each template once,
snapshots the freshly booted guest, and every later create of that shape restores
from the snapshot instead of cold-booting. It is automatic and on by default. The
node warms every template that lands on it, and every shape a create asked for
and did not find, once each. See [TEMPLATES.md](TEMPLATES.md#warm-templates) for the
details and the limits, and
[ARCHITECTURE.md](ARCHITECTURE.md#snapshots-and-warm-creates) for how the pool uses
them.
