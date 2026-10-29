# Metering

Burrow meters every sandbox and keeps the record somewhere the sandbox cannot
take with it. This document is the design: what is counted, where it lives,
how the record survives a deleted sandbox or a dead node, and how to read
it.

Burrow has no prices, invoicing, plans or payment integration, and will not.
It produces exact, attributable usage; what you do with it is yours.

## Status

| Piece | State |
| --- | --- |
| Per-sandbox cpu and network totals on the record and heartbeat | Shipped. See [ARCHITECTURE.md](ARCHITECTURE.md#usage-metering) |
| Lifecycle event log with totals and shape on every event | Shipped. See [CLI.md](CLI.md#events) |
| Event delivery acknowledged before a lifecycle call returns | Shipped. See [ARCHITECTURE.md](ARCHITECTURE.md#the-event-log) |
| Usage intervals in the orchestrator's store | Shipped |
| `QueryUsage` API and `burrow usage` | Shipped. See [CLI.md](CLI.md#usage) |
| Resource samples for charts, over OpenTelemetry | Shipped |

## What is counted

Three things are measured on the node that runs the sandbox, because nothing
else can see them:

- **CPU time**, from the cgroup that caps the sandbox. It covers the VMM and
  the guest's vCPUs, and excludes the daemon's own work and the egress proxy's
  share of a request.
- **Network bytes**, in and out, from nftables counters hooked ahead of policy,
  so what a sandbox tried to send is counted whether or not it was allowed.
  Bytes are IP bytes, headers included, so a download reads a percent or two
  above its body.
- **Time in a state at a shape**: seconds running or suspended, with the vcpus
  and memory the sandbox had. A suspended sandbox consumes no cpu but holds
  its disk and its memory image, which is why the state is recorded.

Totals are monotonic for a sandbox's life and persist with it across suspend,
resume and a daemon restart. A fork starts from zero: a restore copies state,
not the bill for producing it. Every reading is taken on the reaper's tick and
once more as a VM stops, so the totals on a `stopped` or `destroyed` event
are the VM's last. Restoring or booting a VM is work of the interval it
starts: the `started` event carries the totals from before the VM was made,
so a suspended or stopped interval has no cpu, and the few cpu-seconds a Mac
node spends restoring a 4 GiB guest are counted as running. Bytes that reach
a suspended or stopped sandbox are not counted at all, since its tap drops
them and no guest receives them; on a Mac node nothing reaches one.

### On a Mac node

A macOS sandbox has no cgroup and no nftables, so the same three meters come
from elsewhere, into the same totals:

- **CPU time** is the user and system time of the
  `com.apple.Virtualization.VirtualMachine` process that runs the guest, read
  with `proc_pid_rusage`. The framework does not name that process, so the
  node lists those processes before and after it starts or restores a VM,
  with starts serialised so exactly one is new, and keeps the one whose
  responsible process is burrowd. The process covers the guest's vCPUs and
  the framework's device work for it, like a VMM in a cgroup. If it cannot be
  told apart, the node logs an error and leaves that VM's cpu uncounted rather
  than guessing.
- **Network bytes** are counted by the userspace network stack that is the
  guest's NIC, on every frame read from or written to the guest, before any
  policy decision: direct traffic, proxied egress, UDP and DNS alike, and
  dropped frames as sent.
- **Time in a state at a shape** is recorded exactly as on Linux.

## Where the record lives

The sandbox record is not the usage record. It is deleted when the sandbox
is, and it lives on one node. Two things are built so usage does not share
either fate.

**The event log.** Every lifecycle transition is an event: `created`,
`started`, `agent_ready`, `stopped`, `destroyed`, `snapshot_created`, and
`recovered` for each sandbox a node finds when it starts. The node
writes it to its own store before anyone is told, and each event carries the
sandbox's totals and shape at that instant. The node then pushes it to the
orchestrator, and the lifecycle call that caused it does not return until the
orchestrator has committed it, keyed by node and node position so a retried
push records nothing twice. An event therefore outlives the node that
recorded it, and nothing a caller saw succeed is missing from the log.

**The ledger.** A table of intervals in the orchestrator's store, SQLite or
PostgreSQL, one row per stretch a sandbox spent in one state at one shape:

| Column | Meaning |
| --- | --- |
| `id` | Row id, ascending in the order rows were written |
| `sandbox_id`, `node_id`, `template`, `metadata` | What was running, where, and its tags, copied so a grouping survives the sandbox |
| `state`, `vcpus`, `mem_mib` | What was being consumed: `running`, `suspended` or `stopped`, at that shape |
| `started_at`, `ended_at` | The interval, unix milliseconds |
| `cpu_usage_usec`, `rx_bytes`, `tx_bytes` | Usage inside the interval, as the difference of the totals at its two bounds |
| `closed_by` | The event that ended it, `checkpoint`, `write_off` or `vanished` |

Rows are appended by the ledger writer, which runs on the leading replica and
consumes each node's log in that node's order, and are never updated or
deleted. A state that crosses an hour is split at a heartbeat in the first
minute of the new one, so a sandbox that ran for a day and was suspended twice
produces a row per state change plus a row per hour. Usage is always a
difference of two totals, never a sum of samples, so a replayed event changes
nothing and a missing one moves a boundary without changing the amount.

The interval still running for each sandbox is kept beside the ledger with the
totals it started from and the latest totals a heartbeat reported for it.
That is what the hourly split, a write-off and a query of the current hour
read.

## Grouping

Usage is grouped by whatever the sandbox was tagged with. Metadata set on
create, `team=search` or `job=nightly-build`, is copied onto every event and
every ledger row, so `burrow usage --group-by team` works for sandboxes that
no longer exist and a tag changed later never rewrites history. Nothing else
identifies a sandbox's owner; the tags are the attribution.

## When things die

**The sandbox is destroyed.** The node emits `destroyed` with the final totals
before its record goes. The ledger closes the last open interval with those
numbers, and the row stays. A month's `SUM` over intervals needs no sandbox
to exist.

**The node dies with sandboxes running.** Every heartbeat's totals are
recorded against the sandboxes' open intervals, and those are checkpointed on
the hour from them. When the node is written off (`--node-expiry-secs` on the
orchestrator), every open interval on it is closed at the time of its last
heartbeat with the totals that heartbeat carried, as `write_off`. At most one
reaper tick and one heartbeat of usage, about fifteen seconds, goes
unrecorded, and no time after the node went silent is ever attributed.

**The node dies with sandboxes suspended.** Suspended time runs from
`stopped` until `started` or `destroyed`. A write-off closes those intervals
too.

**The node restarts.** A node stopping suspends its running sandboxes and
writes each one's state before it reports the `stopped` event, so a stop cut
short by its deadline still leaves them resumable. On start it logs
`recovered` for every sandbox it holds, in the state it found it, which is
how the ledger learns of a sandbox it had no open interval for.

A sandbox whose VM was running when the node died, killed or crashed before
it could suspend, has lost its memory and kept its disk. It comes back
`stopped`, with `state_reason` on its record saying why, and `burrow boot`
starts it again. Its `stopped` event has the detail `lost` and the totals the node last
wrote down; the ledger closes the running interval at the last heartbeat
before the crash, with whichever totals are further on, so the stretch the
node was down is attributed to no one.

A sandbox the node cannot put back in service, because its address or tap
cannot be set up again or its record cannot be read, keeps its row and its
files and is listed as `failed` with the reason. It is counted as stopped,
the next restart tries again, and `burrow remove` deletes it with a
`destroyed` event. Only a sandbox with neither memory nor disk left is
dropped, and it gets a `destroyed` event with the last totals the node had.

**A sandbox disappears without a `destroyed`.** This should not happen, and
is covered by a backstop: an open interval whose sandbox no heartbeat has
reported for two minutes, and that no placement names, is closed at the last
heartbeat that did, as `vanished`. It catches what a node's lost store or a
lost event left open.

**The node dies before an event reached the orchestrator.** A lifecycle call
does not return until the orchestrator has committed its event, so nothing a
caller saw succeed is unrecorded. While the control plane is unreachable,
events queue in the node's store and are pushed in order, oldest first, once
it answers. The node's `--event-delivery` decides what lifecycle calls do
meanwhile: `proceed`, the default, lets them return with their events queued;
`fail` refuses them until the queue is delivered. What the node does on its
own, an idle suspend or a shutdown, always proceeds and queues.

**The orchestrator dies.** Its store is the record. With PostgreSQL behind it
the host does not matter; with SQLite, replicate the file. Nodes keep running
sandboxes, metering them and queueing events, and each node pushes again from
wherever the orchestrator's copy of its log ends. With several replicas a node
pushes to whichever one it reaches; the ledger writer moves with the leader.

## Reading usage

`QueryUsage` takes a time window, an optional sandbox and tags to filter by,
and a grouping by sandbox, template, node, state or tag, and returns the
intervals or their sums per group and state. `burrow usage` is the CLI over
it, and the SDKs have `usage()`:

```sh
burrow usage --from 2026-10-01 --to 2026-11-01 --group-by team
burrow usage --sandbox build-env
```

An interval belongs to the window it started in, so adjacent windows never
count one twice; with the hourly split, a window's edge is accurate to the
hour. The current stretch of each open interval, up to its last heartbeat, is
included as a row marked open unless `--closed` is given. A sum carries
duration, duration weighted by vCPUs and by memory, cpu and bytes, which are
the inputs to any rate card.

Whatever consumes the ledger downstream exports it with a cursor over row
ids: each page carries `next_after`, and `--after` continues from it, so a
re-run after a failure continues where it stopped. Rows are committed one
writer at a time, so ids become visible in order and a cursor never passes a
row that commits after it. Open intervals have no id and never appear on a
page after the first.

### On upgrade

Events recorded before nodes carried a shape have 0 vCPUs and 0 MiB, and
counting them would put zero vCPU-hours and GiB-hours on all of that
history. So each node's ledger starts at that node's first event with a
shape, which is the first event its upgraded daemon logs: the `recovered`
events of the restart that upgraded it. Nothing before that becomes an
interval; those events stay in the log, where `burrow events` still shows
them. From the upgrade on, every sandbox the node holds is counted, the
suspended ones included.

## Example: a provider charging its customers

Burrow stops at usage. Here is how a provider running Burrow turns it into a
charge, entirely on its own side.

The provider tags every sandbox it creates on a customer's behalf:

```sh
burrow create --template python-3.12 \
  --tag customer=acme --tag project=ci --tag plan=team
```

Its own services set those tags, so a customer never chooses them. The
customer runs a build for 40 minutes, the sandbox idles and is suspended for
the rest of the day, and the provider's reaper destroys it the next morning.
Burrow's ledger holds a running interval and the suspended stretch, split at
each hour and closed by the `destroyed` event. Summed with `--group-by state`
they read:

| state | vcpus | mem_mib | duration | cpu | egress |
| --- | --- | --- | --- | --- | --- |
| running | 2 | 2048 | 40 min | 18.2 cpu-min | 1.3 GiB |
| suspended | 2 | 2048 | 23 h 20 min | 0 | 0 |

At month end the provider pulls everything for the customer:

```sh
burrow usage --from 2026-10-01 --to 2026-11-01 --group-by customer --format json
```

and applies its own rate card to the sums, for example:

| Meter | Provider's rate | This sandbox |
| --- | --- | --- |
| Running vCPU-hours | $0.05 | 2 × 0.667 h = 1.33 h, $0.07 |
| Running GiB-hours | $0.01 | 2 × 0.667 h = 1.33 h, $0.01 |
| Suspended GiB-hours, for the state held on disk | $0.001 | 2 × 23.3 h = 46.7 h, $0.05 |
| Egress per GiB | $0.09 | 1.3 GiB, $0.12 |

The sandbox is gone by the time the invoice runs; the intervals are not. If
the provider changes its rates, the same intervals price differently next
month and history is untouched, because Burrow never stored a price. A
`plan=team` tag lets the provider apply a different card per plan, and the
`project` tag lets the customer see its own breakdown, both from the same
rows. Daily or hourly billing is the same query over a shorter window: open
intervals are checkpointed hourly, and the current stretch is returned as an open
row, so nothing in the current hour is invisible.

## Samples and charts

Live cpu, memory and network for dashboards is a different problem from
metering and uses a different store. Each node exports them as OpenTelemetry
metrics, tagged with the sandbox's tags, on the same exporter that carries
traces.
Point the collector at ClickHouse, Prometheus or nothing. Burrow does not run
an analytics database, and the ledger never reads one: the record is the
intervals, so it cannot disagree with the control plane.

### Example: per-customer charts in Grafana

Each node's `--otlp-endpoint` carries metrics as well as traces. The metrics
are `burrow.sandbox.cpu_usec`, `burrow.sandbox.rx_bytes` and
`burrow.sandbox.tx_bytes`, cumulative monotonic counters of the same totals the
ledger is built from, and `burrow.sandbox.mem_mib`, a gauge of the memory a
running VM holds, 0 while it is suspended or stopped. There is one point per
sandbox per reaper tick, ten seconds, each carrying `sandbox_id`, `template`,
`node_id` and every metadata tag as attributes; a tag of one of those three
names does not replace it.

A collector that keeps them in Prometheus:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
exporters:
  prometheusremotewrite:
    endpoint: http://prometheus:9090/api/v1/write
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheusremotewrite]
```

The provider from the example above then charts a customer's live cpu as

```promql
sum by (customer) (rate(burrow_sandbox_cpu_usec_total[5m])) / 1e6
```

and its egress for the day as

```promql
sum by (customer) (increase(burrow_sandbox_tx_bytes_total[24h]))
```

For ClickHouse, swap the exporter for `clickhouse` with a DSN and the
collector creates its tables; the same attributes become columns to group
by. The numbers on these charts and the numbers on the invoice come from the
same counters, read at different moments, but only the intervals are the
record: a chart is for looking, the ledger is for charging.
