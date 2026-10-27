# Metering

Burrow meters every sandbox and keeps the record somewhere the sandbox cannot
take with it. This document is the design: what is counted, where it lives,
how the record survives a deleted sandbox or a dead node, and which parts
exist today.

Burrow has no prices, invoicing, plans or payment integration, and will not.
It produces exact, attributable usage; what you do with it is yours.

## Status

| Piece | State |
| --- | --- |
| Per-sandbox cpu and network totals on the record and heartbeat | Shipped. See [ARCHITECTURE.md](ARCHITECTURE.md#usage-metering) |
| Lifecycle event log with totals and shape on every event | Shipped. See [CLI.md](CLI.md#events) |
| Event delivery acknowledged before a lifecycle call returns | Planned, replaces the current tail |
| Usage intervals in the orchestrator's store | Planned |
| `QueryUsage` API and `burrow usage` | Planned |
| Resource samples for charts, over OpenTelemetry | Planned |

## What is counted

Three things are measured on the node that runs the sandbox, because nothing
else can see them:

- **CPU time**, from the cgroup that caps the sandbox. It covers the VMM and
  the guest's vCPUs, and excludes the daemon's own work and the egress proxy's
  share of a request.
- **Network bytes**, in and out, from nftables counters hooked ahead of policy,
  so what a sandbox tried to send is counted whether or not it was allowed.
- **Time in a state at a shape**: seconds running or suspended, with the vcpus
  and memory the sandbox had. A suspended sandbox consumes no cpu but holds
  its disk and its memory image, which is why the state is recorded.

Totals are monotonic for a sandbox's life and persist with it across suspend,
resume and a daemon restart. A fork starts from zero: a restore copies state,
not the bill for producing it.

## Where the record lives

The sandbox record is not the usage record. It is deleted when the sandbox
is, and it lives on one node. Two things are built so usage does not share
either fate.

**The event log.** Every lifecycle transition is an event: `created`,
`started`, `agent_ready`, `stopped`, `destroyed`, `snapshot_created`. The node
writes it to its own store before anyone is told, and each event carries the
sandbox's totals and shape at that instant. The orchestrator keeps a copy of
every node's log in its own store, keyed by node and node position so nothing
is recorded twice. An event therefore outlives the node that recorded it.

**The ledger.** A table of intervals, one row per stretch a sandbox spent in
one state at one shape:

| Column | Meaning |
| --- | --- |
| `sandbox_id`, `template`, `metadata` | What was running and its tags, copied so a grouping survives the sandbox |
| `state`, `vcpus`, `mem_mib` | What was being consumed |
| `started_at`, `ended_at` | The interval, unix milliseconds |
| `cpu_usec`, `rx_bytes`, `tx_bytes` | Usage inside the interval, as the difference of the totals on its two bounding events |

Rows are appended by the ledger writer as it consumes the event log and are
never updated or deleted. A sandbox that ran for a day and was suspended twice
produces about five rows. Usage is always a difference of two totals, never a
sum of samples, so a replayed or missing event moves a boundary and never
changes the amount.

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

Each case below is how the planned ledger behaves; the event log it reads
behaves this way today.

**The node dies with sandboxes running.** The last heartbeat carried their
totals, and the orchestrator checkpoints open intervals on the hour from
heartbeat totals. When the node is written off, every open interval on it is
closed at the time of its last heartbeat with the totals that heartbeat
carried. At most one heartbeat interval of usage, five seconds, goes
unrecorded, and no time after the node went silent is ever attributed.

**The node dies with sandboxes suspended.** Suspended time runs from
`stopped` until `started` or `destroyed`. A write-off closes those intervals
too.

**The node dies before an event reached the orchestrator.** With the current
tail, the exposure is the stream round trip, a few milliseconds, and it costs
narrative rather than money: a `snapshot_created` might be missing from the
log while the snapshot plainly exists in the object store. The planned push
with acknowledgement removes even that: a lifecycle call does not return until
the orchestrator has committed its event, so nothing a caller saw succeed is
unrecorded. Events queue in the node's store while the control plane is
unreachable and are retried in order; a node flag chooses whether lifecycle
calls proceed or fail during that time.

**The orchestrator dies.** Its store is the record. With PostgreSQL behind it
the host does not matter; with SQLite, replicate the file. Nodes keep running
sandboxes, metering them and appending events, and the next orchestrator
resumes every node's log from the last position it had copied.

## Reading usage

Planned, like the ledger it reads. `QueryUsage` will take a time window and a grouping by sandbox, template or tag,
and return intervals or their sums, with `burrow usage` as the CLI over it:

```sh
burrow usage --from 2026-10-01 --to 2026-11-01 --group-by team
burrow usage --sandbox build-env
```

Whatever consumes the ledger downstream exports it with a cursor over row
ids, so a re-run after a failure continues where it stopped.

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
Burrow's ledger holds two intervals for it, closed by the `destroyed` event:

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
intervals are checkpointed hourly, so nothing in the current hour is
invisible.

## Samples and charts

Per-second cpu, memory and network for dashboards is a different problem from
metering and uses a different store. The plan is for the daemons to export
those as OpenTelemetry metrics, tagged with the sandbox's tags, on the same
exporter that carries traces.
Point the collector at ClickHouse, Prometheus or nothing. Burrow does not run
an analytics database, and the ledger never reads one: the record is the
intervals, so it cannot disagree with the control plane.

### Example: per-customer charts in Grafana

Each node already takes `--otlp-endpoint`; the same flag will carry metrics.
The metrics are `burrow.sandbox.cpu_usec`, `burrow.sandbox.rx_bytes`,
`burrow.sandbox.tx_bytes` and `burrow.sandbox.mem_mib`, one point per sandbox
per reaper tick, each carrying the sandbox id, template, node and every
metadata tag as attributes.

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
