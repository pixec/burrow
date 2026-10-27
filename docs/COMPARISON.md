# Burrow compared

Last reviewed: 2026-10-27. Vendors change their limits often. Check a vendor's
own docs before relying on a cell here.

Every project on this page runs untrusted code in an isolated VM or sandbox,
and the surface APIs look alike: create a sandbox, run commands, move files,
publish a port, pause it, resume it. The decision between them is mostly about
who runs it, what the network allows by default, and what survives a failure.

**Who runs it.** Vercel Sandbox, Modal and Cloudflare Sandbox are managed
services with no self-hosted option. E2B is a managed service whose runtime is
also Apache-2.0: it runs on one machine of yours, and E2B runs it in your cloud
for Enterprise customers. microsandbox embeds a microVM in your own process.
PandaStack and Burrow are control planes plus per-host agents that you run on
your own KVM hosts. PandaStack is also sold as a managed cloud.

Burrow is for the case where the workload cannot leave your hardware, or where
you are the platform and your users' code is the untrusted part. If you want a
sandbox in five minutes without owning a machine, use a managed service.

## At a glance

| | Burrow | Vercel Sandbox | E2B | microsandbox | PandaStack |
| --- | --- | --- | --- | --- | --- |
| Runs on | Your KVM hosts, directly or as a Kubernetes DaemonSet | Vercel's regions | E2B Cloud; your cloud on Enterprise; one machine of yours with Embed | Your laptop or server, in-process; a cloud in private beta | Your KVM hosts, or PandaStack Cloud |
| Isolation | Firecracker, optional jailer | Firecracker | Firecracker, built from E2B's fork | libkrun microVM | Firecracker |
| Max runtime | Operator policy, unlimited by default | 5 min default; up to 45 min on Hobby, 24 h on Pro per session | 1 h on Hobby, 24 h on Pro per session | Unlimited unless you set a max duration or idle timeout | `ttl_seconds`, 1 h by default and refreshed by API calls; persistent sandboxes have none |
| Egress default | Denied, DNS included | Allowed | Allowed | Public internet allowed; private ranges, host and metadata blocked | Allowed |
| Domain allowlist | SNI or `Host`, connection pinned to the addresses Burrow's resolver returned; optional TLS inspection | SNI only; TLS terminated only for brokering or forwarding rules | `Host` on port 80, SNI on 443, CIDR only elsewhere | Host, domain, CIDR and port rules; hostname rules need TLS interception by default | None; three fixed drops |
| Egress audit | Every proxy and DNS decision is a queryable row | Not documented | Not documented | Not documented | API calls only |
| Pause and resume | With memory; idle auto-suspend, wake on traffic; a daemon restart is a suspend and resume; resumes on another node through object storage | Filesystem only; a resume is a new VM | With memory; auto-pause on timeout | With memory, locally; not on its cloud | With memory; pause in RAM or hibernate to disk, wake on request |
| Snapshots and fork | Live fork with memory in about 120 to 180 ms, forks of forks, copy-on-write | Filesystem snapshots; taking one stops the sandbox; fork | Live fork with memory, up to 100 per request | Disk or full snapshots, copy-on-write memory, fork | Fork trees with copy-on-write memory and disk |
| Templates | Any OCI image, Docker Sandbox Kits, cached build steps, systemd images | Managed images or OCI images in Vercel Container Registry | Docker images plus cached build steps | Any OCI image | OCI images that ship systemd and sshd, plus four first-party |
| Moving between hosts | Suspended sandboxes and snapshots in object storage resume on any matching node with memory paged in lazily; `burrow move` | Regions with failover for creation; snapshots tied to a region | Paused sandboxes live in object storage and resume with memory paged in lazily | One machine | Snapshots in object storage; lazy streaming restore is opt-in |
| Persistent volumes | Node-local; one writer or many readers, enforced | Drives: one read-write mount, read-only snapshots, one region | Private beta | Bind, named, disk-image and tmpfs mounts | Host-local; one writer is not enforced |
| Lifecycle events | Fleet event log, followable and resumable; no webhooks | No webhooks documented | Signed webhooks | Not documented | Per-sandbox SSE stream; no webhooks |
| SDKs | TypeScript, Python, gRPC, CLI | TypeScript, Python, CLI | TypeScript, Python | TypeScript, Python, Rust, Go, Ruby | TypeScript, Python, CLI, REST |
| Billing | None; usage totals per sandbox | Active CPU, memory, creations, snapshot storage | Per second of vCPU and memory, plus plan | None locally; cloud prices not published | None self-hosted; per second on Cloud |
| License | AGPL-3.0 | Proprietary runtime; SDK Apache-2.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 |

Two more managed services come up in the same evaluations. Neither is
self-hostable, and Modal is not a microVM by default.

| | Modal Sandboxes | Cloudflare Sandbox |
| --- | --- | --- |
| Isolation | gVisor, or a VM runtime with its own kernel | A VM per instance, hypervisor not named |
| Max runtime | 5 min default, 24 h max | Inactivity timeout up to 6 h; no guaranteed lifetime |
| Egress default | Allowed | Allowed |
| Domain allowlist | Beta; SNI on port 443 only | Your own Worker as an egress proxy; HTTPS visible only with interception on |
| Egress audit | Blocked TLS connections logged to the sandbox's output | Whatever your Worker logs |
| Pause and resume | No; memory snapshots are alpha and end the sandbox | No; disk, memory and processes end with the instance |
| Snapshots | Filesystem snapshots, 30 days by default | Root filesystem only, public beta, 30 days |
| SDKs | Python, JavaScript, Go | TypeScript, through Workers |

Daytona is left out. Its sandboxes are containers by default, its domain
allowlist is not documented, and its open-source repository was archived in
June 2026.

## Where Burrow differs

**Egress is denied until you allow it.** Every service on this page except
Burrow gives a new sandbox the internet and lets you restrict it afterwards.
Burrow starts at nothing, DNS included, and makes you name what the workload
may reach. For code you did not write, a default-closed network is most of the
threat model.

**Allowed names are pinned to addresses.** A filter that matches the name in
the SNI or `Host` header trusts a name the client supplied. E2B's docs say
domain filtering reads the `Host` header on port 80 and the SNI on port 443.
Vercel and Modal match the SNI. Burrow runs the resolver its sandboxes use.
It records which addresses it returned to which sandbox for which name, and
the proxy refuses a connection to an address that sandbox was never told. In
testing, a spoofed name reaching an arbitrary host and the same trick reaching
the cloud metadata endpoint were both refused with a reason in the audit log.
See [FIREWALL.md](FIREWALL.md).

Pinning does not stop domain fronting inside one TLS session. For that, turn
on inspection: Burrow then terminates TLS for the sandbox and checks the inner
host too. microsandbox goes further by default. Its hostname rules fail closed
unless TLS interception is on.

**Credential brokering.** With inspection on, the proxy sets a header on the
host side, so the workload calls an authenticated API without holding the
key. Requests can also be forwarded to an endpoint you run. Vercel has the
same two features, matchers included. E2B has per-host header injection and
workload identity tokens. microsandbox substitutes secrets outside the VM for
the hosts you name.

**Every proxy and resolver decision is a row.** `burrow audit` shows what a
sandbox tried to reach and why it was refused. Packets the firewall drops
before the proxy, such as a connection to a port other than 80 or 443, are not
logged. None of the others document a per-sandbox egress log. Modal logs
blocked TLS connections to the sandbox's own output.

**No ceiling you did not set.** A managed sandbox stops because a plan says
so. Burrow's lifetime, idle suspend and suspended TTL are operator policy, and
`0` means unlimited. You trade a vendor's limit for your own capacity
planning.

**Node labels instead of regions.** Burrow has no regions. Operators label
nodes and a create names the labels it needs. That covers "put this on a GPU
box" or "keep this tenant on dedicated hardware". It does not give you a global
footprint you did not build.

## Persistence

What comes back after a pause differs.

Vercel persists the filesystem and nothing else. Stopping a sandbox snapshots
its disk and ends the VM. A resume is a new VM on that disk, so processes and
memory are gone. Cloudflare keeps nothing unless your code took a filesystem
snapshot. Modal has filesystem snapshots, and its memory snapshots are alpha.

Burrow, E2B and PandaStack suspend the VM itself, memory included, so a
resumed sandbox carries on with its processes where they were. microsandbox
does the same locally. In Burrow:

- `burrow stop` and `burrow start` suspend and resume with memory. Each
  suspend after the first writes only the pages touched since, as a diff.
- `idle_suspend_secs` parks an idle sandbox, and traffic to its edge hostname
  wakes it. This is Burrow's equivalent of hibernate.
- A node daemon that receives `SIGTERM` suspends every running sandbox and
  re-registers them on start. A daemon restart is a pause and a resume.
- `burrow shutdown` and `burrow boot` are the cold pair. Processes end, the
  disk and volumes are kept, and init runs again.

Forks restore rather than boot. A fork of a running sandbox writes its memory
without stopping it, hard-links the memory layers into the child and copies
the scratch disk with a reflink or sparse copy. A fork of a fork works, and a
deep chain is flattened behind the create. Three successive forks on the dev
harness took 138, 124 and 175 ms end to end. PandaStack's fork trees work the
same way. Its plain fork copies the disk only and cold-boots.

Retention is close to Vercel's. `--keep-last-snapshots` takes 1 to 10, and
`--keep-evicted-snapshots` lets an evicted snapshot live out its expiry
instead of being deleted. Vercel expires a snapshot 30 days after last use.
Burrow keeps snapshots until something deletes them, unless you set
`--snapshot-expiration-secs`.

Burrow has no `checkpoint` command. Memory without the matching disk is not a
restore point, because the guest keeps writing after the memory was captured.
See [PERSISTENCE.md](PERSISTENCE.md).

## When a host dies

E2B stores paused sandboxes in object storage and pages memory in lazily over
`userfaultfd` on resume, so a paused sandbox can resume on another node.
PandaStack keeps snapshots in object storage and can stream memory over
`userfaultfd` and the root disk over NBD, so a host that has never seen the
template can restore. That streaming is opt-in. By default it downloads.

Burrow does the same for memory. With `burrowd --object-store`, every suspend
and every `burrow commit` uploads the state to an S3-compatible bucket as
content-addressed chunks, so a suspend after the first sends only what changed.
When a node is written off, its suspended sandboxes are kept with no node, and
`burrow start` resumes one on any node with the same CPU architecture and
Firecracker version. That node fetches the disk, starts the guest at once, and
serves memory over `userfaultfd` as the guest faults on it, filling in the rest
behind it. On the dev harness, a sandbox resumed on another node about 0.6 s
after its own node was written off, with its processes still running. `burrow
move` does the same for a live node, so draining a host for maintenance does
not have to end its sandboxes.

A node that is cut off rather than dead does not resume what another node may
have adopted. It holds a lease through its heartbeats that runs out before the
orchestrator writes it off, and a resume first records in the store that the
sandbox is running there, so a stale copy is never resumed alongside the live
one. See [PERSISTENCE.md](PERSISTENCE.md#surviving-a-node).

Still true today:

- A running sandbox dies with its node. Its stored copy is from its last
  suspend, and is not resumed in its place.
- The scratch disk arrives whole before the guest starts. Only memory is lazy;
  PandaStack's NBD streaming covers the disk as well.
- Forks stay on the source's node.
- Volumes are block devices on one node, and a sandbox with one does not move.

The control plane is not the weak point. With PostgreSQL, several orchestrator
replicas run behind one address. The database decides name, capacity and
address-slice claims, and one replica leads background work under a Postgres
advisory lock. Killing the leader on the dev harness lost no calls. A single
process on SQLite is still supported.

## Where the managed services are ahead

- **Nothing to operate.** Burrow needs KVM hosts, nftables, a WireGuard mesh
  between nodes, PostgreSQL for a replicated control plane, an S3-compatible
  bucket for state that outlives a node, and someone to care when a node dies. Upgrades are lighter than they were: the guest agent
  replaces itself in place on its next handshake, so a new release does not
  mean re-importing every template.
- **Regions.** Vercel places sandboxes in regions with failover for creation.
  Burrow runs where your nodes are.
- **Webhooks.** E2B delivers signed lifecycle webhooks. Burrow has a fleet-wide
  event log you can replay and follow from the last position you saw
  (`burrow events -f`, the `TailEvents` API), with each sandbox's cpu and
  network totals on every event. It has no webhooks yet. See
  [METERING.md](METERING.md).
- **Tenancy and billing.** The managed services have accounts, quotas and
  invoices. Burrow meters usage and stops there. Tenancy is your own API in
  front of it.
- **One warm shape per template.** A Burrow template holds one warm snapshot
  at one CPU and memory shape. A template used at two shapes is fast at only
  one of them. The managed services hide this.

## The self-hosted peers

### microsandbox

microsandbox is a library and a CLI, not a service. A sandbox boots as a child
of your process, with no daemon to run. It runs on Apple Silicon Macs, on Linux
with KVM and on Windows with WHP, so it is the only option here that sandboxes
on a developer laptop without a nested VM. Its README reports boot under 100 ms
on an M1. It takes any OCI image, snapshots with copy-on-write memory, forks
live sandboxes, and ships SDKs for five languages, an MCP server and agent
skills. It calls itself beta.

It is not a fleet. There is no placement across machines, no mesh between
sandboxes on different hosts and no edge that routes a hostname to a sandbox.
Its own cloud, in private beta, offers disk snapshots only.

Reach for microsandbox when the sandbox lives next to the code calling it: a
local agent, a desktop app, a CI step on one machine.

### E2B, self-hosted

E2B's runtime is the same code as E2B Cloud. Embed runs the whole stack on one
Linux host with KVM, as Compose, Terraform or a Kubernetes manifest. A
multi-node deployment is something E2B runs for you in your cloud. If you want
E2B's API and lazy restore on your own hardware and one machine is enough, it
is a strong option.

### PandaStack

PandaStack has the same shape as Burrow: a Go API over Postgres scheduling onto
per-host agents that run Firecracker. It runs on Apple Silicon through Lima.
The engine is Apache-2.0 with no metering code. Every create restores a baked
snapshot, which its docs put at 49 ms p50 server-side. Sandboxes pause in RAM or
hibernate to disk, both with memory, and persistent ones hibernate after five
minutes idle. It also has managed Postgres in its own microVM, in beta, and a
REPL, LSP, MCP server and browser terminal beside exec.

The gap is the network. PandaStack's networking docs say egress is otherwise
open and there is no outbound allowlist. Its rules are three drops, for
cross-tenant traffic, link-local addresses and a list of mining ports, in the
host's shared `FORWARD` chain. Guests resolve against public resolvers
directly. The audit log records API calls, not what a sandbox reached. Its
docs also say the agent does not enforce exclusive writable volume attachment.
Burrow enforces it.

Reach for PandaStack when you want sandboxes and Postgres on one control plane
and open egress is acceptable. Reach for Burrow when the network boundary
around untrusted code is the product.

## Templates

Vercel starts sandboxes from managed images or its own registry. E2B builds
templates from Docker images and cached steps. Burrow imports any OCI image
with `burrow pull python:3.12-slim`, honours Docker Sandbox Kit descriptors,
builds templates from cached steps, and runs systemd images under its own
init. Registry credentials go only to the registry's own host, digests are
verified, and layer unpacking is escape-proof and budgeted. See
[TEMPLATES.md](TEMPLATES.md).

Burrow templates live on nodes. A template is copied to another node on
demand, node to node and verified by digest. Warm snapshots are rebuilt on
each node.

## Reaching a sandbox

All of them publish a port to a URL or an address. Vercel and E2B give you a
hostname on their domain.

Burrow's edge runs on each node and serves only that node's sandboxes. You
point a wildcard DNS record at each node. It wakes a suspended sandbox on
traffic, forwards the client address, and carries raw TCP as well as HTTP. A
node with no edge still publishes ports at its own address. A share gives a
sandbox a tailcat address with no port open on the node. See
[EDGE.md](EDGE.md) and [SHARE.md](SHARE.md).

## The CLI

Burrow's CLI and Vercel's are both modelled on Docker's: `create`, `ps`,
`exec`, `connect`, `cp`, `stop`, `start`, `logs`, `inspect`, `stats`, `top`,
`commit`, `fork`, `rm`. Anyone who has used one will find the other
unsurprising. E2B leads with its SDKs.

## Choosing

Use **Vercel Sandbox** if you are already on Vercel and want sandboxes to be
somebody else's problem.

Use **E2B** if you want a service built around AI agents, with webhooks, and
the option to run its open runtime on one machine.

Use **Modal** or **Cloudflare Sandbox** if you already run on that platform and
default-open egress is acceptable.

Use **microsandbox** if the sandbox should live inside your own process on one
machine, laptops included.

Use **PandaStack** if you want sandboxes and managed Postgres on one
self-hostable control plane and open egress suits you.

Use **Burrow** if the code has to run on hardware you control, if egress must
be denied by default and audited, or if you are building a platform whose
users' code is the untrusted part and the isolation boundary has to be yours.
