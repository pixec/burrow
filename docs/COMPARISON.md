# Burrow, Vercel Sandbox and E2B

All three run untrusted code in Firecracker microVMs, and the surface APIs look
alike: create a sandbox, run commands, move files, publish a port, pause it,
resume it. The decision between them is mostly not about features.

**Vercel Sandbox and E2B are managed services. Burrow is software you run.**
That is the axis. If you want a sandbox in five minutes without owning a
machine, this page ends with "use one of the other two". Burrow is for the case
where the workload cannot leave your hardware, or where you are the platform
and your users' code is the thing being sandboxed.

## At a glance

| | Burrow | Vercel Sandbox | E2B |
| --- | --- | --- | --- |
| Runs on | Your KVM hosts | Vercel's infrastructure | E2B's, or your VPC on Enterprise |
| Isolation | Firecracker, optional jailer | Firecracker | Forked Firecracker |
| Max runtime | Whatever you set, unlimited by default | Session timeout, 5 minutes by default | 1 hour on Hobby, 24 hours on Pro |
| Egress default | Denied | Allowed | Allowed |
| Pause and resume | Filesystem and memory | Filesystem only | Filesystem and memory |
| Snapshots and fork | Yes | Yes | Yes |
| Templates from OCI images | Yes | Vercel Container Registry | E2B templates |
| Regions and failover | No, node labels instead | Yes | Yes |
| Persistent volumes | Node-local, readers or one writer | Drives, in beta, one reader or writer | Yes, multi-mount |
| SDKs | TypeScript, plus gRPC | TypeScript, Python | TypeScript, Python |
| Egress audit trail | Yes, queryable | Not documented | Not documented |
| Billing and quotas | None, you own the capacity | Per plan | Per plan |

## Where burrow genuinely differs

**Egress is denied until you allow it.** Both managed services give a new
sandbox the open internet and let you restrict it afterwards. Burrow starts at
nothing and makes you name what the workload may reach, per sandbox. For code
you did not write, the difference between a default-open and a default-closed
network is most of the threat model.

**Allowed names are pinned to the addresses they resolved to.** This is the
part worth reading carefully if you are comparing firewalls. E2B's docs are
explicit that domain filtering works by reading the `Host` header on port 80
and the SNI on port 443. Matching on a name the client supplies means a client
that lies about the name defeats the filter, which is domain fronting. Burrow
resolves allowed domains itself, remembers which addresses that sandbox was
told they resolve to, and refuses a connection to an address that was never
handed out under that name. Both of the attacks that found this in testing, a
spoofed name reaching an arbitrary host and the same trick reaching the cloud
metadata endpoint, are refused with a specific reason in the audit log. See
[FIREWALL.md](FIREWALL.md).

E2B also warns that a blocked connection can look successful from inside the
sandbox, because the connection is established before the filter runs, so you
have to check application-level responses. Burrow refuses before anything is
forwarded.

**Optional TLS inspection, and credentials the sandbox never holds.** Turn on
inspection for a sandbox and burrow terminates its TLS, so the host named
inside the session is checked too, not just the SNI. On top of that the proxy
can inject an API key into matching requests on the host side, which means the
workload calls an authenticated API without the key ever being readable from
inside the guest. E2B has per-host header injection for TLS traffic, including
workload identity tokens, which is the closest equivalent. Vercel does not
document one.

**Every refusal is a queryable row.** `burrow audit` gives you what a sandbox
tried to reach and why it was denied. Neither service documents an equivalent.

**No ceiling you did not set.** A managed sandbox stops because your plan says
so. Burrow's lifetime, idle-suspend and suspended-TTL are all operator policy,
and `0` means unlimited. You are trading a vendor's limit for your own capacity
planning.

**Node labels instead of regions.** Burrow has no region concept. Operators
label nodes and a create names the labels it needs, which covers "put this on a
GPU box" or "keep this tenant on dedicated hardware" but does not give you
Vercel's `--failover-regions` or a global footprint you did not build.

## Where the managed services are ahead

Being honest about this matters more than the list above.

- **Nothing to operate.** Burrow needs KVM hosts, nftables, a WireGuard mesh
  between nodes, and someone to care when a node dies. That is a real cost that
  a managed service simply does not have.
- **Python.** Both ship a Python SDK. Burrow has TypeScript and the protos.
- **Regions and failover.** Vercel places sandboxes in regions with failover
  lists; E2B runs globally. Burrow runs where your nodes are.
- **Volumes across nodes.** All three have persistent volumes now, but only
  E2B's are network-backed and mountable from anywhere. Burrow's are block
  devices on one node, so mounting one pins the sandbox there. Vercel's Drives
  are region-pinned for the same reason and are currently single reader, single
  writer; burrow allows many concurrent readers, though not alongside a writer.
  See [VOLUMES.md](VOLUMES.md).
- **Lifecycle events.** E2B has a lifecycle events API and webhooks. Burrow has
  polling and the audit trail.

## Lifecycle and timeouts

Vercel gives a sandbox a session timeout, five minutes unless you pass
`--timeout`. E2B has an inactivity timeout of five minutes and a plan-level cap
on continuous runtime, one hour on Hobby and twenty-four on Pro; pausing and
resuming resets that counter, so a paused-and-resumed sandbox can live
indefinitely in wall-clock terms.

Burrow has three independent clocks, all optional, all operator-set:
`--max-lifetime-secs`, `--idle-suspend-secs` and `--suspended-ttl-secs`, where
`0` means unlimited. An idle sandbox suspends to disk and wakes on the next
request, which is the same shape as E2B's auto-pause and auto-resume.

Paused sandboxes cost nothing but disk in all three.

## Persistence

All three snapshot a prepared filesystem and fork it into independent copies,
and all three let a stopped sandbox come back under the same name. What comes
back is not the same thing in all three.

Vercel persists the filesystem between sessions and nothing else. Stopping a
sandbox snapshots its disk and ends the VM; a resume is a new VM on that disk,
which its own docs describe as sessions "separated by snapshots". Running
processes do not survive it, and neither does anything held in memory.

Burrow and E2B both suspend the VM itself, memory included, so a resumed
sandbox carries on with its processes where they were. That is the difference
between resuming a machine and rebooting one onto the disk it left behind. It
matters when the thing you paused was a long-lived process, a warmed cache, or
a shell session someone is going to come back to; it does not matter at all if
each session starts by running a command from scratch.

Both approaches are defensible. Restoring memory is what makes burrow's warm
snapshots fast, and it is also why a burrow sandbox cannot move between nodes.

Retention is close, which is not a coincidence: burrow's
`--keep-last-snapshots` takes 1 to 10 exactly like Vercel's, and
`--keep-evicted-snapshots` is burrow's spelling of Vercel's
`--delete-evicted-snapshots false`, letting a snapshot that fell past the cap
live out its expiration instead of being deleted at once.

The defaults differ in the direction you would expect from who pays for the
disk. Vercel expires a snapshot 30 days after its last use; burrow keeps
snapshots until something deletes them, unless you set
`--snapshot-expiration-secs`. That difference is also why burrow refuses
`--keep-evicted-snapshots` unless an expiry is set: with Vercel's default
always present, an evicted-but-kept snapshot is always reclaimed eventually,
whereas on burrow it would sit there forever under a policy whose whole purpose
is to bound what is kept.

Burrow has no `checkpoint` command, deliberately. Memory without the matching
disk is not a restore point, because the guest keeps writing after the memory
was captured. See [PERSISTENCE.md](PERSISTENCE.md).

## Templates

Vercel starts sandboxes from images in its own registry. E2B has a template
build system with tags and versioning. Burrow imports any OCI image with
`burrow pull python:3.12-slim`, which converts a registry image into a bootable
rootfs, and also builds templates from cached steps. Registry credentials are
sent only to the registry's own host, digests are verified, and layer unpacking
is escape-proof and budgeted. See [TEMPLATES.md](TEMPLATES.md).

The practical difference is that burrow templates are node-local. A template
replicates to other nodes on demand, but a sandbox does not move between nodes,
because its snapshots and disk are files on one machine.

## Reaching a sandbox

All three publish a port to a URL. Vercel and E2B give you a hostname on their
domain, with custom domains available.

Burrow's edge runs on each node, serving only the sandboxes that node holds,
and you point a wildcard DNS record at each machine. It wakes a suspended
sandbox on traffic, forwards the client address, and does raw TCP as well as
HTTP, so a Postgres client outside the cluster can reach a sandbox. A node with
no edge configured still publishes ports, just at a bare address and port. See
[EDGE.md](EDGE.md).

## The CLI

Burrow's CLI and Vercel's are both modelled on Docker's, so they read almost
the same: `create`, `ps`, `exec`, `connect`, `cp`, `stop`, `start`, `logs`,
`inspect`, `stats`, `top`, `commit`, `fork`, `rm`. Anyone who has used one will
find the other unsurprising. E2B leads with its SDKs instead.

## Choosing

Use **Vercel Sandbox** if you are already on Vercel and want sandboxes to be
somebody else's problem.

Use **E2B** if you want a managed service built specifically around AI agents,
with a mature Python story and lifecycle webhooks.

Use **Burrow** if the code has to run on hardware you control, if you need
egress denied by default and audited, or if you are building a platform whose
own users' code is the untrusted part and you need the isolation boundary to be
yours rather than rented.
