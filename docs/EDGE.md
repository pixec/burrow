# Reaching a sandbox from outside

Two ways in, and the protocol decides which one you get.

HTTP goes through the edge router on the node holding the sandbox, which serves
a published guest port at `<port>-<sandbox-id>.<domain>`. The edge speaks
plaintext, so a reverse proxy in front of it terminates TLS for those hostnames.

Everything else goes to the published port on the node's own address: raw TCP,
no hostname routing, no inspection. See [Raw TCP and other
protocols](#raw-tcp-and-other-protocols).

## Where the edge runs

```sh
burrowd serve --edge-listen 0.0.0.0:8080 --edge-domain node-a.sandbox.example.com
```

Both flags read an environment variable instead, which is what a container
deployment usually sets: `BURROWD_EDGE_LISTEN` and `BURROWD_EDGE_DOMAIN`.

An edge runs on a node and serves only that node's sandboxes. There is no
fleet-wide edge and no orchestrator-side one: traffic goes straight to the node
holding the sandbox and never touches the control plane. Your control plane is
not a bandwidth bottleneck, an orchestrator that is down does not take sandbox
traffic with it, and a client near the node does not pay a round trip to
wherever the orchestrator lives.

The edge is opt-in per node and off by default. A node with no edge has no
hostname routing at all. Its published ports still work at the node address, and
that address is the whole answer: `burrow expose` and `burrow port` print it
alone, and the SDK's `domain()` returns a bare `host:port` rather than a
hostname that resolves nowhere.

`--edge-listen` without `--edge-domain` starts an edge that answers for any
hostname and advertises no URL for its sandboxes. The daemon warns about it.
Give every edge a domain.

Node-scoped hostnames are safe because sandboxes are node-pinned. Snapshots and
disks are node-local and a sandbox never moves, so the node named in a hostname
is settled at creation and stays correct for the sandbox's whole life.

### What the edge does

It parses `<port>-<sandbox-id>` out of `Host` and resolves it against the
sandboxes this node holds. No registry lookup, no second hop. A sandbox this
node does not hold is a `404`, because DNS sent the client here and there is
nowhere else to ask.

It reads and parses the whole request head, up to the blank line that ends it,
including obs-fold continuation lines: every header is examined, because the
forwarding headers a client sent have to be removed wherever they appear. The
head is then rewritten, replayed to the guest, and the body onward is spliced
without being parsed. The head is capped at 16 KiB and has 15 seconds to arrive.
Routing happens before the sandbox is looked up, so a head that could never be
forwarded does not wake a suspended sandbox first.

A connection carries exactly one request. The edge sets `Connection: close` on
the head it forwards, so the guest ends the connection after answering, and the
edge reads the client only as far as that request's own body. See [One request
per connection](#one-request-per-connection).

## DNS and certificates

Every published port is its own hostname and sandbox ids are not known ahead of
time, so you need a wildcard on both sides. Give each node a wildcard pointing
at that node:

```
*.node-a.sandbox.example.com.  300  IN  A  203.0.113.11
*.node-b.sandbox.example.com.  300  IN  A  203.0.113.12
```

One wildcard shared across nodes does not work. A hostname has to resolve to the
node holding the sandbox, and a node that does not hold it answers `404` rather
than passing the request on.

Certificates follow the records: a wildcard per node domain, terminated by a
proxy on the node itself. Wildcards are issued over DNS-01, so give the proxy an
API token for the zone. HTTP-01 cannot issue a wildcard.

Keep the node domains under one parent zone. One zone to delegate, one API token
for the challenge, and node names that read as what they are.

## A Caddyfile

```caddy
*.node-a.sandbox.example.com {
	tls {
		dns cloudflare {env.CLOUDFLARE_API_TOKEN}
	}
	reverse_proxy 127.0.0.1:8080
}
```

Bind the edge to the address the proxy forwards to:

```sh
burrowd serve \
  --edge-listen 127.0.0.1:8080 \
  --edge-domain node-a.sandbox.example.com \
  --edge-trusted-proxy 127.0.0.1
```

Caddy sets `X-Forwarded-For` itself, so the edge has to be told that the address
it sees belongs to Caddy and not to the client. That is `--edge-trusted-proxy`.

Caddy also passes the incoming `Host` through to the upstream by default, which
is what this example relies on: the edge routes on `Host`, so a `header_up Host`
line that replaces it with anything other than a `<port>-<sandbox-id>.<domain>`
name gets a `404`.

## One request per connection

A connection is routed by the hostname in its first request, so every request on
it would reach the sandbox that first one named. A reverse proxy in front keeps
upstream connections alive and pools them per upstream, not per hostname, so the
next request down a pooled connection is routinely a different customer's. That
is why the edge does not let a connection carry two.

The head the guest receives carries `Connection: close`, whatever the client
sent, so the guest answers once and closes. That close is what ends the splice:
the edge does not parse responses and never has to find a response boundary. The
client is read only as far as its own request body, so a request pipelined behind
the first is never written to a guest at all. Framing the edge cannot read the
same way the guest would, such as a `Content-Length` that is not plain digits or
one sent alongside `Transfer-Encoding`, is a `400` rather than a guess.

The exception is an upgrade. A client that asks for one keeps its `Connection:
upgrade`, and the edge reads the guest's answer: `101` means one request that
never ends, and the connection is spliced both ways from there. Any other status
means this was an ordinary request after all, and the connection ends with it.

So your proxy cannot multiplex two sandboxes onto one edge connection, however it
pools: the edge will have closed it. What that costs is keep-alive between the
proxy and the edge, which is a TCP connect and a head parse per request. On the
development harness that is roughly 1 to 2 ms per request against a guest that
answers in about 1 ms on a kept-alive connection, and it grows with the round
trip between your proxy and the node. Between your customer and your proxy
keep-alive is untouched, and that is the connection which crosses the internet.

## Why the edge does not terminate TLS

The edge decides where a connection goes by reading `Host`, so it has to see the
request in the clear and cannot be the thing that terminates TLS. Everything
after the head is spliced without being parsed, which is what keeps WebSocket
upgrades, streaming responses and long-lived request bodies working.

TLS therefore terminates one hop earlier, in a proxy that forwards to the edge
over plaintext on a private address.

## Trusting the proxy

By default the edge trusts nothing. It takes the client address from the TCP
peer it accepted and replaces every forwarding header the request carried, so a
client cannot influence what a guest sees.

`--edge-trusted-proxy` takes an address or a CIDR and repeats:

```sh
--edge-trusted-proxy 127.0.0.1 --edge-trusted-proxy 10.0.0.0/24
```

When the peer matches, the edge keeps the incoming `X-Forwarded-For` chain and
appends its own hop, and honours the incoming `X-Forwarded-Proto` and
`X-Forwarded-Host` so a guest can rebuild the URL the client actually used. The
chain is parsed rather than copied, and truncated to 16 hops before the edge's
own is appended: a trusted proxy's own upstream is still not trusted. When the
peer does not match, the chain is discarded. A malformed
`--edge-trusted-proxy` value fails startup rather than being ignored.

> **Warning.** Only set `--edge-trusted-proxy` when the edge is reachable
> through that proxy and nothing else. If a client can also connect to the edge
> directly from a trusted address, it can send any `X-Forwarded-For` it likes
> and a guest will believe it. Bind the edge to loopback or to a private
> interface, and firewall the port.

## No edge may be reachable from a sandbox

An edge proxies into a published port on nothing but a hostname. That is what it
is for, and it is also why a sandbox that can reach one has reached every
sandbox that edge serves, including sandboxes it shares no private network with.
The policy rules never see those packets.

Burrow enforces this itself. Every node denies its sandboxes every edge router
in the fleet, its own included, and the orchestrator's address as well. The
orchestrator is denied for its own reason: its API creates and deletes sandboxes
and routes exec and logs into them, which is a control surface no sandbox may
reach. The drop is rendered ahead of every accept, the conntrack established
accept included, and it matches on destination only, since traffic *from* those
addresses is how an edge reaches a guest port in the first place. Nodes learn
which peers serve an edge from the orchestrator on each heartbeat, so turning one
on anywhere denies it everywhere. A sandbox in `--net open` has NAT'd egress to
anywhere its node can route, which is exactly why this is enforced by address
rather than left to a network boundary.

What that asks of you:

- Do not put anything a sandbox is meant to reach on an address that also serves
  an edge or the orchestrator. The denial is per address, not per port.
- Give the orchestrator and each node's edge an IPv4 address. The ruleset matches
  on `ip daddr`, so an edge reachable only over IPv6 cannot be denied.
- Check it after a topology change. `burrow exec` into a sandbox in open mode and
  try to fetch another sandbox's published port through an edge hostname. It
  should hang and time out, not answer.

## Raw TCP and other protocols

The edge routes on `Host`, so it only ever handles HTTP. A raw TCP connection
carries nothing that names a sandbox, so there is nothing to route on. WebSocket
works only because it begins life as an HTTP request.

Postgres, Redis, SSH, a game server, anything that is not HTTP: reach it through
the published port on the node address.

`burrow expose` maps a guest port onto a host port of the node holding the
sandbox, using DNAT. Your customer connects to `<node-address>:<host-port>` with
an ordinary client for that protocol. No hostname routing, no TLS termination,
nothing inspects the bytes. Burrow moves them and does nothing else.

Host ports come from `20000-29999`, chosen to sit above the ephemeral ports the
host uses for its own outbound sockets. It is a constant in the daemon with no
flag to change it. You may request a specific host port; one outside the range is
refused, and so is one already taken.

The address is the node's and sandboxes are node-pinned, so the mapping is stable
for the sandbox's whole life. It disappears when the sandbox is deleted.

Wake-on-traffic belongs to the edge, not to the port. A connection to a published
port goes straight to the guest, so a sandbox parked by `idle_suspend_secs` is
not there to accept it. Leave idle suspension off for a sandbox whose only way in
is a raw TCP port, or resume it through the API before you connect.

The other way in for raw TCP is a share, which is a tunnel rather than a port:
`burrow share` hands out a tailcat address that a `tailcat` client dials from
anywhere, the connection is terminated on the node and dialed into the guest,
and so it wakes a suspended sandbox and needs no port on the node at all. See
[SHARE.md](SHARE.md).

### A published port is not reachable from another sandbox

The DNAT rule matches only traffic that arrived from outside the fleet. Traffic
from a sandbox tap or from the mesh is excluded, so one sandbox cannot reach
another sandbox's published port, whatever its egress mode.

This is deliberate and it is part of the guest-to-guest isolation boundary:
membership of a private network is the only way one sandbox reaches another.
Published ports are not a side channel between tenants.

### Authentication is entirely the workload's problem

The egress firewall governs traffic *leaving* a sandbox. It has no bearing on
inbound connections to a published port, and nothing in burrow authenticates a
client connecting to one.

A published Postgres with trust authentication is open to anyone who can reach
the node. Configure the workload's own authentication, and treat the published
port as being on the public internet, because it is.

### A worked example

```sh
burrow expose sbx_2f0c 5432
# node-a:20003 -> guest :5432

burrow port sbx_2f0c
# node-a:20003 -> guest :5432

psql "postgresql://app:$PASSWORD@node-a:20003/app"
```

`burrow unexpose sbx_2f0c 20003` withdraws the mapping.

### Surfacing it to your customers

Two shapes work. Hand over `host:port` directly, which is the simplest thing and
correct while the sandbox lives. Or put a TCP load balancer in front, mapping a
stable public endpoint to the current node and port, so your customers get a name
you control rather than a node address. A proxy in front is also where you add
TLS if the protocol does not already have it.

### Keeping connection strings honest

Recreating a sandbox gets a new id, a new node port and possibly a different
node, so every stored connection string has to be refreshed. It is the same
lifecycle point [custom domains](#keeping-the-mapping-honest) makes about
hostname mappings, and it bites the same way: a stale connection string points at
a port that is closed, or worse, at one since handed to another sandbox.

Refresh the mapping whenever you recreate a sandbox, and remove it when you
delete one.

### Hostname-addressed TCP is not supported

There is no way today to give a non-HTTP service its own hostname through burrow.

The plausible future shape is SNI routing. A TLS ClientHello carries the server
name before any application bytes, and the egress proxy already parses SNI, so an
edge could read a hostname from a ClientHello the way it reads one from a `Host`
header. That is a possibility rather than a plan, and it would only ever cover
protocols wrapped in TLS. A plaintext protocol carries nothing to route on, and
that will not change.

## Custom domains

Your customers want their sandbox at `app.customer.com`, not at
`<port>-<sandbox-id>.<domain>`. You can do that today with a thin router in front
of a node's edge.

The edge addresses a sandbox by id, because the id is the only thing it can know.
Which vanity hostname belongs to which customer's sandbox is product state: it
lives in your database next to the customer, the project and the billing plan. So
the mapping stays with you, and the router that owns it sits in front of the edge.

Your router looks up the hostname, rewrites `Host` to the burrow form, and
proxies to the edge on the node holding that sandbox. The edge then sees a
request it already understands.

```mermaid
sequenceDiagram
    autonumber
    participant U as browser
    participant R as your router
    participant E as the node's edge
    participant G as guest

    U->>R: GET / (Host: app.customer.com)
    R->>R: look up app.customer.com in your database
    R->>E: GET / (Host: 8000-sbx_a.node-a.sandbox.example.com)
    E->>G: resolve, wake if suspended, splice
    G-->>U: response
```

### A Caddyfile with on-demand TLS

On-demand TLS issues a certificate the first time a hostname is requested, which
is what makes an unbounded set of customer domains workable. The `ask` endpoint
is how Caddy checks with you first.

```caddy
{
	on_demand_tls {
		ask http://127.0.0.1:9000/check
	}
}

https:// {
	tls {
		on_demand
	}
	# The load-bearing line: the edge routes on Host, so the customer's
	# hostname has to become the burrow hostname before it gets there.
	reverse_proxy 127.0.0.1:8080 {
		header_up Host 8000-sbx_a.node-a.sandbox.example.com
	}
}
```

That maps one hostname, which is the honest shape of a static config: the
sandbox id and the node are product state, and a Caddyfile does not have them.
There is no label expression that derives them either. `{http.request.host}`
carries the customer's own name, and a label index picks a piece of it, so
`app.customer.com` yields `customer` and a hostname with no `<port>-<id>` label
at all, which the edge answers `404`. Nor is
`header_up Host {http.reverse_proxy.upstream.hostport}` a way out: that sets the
upstream `Host` to `127.0.0.1:8080`, which is another `404`.

So resolve the hostname in a service of your own instead, and have Caddy ask it.
The shape is the same either way: look up `app.customer.com`, and send the
request on to that sandbox's node with
`Host: <port>-<sandbox-id>.<node-domain>`. One way to write that in Caddy is a
`forward_auth`-style lookup that returns the burrow hostname and the node, copied
onto the request before it is proxied; another is to put your own small router in
front and have Caddy do nothing but TLS.

> **Warning.** Whatever the router is, it must not send two customers' requests
> down one connection to the edge. Connection pools are keyed by upstream
> address, so a pool in front of one node's edge holds connections shared by
> every sandbox on it. The edge closes each connection after one request for
> exactly this reason, and will not serve a second, so the failure mode is a
> retry rather than a cross-tenant leak. See [One request per
> connection](#one-request-per-connection).

Your `ask` service receives `GET /check?domain=app.customer.com` and answers
`200` if that hostname is one you serve, anything else if it is not. Keep it fast
and keep it strict: it runs on the first request for a hostname, and it is the
only thing standing between your ACME quota and anyone who points a DNS record at
you.

### Getting the client IP right

Your router is now the peer the edge accepts, so without being told, the edge
reports the router's address as the client. Name the router in
`--edge-trusted-proxy` and it keeps the chain the router sends and appends its own
hop. See [Trusting the proxy](#trusting-the-proxy).

> **Warning.** Once `--edge-trusted-proxy` names your router, the edge must not
> be reachable from anywhere else. A client that can connect to it directly from
> a trusted address can send any `X-Forwarded-For` it likes, and your guest will
> believe it. Custom domains are exactly when this goes wrong, because the
> temptation is to expose both the router and the edge. Bind the edge to
> loopback or a private interface, and firewall the port.

### Certificates at scale

On-demand TLS issues one certificate per hostname and ACME rate limits are per
registered domain, so your customers' own domains each get their own budget. The
one to watch is yours: if you also serve subdomains of a domain you own, every
customer on it draws from the same limit. The `ask` endpoint is what keeps that
budget yours, since without it anyone can point a hostname at your router and
make you request a certificate for it.

### Keeping the mapping honest

A sandbox never moves between nodes, so a mapping is stable for that sandbox's
whole life. It is not stable across sandboxes:

- Update the mapping when you recreate a customer's sandbox. The new sandbox has
  a new id, and may be on a different node.
- Remove it when you delete the sandbox, or your router will keep proxying to a
  hostname the edge answers `404` for.

Ids from `CreateSandbox` are minted by the orchestrator and are uuids, so one of
those is never handed out twice. A fork is different: `ForkSandbox` takes a
caller-chosen child id, and the check that refuses a duplicate looks at the
sandboxes that exist and the ones being built, not at deleted ones. Fork a child
with an id you used before and you will get it. Treat a mapping as belonging to a
sandbox rather than to an id, and remove it when you delete one.

Your router has to reach the edge on the node holding the sandbox, so record the
node alongside the id. `burrow expose` returns the edge URL to store when the
holding node runs an edge, and a bare `<node-address>:<host-port>` when it does
not, which is a hostname you cannot proxy to. Custom domains need an edge on
every node you place customer sandboxes on.

Burrow has no native hostname aliases: the edge resolves `<port>-<sandbox-id>`
and nothing else, so the router pattern above is how a custom domain is served.

## What a guest receives

The edge rewrites the request head before replaying it. Five headers are set, and
every occurrence the client sent is removed first:

| Header | Value |
| --- | --- |
| `Forwarded` | RFC 7239 element per hop, for example `for=203.0.113.7;proto=https;host="8000-sbx_a.node-a.sandbox.example.com"` |
| `X-Forwarded-For` | The chain, client first, edge peer last |
| `X-Forwarded-Proto` | `http`, or what a trusted proxy terminated |
| `X-Forwarded-Host` | The hostname the request was made to |
| `Connection` | `close`, or `upgrade` where the client asked for one |

`X-Real-IP` and any `Forwarded` header from the client are stripped and not
replaced. `Keep-Alive` and `Proxy-Connection` are stripped as well: they describe
a hop the edge owns. Read the client address from `X-Forwarded-For` or `Forwarded`. Entries
in the chain that are not IP addresses are dropped, so every entry a guest sees
parses. The first entry is the client:

```js
const client = (req.headers['x-forwarded-for'] ?? '').split(',')[0].trim();
```

```python
client = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
```

Both headers are trustworthy because a guest can only be reached through the
edge, and the edge writes them itself.

Only the head is rewritten. The body is spliced untouched, and the head is capped
at 16 KiB. The cap is applied twice, and the two ends differ. A head that is
already over 16 KiB as sent is not read to its end, so there is no request to
answer and the connection is dropped without a response. A head that fits as sent
but no longer fits once the edge's own headers are added is refused with `400`,
never truncated.

None of this applies to a published port reached directly. That is raw TCP, and
nothing writes a header into it.

## The first request wakes the sandbox

A sandbox parked by `idle_suspend_secs` is resumed by traffic arriving at its
node's edge, so the first request after a suspend waits for a snapshot restore
before it reaches the guest. How long that takes depends on the guest's memory
size and the node's storage, so measure it on your own hardware rather than
budgeting for a number from here, and set your proxy read timeout above what you
measure. Later requests do not wait, because traffic also counts as use and holds
the idle timer open.

Requests that do not name a live sandbox never reach a guest. The edge answers
`400` for a missing or malformed `Host`, for framing it cannot read the way the
guest would, and for a head that no longer fits once rewritten; `404` for a
hostname outside the node's domain or a sandbox this node does not hold; and
`502` when the sandbox cannot be resumed. A head that never ends, or does not
arrive within 15 seconds, gets no answer at all.
