# Sharing a sandbox through a tailcat address

A share gives one sandbox an address that any [`tailcat`](https://github.com/tailscale/tailcat)
client can dial from anywhere: no host port, no edge, no DNS, and nothing
inbound to the node. The tunnel is WireGuard, bootstrapped through a DERP relay
and upgraded to a direct UDP path when NAT traversal allows, which is usually.

```sh
burrow share sbx_2f0c --port 22 --port 5432
# tcXXXXXXXXXXXXXXXXXXXX
```

Whoever holds that address can then, with the stock CLI:

```sh
tailcat ssh <addr>                          # a shell, if the guest runs sshd
tailcat <addr> 5432                         # stdin/stdout to guest :5432
tailcat forward <addr> 15432:5432           # a local port onto guest :5432
tailcat socks <addr> curl http://server.tailcat:8080/
```

## The address is the credential

An address encodes the share's WireGuard public key, its path-discovery key,
a pre-shared key, and the relay to meet at. There is no account and no login:
knowing the address is what lets a client connect. Share it the way you would
share an SSH private key.

Two things narrow that. `--allow nodekey:<hex>` admits only the named client
keys; a client prints its own with `tailcat printpub` (and makes it persistent
with `tailcat genkey --client --key=client-default`), and anything else holding
the address is ignored silently. And `burrow share <id> --rotate`
issues new keys, which is a new address, so an address that leaked stops
working the moment you rotate. `burrow unshare <id>` revokes the share
outright.

`--port` limits which guest TCP ports the share reaches. Omitted, every port
is reachable, on the grounds that the sandbox is yours and the address is the
gate. UDP is the other way round: nothing is reachable unless `--udp-port`
names it, or `--udp-port all` opens every port. A UDP flow is one client
source talking to one guest port; it ends after two minutes without a
datagram in either direction, and the client's identity does not travel with
it, since the PROXY protocol has no form for datagrams. The `tailcat` CLI
reaches UDP through `tailcat socks` (SOCKS5 UDP ASSOCIATE); the Go library has
`DialUDPPort`.

## What the guest sees

Connections are terminated in burrowd, on the node, and dialed into the guest
from there, exactly as the edge does for HTTP. Two things follow.

A connection wakes a suspended sandbox, and a sandbox with a shared connection
open is never suspended as idle, however long the session. This is the answer
to the raw-TCP gap in [EDGE.md](EDGE.md): a published port cannot wake a
sandbox, a share can.

The guest sees every connection arrive from the host side of its own /30, not
from the client. If a service in the guest needs to know who connected, share
with `--proxy-protocol`: burrowd then prefixes each connection with a PROXY
protocol v2 header, which nginx, Caddy, HAProxy, pgbouncer and most
frameworks accept with a flag. The header carries:

- as source, the client's public IP and port when the tunnel has a verified
  direct path to it, with the guest as destination; otherwise the client's
  tunnel address, an IPv6 in `fd7a:115c:a1e0::/48` derived from its key;
- TLV `0xE0`, the client's tunnel address as text, always;
- TLV `0xE1`, the client's node key as `nodekey:<hex>`, always.

The tunnel address and node key are the stable identity: they follow the
client across networks and cannot be forged, because the tunnel authenticated
them. The public IP is what an ordinary server on the internet would see, and
is absent for a client still on the relay. It is never taken from anything the
client merely claimed about itself.

Only enable the header for a service that expects it. A service that does not
will read the header bytes as the start of the client's request.

## Isolation

A guest cannot reach the tunnel sockets, because a guest cannot initiate a
connection to its host at all except for DNS and the egress proxy. So a share
is not a way for one sandbox to reach another, and the invariant in
[EDGE.md](EDGE.md) that no edge is reachable from a sandbox holds for shares
without a rule about them.

Clients inside the tunnel are held to their own tunnel address by WireGuard's
allowed IPs, so a client cannot send as another client, and the only
destination a share admits is the guest it belongs to.

## Relays

The relay only bootstraps and, when NAT traversal fails, carries the traffic.
By default nodes use tailcat's public relays, which are free and rate limited;
a node picks the lowest-latency region once and remembers it in
`tailcat-region.json` in its data directory, because the region is part of
every address it hands out. A fleet with real traffic runs its own
[`derper`](https://github.com/tailscale/tailscale/tree/main/cmd/derper) and
points nodes at a DERP map naming it:

```sh
burrowd serve --tailcat-derp-map-url https://derp.example.com/derpmap.json
burrowd serve --tailcat-region 900    # a region of that map, instead of the nearest
burrowd serve --no-tailcat            # refuse shares on this node
```

Each share holds one relay connection for as long as it exists, which is why
shares are created on request rather than for every sandbox.

## Persistence

A share survives node restarts: its keys are stored with the sandbox and the
server is started again on recovery, so the address clients hold keeps
working. It is deleted with the sandbox. A relay that is unreachable when the
node comes up does not lose the share; the server keeps reconnecting.
