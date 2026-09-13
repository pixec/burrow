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

## When to use one

A share is the answer whenever you control what runs at the far end, because it
carries any protocol including UDP, wakes a parked sandbox, and needs no port on
the node standing open to whoever finds it. It asks one thing in return: the far
end has to run the `tailcat` client.

It is not the way to get the caller's address into the guest. A published port
already does that, and does it for every caller rather than only the ones that
managed to hole-punch; what a share adds there is that the same is true of a
protocol the edge cannot route and of a node with nothing open to the internet.

That rules it out for anyone you cannot ask to install something, which is most
of the internet. A browser, a webhook from a payment provider, an OAuth
callback: those need a public hostname, which is what the [edge](EDGE.md) is
for. A customer pointing their own `psql` at you with no burrow-specific
software needs a [published port](EDGE.md#raw-tcp-and-other-protocols). There
is a table comparing all three in [EDGE.md](EDGE.md#which-way-in).

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
datagram in either direction. The `tailcat` CLI reaches UDP through
`tailcat socks` (SOCKS5 UDP ASSOCIATE); the Go library has `DialUDPPort`.

## What the guest sees

Connections are terminated in burrowd, on the node, and dialed into the guest
from there, exactly as the edge does for HTTP. Two things follow.

A connection wakes a suspended sandbox, and a sandbox with a shared connection
open is never suspended as idle, however long the session. This is the answer
to the raw-TCP gap in [EDGE.md](EDGE.md): a published port cannot wake a
sandbox, a share can.

The guest sees each client's own public IPv4 as the packet source, so it can
tell its callers apart with no idea a tunnel is involved.

## Client source addresses

The guest sees the client's public IPv4 on the packet, the way it would on
the open internet. No header to parse. TCP and UDP both. This is the
default; `--no-transparent-ip` sources from the sandbox gateway instead.

Disco authenticates a UDP address with a pong. That address is the real
IP. burrowd binds it with `IP_TRANSPARENT` and dials the guest from it, so
`getpeername` inside the sandbox is `203.0.113.9`, or whatever the client
was on. Guest replies are addressed to that public IP; a prerouting mark on
packets that belong to a transparent socket, plus a policy rule that delivers
marked packets locally, is what brings them back instead of forwarding them
out as if the guest had dialled the internet.

The sending path can fall back to the relay a few seconds after idle. The
verified address is not forgotten: the next connection still comes from that
IPv4, until disco pongs a different one (the client moved networks). A
client that has never hole-punched has no public IPv4 we can put on the
packet, and is sourced from the sandbox gateway. An IPv6-only path cannot
appear on the IPv4 tap, same treatment.

The first share on a node installs the policy rule and the nftables mark. The
sandbox firewall is not involved.

`socket transparent` needs the `nft_socket` module and the privileges to add
a route, so a node can fail to install any of it. That does not cost you the
share: the node logs what it could not do and serves from the gateway, which
is also what happens to shares it restores after a restart. `burrow share
--show` reports what a share is actually doing rather than what was asked
for. An operator who does not want that routing and nftables state on a
machine at all can start `burrowd --no-transparent-ip`, which pins every
share there to the gateway.

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
