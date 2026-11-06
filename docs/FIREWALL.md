# Sandbox firewall

A sandbox with no network boundary is only half a sandbox. Burrow gives each one
three pieces of host-side machinery: an nftables ruleset rendered per sandbox, an
egress proxy that decides by name, and a DNS resolver that answers only what the
policy allows.

Policy lives in `NetworkPolicy` (`crates/burrow-proto/proto/common.proto`). Set
it at creation with `--net` and the flags below, and replace it on a running
sandbox with `burrow config network-policy`.

## Network modes

| Mode | Egress | DNS | Use it for |
| --- | --- | --- | --- |
| `none` (default) | Nothing in or out | `.internal` names only | Untrusted code over private data |
| `allowlist` | Only what you name, via the proxy | Names matching `allow_domains` | Workloads that need specific services |
| `open` | NAT'd egress off the node | Everything | Trusted workloads |

### `none`

No egress, DNS included. A `none`-mode sandbox's queries for public names are
refused and audited, never forwarded, so it cannot tunnel data out through
queries either. Private-network peers and `.internal` names still work.

### `open`

NAT'd egress to the public internet, over IPv4 and IPv6. DNS lookups are still
audited and `deny_cidrs`, `deny_ports` and `is_ipv6_denied` still apply, but
connections bypass the proxy, so nothing is enforced or audited per connection
or per domain. The one exception is opt-in: with `is_tls_inspected`, HTTPS to
the hosts named by request rules goes through the proxy so a credential can be
brokered onto it. See [Selective inspection in open mode](#selective-inspection-in-open-mode).

Open means off the fleet, not everywhere. Every sandbox address comes out of one
pool (`10.99.0.0/16`), and an open-mode sandbox is denied that whole range, on
its own node and over the mesh on every other, before its blanket egress accept
is reached. Private networks are unaffected, because the rules that permit a peer
are rendered ahead of the denial: membership stays the only way one sandbox
reaches another. Its own gateway is untouched too, since the resolver lives on
the host and is governed by a different chain.

### `allowlist`

Deny by default, then name what is permitted. Egress is redirected through the
proxy, which checks every connection.

- **`allow_domains`** (`--allow-domain`): allow by domain glob, such as
  `pypi.org` or `*.pythonhosted.org`. Matched against the TLS SNI, or against the
  `Host` header for plain HTTP through the proxy. See the domain-fronting caveat
  below.
- **`allow_cidrs`** (`--allow-cidr`): allow by IPv4 CIDR, such as `10.2.0.0/16`.
  This is an L3 allowance, so matching traffic goes direct rather than through
  the proxy and nothing inspects it. Use it for non-TLS protocols and private
  ranges. Entries are strictly validated, address and prefix only.
- **`allow_ports`** (`--allow-port`): narrow the `allow_cidrs` allowance to
  specific ports, 1 to 65535. Empty means every port.
- **`deny_cidrs`** (`--deny-cidr`): block IPv4 or IPv6 ranges, such as
  `169.254.169.254/32` or `2001:db8::/32`. Deny beats every allowance in every
  mode. The rules are rendered before any accept, and the proxy refuses a
  connection whose upstream address falls in a denied range, so a denied range
  stays unreachable even if an allowed domain resolves into it or `allow_cidrs`
  or `open` would otherwise grant it. A range covers its own family only: an
  IPv4 list says nothing about IPv6, so name the v6 ranges as well, or deny
  IPv6 outright (see [IPv6](#ipv6)). An entry that does not parse costs the
  sandbox its egress rather than being skipped.
- **`deny_ports`** (`--deny-port`): block destination ports in every mode. See
  [Denied ports](#denied-ports).
- **`deny_domains`** (`--deny-domain`): block by domain glob. Like `deny_cidrs`
  it beats every allowance in every mode, `open` included: a name matching one
  is not resolved, not connected to, and not requested inside an inspected
  session. See [Denied domains and HTTP rules](#denied-domains-and-http-rules).

An allowlist policy with nothing in it behaves like `none`: no egress, and DNS
answers `.internal` names only.

```sh
burrow create --template base --net allowlist \
  --allow-domain pypi.org --allow-domain '*.pythonhosted.org' \
  --allow-cidr 10.2.0.0/16 --allow-port 5432 \
  --deny-cidr 169.254.169.254/32
```

### Domain patterns

The only wildcard is a leading `*.`, and it stands for one or more labels.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `example.com` | `example.com` | `www.example.com` |
| `*.example.com` | `www.example.com`, `a.b.example.com` | `example.com` |

A bare `*` matches every host. A wildcard anywhere else, such as
`a.*.example.com`, is not a pattern at all: as a rule's `domain` it is refused
when the policy is set, and in `allow_domains` it is simply a dead entry, so an
allowance you thought you had is one nothing can use. A port suffix on either
side is ignored. A leading wildcard never covers the apex: add `example.com`
alongside it when the sandbox needs both.

## Denied ports

`deny_ports` refuses connections by destination port, in every mode and ahead
of every allowance: `open`, `allow_cidrs`, `allow_ports` and private-network
peers included. It is how a sandbox keeps open egress but loses one protocol,
outbound mail being the usual case:

```sh
burrow create --template base --net open \
  --deny-port tcp/25 --deny-port tcp/465 --deny-port tcp/587
```

Each entry is a `PortRule`:

| Field | Meaning |
| --- | --- |
| `protocol` | `tcp`, `udp`, or unspecified for both |
| `port` | First port, 1 to 65535 |
| `port_end` | Last port, inclusive; 0 means `port` alone |
| `cidrs` | Destination ranges it is limited to, IPv4 or IPv6; empty is every destination |

On the command line the same entry is `[tcp/|udp/]PORT[-END][@CIDR,...]`:
`tcp/25`, `tcp/465-587`, `5432` (TCP and UDP), `udp/53@10.0.0.0/8`.

A rule with no `cidrs` applies over IPv4 and IPv6 alike. One with `cidrs`
applies to the families its ranges name: `5432@10.0.0.0/8` says nothing about
IPv6 traffic to port 5432.

How it is enforced:

- **nftables** drops matching packets in the sandbox chain, beside the
  `deny_cidrs` drops and ahead of the established accept, so a connection opened
  under an earlier policy does not outlive the denial on its conntrack entry. A
  rule matches the connection's original direction only, which keeps replies to
  inbound traffic working when the remote side's ephemeral port happens to fall
  in a denied range; packets conntrack has no direction for are dropped too.
- **The egress proxy** refuses a connection to a denied TCP port and writes an
  audit record with the reason `destination port is denied`. On Linux that is
  the path for TCP 80 and 443 in allowlist mode, which are redirected to the
  proxy before the sandbox chain sees them, so `--deny-port tcp/443` on an
  allowlist sandbox is refused, and recorded, by the proxy.
- **macOS nodes** decide every flow in userspace, so every refused port is
  audited there, direct or proxied, and a flow to a private-network peer, on
  the same Mac or across the mesh, meets the sender's denials in the router
  exactly as it meets them in a Linux sandbox chain.

As with `deny_cidrs`, a drop the Linux sandbox chain makes on its own is not
written to the audit log: nftables decides those packets without consulting the
daemon. The proxy, the resolver and macOS nodes record every refusal they make.

Validation happens at the API door: at most 64 rules per policy and 16 ranges
per rule, ports in range, `port_end` either 0 or between `port` and 65535, and
every range a strict `address/prefix`. A rule a node cannot parse, which can
only mean the stored policy is not the one that was validated, costs the
sandbox its egress in both families rather than being skipped.

## IPv6

Every sandbox has an IPv6 address on its own link beside its IPv4 one, out of
the fleet pool `fd99:b070::/48`. What it may reach over IPv6 depends on the
mode, and `is_ipv6_denied` (`--deny-ipv6`) takes it all away:

| Mode | IPv6 by default | With `is_ipv6_denied` |
| --- | --- | --- |
| `none` | Nothing | Nothing |
| `allowlist` | TCP 80 and 443 to the egress proxy, held to the same allowlist, pinning and denials as IPv4; nothing else | Nothing: no redirect to the proxy, and the proxy refuses an IPv6 destination |
| `open` | NAT'd egress to the public internet, except the fleet's v6 pool and link-local | Nothing |

In every mode, with or without the denial, link-local destinations are dropped
and the link to the sandbox's own gateway keeps working (neighbour discovery,
ping to the gateway), since that is not egress. IPv4 is unaffected by the
denial.

The default is unchanged from before the field existed, so existing policies
behave as they did. In practice the resolver never returns AAAA records, so
IPv6 egress in open mode reaches only addresses a workload already knows. That
is exactly the bypass to close when a policy relies on `deny_cidrs` or
`deny_ports`: either deny IPv6 outright, or write the v6 ranges into
`deny_cidrs` and leave `deny_ports` unscoped, so both apply on the IPv6 path.

```sh
burrow create --template base --net open --deny-ipv6 \
  --deny-port tcp/25 --deny-port tcp/465 --deny-port tcp/587
```

## How enforcement works

- **nftables fails closed.** Each sandbox's tap gets antispoof rules and a
  per-sandbox chain ending in `drop`. Rules are rendered from parsed, validated
  values only, so a record carrying an invalid policy renders with no allowances
  rather than poisoning the node's ruleset.
- **The egress proxy** receives all TCP egress by NAT redirect in allowlist mode.
  It classifies each connection by TLS SNI or HTTP `Host`, checks the allowlist,
  and refuses anything it cannot identify, ClientHellos carrying ECH included,
  since ECH hides the real name.
- **The DNS proxy** answers `.internal` names for private networks and forwards
  anything else upstream only when the policy allows the name: everything in
  `open`, names matching `allow_domains` in `allowlist`, nothing in `none` or
  under an empty policy. That closes the classic DNS-tunnel channel.

  A guest cannot opt out of it. The only accept for port 53 is to the sandbox's
  own gateway, so rewriting `/etc/resolv.conf` to `8.8.8.8` does not reach
  `8.8.8.8`: the packets match no rule and the chain drops them, over TCP as
  well as UDP. Where burrow's own resolver forwards to is the node's business,
  set with `--dns-upstream`. A sandbox in `none` mode has every public name
  refused, since a name is attacker-chosen bytes leaving the sandbox.
- **The control plane is not a destination.** Every sandbox on a node is denied
  the address its orchestrator answers on, ahead of every accept and of
  conntrack. An open-mode sandbox has NAT'd egress to anywhere the node can
  route, and the orchestrator is somewhere the node can route, so without that
  denial it could reach an API that creates and deletes sandboxes and routes exec
  into them. Every node's edge router is denied the
  same way, for a related reason: an edge proxies into a sandbox's published
  port by id, so reaching one reaches every sandbox it serves without a packet
  ever meeting a rule about sandboxes. So is every node itself, at its API
  address and at its Access endpoint, which may be another host: both are ways
  into sandboxes, and a token is all that stands between a sandbox and another
  node's Access service. The orchestrator's address is resolved from
  `--orchestrator` when the node starts and the edges and nodes arrive on the
  heartbeat, so none of them should share an address with anything sandboxes
  are meant to reach.
- **Everything is audited.** Every connection decision, allowed or refused, with
  destination, byte counts and reason, and every refused DNS query, goes to the
  node's audit log.

```sh
burrow audit --sandbox <id> --denied --limit 50
```

For the nftables chain structure and the DNS pinning that ties a name to an
address, see [ARCHITECTURE.md](ARCHITECTURE.md#firewall-structure).

## Domain fronting and TLS inspection

For an ordinary allowed domain the proxy matches the name in the handshake and
forwards the connection without decrypting it. A client inside the sandbox can
therefore negotiate an allowlisted SNI and send a different `Host` inside the
encrypted session. Against shared CDN infrastructure that request may reach an
origin you did not allow. Many providers reject the mismatch, but the boundary
itself cannot see inside the session.

Two answers, depending on your threat model. Prefer narrow, single-purpose
hostnames whose infrastructure hosts nothing else. Or turn on `is_tls_inspected`: the
proxy then terminates TLS for that sandbox with a certificate it signs on the
node, chained to a root installed into the guest's trust store at handshake (see
[The inspection root](#the-inspection-root)), parses every request inside the session, and
requires the inner `Host` to be allowlisted *and* to match the name the session
was opened for.

```sh
burrow create --template base --net allowlist \
  --allow-domain api.example.com --inspect-tls
```

What inspection costs is that the proxy can read payloads, which is why it is
opt-in. In allowlist mode it covers every HTTPS connection; in open mode only
the hosts that request rules name (see
[Selective inspection in open mode](#selective-inspection-in-open-mode)).
`--inspect-tls` is refused with `--net none`, and `allow_cidrs` destinations
bypass it because they never reach the proxy.

Inside an inspected session the proxy is strict. It refuses requests carrying
smuggling ambiguities, meaning folded header lines, malformed or conflicting
`Content-Length` and `Transfer-Encoding`, or a duplicate `Host`. Protocol
upgrades are relayed only when the server actually answers `101`.

### HTTP/2 in an inspected session

Inspection does not force clients down to HTTP/1.1. The proxy offers the origin
exactly the protocols the sandbox offered in its ClientHello, then presents the
sandbox only the one the origin agreed to, so both halves of the session always
speak the same version of HTTP and nothing is translated between them. A sandbox
offering only `h2` to an origin that does not speak it is refused rather than
downgraded.

HTTP/2 requests are held to the HTTP/1.1 rules, per stream:

- The host comes from `:authority`, falling back to `Host` when there is no
  `:authority`. A request naming neither is refused, and so is one whose
  `:authority` and `Host` disagree.
- That host must be allowlisted and must match the name the session was opened
  for, the same check that closes domain fronting on HTTP/1.1.
- Request rules apply per stream exactly as they do on HTTP/1.1: the same
  matchers select the same requests, a set header replaces every value the client
  sent under that name, and a forwarded stream goes to the endpoint rather than
  to the origin. h2 is not the way around a rule.
- Refused outright: repeated pseudo-headers, pseudo-headers after ordinary
  headers, undefined pseudo-headers, connection-specific headers (`Connection`,
  `Transfer-Encoding`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`), a `TE` other
  than `trailers`, a malformed or conflicting `Content-Length`, and a body that
  does not match the length it declared.
- `CONNECT` is refused and extended `CONNECT` is never negotiated.
- Server push is disabled in both directions. Request trailers are not forwarded
  and a request carrying them is refused; response trailers pass through, so
  gRPC-style responses still work.

Each stream is judged on its own and writes its own audit record naming the host
it asked for. A refused stream is answered `403` and the rest of the connection
carries on, and the connection's own record says how many streams it carried and
how many were refused. Per connection the proxy accepts at most 64 concurrent
streams, decodes at most 16 KiB of headers per message, and drops a connection
that opens and resets more than 32 streams without using them.

Two caveats if you read the audit log for accounting rather than for decisions.
An HTTP/2 connection's own record reports **zero bytes**: the traffic is
attributed to the per-stream records instead, and counting it twice would be
worse than counting it once in the narrower place. Summing across every record
stays correct; reading one connection record does not. And an HTTP/2 stream
counts DATA payload only, header bytes excluded, whereas an HTTP/1.1 record
counts the literal bytes of the head it relayed. Treat HTTP/2 byte counts as
traffic rather than as wire cost.

### The inspection root

A guest is told to trust one certificate, the inspection root, and the proxy
presents leaves that chain to it. Processes load their trust store once, when
they start, so a guest that wakes on a node whose leaves chain to another root
fails every inspected connection its running processes make. Where that root
comes from decides whether inspected sandboxes can move.

**Fleet root (recommended).** One root for the fleet, made once on an operator
machine, and an intermediate per node signed by it. The node keeps its
intermediate's key and sends the intermediate behind every leaf; guests hold only
the root, so a move, an adopt after a node failure, a restore or a fork changes
nothing inside the guest. `burrowd ca` makes both as files, with no openssl:

```sh
burrowd ca init --out-dir ./fleet-ca                  # root.pem, root.key (10 years)
burrowd ca issue --node node-a --out-dir ./fleet-ca \
  --root-cert ./fleet-ca/root.pem --root-key ./fleet-ca/root.key   # node-a.pem, node-a.key (1 year)
```

Copy `root.pem` and the node's own pair to each node and start it with all
three:

```sh
burrowd serve ... --inspect-ca-cert /etc/burrow/node-a.pem \
  --inspect-ca-key /etc/burrow/node-a.key --inspect-root-cert /etc/burrow/root.pem
```

`root.key` never goes on a node: it signs intermediates and nothing else, and
`burrowd ca issue` refuses to overwrite files that exist. Each intermediate is
constrained to `pathlen:0`, so a node's key can sign leaves and never another
authority. At startup the node refuses to run when its certificate is not a CA,
has expired, does not match its key or does not chain to the root, because each
of those would hand every inspected sandbox a proxy it rejects. It warns at
startup and hourly from its heartbeat once the intermediate has 30 days left;
renew with `burrowd ca issue` and restart, and guests notice nothing, since the
root is unchanged. Leaves last 30 days, are re-minted at half their life and
never outlive the intermediate.

**Per-node root (the default).** A node given none of the three flags generates
its own authority in `--data-dir` (`inspect-ca.pem`, `inspect-ca.key`) and is its
own root. That is fine for one node, but no other node can serve its guests, so
an inspected sandbox created there cannot leave it.

**Placement.** Every node reports its root's SHA-256 fingerprint
(`NodeInfo.inspection_root_fingerprint`), and every inspected sandbox and
snapshot records the fingerprint its guest was given, on its record and in the
durable manifest. The orchestrator moves, adopts and restores an inspected
sandbox, and places an inspected create from a durable snapshot, only on a node
with the same root, and refuses otherwise before the source lets go:

```
FailedPrecondition: sandbox sbx_0fc3...'s guest trusts the TLS inspection root
8d75e0..., and node node-b's inspection root is 344458...; inspected sandboxes
move only between nodes under one fleet root (`burrowd ca`)
```

The node checks again before it restores a guest, so a node whose root changed
since its last heartbeat refuses as well. Moving a node from a per-node root to
a fleet root leaves the sandboxes already there trusting the old one; each is
handed the new root on its next resume, but processes already running keep the
old one until they restart.

**Inside the guest.** The agent writes the root into each trust bundle between
`# BEGIN burrow inspection ca` and `# END burrow inspection ca`, replacing
whatever a previous handshake wrote there, so a bundle holds exactly one Burrow
certificate however often the sandbox moves; everything the image trusted on its
own is left alone. Windows puts it in the machine Root store under the friendly
name `Burrow inspection CA` and removes any earlier certificate carrying that
name. On macOS, see below.

### macOS guests and Apple's TLS stack

A macOS guest gets the root in `/etc/ssl/cert.pem`, which curl, LibreSSL and most
tools built on OpenSSL read, in any bundle the image names, and in the System
keychain. URLSession, Safari, Swift and Go on darwin verify through the Security
framework instead, which takes a root as an anchor only from the admin trust
settings. A running guest cannot change those without a person: trustd
authorizes each change again in its own process and wants an administrator in a
dialog, even with `com.apple.trust-settings.admin` rewritten to `allow` in the
rights database, and its settings under `/private/var/protected/trustd` are
closed to root, Full Disk Access or not.

So the Mac node writes them while nothing runs from the disk: before every cold
boot of a macOS sandbox it attaches the disk image, mounts the Data volume
(unencrypted; `nobrowse`), and makes the node's inspection root the one entry in
trustd's `Admin.plist` marked as Burrow's, as `security add-trusted-cert -d -r
trustRoot` would have. A new root (a moved sandbox, a rotated fleet root)
replaces the last one, a sandbox no longer inspected keeps none, and whatever
else the image trusted stays. It takes about a second. A restore never does
this, since the saved kernel would not know its disk changed; a sandbox told a
new root while running gets it in the bundles at once and in the Security
framework at its next cold boot. No MDM, profile or administrator is involved.

The agent reports `inspection-root-trusted` in Health when the Security framework
takes the installed root as an anchor, and the node warns at create when an
inspected macOS sandbox's agent does not, which means writing it onto the disk
failed (the node logs why).

### When a guest does not trust the inspection CA

At handshake the agent writes the inspection root into the guest's system trust
bundles, such as `/etc/ssl/certs/ca-certificates.crt`. Some images never
read those: they ship a bundle of their own and point their tooling at it with an
environment variable, and inspected requests from such an image fail to verify
even though the CA is installed correctly.

`curlimages/curl` is the clearest example. It sets `CURL_CA_BUNDLE=/cacert.pem`,
so curl never reads the system store. The symptom is a certificate error naming a
self-signed certificate in the chain while the leaf itself is correct:

```
issuer: CN=burrow sandbox inspection; O=burrow
curl: (60) SSL certificate ... self-signed certificate in certificate chain
```

The CA is not missing, the client is reading a different file. Point the tool at
the system bundle, or add the CA to the one the image uses:

```sh
burrow exec app -- curl --cacert /etc/ssl/certs/ca-certificates.crt https://api.example.com/
```

The variables worth checking in an image are `CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` (Python) and `NODE_EXTRA_CA_CERTS` (Node). A template that
sets one of them needs the inspection CA in that file too.

## Request rules

To a request that has already passed every check, the proxy can do two things:
set headers on it, or send it to an endpoint you control. Both are written as
rules on the network policy, and a rule names a domain glob, an optional matcher,
and one action.

Rules are evaluated in the order you wrote them and the first whose domain and
matcher both match wins. A rule with no matcher applies to every request to its
domain, so it shadows every rule after it for that domain: write the narrow rules
first.

All of this needs `is_tls_inspected`. Acting on a request means reading it, and
outside an inspected session there is no request to read, so a policy carrying
rules without inspection is refused at the API door rather than half-applied.

A rule may carry `expires_at_unix_ms`; see [Rule expiry](#rule-expiry).

### Credentials brokering

Untrusted code often has to authenticate to an external service without being
trusted with the key. Brokering sets the credential on egressing requests on the
host side, so the secret never enters the guest.

```sh
burrow create --template base --net allowlist \
  --allow-domain api.example.com --inspect-tls \
  --inject-header 'api.example.com:Authorization=Bearer <token>'
```

That is shorthand for a rule with no matcher: on every request to a matching
domain the proxy sets the header, replacing any value the client sent, so code
inside the sandbox can neither read it nor spoof it.

The value need not be on the command line. A header value, or a forward rule's
secret, may name a stored secret as `${secret:<name>}`, which the orchestrator
substitutes before the policy reaches a node:

```sh
burrow secret set github --value ghp_...
burrow create --template base --net allowlist \
  --allow-domain api.github.com --inspect-tls \
  --inject-header 'api.github.com:Authorization=Bearer ${secret:github}'
```

A reference to a secret that is not stored refuses the create rather than
sending the literal text. A secret can be limited to the sandboxes that may use
it; see [Scoped secrets](#scoped-secrets).

- Brokering only applies to domains the policy already allows. A rule never
  widens access, it only decides what a permitted request carries.
- It applies inside inspected TLS sessions, over HTTP/1.1 and HTTP/2 alike.
  Plaintext HTTP through the proxy is relayed untouched.
- Header names must be RFC 9110 tokens, and values may not contain CR, LF or NUL.
  A value that could forge a header line is refused at the API door rather than
  written into a request.

The secret lives in the sandbox's policy on the host, sealed at rest: the node
writes its sandbox records with every brokered value encrypted under a key at
`<data-dir>/secrets.key`, generated on first start and readable by the daemon
alone, so a copy of `node.db` without it says nothing. Every response that carries
a policy back out of a node (`CreateSandbox`, `GetSandbox`, `ListSandboxes`,
`PauseSandbox`, `ResumeSandbox`, `UpdateNetworkPolicy`) replaces each value with
`<redacted>`, keeping the domain and header name visible so an operator can still
see which credential goes where. The orchestrator mirrors what the node returns,
so it never holds the real value either. Only the node's own store does, which is
what lets brokering survive a restart.

### Request matchers

A rule may carry a matcher that narrows which requests it applies to.

**A matcher never blocks.** This is the one thing to get right about the feature.
It selects which requests a rule's action applies to. A request matching no rule
is still allowed and still reaches the origin, it just goes out unmodified. To
have a request refused, leave its domain out of `allow_domains`, or forward the
domain to an endpoint that refuses it.

A matcher has four dimensions, and every one you give must match:

| Dimension | Compared against | Case |
| --- | --- | --- |
| `path` | The path alone, without the query string | Sensitive |
| `method` | A list; any one matching is enough | Sensitive |
| `query` | Query entries, all of them ANDed | Keys and values sensitive |
| `headers` | Header entries, all of them ANDed | Names insensitive, values sensitive |

Each string comparison is one of `exact`, `starts_with` or `regex`. A regex is
unanchored, so `^` and `$` mean what they say. When a request repeats a query key
or a header name, the entry is satisfied if any of its values matches. Query keys
and values are compared percent-decoded and split before decoding, so an encoded
`&` inside a value stays inside it.

Regexes run on a linear-time engine with no backtracking, so no pattern can make
a request cost unbounded work whatever the guest sends. One that does not compile
is refused when the policy is set, not when a request would have used it.

From the CLI a rule is a small JSON object, because four dimensions and three
comparators in flag grammar would be a language nobody could read back:

```sh
burrow create --template base --net allowlist \
  --allow-domain api.example.com --inspect-tls \
  --rule '{"domain":"api.example.com",
           "match":{"path":{"startsWith":"/v1/"},"method":["GET"]},
           "setHeaders":{"Authorization":"Bearer <token>"}}'
```

A `GET /v1/users` carries the credential. A `POST /v1/users` and a
`GET /v2/users` do not, and both still succeed.

`--rule` entries are sent before `--inject-header` ones, since an injection
carries no matcher and would otherwise shadow every rule written after it.

### Request forwarding

A rule's action may instead be: send this request to an endpoint you control.

```sh
burrow create --template base --net allowlist \
  --allow-domain api.example.com --inspect-tls \
  --rule '{"domain":"api.example.com",
           "forward":{"url":"https://gate.example.com/inspect",
                      "secret":"<shared secret>"}}'
```

The forwarded request keeps its method, headers and body. Its target is the
forward URL's path followed by the original path and query, so a request for
`/v1/users?a=1` arrives at the endpoint above as `POST /inspect/v1/users?a=1`.
The origin the sandbox named never sees it.

A `forward` rule with no matcher is how you restrict a domain to specific paths:
everything to that domain goes through your endpoint, and your endpoint rejects
what you do not want. Burrow leaves that decision to you deliberately, because
which paths of an API a workload may use is a question about your API, not about
the network.

The endpoint is told where the request came from:

| Header | What it says |
| --- | --- |
| `burrow-forwarded-host` | The host the sandbox asked for |
| `burrow-forwarded-scheme` | `https` for an inspected session |
| `burrow-forwarded-port` | The port the sandbox was connecting to |
| `burrow-forwarded-path` | The original path and query |
| `burrow-forwarded-sandbox` | The sandbox id |
| `burrow-forwarded-secret` | The shared secret from the rule, if you set one |

The guest cannot forge any of them: every header in the `burrow-forwarded-`
prefix is stripped from the sandbox's request before the node sets its own.

#### Choosing between https and http

The forward URL takes either scheme, and the choice is about one thing, which is
what protects the shared secret on its way to your endpoint.

With `https://` the node dials your endpoint over TLS and verifies its
certificate against the public root store, exactly as it verifies any origin a
sandbox reaches. That buys two things: the secret and the request are protected
in transit, so seeing the traffic is no longer enough to replay it, and the
endpoint's identity is checked, so a name that resolves somewhere you did not
intend does not receive your secret. Verification is mandatory. There is no
option to skip it and no way to supply your own certificate authority for the
forward endpoint. A certificate that does not verify ends the request with an
error, and nothing retries it in plaintext. If you need a private authority here,
ask for it rather than assume it, because it moves the trust boundary.

With `http://` the request and the secret go out in the clear. That is reasonable
when the endpoint is on the node's own private network or on loopback, where
anyone who can read the traffic already has the node. It is not reasonable
anywhere else, and burrow cannot tell the difference for you.

#### What the shared secret proves, and what it does not

Burrow has no OIDC issuer and does not pretend to have one, so a forwarded
request carries no signature. It carries the shared secret you configured on the
rule, held on the node and never in any guest. Read the guarantee exactly:

- Seeing the secret proves the request came from a node holding that rule. It
  authenticates **the node**, not the sandbox.
- It says nothing about the request's contents. It is a bearer token, not a
  signature over the body.
- It is only as safe as everything that holds it. An endpoint that logs it,
  echoes it or leaks it has handed over the whole guarantee, and rotating the
  rule is the only repair.
- Over `http://` it does not survive being read off the wire. Anyone who can see
  the traffic can replay it.
- The `burrow-forwarded-*` headers are claims by the node, believable exactly as
  far as the node is.

Two requirements follow, not suggestions. The endpoint must either verify as an
`https://` endpoint or be reachable only by the node, on a private address or a
loopback interface. And it must not be given authority that a node compromise
should not also grant, because a node compromise grants it.

#### Limits

- Forwarding requires `is_tls_inspected`, like every other rule.
- The URL is `http://` or `https://` with no query string and no fragment,
  validated at the API door. A port you do not name defaults to 80 for `http://`
  and 443 for `https://`.
- An `https://` endpoint is verified against the public roots on every request,
  and HTTP/1.1 and HTTP/2 sessions forward the same way.
- A forwarded body is buffered rather than streamed, up to 8 MiB. A larger
  request is refused rather than truncated.
- On HTTP/1.1 a session whose policy could forward serves **one request per
  connection**. A forwarded request's answer does not come from the origin and
  cannot be written down a socket already relaying the origin's responses, so the
  connection is closed after the request and clients reconnect. HTTP/2 has no such
  limit, since each stream is judged and forwarded on its own.
- The proxy still opens the TLS connection to the origin, because that is how it
  learns which version of HTTP the session speaks. The request itself never
  reaches it.

### Limits on rules

Guest-controlled input reaches every matcher, so what a policy may ask the proxy
to evaluate is bounded:

| Bound | Value |
| --- | --- |
| Rules per policy | 32 |
| Methods, query entries and header entries per matcher | 8 each |
| Headers a rule may set | 8 |
| Pattern length | 256 bytes |
| Compiled size of one regex | 64 KiB |
| Forwarded request body | 8 MiB |

A request head is already capped at 16 KiB on both protocols, so the work one
request can cost is the product of two bounded numbers.

### Selective inspection in open mode

An open-mode sandbox can have a credential brokered onto its requests to a few
named HTTPS hosts while the rest of its traffic stays exactly as open mode
leaves it: not proxied, not inspected, not pinned.

```sh
burrow create --template base --net open --inspect-tls
burrow secret set api-token --value "$TOKEN" --allow-sandbox <sandbox-id>
burrow config network-policy <sandbox-id> --net open --inspect-tls \
  --rule '{"domain":"api.example.com","match":{"method":["GET","POST"]},
           "setHeaders":{"authorization":"Bearer ${secret:api-token}"},
           "expiresIn":"1h"}'
```

In open mode `is_tls_inspected` means two things. At creation the guest is
given the inspection root, as in allowlist mode: with a fleet root it keeps
trusting the proxy across moves, adopts, forks and restores, and it moves only
between nodes under that root (see [The inspection root](#the-inspection-root)).
And the hosts named by the
policy's live request rules, and only those, are inspected. Each such rule's
`domain` must be an exact host name: a glob would have the node inspect hosts
nobody wrote down, so it is refused at the API door. `http_rules` are refused in
open mode, since bounding what a host may carry is an allowlist notion.

How a connection is chosen for inspection:

1. **The resolver decides which addresses.** When an open-mode sandbox looks up
   a name some live rule names, the resolver pins the answer as it does for
   every lookup and, before replying, adds each (sandbox, address) pair to an
   nftables set, `inspected` in the `burrow_nat` table, with a timeout equal to
   the pin's lifetime (60 seconds to one hour). One prerouting rule redirects
   TCP 443 from a pair in that set to the egress proxy. Nothing else from the
   sandbox is redirected: other ports, other addresses and plain HTTP leave
   through open mode's ordinary accept and masquerade. Private, link-local and
   fleet addresses are never added.
2. **The proxy decides by name.** A redirected connection whose SNI names a host
   with a live rule is terminated and inspected, exactly as in allowlist mode:
   the inner `Host` must match the SNI, the destination must be pinned to that
   name for this sandbox, smuggling ambiguities are refused, and rules apply per
   request over HTTP/1.1 and HTTP/2. A redirected connection naming some other
   host, which happens when an inspected host shares an address with others or
   when its rule expired after the lookup, is relayed untouched, as open mode's
   ordinary egress, after the denials open mode always has (`deny_cidrs`,
   `deny_domains`, `deny_ports`, internal and metadata addresses).
3. **What cannot be named fails closed.** A redirected connection with no SNI,
   or with an encrypted ClientHello (ECH), is refused and audited, since it was
   redirected because its address belongs to an inspected host. An inspected
   connection to an address the resolver did not give this sandbox for that
   name is refused rather than relayed without its credential.

Properties worth knowing:

- **A credential only reaches the real origin.** The proxy verifies the
  origin's certificate against the public roots for the inspected name, and the
  destination must be pinned, so a guest cannot steer a brokered request to an
  address of its choosing.
- **Bypassing inspection only loses the credential.** A guest that resolves the
  host elsewhere (DNS over HTTPS, a hard-coded address, IPv6, whose answers the
  resolver never gives) reaches it directly, without the credential. Nothing
  leaks; the brokering simply does not happen.
- **IPv6.** The resolver returns no AAAA records, so inspected hosts are reached
  over IPv4 and redirected there. `is_ipv6_denied` and `deny_ports` apply as in
  any open-mode sandbox; a denied port 443 is refused by the proxy for
  redirected connections.
- **The guest must trust the root.** It is installed at creation, by the agent
  at handshake on Linux and Windows and onto the disk before boot on macOS; see
  [When a guest does not trust the inspection CA](#when-a-guest-does-not-trust-the-inspection-ca)
  for images that read their own bundle. A client that pins certificates for
  the inspected host will refuse the proxy's.
- **Live.** Adding a rule takes effect at once for every address the resolver
  has given the sandbox for that host and not yet forgotten, since the update
  re-renders the set from the pins, and at the next lookup otherwise. An
  address the guest learned some other way goes direct, without the
  credential. Removing or expiring a rule takes effect at the next request, including the next request on an already open session,
  because a session reads its rules from the node's current policy on every
  request. Its redirect lapses when the policy is re-rendered, which happens on
  the update itself and, for an expiry, within the reaper's ten-second tick;
  until then a redirected connection to the host is relayed untouched.
- **macOS nodes** make the same decision in the userspace stack: HTTPS to an
  address pinned for a live inspected host is handed to the proxy, everything
  else is dialled directly. There is no nftables set; each new flow reads the
  pins and the live rules, so an expired rule stops a new flow being proxied at
  once.
- **Mixed-version fleets.** A node names the policy fields it enforces
  (`NodeInfo.policy_features`: `deny_ports`, `ipv6_denied`, `rule_expiry`,
  `rule_binding`, `open_inspection`). A node predating a field would decode a
  policy carrying it and drop it silently, so the orchestrator places, forks,
  moves and updates a policy using one only on a node that names it, and
  refuses otherwise. A create from a snapshot that keeps the snapshot's own
  policy, which the orchestrator does not see, is placed away from its holder
  only on a node naming all of them.

### Rule expiry

`expires_at_unix_ms` on a request rule is the unix time in milliseconds at which
it stops applying; 0, the default, never expires. From the CLI a `--rule` takes
`"expiresIn"` (seconds, or a number with `s`, `m`, `h` or `d`) or
`"expiresAtUnixMs"`.

- The proxy compares every request against the node's clock, so an expired rule
  stops applying without a call: it sets nothing and forwards nothing, the next
  matching rule applies instead, and in open mode its host stops being
  inspected.
- The rule stays in the policy until an update removes it. Every policy a node
  returns reports it with `is_expired` set.
- Both ends are audited. A connection's record names the rules that set headers
  on its requests (`headers set by rule 0 (api.example.com) on 3 of 4
  requests`; per stream on HTTP/2), and when a rule expires the node writes a
  record with destination `policy` and the reason `request rule N for <domain>
  expired`, filed with the refusals so `burrow audit --denied` shows it.
- Expiry is measured on the node's clock, so nodes need synchronised time.

### Scoped secrets

A stored secret is usable by every sandbox unless it is scoped. `SetSecret`
takes `allowed_sandboxes` (sandbox ids or names) and `allowed_tags`
(`key=value`), on the CLI `--allow-sandbox` and `--allow-tag`. A scoped secret
resolves only for a sandbox named by id or name, or carrying one of the tags;
anywhere else the create, fork or update that references it is refused with
`PERMISSION_DENIED`. The same scope applies to a Kit credential of that name,
which a sandbox outside the scope does not receive. Leaving both lists empty
keeps today's behaviour, and setting a secret replaces its scope with its value.

```sh
burrow secret set api-token --value "$TOKEN" --allow-sandbox sbx_abc123
burrow secret set ci-token --allow-tag team=ci < token.txt
burrow secret ls
# api-token   sandbox=sbx_abc123
# ci-token    tag:team=ci
```

- **Enforced where `${secret:...}` is resolved,** in the orchestrator, against
  the sandbox the policy is for: its id (already assigned on a create), its
  name and its tags.
- **A grant does not travel.** A rule that took a value from a scoped secret is
  stamped with `bound_sandbox_id`. If its policy is copied to another sandbox, by
  a fork or a create from a snapshot, the rule refuses the requests it would
  have claimed there (`403`) instead of brokering a credential its scope does
  not cover or sending those requests without it.
- **Resolution is a moment.** Re-scoping or deleting a secret does not reach
  policies that already hold its value; remove the rule, or let it expire, to
  revoke a grant.
- **Tags are as strong as whoever sets them.** Anyone who can update a
  sandbox's tags can bring it into a tag scope; scope by id when that matters.
- **Integrity.** The scope is stored beside the sealed value and bound into its
  sealing context, so rewriting the scope in the store leaves a value that no
  longer unseals rather than one more sandboxes may use. Values are never
  returned or logged; `ListSecrets` returns names and scopes.

## Denied domains and HTTP rules

Two more fields narrow a policy below the host. Both come from the Sandbox Kit
network policy, and `deny_domains` also has a flag.

**`deny_domains`** refuses a set of domain globs before anything grants them.
It applies in every mode, so an `open` sandbox with `--deny-domain
'*.corp.example'` cannot resolve or connect to those names however unfiltered
the rest of its egress is, and an allowlist that names `*.example.com` and
denies `internal.example.com` reaches every subdomain but that one. Inside an
inspected session a request naming a denied host is answered `403`. Besides the
patterns in [Domain patterns](#domain-patterns), a deny entry may be `*`, which
denies every host.

**`http_rules`** decide per request, by host, method and path. A rule names a
list of host globs (`*` is every host), a list of methods (empty, or `ANY`, is
every method) and a list of path globs (empty is every path; `*` matches within
one segment, `**` across segments, so `/repos/**` covers `/repos` and everything
under it). Each rule is either an allow or a deny:

- A **deny** rule refuses matching requests with `403`, whatever `allow_domains`
  or any allow rule says. `DELETE` on an allowed host, or anything under
  `/admin/`, can be closed off this way.
- An **allow** rule for a host that `allow_domains` does not grant makes it a
  *bounded host*: the proxy admits connections to it and resolves it, but every
  request must match some allow rule by method and path or it is answered
  `403`. Traffic the proxy cannot read is refused outright: a connection to a
  bounded host on a port other than 80 or 443, or on 443 without inspection, is
  closed and audited as `bounded host requires inspection`. A host granted by
  `allow_domains` is not bounded and carries any traffic, deny rules aside.

Like request rules, `http_rules` need `is_tls_inspected`, and a policy carrying them
without it is refused at the API door. Plain HTTP on port 80 is already read
request by request, so both fields apply there too. A policy carries at most 64
HTTP rules, methods are uppercase tokens, and every path glob starts with `/`.
The refusing rule is named in the audit record's reason.

## Live updates

`UpdateNetworkPolicy` replaces a running sandbox's policy without restarting
anything in the guest. Firewall rules, proxy allowlist, DNS filtering and header
injection all re-render immediately, which is what lets a job install its
dependencies under a permissive policy and then lock itself down before the
untrusted step.

```sh
# Permissive setup phase.
burrow create --template base --net allowlist \
  --allow-domain pypi.org --allow-domain '*.pythonhosted.org'
# ...install dependencies, fetch data...

# Lock down before the untrusted step.
burrow config network-policy <sandbox-id> --net none
```

The update replaces the policy wholesale rather than patching it: a field left
out is an allowance withdrawn, which is what makes locking a sandbox down one
call. It is also a denial withdrawn: an update that leaves out `deny_ports` or
`is_ipv6_denied` lifts them, so a client changing one field sends the others
again. Forks, snapshots and moves carry the whole policy, these fields
included.

Tightening mid-connection is enforced at the boundary. nftables rules apply to
new packets immediately and the proxy re-checks per request on inspected
sessions, while connections already established keep their conntrack entry. So a
tightening bites new connections and, inside an inspected session, the next
request, rather than cutting a transfer in flight. Denials are the exception:
`deny_cidrs`, `deny_ports` and `is_ipv6_denied` are rendered ahead of the
established accept, so a connection they now cover stops at its next packet.

One transition is refused rather than applied: **`is_tls_inspected` can only be
enabled at creation.** The guest trusts Burrow's CA because it was installed into
its trust store during the agent handshake, so turning inspection on later would
break every TLS connection the sandbox makes instead of inspecting them. Turning
it off, and every other change, is live. For the same reason an inspected
sandbox moves only between nodes under one root; see
[The inspection root](#the-inspection-root). A sandbox that may need a credential
brokered later is therefore created with `--net open --inspect-tls` and no
rules, which inspects nothing until a rule is added.

Brokered values come back from every read as `<redacted>`, so a client that
reads a policy, adds or removes one rule and sends it back would otherwise send
the placeholder as the credential. Instead, a `<redacted>` header value is
replaced with the value of the same header on a rule for the same domain in the
policy being replaced, and a `<redacted>` forward secret with the secret of the
rule with the same domain and URL; a placeholder with nothing to stand for is
refused. Read-modify-write is therefore safe, and so is sending a whole policy
with `${secret:...}` references each time.

## Private networks

Sandboxes can join named private networks (`NetworkMembership`). Members reach
each other at `<alias>.<network>.internal` whatever their egress mode.

```sh
burrow create --template python --network team --alias api
burrow create --template python --network team --alias worker
# from `worker`:  curl http://api.team.internal:8080/
```

Membership and egress policy are independent: a `none`-mode sandbox still talks
to its peers if it is a member, and `.internal` names always resolve. A sandbox
outside the network gets `NXDOMAIN`, so names cannot be used to enumerate the
fleet, and resolving a name is not what grants access anyway. The rules are, and
a non-member that learned an address by other means still cannot reach it.

Membership is the *only* way one sandbox reaches another, whatever the egress
mode and whichever nodes they are on. The three routes that are not the direct
one are closed too: a published port is reachable only from off-fleet traffic,
the node's own services admit nothing but the resolver and the egress proxy, and
every node's edge router, which would proxy into a published port for anyone who
asked, is denied to every sandbox along with the orchestrator's API. See
[ARCHITECTURE.md](ARCHITECTURE.md#naming-sandboxes-on-a-private-network) for how
the directory is built.

## Published ports

`ExposePort` maps a host port to a guest port by DNAT:

```sh
burrow expose <id> 8000
burrow port <id>
burrow unexpose <id> <host-port>
```

Published ports are reachable only from external traffic, never from
other sandboxes or mesh peers. Host ports come from the fixed range 20000 to
29999.

## macOS nodes

A macOS sandbox runs under Virtualization.framework, and a Mac has no
nftables. Its one NIC is attached to a datagram socket pair whose other end is
a userspace network stack in burrowd (`burrow_net::usernet`, built on
smoltcp), so every frame the guest sends arrives there and nowhere else. The
link has one guest on it, which makes anti-spoofing a property of the
attachment, and the node itself is unreachable unless the stack dials a
connection on the guest's behalf.

The policy is the same one, decided by the same code. `burrow_net::policy`
holds the decision the Linux ruleset encodes, and a test renders the ruleset
and checks it against that decision for every mode, allowed and denied CIDRs,
port restrictions, peers, the node's own address and the control plane, so the
two cannot drift. Per new flow:

| Linux | macOS |
| --- | --- |
| Allowlist TCP 80/443 redirected to the egress proxy | The terminated connection is handed to the same proxy, which checks SNI or `Host`, the DNS pin, `deny_cidrs`, `deny_ports`, inspection and request rules |
| Forward chain accept (open mode, `allow_cidrs`/`allow_ports`, peers), masquerade | A host socket dialled to the destination and spliced to the guest |
| `tohost` accept for the resolver | Queries answered by the same resolver with the same allowlist, pinning and audit |
| Chain drop | TCP reset, UDP dropped, either way audited |

Two differences follow from the stack dialling from the node rather than
routing through it. The node's own addresses and loopback are denied as
destinations, which on Linux the host input chain does. And a TCP SYN is held
unanswered until the destination is decided and, for a direct flow, until the
upstream connection is up, so a refused or unreachable destination gets a
reset rather than a timeout.

Every flow the stack decides itself is audited, allowed or not, with bytes in
each direction: direct connections, UDP flows and refusals. On Linux nftables
decides those silently, so a macOS node's log has records a Linux node's does
not. Proxied connections and DNS write the same records on both.

Live updates apply to the next flow, and a direct connection the new policy
denies is reset at once and recorded as such, which is what the conntrack
flush after a re-render does on Linux.

Private networks work as on Linux, decided by the same code. A Mac node
claims an address slice at registration like any node, and a packet a guest
sends to another sandbox's address is not terminated: an in-process router
hands it, a hop on, to the stack of the sandbox holding that address, or over
the mesh to the node holding it. The Mac's end of the mesh is a userspace
WireGuard endpoint on one UDP socket, speaking to the Linux nodes' kernel
WireGuard with each peer's slice as its `AllowedIPs`, and keys and peers from
the orchestrator under the same pinning. Each new flow is decided once with
`burrow_net::policy::decide_peer`: the sender's own decision (so a peer is
exempt from the allowlist redirect, as the `prerouting` accept makes it on
Linux, though never from its `deny_cidrs`, `deny_ports` or IPv6 denial) and
the receiver's membership, which is what a flow arriving over the
mesh meets in a Linux sandbox chain; a test renders the ruleset for the same
pairs, on one node and across the mesh, and checks they agree. Replies follow
the tracked flow. A policy update re-decides every tracked flow and resets
both TCP ends of one it now denies. Only addresses in the sandbox pool are
ever forwarded, and `.internal` names are answered from the same directory,
`NXDOMAIN` for a non-member. TCP SYNs crossing the mesh have their MSS clamped
to 1380, what a 1420-byte WireGuard MTU carries whole.

Published ports listen on one address, never on every interface unless asked:
`--publish-address`, by default the address the node is advertised at when
that is one of the Mac's own, and otherwise the address `--listen` binds. That
is the address the orchestrator reports the port at, as Linux's DNAT serves
whatever reaches the node from outside.

Not yet on macOS: IPv6 (the guest is not offered a router, so it has
link-local addresses only, and `is_ipv6_denied` changes nothing a macOS guest
can reach; v6 is never forwarded to a peer or over the mesh), UDP published
ports, and ICMP beyond pinging the
gateway and echo between peers.
