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

No traffic in or out, DNS included. A `none`-mode sandbox cannot resolve a
public name, so it cannot tunnel data out through queries either.

### `open`

NAT'd egress to the public internet. Traffic is still audited at L3 and L4 and
`deny_cidrs` still applies, but nothing is enforced per domain.

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
- **`deny_cidrs`** (`--deny-cidr`): block IPv4 ranges. Deny beats every
  allowance in every mode. The rules are rendered before any accept, and the
  proxy refuses a connection whose upstream address falls in a denied range, so
  a denied range stays unreachable even if an allowed domain resolves into it or
  `allow_cidrs` or `open` would otherwise grant it. An entry that does not parse
  costs the sandbox its egress rather than being skipped.

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

A wildcard anywhere else is not a pattern at all. `a.*.example.com` and a bare
`*` match nothing, and as a rule's `domain` they are refused when the policy is
set. In `allow_domains` they are simply dead entries, so an allowance you thought
you had is one nothing can use. A leading wildcard never covers the apex: add
`example.com` alongside it when the sandbox needs both.

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
  set with `--dns-upstream`. A sandbox in `none` mode gets no DNS at all rather
  than filtered DNS, since a name is attacker-chosen bytes leaving the sandbox.
- **The control plane is not a destination.** Every sandbox on a node is denied
  the address its orchestrator answers on, ahead of every accept and of
  conntrack. An open-mode sandbox has NAT'd egress to anywhere the node can
  route, and the orchestrator is somewhere the node can route, so without that
  denial it could reach an API that creates and deletes sandboxes and routes exec
  and logs into them. Every node's edge router is denied the same way, for a
  related reason: an edge proxies into a sandbox's published port by id, so
  reaching one reaches every sandbox it serves without a packet ever meeting a
  rule about sandboxes. The orchestrator's address is resolved from
  `--orchestrator` when the node starts and the edges arrive on the heartbeat, so
  neither should share an address with anything sandboxes are meant to reach.
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
hostnames whose infrastructure hosts nothing else. Or turn on `inspect_tls`: the
proxy then terminates TLS for that sandbox using a per-node CA installed into the
guest's trust store at handshake, parses every request inside the session, and
requires the inner `Host` to be allowlisted *and* to match the name the session
was opened for.

```sh
burrow create --template base --net allowlist \
  --allow-domain api.example.com --inspect-tls
```

What inspection costs is that the proxy can read payloads, which is why it is
opt-in. `--inspect-tls` requires `--net allowlist`, and `allow_cidrs`
destinations bypass it because they never reach the proxy.

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

### When a guest does not trust the inspection CA

At handshake the agent appends the node's inspection CA to the guest's system
trust bundles, such as `/etc/ssl/certs/ca-certificates.crt`. Some images never
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

All of this needs `inspect_tls`. Acting on a request means reading it, and
outside an inspected session there is no request to read, so a policy carrying
rules without inspection is refused at the API door rather than half-applied.

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

- Brokering only applies to domains the policy already allows. A rule never
  widens access, it only decides what a permitted request carries.
- It applies inside inspected TLS sessions, over HTTP/1.1 and HTTP/2 alike.
  Plaintext HTTP through the proxy is relayed untouched.
- Header names must be RFC 9110 tokens, and values may not contain CR, LF or NUL.
  A value that could forge a header line is refused at the API door rather than
  written into a request.

The secret lives in the sandbox's policy on the host. Every response that carries
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

- Forwarding requires `inspect_tls`, like every other rule.
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
call.

Tightening mid-connection is enforced at the boundary. nftables rules apply to
new packets immediately and the proxy re-checks per request on inspected
sessions, while connections already established keep their conntrack entry. So a
tightening bites new connections and, inside an inspected session, the next
request, rather than cutting a transfer in flight.

One transition is refused rather than applied: **`inspect_tls` can only be
enabled at creation.** The guest trusts Burrow's CA because it was installed into
its trust store during the agent handshake, so turning inspection on later would
break every TLS connection the sandbox makes instead of inspecting them. Turning
it off, and every other change, is live.

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

Published ports are reachable only from genuinely external traffic, never from
other sandboxes or mesh peers, and host ports are constrained to the
operator-configured range.
