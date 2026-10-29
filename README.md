# Burrow

Firecracker microVM sandboxes for untrusted code, run on your own hardware.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Releases](https://img.shields.io/github/v/release/pixec/burrow?display_name=tag)](https://github.com/pixec/burrow/releases)
[![TypeScript SDK](https://img.shields.io/npm/v/%40pixec%2Fburrow?label=npm)](https://www.npmjs.com/package/@pixec/burrow)
[![Python SDK](https://img.shields.io/pypi/v/pixec-burrow?label=pypi)](https://pypi.org/project/pixec-burrow/)

A sandbox is a Linux VM with its own kernel and disk and a network that denies
everything until a rule allows it. Sandboxes are created from OCI images,
restore from warm snapshots in about 30 ms, suspend and resume with their
memory intact, and are driven from a gRPC API, a CLI, or the TypeScript and
Python SDKs.

Burrow is built for the developer writing against it and for the people their
product serves. So the SDKs do not invent an API of their own: each mirrors its
language's. In TypeScript, files are `node:fs/promises` and processes are
`node:child_process`; in Python, they are `open()`, `os`, `shutil`, `pathlib`
and `subprocess`.

```ts
import { Sandbox } from "@pixec/burrow";

await using sandbox = await Sandbox.create({
  template: "python-3.12-slim",
  networkPolicy: { mode: "allowlist", allowDomains: ["pypi.org", "*.pythonhosted.org"] },
});
const { stdout } = await sandbox.childProcess.execFile("python3", ["-c", "print(1 + 1)"]);
console.log(stdout); // "2\n"
```

## Features

<table>
<tr>
<td width="50%" valign="top">

**Persistence.** Suspend a sandbox to disk and resume it later with its
processes where they were. Snapshot a prepared workspace and fork it into
independent copies. With an object store, suspended sandboxes and snapshots
restore on any matching node, including after the node that held them is gone,
with memory paged in as the guest touches it. Every VM a sandbox has
run is recorded as a session.
[Read PERSISTENCE.md](docs/PERSISTENCE.md)

</td>
<td width="50%" valign="top">

**Egress policy.** No egress by default. Grant it by domain or CIDR; allowed
names are pinned to the addresses the sandbox was told they resolve to, DNS is
filtered in every mode, and every decision the proxy and resolver make is
audited and queryable.
[Read FIREWALL.md](docs/FIREWALL.md)

</td>
</tr>
<tr>
<td valign="top">

**Credential brokering.** With TLS inspection on, the proxy injects an API key
on the host side, by domain, method and path, so the workload calls an
authenticated API without holding the secret.
[Read FIREWALL.md](docs/FIREWALL.md#credentials-brokering)

</td>
<td valign="top">

**Templates from OCI images.** `burrow pull python:3.12-slim` converts a
registry image into a bootable rootfs. An image that is a [Docker Sandbox
Kit](docs/TEMPLATES.md#sandbox-kits) carries a descriptor saying what to
provision: hooks, credentials, volumes and network policy.
[Read TEMPLATES.md](docs/TEMPLATES.md)

</td>
</tr>
<tr>
<td valign="top">

**Volumes.** Block devices on a node that outlive the sandboxes mounting them:
one writer or many readers, attached at create, kept through a rebuild of the
root disk. [Read VOLUMES.md](docs/VOLUMES.md)

</td>
<td valign="top">

**Multiple nodes.** An orchestrator places sandboxes across KVM nodes joined
by a WireGuard mesh, and runs as several replicas over PostgreSQL. Private
inter-sandbox networks work across hosts, and published ports are reachable
through a per-node edge with wildcard DNS.
[Read EDGE.md](docs/EDGE.md)

</td>
</tr>
</table>

## Documentation

| Page | Covers |
| --- | --- |
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | Development harness setup, first sandbox, CLI and SDK examples, releases |
| [docs/CONCEPTS.md](docs/CONCEPTS.md) | What a sandbox is, its lifecycle, and the security model |
| [docs/CLI.md](docs/CLI.md) | Every `burrow` command, its flags, and an example |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Request path, guest, networking, snapshots, placement, and the dev harness |
| [docs/TEMPLATES.md](docs/TEMPLATES.md) | OCI imports, Sandbox Kits, builds, warm snapshots, and distribution between nodes |
| [docs/FIREWALL.md](docs/FIREWALL.md) | Egress modes, denied ranges, live policy updates, and request rules: brokering, matchers and forwarding |
| [docs/EDGE.md](docs/EDGE.md) | Reaching a sandbox from outside: choosing between the edge, a published port and a share, then HTTPS, wildcard DNS, a Caddyfile and custom domains |
| [docs/SHARE.md](docs/SHARE.md) | Sharing a sandbox through a tailcat address: a WireGuard tunnel over a DERP relay, no port on the node, and the client's own IP into the guest |
| [docs/PERSISTENCE.md](docs/PERSISTENCE.md) | Suspend and resume, sessions, fork, and snapshot retention |
| [docs/VOLUMES.md](docs/VOLUMES.md) | Storage that outlives a sandbox, and the rules that follow from block devices |
| [docs/METERING.md](docs/METERING.md) | What is metered, where the record lives, and how it survives a deleted sandbox or a dead node |
| [docs/TAGS.md](docs/TAGS.md) | Tagging sandboxes and filtering by tag |
| [docs/COMPARISON.md](docs/COMPARISON.md) | How Burrow compares to Vercel Sandbox, E2B, microsandbox, PandaStack, Modal and Cloudflare Sandbox |

## License

Burrow is licensed under the GNU Affero General Public License, version 3.
See [LICENSE](LICENSE) for the full text.
