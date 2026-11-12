# Burrow

MicroVM sandboxes for untrusted code, run on your own hardware.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Releases](https://img.shields.io/github/v/release/pixec/burrow?display_name=tag)](https://github.com/pixec/burrow/releases)
[![TypeScript SDK](https://img.shields.io/npm/v/%40pixec%2Fburrow?label=npm)](https://www.npmjs.com/package/@pixec/burrow)
[![Python SDK](https://img.shields.io/pypi/v/pixec-burrow?label=pypi)](https://pypi.org/project/pixec-burrow/)

A sandbox is a VM with its own kernel and disk and a network that denies
everything until a rule allows it. Linux sandboxes run under Firecracker or
Cloud Hypervisor on KVM nodes, chosen per template, and macOS sandboxes run
under Virtualization.framework on Mac nodes. Sandboxes are created from OCI images,
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

</td>
<td width="50%" valign="top">

**Egress policy.** No egress by default. Grant it by domain or CIDR; allowed
names are pinned to the addresses the sandbox was told they resolve to, DNS is
filtered in every mode, and every decision the proxy and resolver make is
audited and queryable.

</td>
</tr>
<tr>
<td valign="top">

**Credential brokering.** With TLS inspection on, the proxy injects an API key
on the host side, by domain, method and path, so the workload calls an
authenticated API without holding the secret.

</td>
<td valign="top">

**Templates from OCI images.** `burrow pull python:3.12-slim` converts a
registry image into a bootable rootfs. An image that is a Docker Sandbox
Kit carries a descriptor saying what to provision: hooks, credentials,
volumes and network policy.

</td>
</tr>
<tr>
<td valign="top">

**Volumes.** Block devices on a node that outlive the sandboxes mounting them:
one writer or many readers, attached at create, kept through a rebuild of the
root disk.

</td>
<td valign="top">

**Multiple nodes.** An orchestrator places sandboxes across KVM nodes joined
by a WireGuard mesh, and runs as several replicas over PostgreSQL. Private
inter-sandbox networks work across hosts, and published ports are reachable
through a per-node edge with wildcard DNS.

</td>
</tr>
</table>

## Documentation

The documentation is available at [burrow.pixec.net](https://burrow.pixec.net).

## Sponsors

Thanks to the following sponsors for helping fund Burrow's development.
To become a sponsor, open an issue or write to `oss+burrow[at]pixec.net`.

| Company | About |
| --- | --- |
| [BoxCompute](https://boxcompute.ai) | BoxCompute provides cloud computers for AI agents. Each agent gets its own Linux virtual machine that keeps running after you close the browser; connect tools such as Claude Code, Codex or Cursor, or describe a task to BoxCompute's built-in agent, which sets up the software, runs your app, and gives you a live preview link. |

## License

Burrow is licensed under the GNU Affero General Public License, version 3, in [LICENSE](LICENSE).
Contributions are accepted under the [Contributor License Agreement](CLA.md).
