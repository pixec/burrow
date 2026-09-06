# Burrow

Burrow runs untrusted code in Firecracker microVMs on hardware you own. A
sandbox is a long-lived Linux machine with its own kernel, its own disk, and a
network that denies everything until you allow something. You drive it from a
gRPC API, a CLI, or the TypeScript and Python SDKs.

## Why not just a container

A container shares the host kernel with the code it is confining. For running
AI-generated or user-submitted code, that is one bug away from being no
boundary at all. A Burrow sandbox gets its own kernel behind Firecracker's very
small device model, and optionally the Firecracker jailer on top of that.

The cost is a boot: 1.2s to 2.2s cold. Most creates do not pay it, because
nodes keep warm snapshots of each template and restore from one in 40ms to
50ms. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit
together.

## What you get on top of the VM

Sandboxes are meant to stick around. Pause one to disk and resume it later with
its processes where they were, snapshot a prepared workspace and fork it into
as many independent copies as you need, and list every VM a sandbox has ever
run as a session. Each sandbox reports the CPU and bytes it actually consumed.
See [docs/PERSISTENCE.md](docs/PERSISTENCE.md).

Egress starts at nothing. You grant it by domain or by CIDR; allowed names are
pinned to the addresses that sandbox was told they resolve to, DNS is filtered
in every mode, and refusals are audited. Turn on TLS inspection for a sandbox
and the proxy can also inject credentials on the host side, so the workload
calls an authenticated API without ever holding the key. See
[docs/FIREWALL.md](docs/FIREWALL.md).

Templates come from OCI images. `burrow pull python:3.12-slim` converts a
registry image into a bootable rootfs, or you can build a template from cached
steps ([docs/TEMPLATES.md](docs/TEMPLATES.md)). Sandboxes carry key-value tags you
can filter on ([docs/TAGS.md](docs/TAGS.md)).

It is multi-node from the start: an orchestrator places sandboxes across KVM
nodes joined by a WireGuard mesh, and private inter-sandbox networks work
across hosts.

## Releases

Tagged releases publish static musl binaries for `x86_64` and `aarch64`:
`burrowd`, `burrow-orchestrator`, `burrow` and `burrow-agent`, each named
`<binary>-<arch>-<version>`, with a `SHA256SUMS` file per architecture. The
same tag publishes multi-arch container images:

```
ghcr.io/pixec/burrow-orchestrator:<version>
ghcr.io/pixec/burrow-node:<version>
```

To run those images on Kubernetes, see [deploy/k8s](deploy/k8s/README.md).

## Quickstart

Burrow needs KVM. On Linux you can run `burrowd` on the host directly. On macOS
the dev harness runs inside a nested-virtualization VM, which needs an M3 or
newer Mac on macOS 15 or later.

Set up the VM and the cross-compiler once:

```sh
colima start burrow --vm-type vz --nested-virtualization --cpu 4 --memory 8 --disk 40
brew install zig
cargo install cargo-zigbuild
```

Build the Linux binaries and bring up the stack. `cargo xtask build` targets
`aarch64-unknown-linux-musl` by default, which is what the harness runs; pass
`--target` for anything else. The harness runs an orchestrator and two nodes,
so cross-node behaviour is exercised rather than assumed.

```sh
cargo xtask build
docker --context colima-burrow compose -f deploy/dev/compose.yaml up -d --build
```

The harness sets the API token to `dev-token` and the orchestrator listens on
`127.0.0.1:7070`, which is where the CLI looks by default:

```sh
export BURROW_API_KEY=dev-token
alias burrow='cargo run -q -p burrow-cli --'
```

Give the node a kernel. An OCI image carries a userland and no kernel, so the
node supplies one for every template it builds. `--guest-kernel` names it, and
it defaults to `vmlinux` under the data directory:

```sh
docker --context colima-burrow exec burrow-node-1 sh -c '
  curl -fsSL -o /var/lib/burrow/vmlinux \
    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/aarch64/vmlinux-6.1.141'
```

Then import an image as a template, create a sandbox from it, and run
something. Templates come from OCI images; burrow ships none of its own, and a
create must name one:

```sh
burrow pull python:3.12-slim
burrow create --template python-3.12-slim
burrow exec <id> -- python3 -c 'print(1 + 1)'
```

That sandbox has no egress. To give it some:

```sh
burrow create --template python-3.12-slim --net allowlist --allow-domain pypi.org --allow-domain '*.pythonhosted.org'
```

## Documentation

| Page | Covers |
| --- | --- |
| [docs/CONCEPTS.md](docs/CONCEPTS.md) | What a sandbox is, its lifecycle, and the security model |
| [docs/CLI.md](docs/CLI.md) | Every `burrow` command, its flags, and an example |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Request path, guest, networking, snapshots, placement, and the dev harness |
| [docs/TEMPLATES.md](docs/TEMPLATES.md) | OCI imports, builds, warm snapshots, and distribution between nodes |
| [docs/FIREWALL.md](docs/FIREWALL.md) | Egress modes, denied ranges, live policy updates, and request rules: brokering, matchers and forwarding |
| [docs/EDGE.md](docs/EDGE.md) | Reaching a sandbox from outside: the node edge, HTTPS, wildcard DNS, a Caddyfile, raw TCP, and custom domains |
| [docs/PERSISTENCE.md](docs/PERSISTENCE.md) | Suspend and resume, sessions, fork, and snapshot retention |
| [docs/VOLUMES.md](docs/VOLUMES.md) | Storage that outlives a sandbox, and the rules that follow from block devices |
| [docs/TAGS.md](docs/TAGS.md) | Tagging sandboxes and filtering by tag |
| [docs/COMPARISON.md](docs/COMPARISON.md) | How Burrow compares to Vercel Sandbox and E2B |
