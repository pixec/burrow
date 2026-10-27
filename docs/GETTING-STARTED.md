# Getting started

Burrow needs KVM. On Linux, run `burrowd` on the host directly. On macOS the
dev harness runs inside a nested-virtualization VM, which needs an M3 or newer
Mac on macOS 15 or later.

**1. VM and cross-compiler, once.**

```sh
colima start burrow --vm-type vz --nested-virtualization --cpu 4 --memory 8 --disk 40
brew install zig
cargo install cargo-zigbuild
```

**2. Build and bring up the stack.** The harness runs
`aarch64-unknown-linux-musl`; swap the target for anything else. `burrow-guest`
is the guest init and is excluded from the workspace defaults, so it is named
explicitly. The harness runs an orchestrator and two nodes, so cross-node
behaviour is exercised rather than assumed.

```sh
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl \
  -p burrow-orchestrator -p burrow-daemon -p burrow-cli -p burrow-guest
docker --context colima-burrow compose -f deploy/dev/compose.yaml up -d --build
```

**3. Point the CLI at it.** The harness sets the client token to `dev-token`
and gives the orchestrator and both nodes `dev-node-token` for the node-facing
hop. The two are separate on purpose; see
[CONCEPTS.md](CONCEPTS.md#api-callers-are-authenticated).

```sh
export BURROW_API_KEY=dev-token
alias burrow='cargo run -q -p burrow-cli --'
```

**4. Give the node a kernel.** An OCI image carries a userland and no kernel,
so the node supplies one for every template it builds. `--guest-kernel` names
it, and it defaults to `vmlinux` under the data directory:

```sh
docker --context colima-burrow exec burrow-node-1 sh -c '
  curl -fsSL -o /var/lib/burrow/vmlinux \
    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/aarch64/vmlinux-6.1.141'
```

**5. Pull, create, run.** Burrow ships no image of its own, so a create must
name a template you imported:

```sh
burrow pull python:3.12-slim
burrow create --template python-3.12-slim
burrow exec <id> -- python3 -c 'print(1 + 1)'
```

That sandbox has no egress. To give it some:

```sh
burrow create --template python-3.12-slim --net allowlist \
  --allow-domain pypi.org --allow-domain '*.pythonhosted.org'
```


## SDKs and CLI

The same operations are available from the `burrow` CLI and the
[TypeScript](../sdk/typescript/README.md) and [Python](../sdk/python/README.md) SDKs.

<details>
<summary><b>Python</b></summary>

```python
from burrow import Sandbox

with Sandbox.create(template="python-3.12-slim") as sandbox:
    result = sandbox.run_command("python3", ["-c", "print(1 + 1)"])
    print(result.stdout)  # "2\n"
```

</details>

<details>
<summary><b>CLI</b></summary>

```sh
burrow pull python:3.12-slim
id=$(burrow create --template python-3.12-slim --net allowlist --allow-domain pypi.org)
burrow exec "$id" -- pip install cowsay
burrow stop "$id"      # suspend to disk
burrow start "$id"     # resume, processes intact
burrow fork "$id"      # an independent copy
```

</details>

## Releases

Tagged releases publish static musl binaries for `x86_64` and `aarch64`:
`burrowd`, `burrow-orchestrator`, `burrow` and `burrow-guest`, each named
`<binary>-<arch>-<version>`, with a `SHA256SUMS` file per architecture. The
same tag publishes multi-arch container images:

```
ghcr.io/pixec/burrow-orchestrator:<version>
ghcr.io/pixec/burrow-node:<version>
```

To run those images on Kubernetes, see [deploy/k8s](../deploy/k8s/README.md).
