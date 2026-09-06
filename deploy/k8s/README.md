# Running burrow on Kubernetes

Yes, with one caveat worth stating before the steps: Kubernetes schedules
burrow's daemons, not its sandboxes. A burrow sandbox is a firecracker microVM
that `burrowd` places, snapshots and restores itself, and the orchestrator does
its own placement across nodes. So the cluster's job here is narrow: run one
control plane, run one node daemon per KVM-capable machine, and keep them
addressable. Nothing about a sandbox is a pod, and `kubectl` cannot see one.

That makes the mapping straightforward:

| Burrow | Kubernetes | Why |
| --- | --- | --- |
| orchestrator | StatefulSet, 1 replica + Service | Single source of truth for the sandbox-to-node mapping; no leader election, so a second replica is a second answer |
| node (`burrowd`) | DaemonSet, `hostNetwork`, privileged | Owns a machine's `/dev/kvm`, taps, nftables and local sandbox state; sandboxes never move between nodes |
| sandbox | *nothing* | A microVM `burrowd` manages directly |

## What the cluster has to give you

- **Machines with `/dev/kvm`.** Bare metal, or instances with nested
  virtualization (GCP with a nested-virt licence, AWS `*.metal`, Azure `Dv3`).
  A node pod on a machine without KVM starts and then fails every create.
- **Permission to run privileged pods.** A burrow node is a hypervisor host: it
  needs `/dev/kvm`, `/dev/net/tun`, `NET_ADMIN` for taps and nftables, and a
  writable cgroup2 tree. Putting it in a pod does not change that. The
  namespace is labelled `pod-security.kubernetes.io/enforce: privileged` for
  clusters that enforce Pod Security Admission.
- **Host networking on those machines.** Peers dial each other's WireGuard mesh
  endpoint directly, and a sandbox's gateway is a host address rather than a pod
  one.

## Images

Tagging a release publishes both images to GHCR for `linux/amd64` and
`linux/arm64` (see [`.github/workflows/release.yml`](../../.github/workflows/release.yml)):

```
ghcr.io/pixec/burrow-orchestrator:<version>
ghcr.io/pixec/burrow-node:<version>
```

The images are defined at [`deploy/node.Dockerfile`](../node.Dockerfile) and
[`deploy/orchestrator.Dockerfile`](../orchestrator.Dockerfile), not under this
directory: nothing about them is Kubernetes-specific. The node file carries two
stages. `dev` is what the compose harness builds and bind-mounts binaries into;
`release` bakes them in for publishing. One file, so the firecracker and
tooling versions cannot drift between what you test on and what you ship.

To build one yourself, stage the binaries where `release` expects them:

```sh
cargo xtask build --target x86_64-unknown-linux-musl
mkdir -p dist/amd64
cp target/x86_64-unknown-linux-musl/release/{burrow-orchestrator,burrowd,burrow-agent} dist/amd64/

docker buildx build --platform linux/amd64 --load \
  -f deploy/orchestrator.Dockerfile -t <registry>/burrow-orchestrator:latest .
docker buildx build --platform linux/amd64 --load --target release \
  -f deploy/node.Dockerfile -t <registry>/burrow-node:latest .
```

Use `buildx`, not the legacy builder: the Dockerfiles pick the binary and the
firecracker release off `TARGETARCH`, which only BuildKit sets. The legacy
builder leaves it empty, which the images now fail on with a message saying so
rather than a confusing missing-file error. `--build-arg TARGETARCH=amd64` is
the escape hatch if you are stuck on it.

## Deploy

Replace the two `CHANGE-ME` tokens first. The manifests point at
`ghcr.io/pixec/...:latest`; pin them to a released version for anything you care
about, so a redeploy is not a silent upgrade.

```sh
kubectl label node <machine> burrow.pixec.net/kvm=true
kubectl apply -f deploy/k8s/00-namespace.yaml
kubectl apply -f deploy/k8s/10-orchestrator.yaml
kubectl apply -f deploy/k8s/20-node.yaml
```

Give each machine a kernel. Templates are built from OCI images, which carry a
userland and no kernel, so the node supplies one. The Firecracker CI kernels are
the usual starting point; take the one matching your machines' architecture:

```sh
kubectl -n burrow exec ds/burrow-node -- sh -c \
  'curl -fsSL -o /var/lib/burrow/vmlinux \
    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141'
```

On `arm64` machines swap `x86_64` for `aarch64` in that URL. `/var/lib/burrow`
is where `--guest-kernel` looks by default; pass the flag if you keep the kernel
elsewhere. Any kernel Firecracker can boot works, so a build of your own with
the drivers you need is fine.

Then import a template; nodes hold templates on local disk, and a fleet with
none can create nothing:

```sh
burrow pull alpine:latest
```

Then point the CLI at the orchestrator:

```sh
kubectl -n burrow port-forward svc/orchestrator 7070:7070
export BURROW_ORCHESTRATOR=http://127.0.0.1:7070
export BURROW_API_KEY=<the api-key from the secret>
burrow health
burrow nodes ls
```

## Things that will bite you

- **Port 53.** `burrowd` binds `0.0.0.0:53` for the guest resolver, because it
  has to answer on every sandbox's gateway address. Under `hostNetwork` that
  collides with anything already on the machine's port 53, and
  `systemd-resolved` bound to `0.0.0.0` is the usual culprit. Move that, or set
  `--dns-listen`.
- **Edge domains are per node.** An edge serves only the sandboxes its own node
  holds and 404s the rest, so each machine needs its own wildcard record
  (`*.<node-name>.sandbox.example.com`) pointing at that machine. A node with no
  edge still works; its published ports are reachable at the node address alone.
  See [EDGE.md](../../docs/EDGE.md).
- **Node identity is the machine.** `--node-id` is the Kubernetes node name, so
  a restarted pod re-registers as itself and keeps its sandboxes. Draining a
  machine in Kubernetes does not drain it in burrow: use
  [`burrow nodes drain`](../../docs/CLI.md#nodes-drain) first, or the sandboxes
  on it are lost rather than suspended.
- **`hostPath` state.** `/var/lib/burrow` follows the machine, not the pod.
  Snapshots are node-local and sandboxes do not move, so this is correct, but
  it also means wiping a machine wipes its sandboxes.
- **Placement labels are per DaemonSet.** The downward API cannot read a
  machine's labels, so `--label` is set in the manifest. For pools that differ,
  run one DaemonSet per pool with its own `nodeSelector` and `--label` flags,
  and constrain creates with
  [`burrow create --node-label`](../../docs/CLI.md#create).
