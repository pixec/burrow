# Templates

Sandboxes boot from templates: prepared rootfs images living on each node under
`<data-dir>/images/<name>/`, alongside the kernel they boot. A template comes
from one of two places, an OCI image imported from a registry, or a build driven
by `BuildTemplate` steps.

Burrow ships no template of its own, so a node holds only what has been imported
onto it, and a create must name one. It also needs a kernel: an OCI image
carries a userland and nothing to boot it, so the node supplies one and links it
into every template it builds. `burrowd serve --guest-kernel <path>` names it,
defaulting to `vmlinux` under the data directory, and a node without one fails
an import with a message saying so. The Firecracker CI kernels are the usual
starting point:

```sh
curl -fsSL -o /var/lib/burrow/vmlinux \
  https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141
```

Swap `x86_64` for `aarch64` on arm machines. Any kernel Firecracker can boot
works, so a build of your own with the drivers you need is fine.

## Import an OCI image

```sh
burrow pull python:3.12-slim --name py312
burrow pull ghcr.io/org/toolchain@sha256:... --name toolchain
burrow create --template py312
```

The reference is `[registry/]repository[:tag|@digest]` and the registry defaults
to Docker Hub. `burrow templates import` is the same command under its longer
name.

Unlike `docker pull` this is a conversion rather than a download into a local
cache. Import pulls the layers, applies whiteouts, installs the Burrow guest
agent as init (OCI images have no init of their own), records the image's
declared environment in `image.json`, and packs the result into an ext4 rootfs.
What you get is a template on a node, and you create sandboxes from the template.

Docker `ENTRYPOINT` and `CMD` are not run, because the guest agent is PID 1 and
you start processes with `burrow exec`. The image's `ENV` and `WORKDIR` are
applied to exec'd commands, and a request's `--env` and `--workdir` win where
they name the same thing. The exception is a [Sandbox Kit](#sandbox-kits),
whose descriptor asks for the entrypoint to be launched.

### How an import is named

Without `--name`, the template name is the last path segment of the reference
plus its tag:

| Reference | Template |
| --- | --- |
| `python:3.12-slim` | `python-3.12-slim` |
| `python:3.13` | `python-3.13` |
| `ghcr.io/org/toolchain:v1` | `toolchain-v1` |
| `alpine:latest` | `alpine` |
| `alpine` | `alpine` |
| `ghcr.io/org/tool@sha256:...` | `tool` |

A reference with no tag resolves to `:latest` when it is pulled, so `alpine` and
`alpine:latest` are the same image and the same template. `latest` is left out
of the name, because a template called `alpine-latest` says nothing that
`alpine` does not.

The tag is in the name so that two tags of one repository are two templates.
Otherwise `python:3.12-slim` and `python:3.13` would both import as `python`,
and the second would silently replace the first.

A digest reference keeps the bare segment: a name carrying 64 hex characters is
not one anybody would type. Pass `--name` when two digests of one repository
have to coexist.

### Replacing a template in place

Importing over a name that already exists is supported and does the right
thing. The new `rootfs.ext4` is published, the template's warm snapshot is
discarded because it was captured on the rootfs that was just replaced, and the
next create rebuilds it. Sandboxes already running are unaffected: they hold
their own copy.

```sh
burrow pull python:3.13 --name python
```

The delete takes the warm snapshot with it, so creates cold-boot until the node
restarts and warms the template again.

### What the daemon enforces on every pull

Image content is untrusted, so:

- **Digest integrity.** Layers, manifests and the image config are all verified
  against their digests, which is what makes `image@sha256:...` pinning real.
  Layer bodies are checked against the manifest's declared sizes too, and capped
  at 8 GiB compressed.
- **Escape-proof unpack.** Layer entries cannot write or delete outside the
  staging directory. Absolute paths, `..` and symlinked-parent tricks fail the
  import, whiteout handling included.
- **Bounded extraction.** Decompression is budgeted at 32 GiB and 1,000,000
  entries per layer, so a decompression bomb fails instead of filling the node's
  disk.
- **Credential hygiene.** Registry credentials (`--registry-auth`, default
  `/etc/burrow/registry-auth.json`) are only sent to token realms on the
  registry's own host, over HTTPS unless that registry is named in
  `--insecure-registry`. Use that flag for dev harnesses only.

The file `--registry-auth` reads is docker-format, so an existing
`~/.docker/config.json` works unchanged, inline `auths` entries and credential
helpers alike.

### Credential helpers

Most real docker configs do not hold the secret. They name a helper and keep it
in a keychain instead, either globally with `credsStore` or per registry with
`credHelpers`:

```json
{
  "credsStore": "osxkeychain",
  "credHelpers": { "123456789.dkr.ecr.eu-west-1.amazonaws.com": "ecr-login" }
}
```

The node speaks the standard helper protocol: it runs `docker-credential-<name>`
with `get`, writes the registry to its stdin, and reads back
`{"ServerURL":..,"Username":..,"Secret":..}`. Install the helper on the node, on
the `PATH` `burrowd` runs with. Resolution follows docker:
`credHelpers[registry]` wins, then `credsStore`, then an inline `auths` entry for
that registry.

A `Username` of `<token>` means the secret is an OAuth2 identity token rather
than a password, and it is redeemed as a refresh-token grant at the registry's
token service. Registries that answer with a plain `Basic` challenge cannot use
one, and say so rather than sending it as a password.

Some limits, because this runs a binary as root on the node:

- The helper name must be `[A-Za-z0-9_-]+` and is resolved on `PATH`. A config
  cannot name a path, and nothing goes through a shell.
- A helper gets five seconds to answer, and a bounded amount of output.
- A helper that fails, times out or answers with something unrecognisable logs a
  warning and is skipped. The pull continues as if no helper were configured,
  using an inline entry if the file has one and pulling anonymously otherwise. It
  never fails a pull that would have worked without it.
- Secrets are never logged, and a helper's stderr is discarded rather than
  captured, since diagnostics are one careless line away from carrying one.

## Sandbox Kits

A [Docker Sandbox Kit](https://github.com/docker/sandbox-kit-spec) is an OCI
image whose manifest annotation carries a descriptor: what the image needs from
the runtime that composes it. A pull keeps that descriptor beside the rootfs,
so a Kit is a template that knows more about itself. One Kit is the workload;
any number of mixins overlay tools, credentials, network grants and hooks onto
it, and a pull of several composes the set into one template named
`kit-<digest>`, so the same set always produces the same image.

```sh
burrow secret set github --value ghp_...
burrow pull docker/sbx-kit-shell:1.0.0 docker/sbx-kit-gh:2.72.0
burrow create --template kit-0123456789abcdef --arg team=alpha
```

A create from such a template is provisioned the way the descriptors ask,
instead of from flags on the request:

1. **Compose.** The descriptors are expanded with `--arg` values and the
   container environment, then merged under the spec's rules: network policies
   union per phase, lifecycle hooks and files concatenate, volumes and ports
   reconcile on their paths and numbers, resources take the maximum. A
   required capability burrow does not implement refuses the create; an
   optional one is skipped.
2. **Install phase.** The sandbox boots with the install-phase network policy
   and credentials. Declared files are written, then each install hook runs
   in dependency order, seeing only the variables it declared plus the
   platform baseline.
3. **Runtime phase.** The policy is swapped to the runtime one. Startup hooks
   run, then the workload's entrypoint and cmd are launched as the image's
   user, in its working directory, under bash.

`burrow shutdown` followed by `burrow boot` runs startup hooks and the
entrypoint again on the same writable disk, which is what the spec means by a
stop and start. `burrow recreate` replaces the writable disk under the same
id, keeping the sandbox's volumes; with `--template` it moves the sandbox onto
another Kit template, pulled first.

What burrow answers:

| Capability | Behaviour |
|---|---|
| `network-policy@1`, `@2` | Hosts to the allowlist, deny hosts to `deny_domains`, bounded entries to HTTP rules the inspecting proxy enforces with 403. A bounded host is refused outright where it cannot be inspected. |
| `credential@1` | API keys only. The secret stays on the host and is injected as a header; the named variable carries a sentinel. Bind one with `burrow secret set <service>`. |
| `volume@1` | One ext4 volume per sandbox and path, named `kit-<sandbox>-<hash>` and labelled with both. Retained across recreation, including paths no longer declared; deleted with the sandbox. `tmpfs: true` mounts a tmpfs. |
| `lifecycle@1` | Install and startup hooks, files, and the interactive tail. |
| `resources@1` | `cpu` and `memory` raise the sandbox's vcpus and memory. |
| `port@1` | Published after the create, like `--publish`. |
| `long-running@1`, `sbx@1` | Accepted; burrow never auto-stops a sandbox unless asked. |

Everything else (`host-mount@1`, `ssh-agent@1`, `agent-skills@1`,
`git-identity@1`, OAuth credentials, the session verbs) is unclaimed: a Kit
that requires one is refused by name, and an optional one is recorded and
skipped. A Kit that is a mixin on its own cannot compose and imports as a
plain template.

Secrets are held by the orchestrator, encrypted at rest under a key generated
at `<data-dir>/secrets.key` on first use. A node sees a secret only inside the
sandbox record that brokers it, sealed the same way in its own store and
redacted on every read like any injected header.

A create or recreation may decline capability types with
`--reject-capability <type>`, which refuses a Kit requiring one and skips one
asking optionally. `burrow inspect --json` carries the selection records and
the permission surface the sandbox was created with under `selection`.

`deploy/kit-tck/burrow-adapter` drives burrow through the spec's runtime
conformance suite. It builds the suite's fixture Kits with the spec's BuildKit
frontend and pushes them to the dev harness's registry, so it needs
`docker buildx` and the harness up:

```sh
export BURROW_API_KEY=dev-token BURROW=target/debug/burrow
kit-tck runtime --adapter deploy/kit-tck/burrow-adapter
```

## Built templates

`BuildTemplate` boots a base template, runs build steps inside the guest, exports
the result and packs it as a new template. Steps are cached: a layer is keyed by
the base image's rootfs digest plus every command up to it, so an unchanged
prefix is reused and changing a step invalidates only what follows.

Build steps are untrusted, so the export is size-capped at 8 GiB and the
resulting image is sized from its actual contents. The TypeScript SDK exposes
this as `Template.build`; see
[sdk/typescript/README.md](../sdk/typescript/README.md).

## Warm templates

A warm template is one that has been pre-booted and snapshotted. Creates of a
matching shape restore from the snapshot instead of cold-booting, which is
milliseconds instead of seconds. A create asking for a different shape cold-boots
instead, because Firecracker takes a restored VM's cpu and memory from the
snapshot.

Nodes do this for you. A template is warmed at the default shape as soon as it
lands, whether it was imported from an image, built, or pulled from another node,
and the exact shape of any create that found no snapshot to restore from is
warmed too. So the first create of a shape cold-boots and the ones after it
restore.

Measured on the dev harness, creates after the snapshot landed settled at
54 to 79 ms, and with pooling off a warm create is about 45 ms for alpine and
41 ms for python. The first create of a shape is a one-off per template and
shape per node, and it is paid again after a node restart only if the snapshot
is gone.

A template holds **one** warm snapshot, at one shape. Warming a second shape
replaces the first rather than joining it, and each template and shape gets one
warm attempt per daemon lifetime. So a template used at two shapes ends up fast
at whichever was warmed last and cold at the other until the node restarts. Use
one shape per template where creates need to be fast.

Warming runs in the background, so no request waits for it. Builds are serialized
on the node, and a build that fails is logged and not retried.

Nodes advertise their warm templates and the orchestrator prefers them for
placement. See
[ARCHITECTURE.md](ARCHITECTURE.md#snapshots-and-warm-creates).

## Distribution

Templates are per-node. When no node that could take a sandbox holds its
template, the orchestrator picks a target with room and tells it to pull the
template from a node that has it (`PullTemplate`, guarded by the cluster token),
then places there. The transfer is node to node, so a rootfs never crosses the
control plane, and artifacts are verified against their digests before they are
adopted.

Warm snapshots do not travel. They encode host CPU features and the exact
Firecracker version, so the receiving node warms the template itself as soon as
the pull finishes.

## Managing templates

```sh
burrow images
burrow templates rm <name>
```

`burrow images` lists what the fleet holds, with each template's size and whether
a warm snapshot is ready. `burrow templates ls` is the same listing.

The dev harness ships a local registry at `test-registry:5000` for exercising
imports. Its committed credentials are dev-only: never reuse them.
