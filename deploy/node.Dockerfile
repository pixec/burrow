# The burrow node image: firecracker + jailer + the tooling burrowd shells out
# to. Not specific to any orchestrator -- the compose harness and the k8s
# manifests both build from this file, as two stages of it.
#
#   dev      binaries bind-mounted from target/ (deploy/dev/compose.yaml)
#   release  binaries baked in from dist/<arch>/ (.github/workflows/release.yml)
#
# The two stages exist so the toolchain is defined once. A dev image that
# installs a different firecracker than the published one is a class of bug
# that only shows up in production.
#
# Build from the repository root:
#
#   docker buildx build --target release -f deploy/node.Dockerfile -t burrow-node .

FROM debian:bookworm-slim AS base

ARG FIRECRACKER_VERSION=v1.16.1
# Set by BuildKit as amd64/arm64. Empty on the legacy builder, which is what
# FC_ARCH is for.
ARG TARGETARCH
# Firecracker names its releases by uname arch (x86_64, aarch64), which is not
# what Docker calls the same machine. Normally derived from TARGETARCH; set it
# explicitly to build without BuildKit.
ARG FC_ARCH=""

# e2fsprogs builds the ext4 images that OCI imports and volumes are made of
# without mounting them (mkfs.ext4 -d).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 nftables e2fsprogs \
        wireguard-tools && \
    rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    arch="$FC_ARCH"; \
    if [ -z "$arch" ]; then \
        case "$TARGETARCH" in \
            amd64) arch=x86_64 ;; \
            arm64) arch=aarch64 ;; \
            "") echo "neither FC_ARCH nor TARGETARCH is set: build with buildx," >&2; \
                echo "or pass --build-arg FC_ARCH=x86_64|aarch64." >&2; exit 1 ;; \
            *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
        esac; \
    fi; \
    curl -fsSL \
        "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${arch}.tgz" \
        | tar -xz -C /tmp; \
    mv "/tmp/release-${FIRECRACKER_VERSION}-${arch}/firecracker-${FIRECRACKER_VERSION}-${arch}" /usr/local/bin/firecracker; \
    mv "/tmp/release-${FIRECRACKER_VERSION}-${arch}/jailer-${FIRECRACKER_VERSION}-${arch}" /usr/local/bin/jailer; \
    rm -rf "/tmp/release-${FIRECRACKER_VERSION}-${arch}"; \
    firecracker --version

# Dev harness: burrowd, burrow-agent and the rootfs builder are bind-mounted
# from the host build, so a rebuild is zigbuild + restart with no image work.
FROM base AS dev
CMD ["/burrow/bin/burrowd"]

# Published image: a cluster cannot bind-mount target/, so the binaries come
# from dist/<arch>/, staged by the release workflow.
FROM base AS release
ARG TARGETARCH
COPY dist/${TARGETARCH}/burrowd /burrow/bin/burrowd
COPY dist/${TARGETARCH}/burrow-agent /burrow/bin/burrow-agent
ENTRYPOINT ["/burrow/bin/burrowd"]
