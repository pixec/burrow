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

# Pinned by digest, not by tag: `bookworm-slim` is republished, so the same
# build a month later would otherwise produce a different image. This is the
# multi-arch manifest list, so it still resolves per platform for the
# amd64/arm64 pair the release workflow builds.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS base

ARG FIRECRACKER_VERSION=v1.16.1
# Set by BuildKit as amd64/arm64. Empty on the legacy builder, which is what
# FC_ARCH is for.
ARG TARGETARCH
# Firecracker names its releases by uname arch (x86_64, aarch64), which is not
# what Docker calls the same machine. Normally derived from TARGETARCH; set it
# explicitly to build without BuildKit.
ARG FC_ARCH=""

# Published checksums, from the release's own
# firecracker-<version>-<arch>.tgz.sha256.txt. This is the hypervisor every
# sandbox on the machine runs under, fetched over the network at build time.
# Bump both together with FIRECRACKER_VERSION.
ARG FC_SHA256_X86_64=382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6
ARG FC_SHA256_AARCH64=8d0e69f6d6f9a1724551f607f18504052c16c1828ee3d4d7b6e6c73380871e0e

# e2fsprogs builds the ext4 images that OCI imports and volumes are made of
# without mounting them (mkfs.ext4 -d).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 nftables e2fsprogs \
        wireguard-tools conntrack && \
    rm -rf /var/lib/apt/lists/*

# The tarball is downloaded to a file rather than piped into tar: a pipe
# extracts as it reads, so a tampered archive would already be unpacked by the
# time any digest could be checked.
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
    case "$arch" in \
        x86_64) want="$FC_SHA256_X86_64" ;; \
        aarch64) want="$FC_SHA256_AARCH64" ;; \
    esac; \
    curl -fsSL -o /tmp/firecracker.tgz \
        "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${arch}.tgz"; \
    echo "${want}  /tmp/firecracker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/firecracker.tgz -C /tmp; \
    rm -f /tmp/firecracker.tgz; \
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
