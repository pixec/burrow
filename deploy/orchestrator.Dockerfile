# The burrow orchestrator image. Not specific to any orchestrator platform.
#
# There is no dev stage here: the compose harness runs the orchestrator from a
# stock debian image with the binary bind-mounted, so it needs nothing built.
#
# Build from the repository root:
#
#   docker buildx build -f deploy/orchestrator.Dockerfile -t burrow-orchestrator .

# Pinned by digest, not by tag: `bookworm-slim` is republished, so the same
# build a month later would otherwise produce a different image. This is the
# multi-arch manifest list, so it still resolves per platform for the
# amd64/arm64 pair the release workflow builds.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# BuildKit sets TARGETARCH; the legacy builder leaves it empty, which would
# otherwise fail below as a puzzling `stat dist//burrow-orchestrator`.
RUN test -n "$TARGETARCH" || { \
        echo "TARGETARCH is empty: build with buildx (docker buildx build ...)," >&2; \
        echo "or pass --build-arg TARGETARCH=amd64|arm64 explicitly." >&2; \
        exit 1; \
    }

COPY dist/${TARGETARCH}/burrow-orchestrator /usr/local/bin/burrow-orchestrator

# The orchestrator is a gRPC server with a data directory and needs nothing root
# gives it. 65532 is the conventional "nonroot" uid, and what
# deploy/k8s/10-orchestrator.yaml pins runAsUser to: that manifest sets
# runAsNonRoot, which admission refuses unless the image agrees.
RUN useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/burrow-orchestrator"]
