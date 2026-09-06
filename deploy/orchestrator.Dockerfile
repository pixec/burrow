# The burrow orchestrator image. Not specific to any orchestrator platform.
#
# There is no dev stage here: the compose harness runs the orchestrator from a
# stock debian image with the binary bind-mounted, so it needs nothing built.
#
# Build from the repository root:
#
#   docker buildx build -f deploy/orchestrator.Dockerfile -t burrow-orchestrator .
FROM debian:bookworm-slim

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

ENTRYPOINT ["/usr/local/bin/burrow-orchestrator"]
