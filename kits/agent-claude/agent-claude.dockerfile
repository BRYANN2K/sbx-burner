# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG CLAUDE_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates jq
# The release manifest lists a SHA-256 per platform; the binary is checked
# against it before it is copied into the kit.
# manifest.json and `.platforms[<platform>].checksum` checked on release
# 2.1.323. TODO(verify): the kit itself is not built yet.
RUN case "$TARGETARCH" in \
      amd64) platform=linux-x64 ;; \
      arm64) platform=linux-arm64 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && release="https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}" \
    && mkdir -p /tmp/claude /out/usr/local/bin \
    && cd /tmp/claude \
    && curl -fsSL "${release}/manifest.json" -o manifest.json \
    && curl -fsSL "${release}/${platform}/claude" -o claude \
    && sum="$(jq -er --arg p "$platform" '.platforms[$p].checksum' manifest.json)" \
    && printf '%s  claude\n' "$sum" | sha256sum -c - \
    && install -m 0755 claude /out/usr/local/bin/claude \
    # The ACP adapter is pointed at /home/agent/.local/bin/claude, the path
    # the built-in claude agent's native installer uses. Ship that path as a
    # symlink so every workload resolves the same CLAUDE_CODE_EXECUTABLE.
    && mkdir -p /out/home/agent/.local/bin \
    && ln -s /usr/local/bin/claude /out/home/agent/.local/bin/claude \
    && chown -R 1000:1000 /out/home/agent

FROM scratch
COPY --from=build /out/ /
ENV CLAUDE_CONFIG_DIR=/home/agent/.claude
