# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG CODEX_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && release="https://github.com/openai/codex/releases/download/rust-v${CODEX_VERSION}" \
 && asset="codex-package-${target}.tar.gz" \
 && mkdir -p /tmp/codex /out/opt/codex /out/usr/local/bin \
 && cd /tmp/codex \
 && curl -fsSLO "${release}/${asset}" \
 && curl -fsSLO "${release}/codex-package_SHA256SUMS" \
 && grep "  ${asset}\$" codex-package_SHA256SUMS | sha256sum -c - \
 && tar -xzf "${asset}" -C /out/opt/codex \
 && ln -s /opt/codex/bin/codex /out/usr/local/bin/codex \
 && chown -R 0:0 /out

FROM scratch
COPY --from=build /out /
ENV CODEX_HOME=/home/agent/.codex
