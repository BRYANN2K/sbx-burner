# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG OPENCODE_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates grep
# GitHub release tarballs carry a SHA256SUMS per platform, verified here like
# the built-in kit does (release v2.3.2, anomalyco/opencode).
RUN case "$TARGETARCH" in \
      amd64) arch=x64-baseline ;; \
      arm64) arch=arm64 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && echo "$arch" > /tmp/arch \
    && base="https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}" \
    && curl -fsSL "${base}/opencode-linux-${arch}.tar.gz" -o "/tmp/opencode-linux-${arch}.tar.gz" \
    && curl -fsSL "${base}/SHA256SUMS" -o /tmp/SHA256SUMS \
    && (cd /tmp && grep "opencode-linux-${arch}.tar.gz$" SHA256SUMS | sha256sum -c -)
RUN mkdir -p /out/usr/local/bin /tmp/oc \
    && tar -xzf "/tmp/opencode-linux-$(cat /tmp/arch).tar.gz" -C /tmp/oc opencode \
    && install -m 0755 /tmp/oc/opencode /out/usr/local/bin/opencode \
    && /out/usr/local/bin/opencode --version | grep -Fx "opencode v${OPENCODE_VERSION}"

FROM scratch
COPY --from=build /out/ /
ENV OPENCODE_DISABLE_AUTOUPDATE=1
ENV OPENCODE_CONFIG_CONTENT={"permission":{"*":"allow"}}
