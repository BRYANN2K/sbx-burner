# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG CURSOR_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
# Release tarballs are pinned per platform; SHA-256s are from the built-in
# kit's generated dockerfile (sbx 0.54, release 2026.11.22-e9042b2).
RUN case "$TARGETARCH" in \
      amd64) arch=x64; sum=7663b1c5d1b56e095ef8e23bef38d66df6cfd665c4873470214e0e411f0f97b3 ;; \
      arm64) arch=arm64; sum=7b7dd0020fb9a2a9e1e7e3f39e2f9f512d1dd9577174ecda8aa82ac31dbc9565 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://downloads.cursor.com/lab/${CURSOR_VERSION}/linux/${arch}/agent-cli-package.tar.gz" -o /tmp/cursor.tar.gz \
    && echo "${sum}  /tmp/cursor.tar.gz" | sha256sum -c - \
    && dir=/out/opt/cursor/versions/${CURSOR_VERSION} \
    && mkdir -p "$dir" /out/home/agent/.local/bin \
    && tar --strip-components=1 -xzf /tmp/cursor.tar.gz -C "$dir" \
    && "$dir/cursor-agent" --version | grep -Fw "$CURSOR_VERSION" \
    && ln -s /opt/cursor/versions/${CURSOR_VERSION}/cursor-agent /out/home/agent/.local/bin/cursor-agent \
    && chown -R 1000:1000 /out/home/agent

FROM scratch
COPY --from=build /out/ /
# The built-in sandbox exports the OAuth access-token sentinel on this name;
# the proxy swaps it on requests to api2.cursor.sh once a binding exists.
ENV CURSOR_AUTH_TOKEN=cursor-oat-proxy-managed
