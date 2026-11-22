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
 && chown -R 0:0 /out \
 # Codex config and placeholder auth.json, as in sbx's built-in codex agent: requests go to the
 # ChatGPT backend with the proxy's OAuth sentinel, which the sbx proxy
 # swaps for the stored token. Without ~/.codex the CLI exits at start
 # ("CODEX_HOME ... does not exist") on custom workloads like base-kali.
 # TODO(verify): API-key users (sbx secret set openai without --oauth).
 && mkdir -p /out/home/agent/.codex \
 && printf '%s\n' \
      'approval_policy = "never"' \
      'sandbox_mode = "danger-full-access"' \
      'forced_login_method = "api"' \
      'model_provider = "sandboxd"' \
      '' \
      '[model_providers.sandboxd]' \
      'name = "Sandbox Proxy"' \
      'base_url = "https://chatgpt.com/backend-api/codex"' \
      'experimental_bearer_token = "oai-oat01-proxy-managed"' \
      'requires_openai_auth = false' \
      > /out/home/agent/.codex/config.toml \
 && printf '{\n  "OPENAI_API_KEY": "proxy-managed"\n}\n' > /out/home/agent/.codex/auth.json \
 && chmod 0755 /out/home /out/home/agent /out/home/agent/.codex \
 && chown -R 1000:1000 /out/home/agent

FROM scratch
COPY --from=build /out /
ENV CODEX_HOME=/home/agent/.codex
