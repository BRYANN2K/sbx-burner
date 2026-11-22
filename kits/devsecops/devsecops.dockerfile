# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_SCANNER_VERSION=2.7.1
ARG SYFT_VERSION=1.57.2
ARG GRYPE_VERSION=0.122.1
ARG COSIGN_VERSION=3.1.4
ARG TRIVY_VERSION=0.76.2
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
WORKDIR /dl
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# fetch <base-url> <asset> <checksums-asset>: download and verify one asset.
RUN cat > /usr/local/bin/fetch <<'EOF' && chmod +x /usr/local/bin/fetch
#!/bin/bash
set -euo pipefail
curl -fsSLO "$1/$2"
curl -fsSL -o "sums-$2" "$1/$3"
grep -E "[ *]$2\$" "sums-$2" | sha256sum -c -
EOF

RUN mkdir -p /out/usr/local/bin \
 && case "$TARGETARCH" in amd64) g=x64; t=64bit ;; arm64) g=arm64; t=ARM64 ;; *) echo "unsupported: $TARGETARCH" >&2; exit 1 ;; esac \
 && fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}" \
      "gitleaks_${GITLEAKS_VERSION}_linux_${g}.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
 && tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_${g}.tar.gz" -C /out/usr/local/bin gitleaks \
 && fetch "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}" \
      "osv-scanner_linux_${TARGETARCH}" "osv-scanner_SHA256SUMS" \
 && install -m 0755 "osv-scanner_linux_${TARGETARCH}" /out/usr/local/bin/osv-scanner \
 && fetch "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
      "syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" \
 && tar -xzf "syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" -C /out/usr/local/bin syft \
 && fetch "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}" \
      "grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" "grype_${GRYPE_VERSION}_checksums.txt" \
 && tar -xzf "grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" -C /out/usr/local/bin grype \
 && fetch "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}" \
      "cosign-linux-${TARGETARCH}" "cosign_checksums.txt" \
 && install -m 0755 "cosign-linux-${TARGETARCH}" /out/usr/local/bin/cosign \
 && fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" \
 && tar -xzf "trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz" -C /out/usr/local/bin trivy \
 && chown -R 0:0 /out && chmod 0755 /out/usr/local/bin/*

FROM scratch
COPY --from=build /out/ /
