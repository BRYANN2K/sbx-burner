# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG DEVIN_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
# Release tarballs are pinned per platform; SHA-256s are from the built-in
# kit's generated dockerfile (sbx 0.54, release 3000.14.30821).
RUN case "$TARGETARCH" in \
      amd64) arch=x86_64; sum=4dc43e3e4388bace60fe2aa8010cbb399402e724892d7175845b1cdef00e7ddb ;; \
      arm64) arch=aarch64; sum=3deb8af6b026060e975ed371936e139818020e5dc5abbcba07cde039f473a5a5 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://static.devin.ai/cli/${DEVIN_VERSION}/devin-${DEVIN_VERSION}-${arch}-unknown-linux.tar.gz" -o /tmp/devin.tar.gz \
    && echo "${sum}  /tmp/devin.tar.gz" | sha256sum -c - \
    && version_dir="/out/home/agent/.local/share/devin/cli/_versions/${DEVIN_VERSION}" \
    && mkdir -p "$version_dir" /out/home/agent/.local/bin \
    && tar -xzf /tmp/devin.tar.gz -C "$version_dir" \
    && "$version_dir/bin/devin" --version | grep -Fw "$DEVIN_VERSION" \
    && printf 'curl-bash\n' > "$version_dir/distribution" \
    && ln -s "$DEVIN_VERSION" /out/home/agent/.local/share/devin/cli/_versions/current \
    && ln -s /home/agent/.local/share/devin/cli/_versions/current/bin/devin /out/home/agent/.local/bin/devin-cli \
    && ln -s devin-cli /out/home/agent/.local/bin/devin \
    && chown -R 1000:1000 /out/home/agent

FROM scratch
COPY --from=build /out/ /
