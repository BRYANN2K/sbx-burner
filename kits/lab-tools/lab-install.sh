#!/usr/bin/env bash
# Shared helpers for recipe tool installers (tools/install.sh).
# The runner copies this file next to the recipe's tools as
# .lab/tools/lab-install.sh. Source it; do not execute it.
#
# Rules for installers:
#   - pin every version;
#   - verify downloads against the upstream checksum file;
#   - never pipe a download into a shell;
#   - GPL/AGPL tools are installed here at run time, never vendored.

LAB_BIN_DIR="${LAB_BIN_DIR:-/usr/local/bin}"
LAB_TOOLS_MANIFEST="${LAB_TOOLS_MANIFEST:-${PWD}/.lab/tools-installed.tsv}"

lab_log() { printf '[lab-install] %s\n' "$*" >&2; }

lab_die() {
  lab_log "error: $*"
  exit 1
}

# lab_arch amd64-name arm64-name → prints the name for this machine.
lab_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf '%s' "$1" ;;
    aarch64 | arm64) printf '%s' "$2" ;;
    *) lab_die "unsupported architecture: $(uname -m)" ;;
  esac
}

lab_sudo() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

lab_download() { # url dest
  curl --fail --silent --show-error --location --retry 3 --output "$2" "$1" \
    || lab_die "download failed: $1 (is the host in the recipe's run.network.install_allow?)"
}

# lab_verify file checksums-file: the checksum file must list the file's
# basename with its SHA-256.
lab_verify() {
  local file="$1" sums="$2" name expected actual
  name="$(basename "$file")"
  expected="$(awk -v n="$name" '{f=$2; sub(/^\*/, "", f); sub(/^.*\//, "", f); if (f == n) {print $1; exit}}' "$sums")"
  [ -n "$expected" ] || lab_die "no checksum for $name in $(basename "$sums")"
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || lab_die "checksum mismatch for $name"
  lab_log "verified $name"
}

lab_record() { # name version licence
  mkdir -p "$(dirname "$LAB_TOOLS_MANIFEST")"
  printf '%s\t%s\t%s\n' "$1" "$2" "${3:-unknown}" >>"$LAB_TOOLS_MANIFEST"
}

# lab_gh_release repo tag asset checksums-asset binary [licence]
# Downloads a GitHub release asset, verifies it, and installs one binary.
# The asset may be a raw binary, a .tar.gz or a .zip.
lab_gh_release() {
  local repo="$1" tag="$2" asset="$3" sums="$4" bin="$5" licence="${6:-unknown}"
  local base="https://github.com/${repo}/releases/download/${tag}" tmp found
  if command -v "$bin" >/dev/null 2>&1 && [ -z "${LAB_FORCE_INSTALL:-}" ]; then
    lab_log "$bin already present, skipping"
    return 0
  fi
  tmp="$(mktemp -d)"
  lab_download "${base}/${asset}" "${tmp}/${asset}"
  lab_download "${base}/${sums}" "${tmp}/${sums}"
  lab_verify "${tmp}/${asset}" "${tmp}/${sums}"
  case "$asset" in
    *.tar.gz | *.tgz) tar -xzf "${tmp}/${asset}" -C "$tmp" ;;
    *.zip) unzip -q -o "${tmp}/${asset}" -d "$tmp" ;;
    *) cp "${tmp}/${asset}" "${tmp}/${bin}" ;;
  esac
  found="$(find "$tmp" -type f -name "$bin" | head -n 1)"
  [ -n "$found" ] || lab_die "binary $bin not found in $asset"
  lab_sudo install -m 0755 "$found" "${LAB_BIN_DIR}/${bin}"
  rm -rf "$tmp"
  lab_record "$bin" "$tag" "$licence"
  lab_log "installed $bin $tag"
}

lab_apt() {
  lab_sudo env DEBIAN_FRONTEND=noninteractive apt-get update -qq
  lab_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
  local pkg
  for pkg in "$@"; do lab_record "$pkg" "apt" "distro"; done
}

# lab_pipx package==version binary [licence]: isolated Python tool install.
lab_pipx() {
  local spec="$1" bin="$2" licence="${3:-unknown}"
  if command -v "$bin" >/dev/null 2>&1 && [ -z "${LAB_FORCE_INSTALL:-}" ]; then
    lab_log "$bin already present, skipping"
    return 0
  fi
  case "$spec" in *==*) ;; *) lab_die "pin the version: $spec" ;; esac
  command -v pipx >/dev/null 2>&1 || lab_apt pipx
  PIPX_HOME=/opt/pipx PIPX_BIN_DIR="$LAB_BIN_DIR" lab_sudo env PIPX_HOME=/opt/pipx PIPX_BIN_DIR="$LAB_BIN_DIR" pipx install "$spec"
  lab_record "$bin" "${spec##*==}" "$licence"
}
