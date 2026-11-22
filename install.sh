#!/bin/sh
# Install burner from a signed GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/BRYANN2K/sbx-burner/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.3.0 --dir "$HOME/bin"
#
# Downloads the release archive and checksums.txt, checks the keyless cosign
# signature of checksums.txt (same signer as `burner update --install`), then
# the archive's sha256, and moves the binary into place. Nothing is run as
# root and nothing else is installed.
set -eu

die() {
  printf 'burner install: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: install.sh [--version vX.Y.Z] [--dir DIR] [--no-cosign]\n'
}

# The whole script runs from main, called on the last line: a truncated
# download defines nothing and runs nothing.
main() {
  repo="BRYANN2K/sbx-burner"
  api="${BURNER_INSTALL_API:-https://api.github.com/repos/$repo/releases}"
  base="${BURNER_INSTALL_BASE:-https://github.com/$repo/releases/download}"
  identity='^https://github\.com/BRYANN2K/sbx-burner/\.github/workflows/release\.yml@refs/tags/v'
  issuer="https://token.actions.githubusercontent.com"

  version=""
  dir="$HOME/.local/bin"
  cosign=1

  while [ $# -gt 0 ]; do
    case "$1" in
      --version)
        [ $# -ge 2 ] || die "--version needs a value"
        version="$2"
        shift 2
        ;;
      --version=*)
        version="${1#--version=}"
        shift
        ;;
      --dir)
        [ $# -ge 2 ] || die "--dir needs a value"
        dir="$2"
        shift 2
        ;;
      --dir=*)
        dir="${1#--dir=}"
        shift
        ;;
      --no-cosign)
        cosign=0
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "unknown option: $1"
        ;;
    esac
  done

  [ -n "$dir" ] || die "--dir is empty"

  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) die "unsupported OS: $(uname -s) (darwin and linux only)" ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) arch=arm64 ;;
    x86_64 | amd64) arch=amd64 ;;
    *) die "unsupported architecture: $(uname -m) (arm64 and amd64 only)" ;;
  esac

  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v tar >/dev/null 2>&1 || die "tar is required"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
  elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
  else
    die "sha256sum or shasum is required"
  fi
  if [ "$cosign" -eq 1 ] && ! command -v cosign >/dev/null 2>&1; then
    die "install cosign (brew install cosign) or rerun with --no-cosign"
  fi

  # file:// only for the test hook (BURNER_INSTALL_API / BURNER_INSTALL_BASE).
  proto='=https'
  if [ -n "${BURNER_INSTALL_API:-}" ] || [ -n "${BURNER_INSTALL_BASE:-}" ]; then
    proto='=https,file'
  fi
  fetch() {
    curl -fsSL --proto "$proto" --proto-redir '=https' --retry 2 -o "$2" "$1" || die "download failed: $1"
  }

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM

  if [ -z "$version" ]; then
    fetch "$api/latest" "$tmp/latest.json"
    version="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)"
    [ -n "$version" ] || die "no release tag in $api/latest"
  fi
  printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "not a release tag: $version"

  asset="burner_${version#v}_${os}_${arch}.tar.gz"
  url="$base/$version"
  fetch "$url/$asset" "$tmp/$asset"
  fetch "$url/checksums.txt" "$tmp/checksums.txt"

  if [ "$cosign" -eq 1 ]; then
    fetch "$url/checksums.txt.sig" "$tmp/checksums.txt.sig"
    fetch "$url/checksums.txt.pem" "$tmp/checksums.txt.pem"
    cosign verify-blob \
      --certificate "$tmp/checksums.txt.pem" \
      --signature "$tmp/checksums.txt.sig" \
      --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer" \
      "$tmp/checksums.txt" >/dev/null 2>&1 || die "signature check failed for checksums.txt"
    printf 'signature  ok (%s)\n' "$version"
  else
    printf 'warning: --no-cosign: the signature of checksums.txt is not checked; the sha256 still is\n' >&2
  fi

  want="$(awk -v f="$asset" '$2 == f {print $1}' "$tmp/checksums.txt" | head -n 1)"
  [ -n "$want" ] || die "$asset is not listed in checksums.txt"
  got="$(sha256 "$tmp/$asset")"
  [ "$got" = "$want" ] || die "checksum mismatch for $asset"
  printf 'sha256     ok (%s)\n' "$asset"

  mkdir -p "$tmp/x"
  tar -xzf "$tmp/$asset" -C "$tmp/x" burner || die "$asset has no burner binary"
  if [ ! -f "$tmp/x/burner" ] || [ -L "$tmp/x/burner" ]; then
    die "$asset has no burner binary"
  fi

  mkdir -p "$dir" || die "cannot create $dir"
  new="$(mktemp "$dir/.burner-new.XXXXXX")" || die "cannot write to $dir"
  cp "$tmp/x/burner" "$new" || {
    rm -f "$new"
    die "cannot write to $dir"
  }
  chmod 0755 "$new"
  mv -f "$new" "$dir/burner" || {
    rm -f "$new"
    die "cannot write $dir/burner"
  }
  printf 'installed  %s\n' "$dir/burner"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *) printf 'PATH       %s is not on PATH: export PATH="%s:%sPATH"\n' "$dir" "$dir" '$' ;;
  esac

  if command -v python3 >/dev/null 2>&1; then
    pv="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      printf 'python3    ok (%s)\n' "$pv"
    else
      printf 'python3    %s: the engine needs 3.11 or newer\n' "${pv:-unknown}"
    fi
  else
    printf 'python3    missing: the engine needs 3.11 or newer\n'
  fi
  if command -v git >/dev/null 2>&1; then
    printf 'git        ok\n'
  else
    printf 'git        missing\n'
  fi
  if command -v sbx >/dev/null 2>&1; then
    printf 'sbx        ok\n'
  else
    printf 'sbx        missing: install Docker Sandboxes\n'
  fi

  printf 'run: burner setup\n'
}

main "$@"
