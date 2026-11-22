# Install burner

burner is one binary for macOS and Linux, on arm64 and amd64. Every release
ships `checksums.txt`, signed keyless with cosign by the release workflow.

## Script

```sh
curl -fsSL https://raw.githubusercontent.com/BRYANN2K/sbx-burner/main/install.sh | sh
```

A pinned version, in another folder:

```sh
curl -fsSL https://raw.githubusercontent.com/BRYANN2K/sbx-burner/main/install.sh | sh -s -- --version v0.3.0 --dir "$HOME/bin"
```

The script:

1. Detects the OS and architecture. Other platforms are refused.
2. Resolves the latest release through the GitHub API, or takes `--version`.
3. Downloads the archive, `checksums.txt` and its signature into a temporary folder, removed on exit.
4. Verifies the cosign signature of `checksums.txt`. The signer must be `.github/workflows/release.yml` of BRYANN2K/sbx-burner on a `v` tag, the same identity `burner update --install` checks. Without cosign it stops. `--no-cosign` skips this step with a warning: the sha256 then proves the download matches `checksums.txt` (integrity), not that the release came from the release workflow (authenticity).
5. Verifies the archive's sha256 against `checksums.txt`. This step is never skipped.
6. Moves `burner` into `~/.local/bin` (or `--dir`), mode 0755. No sudo.
7. Reports python3 (3.11 or newer, for the engine), git and sbx. It never installs them.

Then run `burner setup`.

| Flag | Default |
| --- | --- |
| `--version vX.Y.Z` | the latest release |
| `--dir DIR` | `~/.local/bin` |
| `--no-cosign` | off: the signature is required; with it, integrity only, not authenticity |

## Homebrew

Planned: a `BRYANN2K/tap` tap with `brew install BRYANN2K/tap/burner`. It does not exist yet.

## Manual download

Download `burner_<version>_<os>_<arch>.tar.gz`, `checksums.txt`, `checksums.txt.sig` and `checksums.txt.pem` from the [releases page](https://github.com/BRYANN2K/sbx-burner/releases), then:

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/BRYANN2K/sbx-burner/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar -xzf burner_<version>_<os>_<arch>.tar.gz burner
install -m 0755 burner ~/.local/bin/burner
```

## Update

- `burner update` fast-forwards the recipe catalogs and checks for a newer release.
- `burner update --install` downloads the new release, verifies the cosign signature of `checksums.txt` and then the sha256, and replaces the running binary atomically, in place. A binary installed by the script or by hand updates this way.
- A Homebrew install gets `brew upgrade burner` instead.
- In the menu, Home and Doctor show `burner X available: u to update` when a newer release exists; `u` runs `burner update --install`.
- `BURNER_NO_UPDATE_CHECK=1` turns the release check off.
