---
name: sbom-sign
category: devsecops
summary: Build CycloneDX and SPDX SBOMs of a project with syft, sign the CycloneDX document with a throwaway cosign key pair, and verify the signature offline.
risk: low
time: 15m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/anchore/syft
  - https://github.com/sigstore/cosign
---

# sbom-sign

The agent produces a software bill of materials for a project (CycloneDX and
SPDX JSON), signs the CycloneDX document with a cosign key pair generated
inside the sandbox for this run only, and verifies the signature. Everything
happens offline: no transparency log, no timestamp authority, no KMS.

## When to use it

- To check that an SBOM builds for a repository before wiring it into CI.
- To rehearse an SBOM + signature step without touching real signing keys.
- As the provenance half of `devsecops/container-scan` (scan what you ship,
  attest what you scanned).

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-sbom-sign/`.
- The two SBOMs, the signature bundle, the public key, the verification log
  and the SHA-256 digests of the SBOMs, the bundle and the public key.
- `metrics.components` (SBOM size) and `metrics.signature_verified` (the
  one boolean this run exists to prove).

## Run

```console
$ python -m lab run devsecops/sbom-sign --target ./my-project --dry-run
$ python -m lab run devsecops/sbom-sign --target ./my-project
$ python -m lab run devsecops/sbom-sign --target-repo owner/repo@v1.2.0
$ python -m lab run devsecops/sbom-sign --target-image myorg/app:1.4
$ python -m lab run devsecops/sbom-sign --target-image ./app-image.tar
```

A path or repo is mounted read-only at `/home/agent/target` (a repo is
cloned on the host with your own git login, private repos included). An
image is resolved on the host (local Docker first, then a pull with your
docker login, or a `docker save` tarball) and loaded in the sandbox; syft
builds an image SBOM from it. Credentials never enter the sandbox. No scope
file is needed: the recipe contacts no target host.

To try it on a planted project:

```console
$ bash recipes/devsecops/sbom-sign/evals/make-target.sh /tmp/sbom-demo
$ python -m lab run devsecops/sbom-sign --target /tmp/sbom-demo
$ python -m lab eval devsecops/sbom-sign --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/sbom.cdx.json` | CycloneDX JSON SBOM from syft |
| `artifacts/sbom.spdx.json` | The same project as SPDX JSON |
| `artifacts/sbom.cdx.json.sig` | Sigstore v0.3 bundle: digest + signature + key hint |
| `artifacts/cosign.pub` | Public half of the throwaway key pair |
| `artifacts/signing-config.json` | The cosign signing config, with no Rekor/Fulcio/OIDC/TSA service |
| `artifacts/verify.txt` | `cosign verify-blob` output, `Verified OK` expected |
| `artifacts/digests.txt` | `sha256sum` of the SBOMs, the bundle and the public key |

## Safety

- The private key is generated in `/tmp` inside the microVM, is destroyed
  with the sandbox, and is never written to `evidence/` or sent anywhere.
- Signing is deliberately offline: the signing config lists no Rekor,
  Fulcio, OIDC or TSA endpoint, so `sign-blob` cannot upload the digest to a
  public transparency log.
- An ephemeral key proves integrity *of this run only*. It does not prove
  who produced the SBOM. The real setup is keyless signing in CI (Fulcio +
  Rekor + an OIDC identity); this recipe exists to rehearse the mechanics,
  not to replace that.

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| syft 1.57.2 | Apache-2.0 | Baked into `kits/devsecops`, or installed by `tools/install.sh` |
| cosign 3.1.4 | Apache-2.0 | Same |
