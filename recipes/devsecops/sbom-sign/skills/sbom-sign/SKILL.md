---
name: sbom-sign
description: Produce CycloneDX and SPDX SBOMs with syft, sign the CycloneDX blob offline with a throwaway cosign key pair, and verify the signature. Use when asked to generate or sign an SBOM, attest build components, or demo supply-chain signing without a KMS.
---

# SBOM and offline signature

## 1. Build the SBOMs

```bash
A="$PWD/evidence/artifacts"
mkdir -p "$A"

# path or repo: the read-only directory. image: the image the runner loaded
# into the sandbox Docker engine (a tarball's reference is saved in
# .lab/target-image-ref).
if [ "$LAB_TARGET_KIND" = image ]; then
  IMG="$LAB_TARGET_IMAGE"
  if [ "${IMG#tarball:}" != "$IMG" ]; then IMG="$(cat .lab/target-image-ref)"; fi
  SRC="docker:$IMG"
else
  SRC="dir:$LAB_TARGET_PATH"
fi

syft scan "$SRC" -q \
  -o cyclonedx-json="$A/sbom.cdx.json" \
  -o spdx-json="$A/sbom.spdx.json"
echo "syft exit: $?"

jq '.components | length' "$A/sbom.cdx.json"   # -> metrics.components
```

syft reads manifests, lockfiles and image package databases only; it
downloads nothing (`docker:` reads the local engine, never a registry). If a
`path` target holds an image tarball instead of a source tree, use
`syft scan docker-archive:/home/agent/target/image.tar` (or `oci-archive:`
for an OCI tar) with the same `-o` outputs.

## 2. Make an offline signing config

cosign v3 signs through a *signing config* that lists the services it may
contact. Build one with every service empty so nothing leaves the sandbox:

```bash
cosign signing-config create \
  --no-default-rekor --no-default-fulcio --no-default-oidc --no-default-tsa \
  --out "$A/signing-config.json"
```

## 3. Generate a throwaway key pair

```bash
k="$(mktemp -d)"
COSIGN_PASSWORD= cosign generate-key-pair --output-key-prefix "$k/cosign"
# $k/cosign.key = private key, stays in /tmp. $k/cosign.pub = public key.
cp "$k/cosign.pub" "$A/cosign.pub"
```

`COSIGN_PASSWORD=` sets an empty password: acceptable only because the key
lives for this run and never leaves the microVM. Never reuse a real key.

## 4. Sign the CycloneDX SBOM

```bash
COSIGN_PASSWORD= cosign sign-blob \
  --key "$k/cosign.key" \
  --signing-config "$A/signing-config.json" \
  --bundle "$A/sbom.cdx.json.sig" \
  "$A/sbom.cdx.json"
echo "sign exit: $?"
```

With the empty signing config there is no transparency-log prompt and no
upload. The bundle file *is* the signature material (v0.3 sigstore bundle:
digest + signature + the public-key hint).

## 5. Verify, and prove the check is real

```bash
cosign verify-blob \
  --bundle "$A/sbom.cdx.json.sig" \
  --key "$A/cosign.pub" \
  --insecure-ignore-tlog \
  "$A/sbom.cdx.json" > "$A/verify.txt" 2>&1
echo "verify exit: $?"          # 0 = Verified OK (printed on stderr)
grep -c "Verified OK" "$A/verify.txt"
```

`--insecure-ignore-tlog` is required: the bundle has no Rekor entry, so
cosign would otherwise fail with "not enough verified log entries". The flag
is safe here only because the signature was created in this same run; for
third-party signatures insist on tlog inclusion.

Optional self-check that the verification is not vacuous:

```bash
cp "$A/sbom.cdx.json" /tmp/tampered.json && echo '{}' >> /tmp/tampered.json
cosign verify-blob --bundle "$A/sbom.cdx.json.sig" --key "$A/cosign.pub" \
  --insecure-ignore-tlog /tmp/tampered.json   # must FAIL (exit != 0)
```

## 6. Record digests

```bash
(cd "$A" && sha256sum sbom.cdx.json sbom.spdx.json sbom.cdx.json.sig cosign.pub) \
  > "$A/digests.txt"
```

## Report

- `signature_verified` is `true` only when step 5 exit code is 0 and
  `verify.txt` contains `Verified OK`.
- If verify fails after a successful sign, file a `high` finding (the
  attestation is broken) and attach `verify.txt`.
- Delete `$k` contents at the end of the run? No: leave `/tmp` to the
  microVM teardown. Just never copy the private key into the workspace.

## Pitfalls

- Running `sign-blob` without `--signing-config`: cosign v3 tries to upload
  to the public Rekor log and prompts for ToS acceptance. The empty config
  is what makes signing offline.
- Redirecting only stdout for `verify.txt`: `Verified OK` is printed on
  stderr. Use `> file 2>&1`.
- Putting `cosign.key` under `evidence/` "for the record". The public key,
  the bundle and the digests are the record.
- Treating this signature as long-term provenance. A throwaway key proves
  integrity inside this run only; real pipelines use keyless signing with
  Fulcio + Rekor in CI.
