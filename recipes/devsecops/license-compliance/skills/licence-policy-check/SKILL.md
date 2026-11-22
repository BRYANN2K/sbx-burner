---
name: licence-policy-check
description: Build an SBOM with syft and check component licences against an allow / review / deny policy file. Use when asked about licence or license compliance, open-source obligations, GPL or AGPL dependencies, SPDX ids, or what a project ships.
---

# Licence policy check

## 1. Build the SBOM

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
  -o spdx-json="$A/sbom.spdx.json" 2> "$A/syft.stderr.txt"
echo "syft exit: $?"

# What was found, and by which cataloger.
jq -r '.components[] | select(.type != "file")
  | [.name, .version, ([.licenses[]? | .expression // .license.id // .license.name] | join(" ; "))] | @tsv' \
  "$A/sbom.cdx.json" | sort > "$A/licences.tsv"
wc -l < "$A/licences.tsv"
```

syft reads lockfiles and installed package metadata (for an image: its OS
package database and installed language packages). It does not download
anything; `docker:` reads the local engine, never a registry. Know its blind spots before you trust the list:

- A manifest without a lockfile (`package.json` alone, loose
  `requirements.txt`) gives few or no components.
- For `package-lock.json`, dev dependencies are left out by default.
- Vendored or copied source files are invisible.

## 2. Apply the policy

```bash
python3 fixtures/license-check.py \
  --sbom "$A/sbom.cdx.json" \
  --policy fixtures/license-policy.yaml \
  --out "$A/licence-check.json"
echo "license-check exit: $?"   # 0 = nothing denied, 1 = denied, 2 = bad input

jq -r '.results[] | select(.decision != "allow") | [.decision, .purl, (.licences | join(" ; "))] | @tsv' \
  "$A/licence-check.json"
```

How the script reads an SPDX expression:

- `A OR B`: you may choose, so the most permissive side counts.
- `A AND B`: both apply, so the most restrictive side counts.
- `A WITH exception`: read as `A`. Mention the exception in the report.

## 3. Triage

For each `deny`:

1. **Is it shipped?** Check the lockfile or manifest: a `dev: true` entry,
   a `devDependencies` or test group is not shipped. Shipped means delivered
   to users, in a binary, an image or a bundle. For an `image` target,
   every component in the image is shipped.
2. **Direct or transitive?** Find who pulls it in
   (`jq '.packages | to_entries[] | select(.value.dependencies["<name>"])' /home/agent/target/package-lock.json`).
   The fix is often to replace the parent.
3. **Is the declared licence the real one?** Report what is declared. If the
   package ships a LICENSE file in the target, read it and note a mismatch.

For each `unknown`: look for a LICENSE or COPYING file of that component
inside the target. Found: quote its first line in the hypothesis. Not found:
the next step is to ask the maintainer. Do not infer a licence from the
package name or from memory.

For each `review`: one hypothesis per component, naming the question the
reviewer must answer (linked or modified? distributed or hosted?).

Dev dependencies missing from the SBOM: list denied ones from the lockfile
(`jq -r '.packages | to_entries[] | select(.value.dev) | [.key, .value.license] | @tsv' /home/agent/target/package-lock.json`)
as hypotheses, since the policy applies to shipped code.

## 4. Report

- One finding per denied shipped component. `rule` is the SPDX id,
  `location` is the package URL.
- Remediation options, in this order: replace the component, pick the
  permissive side of a dual licence, get a written exception from the
  policy owner.
- Fill `metrics` from `licence-check.json` `.counts`.

## Pitfalls

- Reporting a dual-licensed `MIT OR GPL-3.0-only` component as denied.
- Treating "no licence declared" as permissive. No licence means no grant.
- Editing the policy to make the check pass.
- Trusting an empty result: no components usually means no lockfile.
- Mixing up `GPL-3.0-only` and `LGPL-3.0-only`, or `-only` and `-or-later`.
