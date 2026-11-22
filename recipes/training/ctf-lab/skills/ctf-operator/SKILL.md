---
name: ctf-operator
description: Operate the agent-lab-sbx CTF as lab operator - build the challenges with random flags, verify each challenge is solvable, test the flag checker, and reset to a clean state. Use when asked to build, verify, health-check, rebuild or reset the CTF lab.
---

# CTF operator

All paths are relative to the workspace. The build directory is `ctf-build/`.
A flag never appears in clear text in the evidence: `mask` keeps `flag{` and
four characters.

```bash
mkdir -p evidence/artifacts
A=evidence/artifacts
H=ctf-build/handout
mask() { sed -E 's/flag\{([0-9a-f]{4})[0-9a-f]{28}\}/flag{\1****}/g'; }
```

## 1. Build and start

```bash
bash fixtures/build.sh        > "$A/build.log" 2>&1; echo "build exit: $?"
bash fixtures/serve.sh start >> "$A/build.log" 2>&1; echo "serve exit: $?"
find ctf-build/handout -type f | sort >> "$A/build.log"
```

Expected: three `built <challenge>` lines, `build ok: 3 challenges`, and
`web-idor listening on http://localhost:8081`.

## 2. Verify each challenge is solvable

Solve from the handout only. Keep each flag in a shell variable and feed it
to the checker on stdin.

### web-idor

```bash
tok="$(cat "$H/web-idor/guest-token.txt")"
{
  echo '$ curl -s -H "X-Token: (guest)" http://localhost:8081/api/notes'
  curl -s -H "X-Token: $tok" http://localhost:8081/api/notes; echo
  echo '$ curl -s -H "X-Token: (guest)" http://localhost:8081/api/notes/1001'
  curl -s -H "X-Token: $tok" http://localhost:8081/api/notes/1001 | mask; echo
} > "$A/solve-web-idor.txt"
flag="$(curl -s -H "X-Token: $tok" http://localhost:8081/api/notes/1001 | grep -oE 'flag\{[0-9a-f]{32}\}')"
printf '%s\n' "$flag" | bash fixtures/check.sh web-idor - >> "$A/solve-web-idor.txt"; echo "check exit: $?"
```

The guest list shows ids `1002` and `1003`. The neighbouring id `1001`
belongs to `admin` and is returned anyway: that is the intended flaw.

### crypto-xor

```bash
flag="$(python3 - "$H/crypto-xor/cipher.hex" <<'PY'
import re, sys
cipher = bytes.fromhex(open(sys.argv[1]).read().strip())
known = b"agent-lab-sbx ctf note: "
key = bytes(c ^ k for c, k in zip(cipher[:6], known[:6]))
plain = bytes(c ^ key[i % 6] for i, c in enumerate(cipher)).decode()
print(re.search(r"flag\{[0-9a-f]{32}\}", plain).group(0))
PY
)"
{
  echo '$ python3 (key = cipher[:6] XOR known header; decrypt with the repeating key)'
  printf '%s\n' "$flag" | mask
  printf '%s\n' "$flag" | bash fixtures/check.sh crypto-xor -
} > "$A/solve-crypto-xor.txt"; echo "check exit: $?"
```

### forensics-meta

```bash
flag="$(exiftool -s3 -Comment "$H/forensics-meta/photo.png" | base64 -d)"
{
  echo '$ exiftool -s3 -Comment photo.png | base64 -d'
  file "$H/forensics-meta/photo.png" | sed 's|.*/||'
  printf '%s\n' "$flag" | mask
  printf '%s\n' "$flag" | bash fixtures/check.sh forensics-meta -
} > "$A/solve-forensics-meta.txt"; echo "check exit: $?"
```

If `exiftool` prints nothing, read the chunk directly:
`strings -n 8 "$H/forensics-meta/photo.png"` shows the base64 text after
`tEXtComment`.

## 3. Test the checker

A deliberately wrong flag still goes through stdin, like a real one.

```bash
{
  echo '$ printf %s <wrong flag> | check.sh web-idor -'
  printf '%s\n' 'flag{wrong}' | bash fixtures/check.sh web-idor -; echo "exit: $?"
  echo '$ check.sh no-such-challenge x'
  bash fixtures/check.sh no-such-challenge x 2>&1; echo "exit: $?"
} > "$A/checker-negative.txt" 2>&1
```

Expected: `WRONG web-idor` with exit 1, `UNKNOWN no-such-challenge` with
exit 2.

## 4. Solvability index and reset

One JSON line per challenge, flags masked by construction:

```bash
for c in web-idor crypto-xor forensics-meta; do
  if grep -q "^OK $c" "$A/solve-$c.txt"; then s=true; else s=false; fi
  printf '{"challenge":"%s","solved":%s,"checker":"%s"}\n' \
    "$c" "$s" "$(grep -oE '^(OK|WRONG)' "$A/solve-$c.txt" | head -n 1)" \
    >> "$A/solvable.jsonl"
done

bash fixtures/reset.sh > "$A/reset.txt" 2>&1; echo "reset exit: $?"
ls ctf-build 2>&1 | head -n 1 >> "$A/reset.txt"
```

Expected: `reset: build directory absent`, `reset: port 8081 closed`,
`reset ok`, then `ls` failing because the directory is gone.

## Triage questions

1. Did every `check.sh` call for a solved challenge print `OK` and exit 0?
2. Did the solve use only the handout and the HTTP interface?
3. Does a second build give different flags? Optional: build twice and
   compare `ctf-build/.server/flags.sha256` (hashes only, they are safe to
   compare, not to publish).
4. After the reset, is the directory gone and the port closed?

## Pitfalls

- Reading `ctf-build/.server/web-idor/notes.json` to "solve" the web
  challenge. That checks the build, not the challenge.
- Passing a flag as an argument and then recording the command. Use `-`.
- Forgetting `serve.sh start`: `web-idor` then looks unsolvable.
- Running `build.sh` twice without a reset: it refuses to overwrite.
- Reporting a healthy lab as findings. No defect means no finding.
