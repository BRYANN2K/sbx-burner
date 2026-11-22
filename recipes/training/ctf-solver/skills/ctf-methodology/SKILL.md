---
name: ctf-methodology
description: Solve CTF challenges by category - web, crypto, forensics, reversing, pwn-lite - with a fixed loop of inventory, first look, hypothesis, solve script and flag check. Use when asked to solve a CTF challenge, find a flag, or work on the training/ctf-lab challenges.
---

# CTF methodology

One loop for every challenge: **inventory → first look → hypothesis → solve
script → check → record**. Save raw output under `evidence/artifacts/` as you
go.

```bash
mkdir -p evidence/artifacts
A=evidence/artifacts
```

## 1. Inventory

Pick the lab root from the env (`LAB_TARGET_KIND`, `LAB_TARGET_PATH`,
`LAB_TARGET_URL`, `LAB_DEMO`):

- `--target-url` (`LAB_TARGET_KIND=url`): the challenge service is at
  `$LAB_TARGET_URL`, in scope. Start from the statement (in
  `$LAB_TARGET_PATH` when a handout directory came with it) and the
  service's own pages; contact no host outside `.lab/scope.json`.

- `--demo` (`LAB_DEMO=1`): the bundled lab in `fixtures/` is already built
  and started by the demo step. `LAB_ROOT=fixtures`, `H=ctf-build/handout`.
- `--target` (`LAB_TARGET_KIND=path`): the user's handouts at
  `$LAB_TARGET_PATH`. When it has `build.sh` and `check.sh`, build it first:

```bash
export CTF_BUILD="$PWD/ctf-build"
LAB_ROOT="${LAB_TARGET_PATH:-fixtures}"
bash "$LAB_ROOT/build.sh" "$CTF_BUILD" > "$A/lab-build.log" 2>&1   # skip under --demo
bash "$LAB_ROOT/serve.sh" start        >> "$A/lab-build.log" 2>&1   # skip under --demo
H=ctf-build/handout
find "$H" -type f | sort > "$A/challenges.txt"
cat "$H"/*/CHALLENGE.md
```

A target without `build.sh`:

```bash
LAB_ROOT="$LAB_TARGET_PATH"
find "$LAB_ROOT" -maxdepth 3 -type f | sort > "$A/challenges.txt"
file "$LAB_ROOT"/* >> "$A/challenges.txt"
jq -r '.targets[].hosts[]?' .lab/scope.json   # services you may contact
```

Read every statement first. Note the flag format. Start with the challenge
that looks easiest.

## 2. Method per category

### Web

1. Map: `curl -s -i http://HOST/` and each endpoint the statement names.
   Save responses to `$A/<challenge>-notes.txt`.
2. Ask in this order: can I read an object that is not mine (change an id)?
   Is a check done only on the client? Is input reflected or put in a query,
   a path or a command? Is there a hidden path (`/robots.txt`, comments)?
3. Change one thing per request and compare with a control request.

For an id in the URL: list your own objects, then request the neighbours.

```bash
tok="$(cat "$H/web-idor/guest-token.txt")"
curl -s -H "X-Token: $tok" http://localhost:8081/api/notes | mask
curl -s -i -H "X-Token: $tok" http://localhost:8081/api/notes/1001 | mask
```

### Crypto

1. Identify the encoding first: `xxd file | head`, hex, base64
   (`base64 -d`), then the cipher the statement names.
2. Write down what is known: key length, a plaintext prefix, a reused key or
   nonce, a small exponent. The intended flaw is almost always there.
3. Repeating-key XOR with a known prefix: `key[i] = cipher[i] ^ known[i]`
   for the first key-length bytes, then decrypt everything.
4. Without a known prefix: guess the key length by the best average Hamming
   distance between blocks, then solve each column as single-byte XOR scored
   on printable English.
5. Keep the solve as a `python3` script. Do not brute force a real key space.

### Forensics

```bash
f=/path/to/file
file "$f"
exiftool -a -G1 -s "$f"          # all metadata, with group names
strings -n 8 "$f" | head -n 40
xxd "$f" | head -n 20
binwalk "$f"                     # embedded files and their offsets
```

Ask: does the type match the extension? Is there text in metadata or after
the end marker? Is something appended or embedded? Is a value encoded
(base64, hex) rather than hidden?

### Reversing

```bash
file ./bin
strings -n 6 ./bin | head -n 60
readelf -h ./bin
r2 -q -c 'aaa; afl' ./bin                 # function list
r2 -q -c 'aaa; pdf @ main' ./bin          # disassembly of main
objdump -d -M intel ./bin | head -n 200
```

Find the comparison that decides success, then compute the input instead of
guessing it. Run the binary only inside the sandbox.

### Pwn-lite

Local binaries only, small classic bugs (overflow into a variable, format
string that prints a value).

```bash
readelf -W -l ./bin | grep GNU_STACK      # RWE means an executable stack
readelf -W -d ./bin | grep -E 'BIND_NOW|FLAGS'
gdb -batch -ex run -ex bt --args ./bin    # where does it crash?
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + b"\n")' | ./bin
```

Send a payload to a service only when its host is in the scope. No shellcode
that leaves the challenge process, no persistence.

## 3. Solve script and check

Write the solve as a script that prints the flag and does not contain it:
`evidence/artifacts/<challenge>-solve.sh` or `.py`. Then check, with the flag
on stdin:

```bash
flag="$(bash "$A/web-idor-solve.sh")"
{
  printf '%s\n' "$flag" | sed -E 's/\{(.{4})[^}]*\}/{\1****}/'
  printf '%s\n' "$flag" | bash "$LAB_ROOT/check.sh" web-idor -
} > "$A/web-idor-check.txt" 2>&1; echo "check exit: $?"
```

`OK <challenge>` with exit 0 makes it a finding. `WRONG` means the lead is
not proven: at most 3 submissions per challenge.

## 4. Finish

```bash
bash "$LAB_ROOT/reset.sh" > "$A/lab-reset.log" 2>&1   # lab-style target or --demo
```

## Triage questions

1. Does the solve script reproduce the flag from a fresh shell?
2. Did the checker accept it, or does it only "look like" a flag?
3. Which weakness does the challenge model (CWE)? That is the finding.
4. For an unsolved challenge: what is the single most promising lead, and
   what exact step would test it?

## Pitfalls

- Guessing before reading the statement. The statement names the flaw.
- Reading the operator's files (`ctf-build/.server/`) instead of solving.
- One-off shell commands with no script: the proof cannot be re-run.
- Running `strings` once and stopping. Metadata, appended data and encodings
  need their own look.
- Spending the whole run on one challenge. Write the hypothesis, move on.
