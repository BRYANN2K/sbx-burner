---
name: flag-hygiene
description: Handle CTF flags safely - keep them out of evidence, commands and logs, mask them, submit them only to the checker, and never guess. Use whenever you obtain, print, store, submit or report a CTF flag.
---

# Flag hygiene

A flag is the secret of the exercise. Treat it like a credential: prove you
have it, do not publish it.

## Workflow

1. **Keep the flag in a shell variable**, never in a file under `evidence/`.

   ```bash
   flag="$(python3 evidence/artifacts/crypto-xor-solve.py ctf-build/handout/crypto-xor/cipher.hex)"
   ```

2. **Mask before anything is written.** Keep the prefix and four characters.

   ```bash
   mask() { sed -E 's/\{(.{4})[^}]*\}/{\1****}/g'; }
   printf '%s\n' "$flag" | mask        # flag{ab12****}
   ```

3. **Submit on stdin**, so the flag is not in the process list or in a
   recorded command.

   ```bash
   printf '%s\n' "$flag" | bash /home/agent/target/check.sh crypto-xor - \
     > evidence/artifacts/crypto-xor-check.txt 2>&1; echo "exit: $?"
   ```

4. **Record the masked flag and the verdict** in
   `evidence/artifacts/<challenge>-check.txt`, and the masked flag in the
   finding's description.

5. **Scan the evidence before you stop.** Adapt the pattern to the flag
   format of the event.

   ```bash
   grep -rnE 'flag\{[0-9a-f]{32}\}' evidence/ && echo "UNMASKED FLAG: fix it"
   ```

## Rules

- A solve script prints the flag at run time. It never contains the flag.
- Raw tool output that contains a flag goes through `mask` before it is
  saved.
- At most 3 checker submissions per challenge. A flag you are not sure of is
  a lead, not a submission.
- Never build a flag from its format and partial data ("it must end in ...").
- Never send a flag anywhere except the challenge's own checker.
- Do not reuse a flag, token or password found in one challenge against
  another host.

## Triage questions

1. Is the value really the flag (right format, accepted by the checker), or
   a decoy?
2. Is any clear-text flag left in `evidence/`, in `tools_run` commands or in
   the summary?
3. Would the masked flag still let a reader match it to the challenge?
   (Prefix plus four characters is enough.)

## Pitfalls

- `echo "$flag" > evidence/artifacts/flag.txt`. Never.
- Recording `check.sh web-idor flag{...}` as the command. Use `-` and stdin.
- Saving an HTTP response that contains the flag without masking it.
- Masking in the evidence file but not in the artifacts it points to.
