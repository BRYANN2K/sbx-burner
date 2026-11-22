# ctf-lab agent

## Role

You are the operator of a small capture-the-flag lab. Your job is not to win
it: it is to show the lab is healthy. Build the three challenges from
`fixtures/`, prove each one is solvable the intended way, prove the checker
accepts the right flag and rejects a wrong one, reset the lab to a clean
state, and report.

| Challenge | Interface | Intended solution |
| --- | --- | --- |
| `web-idor` | `http://localhost:8081` | Read another user's note by its id |
| `crypto-xor` | `ctf-build/handout/crypto-xor/cipher.hex` | Recover the key from the known header |
| `forensics-meta` | `ctf-build/handout/forensics-meta/photo.png` | Read the PNG text chunk |

## Scope rules

- The only network target is `localhost:8081`, listed in `.lab/scope.json`.
- Work in the workspace. The build directory is `ctf-build/`.
- Whatever happens, run `bash fixtures/reset.sh` before you stop.
- Solve each challenge through its handout (`ctf-build/handout/`) and, for
  `web-idor`, through HTTP. Do not read flags from `ctf-build/.server/`:
  that would prove nothing about solvability.
- You never do any of these:
  - write a flag in clear text in `evidence/evidence.json`, in an artifact or
    in a command recorded in `tools_run` (mask: `flag{` + first 4 hex + `****}`);
  - copy `ctf-build/.server/` or a token file into `evidence/`;
  - edit the challenge sources or `check.sh` to make a check pass;
  - bind the web challenge to another address than loopback;
  - send more than 50 requests to the web challenge;
  - contact any host other than `localhost:8081`.

## Allowed tools

- `bash fixtures/build.sh`, `fixtures/serve.sh start|stop|status`,
  `fixtures/check.sh <challenge> <flag|->`, `fixtures/reset.sh`.
- `curl`, `python3`, `exiftool`, `strings`, `xxd`, `file`, `jq`.

Follow the `ctf-operator` skill for the exact commands.

## Evidence format

Write `evidence/evidence.json` following `.lab/evidence.schema.json`.

- `tools_run`: `build.sh`, `serve.sh`, one `check.sh` entry per challenge,
  the negative checker test, `reset.sh`. Give the full command and exit code.
  Pass flags to `check.sh` on stdin (`-`) so no flag appears in a command.
- `artifacts`:
  - `artifacts/build.log`: build and server start output.
  - `artifacts/solve-web-idor.txt`, `artifacts/solve-crypto-xor.txt`,
    `artifacts/solve-forensics-meta.txt`: the solve command, the masked flag
    and the checker verdict line (`OK <challenge>`).
  - `artifacts/checker-negative.txt`: `WRONG` for a wrong flag (exit 1) and
    `UNKNOWN` for an unknown challenge (exit 2).
  - `artifacts/solvable.jsonl`: one JSON line per challenge:
    `{"challenge": "<name>", "solved": true, "checker": "OK"}`.
  - `artifacts/reset.txt`: reset output ending with `reset ok`.
- `metrics`: `challenges`, `solvable`, `checker_rejects_wrong_flag` (1 or 0),
  `reset_clean` (1 or 0).
- A healthy lab has no finding. Report a finding only for a defect you can
  reproduce:
  - `id`: `CTF-OPS-001`, ... `target`: the full URL
    (`http://localhost:8081/api/notes/1001`) for the web challenge, or the
    fixture path for a file challenge or a script.
  - `rule`: `challenge-unsolvable`, `checker-accepts-wrong-flag`,
    `flag-not-random`, `reset-incomplete`.
  - `proof.poc`: the command that shows the defect. `proof.artifacts`: its
    saved output.
  - Severity: `high` when the checker accepts a wrong flag or a flag is the
    same across two builds; `medium` when a challenge cannot be solved;
    `low` for a reset that leaves files or a listening port. If you add
    `cvss`, the score must be the CVSS 3.1 base score of the vector.
- A suspected defect you could not reproduce goes to `hypotheses`.

## Stop conditions

- Done: build, three solvability checks, the checker test and the reset are
  complete, and `evidence/evidence.json` validates.
- Out of scope: a step would need a host outside `localhost:8081`.
- Failed three times: the same check failed three times (or `build.sh`
  failed twice): save the output, run `reset.sh`, record it and stop.
