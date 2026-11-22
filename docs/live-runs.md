# Live runs

Add notes for the agent, watch what it does, and answer its questions while it works.

## Operator notes

```sh
python -m lab run pentest/web-recon --scope scope.yaml --target-app ./my-app \
    --prompt "Focus on the login flow." \
    --prompt-file notes.md
```

`--prompt TEXT` and `--prompt-file FILE` can be repeated. The notes go into `TASK.md` under `## Operator notes`, after the recipe task and the scope section.

- Notes **cannot change the scope.** The scope comes from the scope file. The network policy enforces it.
- The `AGENTS.md` stop conditions still apply.
- `report.json` records each note in `run.operator_notes`: its source, its text (redacted) and the sha256 of the raw text.

## Events

```sh
python -m lab run devsecops/secrets-scan --target ./repo --events -
python -m lab run devsecops/secrets-scan --target ./repo --events events.ndjson
```

`--events` writes one JSON object per line. With `-` the events go to stdout, and every human line goes to stderr. With a file name the file is written in the run directory. A path inside the workspace is refused.

| Event | Meaning |
|---|---|
| `step` | A plan step started, succeeded, failed or was skipped. |
| `agent.message` | What the agent says. |
| `agent.tool` | A tool call, in one line. |
| `finding` | A finding candidate, then proven or rejected by the evidence gate. |
| `blocked` | A host the network policy denied, when `sbx policy log` reports it. |
| `ask` and `answer` | A question from the agent and its answer. |
| `done` | The last event: exit code and report path. |

Every event carries `schema_version`, `seq`, `ts` and `run_id`. The `run_id` is the run directory name. The contract is `lab/schema/events.schema.json`.

Text from the agent is untrusted. Before it is emitted, the runner strips terminal escape sequences and control characters, caps its length and redacts secrets.

## Ask the user

The agent can ask you a question with `lab-ask` from inside the sandbox:

```sh
lab-ask "Login page found. Test with the admin test account?" --choice yes --choice no --text
```

`lab-ask` prints the answer and exits 0. When nobody answers, it prints nothing and exits 3. The agent then uses its documented fallback. It must never guess on a destructive or out-of-scope action.

Ways to answer:

| Channel | How |
|---|---|
| Control socket | `runs/<id>/control.sock`, mode 0600. `burner` uses it. |
| `--answers DIR` | Write a file named `<ask_id>` that holds the answer. |
| `--answers FIFO` | Write to the FIFO. |
| `burner answer <run-dir> <ask-id> <answer>` | From another terminal. |

What happens when nobody answers is set with `--on-ask`:

| Mode | Behaviour |
|---|---|
| `timeout=<dur>` | Wait, then answer "no answer". Default `30m`. |
| `skip` | Answer "no answer" at once. This is the default with `--yes`. |
| `fail` | Abort the run cleanly. Exit code 4. |

### Ask is a convenience, not a boundary

The agent has write access to the workspace, so it could write an answer file itself. The runner does not trust such a file.

- The host keeps its own record of every question and answer in `runs/<id>/asks.jsonl`, outside the workspace. The report copies it into `run.asks`.
- An answer file the runner did not write is reported as **forged**. It is ignored, and the report and the run summary say so.
- An answer is valid only when `lab-ask` returns it.

The hard boundary is the scope plus the network policy. See [Scope and safety](scope-and-safety.md).

## ACP mode

`burner run <recipe> --acp` drives the agent over the Agent Client Protocol
instead of its headless command. The live view and `--json` stay the same.
On top of them:

- `--model ID` picks one of the models the agent offers. Without it, burner
  asks at the start (attended runs) or keeps the agent's default (`--yes`).
  `burner models --agent codex` shows the last list the agent sent.
- `--permission auto|ask`: `auto` (default) allows every request inside the
  sandbox and logs each one; `ask` sends each request to you as a question.
- When the agent ends a turn, burner asks for a follow-up note. Pick Finish
  to end the run.
- The redacted ACP transcript is saved as `acp-transcript.jsonl` in the run
  directory.

Agents wired today: `burner acp agents`. Security rules:
[docs/security/acp.md](security/acp.md).
