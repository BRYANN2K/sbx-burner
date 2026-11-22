# ACP security model

burner drives the agent inside the sandbox over the Agent Client Protocol (v1), through `sbx exec -i <sandbox> <acp command>`. burner is the ACP client and runs on your machine; the agent is the ACP server and runs inside the sandbox.

Approved by the maintainer on 2026-11-22. Each rule has a test with a hostile fake agent in `internal/acp/client_test.go`.

## Threat model
Assume the ENTIRE ACP stream is hostile. Inside the sandbox the agent runs with full trust and root; a malware sample, a poisoned dependency or a prompt-injected agent can kill the agent or write straight into its stdout and speak ACP itself. ACP's own spec says it does not sandbox anything and that every agent-authored string, URI and path is untrusted. burner must stay safe even when the "agent" is an attacker.

## Rules
R1  Capabilities: initialize declares NO client capabilities: fs.readTextFile=false, fs.writeTextFile=false, terminal=false, elicitation (form and url) absent, auth.terminal=false. The agent uses its own tools inside the sandbox only.
R2  Refuse by default: every agent→client request other than session/request_permission (and elicitation/create only if R5 is enabled later) gets JSON-RPC -32601. This covers fs/*, terminal/*, auth/*, mcp/message, vendor methods (cursor/*), `_`-prefixed extensions and unknown names. burner contains NO implementation of fs/* or terminal/* — nothing to misuse.
R3  Permissions: the answer is only one of the offered optionIds (allow_once/allow_always/reject_once/reject_always) or `cancelled`. A permission never triggers anything on the host. Policy per run: full trust = auto-select allow (inside the sandbox, the boundary is the sandbox); the user can switch to "ask me". After session/cancel every pending request is answered `cancelled`.
R4  No host MCP servers: session/new always sends mcpServers: []. Recipe-declared MCP servers run inside the sandbox from the kit, never with host env or headers (no secrets in env/headers — credentials stay in the sbx proxy).
R5  No URL, no browser, no auth flow on the host: no url-elicitation, no terminal auth, never open or fetch any URI from the stream, never follow file paths from the stream. Agent auth happens inside the sandbox through sbx secrets / sbx-managed OAuth only.
R6  Text is hostile: every string is sanitised before display (ANSI/OSC/DCS incl. OSC 52, C0/C1, bidi), capped (4 KB per field, 64 choices), rendered as plain text (no markdown fetch, no images, no hyperlinks made clickable).
R7  Resource limits: max 1 MiB per JSON-RPC message, rate limit on updates, total session byte budget, per-request timeouts; malformed JSON, wrong jsonrpc version, id reuse or an oversize message ends the session and the sandbox is destroyed.
R8  No secrets into ACP: prompts carry task text and notes only; no host env, tokens or paths are sent. Notes are capped (8 KB).
R9  The shared workspace is hostile: anything the agent writes there is read by the runner without following symlinks, with size caps, never executed or opened by burner.
R10 Process hardening: the ACP client runs in burner's Go process with no shell and no exec of agent-supplied strings; optional defence in depth on macOS: run the ACP bridge as a child under `sandbox-exec` with no file writes outside the run dir and no network.
R11 Malware recipes: the sample never runs in the agent's sandbox. Detonation happens in a second throwaway sandbox with no agent and no ACP; only collected artifacts are copied to the agent's sandbox.
R12 Logging: the raw ACP transcript is stored in the run dir (host side, outside the workspace) for audit, redacted with the evidence redactor.


## Tests

| Rule | Test |
|---|---|
| R1 | every test's handshake checks `clientCapabilities` (no fs, no terminal, no terminal auth, no elicitation) |
| R2 | `TestR2RefusesEveryHostMethod`: fs/read_text_file on ~/.ssh, fs/write_text_file on ~/.zshrc, terminal/create, terminal/output, url elicitation, a vendor method, an `_` extension and authenticate all get -32601 |
| R3 | `TestR3OnlyOfferedOptionIDs` |
| R4 | handshake checks `mcpServers: []` |
| R6 | `TestR6TextIsCleaned`: OSC 52 and cursor moves stripped, resource links never rendered |
| R7 | `TestR7ProtocolAbuseEndsTheSession` (oversize message, invalid JSON, wrong jsonrpc version, request id reuse), `TestUpdateFloodEndsTheSession` (over 500 messages per second), `TestPermissionFloodIsBounded` (over 8 pending permissions are refused at once, handlers run one at a time), idle watchdog (30 min without a message ends the turn), 60 s timeout on set_config_option |
| R3 (cancel) | `TestCancelAnswersPendingPermissions`: after session/cancel every pending permission is answered `cancelled` and no late answer is sent |
| R8 | `TestR8NotesCapped` |
| R9–R11 | runner side; tracked in the runner tests |
| R12 | `TestBridgeAutoTrustUnattended` (raw transcript, both directions), `tests/test_acp.py::test_acp_run_end_to_end_with_a_fake_bridge` (redacted into `acp-transcript.jsonl`, raw file removed) |
| R3 (policy) | `TestBridgeAutoTrustUnattended` (auto-allow logged as an `agent.tool` event), `TestBridgeAskModeAsksModelPermissionAndFollowUp` (operator picks; no answer = the reject option) |

## How `burner run --acp` is wired

```
burner run --acp ──> python -m lab run --acp        (sandbox, scope, tools, evidence, report)
                         │ agent step
                         └─> burner acp-bridge ──> sbx exec -i <sandbox> -- <ACP server>
                               ▲ stdout: event | ask | log lines (validated by the runner)
                               └ stdin: operator answers from the ask bridge (control.sock)
```

- The runner finds the bridge through `BURNER_ACP_BRIDGE`, which burner sets to its own path. Without it, `--acp` is refused before any sandbox exists.
- The ACP server is installed inside the sandbox during the install window (`acp-install`); its hosts are install-only and closed before the agent starts.
- Codex: the sbx codex kit has no ACP server, so the runner installs `@agentclientprotocol/codex-acp@2.9.0` with Node from Debian. It drives the kit's own `codex` (`CODEX_PATH`), so the sbx model gateway and the OAuth sentinel keep working.
- Claude: the sbx claude image has no ACP server either, so the runner installs `@agentclientprotocol/claude-agent-acp@0.109.1` the same way. It drives the sandbox's own `claude` (`CLAUDE_CODE_EXECUTABLE=/home/agent/.local/bin/claude` — a real binary on the built-in agent, a symlink the agent-claude mixin ships), so the proxy-managed OAuth sentinel in `~/.claude/.credentials.json` keeps working.
- Cursor: the sbx cursor kit ships a native ACP server (`cursor-agent acp`); nothing is installed. `auto` maps to its `agent` mode (the only mode with tool access), `ask` to read-only `plan` — the closest to ask-before-acting it offers.
- OpenCode: the sbx opencode kit ships a native ACP server (`opencode acp`); nothing is installed. `auto` maps to `build`, `ask` to `plan`. Provider auth is env-based: sbx injects `OPENAI_API_KEY` etc. as proxy-managed sentinels, and its OpenAI OAuth binding is what reaches the model gateway — Anthropic OAuth does not, so pick an `openai/*` model or bind an Anthropic API key.
- Devin: the sbx devin kit ships a native ACP server (`devin acp`); nothing is installed. `auto` maps to `bypass`, `ask` to `accept-edits`. Known upstream bug (reported, not patched by burner): sbx's credential engine writes `~/.local/share/devin/credentials.toml` as JSON, and the CLI fails its TOML parse before serving ACP. Its credential is passthrough: the real Devin token sits in that file inside the guest and the agent can read it (the CLI sends it inside protobuf bodies, out of the proxy's reach). Treat a Devin run as exposing that token to the agent. The other agents only ever see a placeholder.
- Model: `--model ID` must be one of the values the agent offers. Without it, an attended run asks the operator; an unattended run keeps the agent's default. The list is cached in `~/.burner/cache/acp-models-<agent>.json` (`burner models --agent codex`).
- A paid fast mode (option category `speed`) is always set to `off`.
- Permissions: `auto` sets the agent's full-trust mode (the sandbox is the boundary) and answers `allow_once` only, never `allow_always`; with no `allow_once` on offer it answers `reject_once` (or cancels). Every decision is logged with the option kind and name. `ask` keeps the agent's ask-first mode and sends each request to the operator; labels carry the kind and map back by position; no answer means `reject_once`, never `reject_always`.
- Display: secret values seen in the host copy of the target and its git history are masked, fragments included, everywhere. Values from the agent-writable evidence folder count only when they match a known secret pattern or a scanner field (gitleaks `Secret`, trufflehog `Raw`), are capped (200 values, 128 characters) and mask agent-authored text only (agent messages and tools, questions, the transcript, evidence), never runner records such as the policy log. The operator's answers are never rewritten. Masking is linear in the text (6-gram index).
- Teardown: every teardown step has a 300 s timeout and ignores a second Ctrl+C; the transcript is redacted after destroy. If destroy fails or burner has to stop the engine after 3 minutes, burner prints `sbx rm --force <sandbox>`.
- Follow-up notes: in an attended run, each turn end asks for a note; a note becomes the next `session/prompt`. Mid-turn steering is not wired.

Sources: ACP v1 schema (`agentclientprotocol/agent-client-protocol`, schema/v1), ACP security page (https://agentclientprotocol.com/protocol/v1/security), sbx kit capability `com.docker.sandbox/acp@1`.
