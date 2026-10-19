---
name: decision-guard
description: "Use when adding or maintaining a model-judged safety check for agent shell commands across Claude Code, Codex, Copilot CLI, OpenCode, Pi and OMP, including destructive-command approval and per-directory delete approval. Keywords: decision guard, PreToolUse hook, dangerous command, rm -rf approval, OpenAI Decisions API."
version: 2.2.0
tags: [safety, hooks, approval, claude-code, codex, copilot, opencode, pi, omp]
---

# Decision Guard

Judges every shell command an agent is about to run, before it runs. A short deny list (disk erase, raw device writes, `mkfs`,
fork bomb) is refused outright, then your own deny list, then two deterministic rules send recursive deletes and secret
exfiltration to the user, then your own allow list, then a read-only fast path that skips the model for commands proven read-only; everything else is classified `safe` / `risky` / `destructive` by a
decision model: OpenAI's Decisions API (`gpt-6-luna`) when an OpenAI key is set, or the user's own System One compatible
service when a base URL is set (name several under `services` and pick one with `active`). One shared Rust binary
(`~/.decision-guard/bin/decision-guard`), thin adapters per agent.

## Quick Decision

```
Need a pre-execution safety check on agent shell commands, in one or more agents?
  YES → use this skill
  NO, only want static allow/deny rules → use the agent's own permission config
  NO, only auditing after the fact → use the agent's PostToolUse / telemetry hooks
```

## Trigger Phrases

- guard dangerous shell commands
- ask me before the agent deletes a directory
- add a PreToolUse hook that judges commands
- use the OpenAI decision model for command safety
- install decision guard for codex / claude / copilot / opencode / pi / omp

## What it does

| Command | Result |
|---|---|
| `rmdir`, or `rm` with `-r`/`-R`/`--recursive` | Always asks, listing each absolute target. Deterministic, no API call, approval is never remembered, and "the user asked for it" does not skip it |
| The same `rm`/`rmdir` aimed at `/`, the home directory (`~`, `$HOME`, `~/*`, `.` inside it) or a parent of it | **Denied**, never asked: the user must run it in a terminal. `~`, `$HOME` and `${HOME}` are expanded before the check |
| A command matching a glob in your own `deny` list (`config.json`), as the whole command or any part of a chain | **Denied**, before the model or cache. Wins over everything except the built-in deny list |
| A secret (`env`, `.env`, `~/.ssh`, `~/.aws`, `id_rsa`, ...) read in the same command as something that sends data out (`curl -d`/`-T`, `nc`, `scp`, ...) | Always asks, naming the secret and the program, never the rest of the command. Same guarantees as the row above |
| A command matching a glob in your own `allow` list (`config.json`), with no chain/substitution characters | **Allowed**, before the model, with no warning. Can never override the built-in deny list, your deny list, or the two fixed rules above |
| A command where every part is provably read-only (`rg`, `sed -n`, `cat`, `ls`, `git log`, a read-only `python3` script, ...), when `readonly` is on (default) | **Allowed** with no model call, logged as `rule = readonly`. Runs after your allow list and before the cache; never overrides anything above it. A redirect, assignment, loop, `sudo`, `xargs`, `eval` or an unprovable script goes to the model. Try one with `decision-guard check`; the Rules page of `decision-guard web` has the toggle and the tool list |
| Model says `destructive` with probability ≥ `ASK_P` | Asks, unless the user's own recent message asked for exactly this command (probability ≥ `USER_P`) |
| Otherwise | Allowed untouched (the guard never force-approves) |
| No service configured, API error, or timeout | Allowed with a warning on stderr; denied when `DECISION_GUARD_FAIL_CLOSED` is set |

Every verdict is cached per exact command (whitespace-collapsed), so a repeated command never calls the API again.
"Did the user ask for it" depends on the conversation, so it is never cached.

Agents that cannot prompt:

- **Codex**: its hook API does not support `ask`. A model-judged ask becomes a warning (to the user and the model)
  and the call proceeds; a directory delete is still denied.
- **OpenCode**: with `permission.bash` set to `"ask"` the plugin answers each request and OpenCode shows its real
  prompt (safe commands pass without one); otherwise a command that needs approval is rejected.

## Layout

```text
rust/                # the binary: `decision-guard hook <agent>`, `web`, `archive`, `service`; `cargo test` runs its tests
├── src/, tests/
└── scripts/build-dist.sh   # release build for this machine, refreshes dist/ and SHA256SUMS
dist/                 # prebuilt binaries (aarch64-apple-darwin only) + SHA256SUMS, verified by install.sh
scripts/
├── adapters/pi.ts      # Pi and OMP extension (spawns the binary)
├── adapters/opencode.js
└── install.sh          # verifies and installs the binary to ~/.decision-guard/bin, wires the agents
```

`decision-guard web` serves a local page over `decisions.db` and the allow/deny rules; `decision-guard archive` (weekly, scheduled by
`install.sh archive`) moves rows older than 30 days into `archive/*.db.gz`. Details and measured latency are in `README.md`.

Runtime state lives in `~/.decision-guard/`: `key` (OpenAI key, first line, mode 600), `config.json` (your own service,
plus your `allow`/`deny` rules, see "What it does" and `rust/src/rules.rs`),
`cache.json`, `archive/` (gzipped SQLite files holding rows older than 30 days, written by the weekly archive), and
`decisions.db` (SQLite: the audit log, the raw request and response of every call to the decision
service in `api_calls`, and recent user prompts; mode 600). Never commit any of them.

Which service answers: a base URL (`base_url` in `config.json` or `DECISION_GUARD_BASE_URL`, plus an optional
`api_key` / `DECISION_GUARD_API_KEY` and `model` / `DECISION_GUARD_MODEL`) selects your own System One compatible
service and wins; otherwise an OpenAI key (`OPENAI_API_KEY` or the `key` file) selects OpenAI's Decisions API.
`config.json` may name several under `services`, with an `active` key picking one: the entry's keys win over the
top-level ones, and `decision-guard service [<name>]` prints or switches them. Plain `http` is only accepted for
localhost and private addresses.

Env knobs: `DECISION_GUARD_ASK_P` / `ask_p` (probability of "destructive" that asks, default 0.5),
`DECISION_GUARD_USER_P` / `user_p` (probability the user asked for it that skips the question, default 0.85),
`DECISION_GUARD_FAIL_CLOSED` (deny when the command could not be judged), `DECISION_GUARD_TIMEOUT_MS` / `timeout_ms` (per request, default 8000),
`DECISION_GUARD_BUDGET_MS` / `budget_ms` (whole decision, default 12000; keep it under the agent's hook limit: OMP/Pi 30 s, Claude Code and Codex hooks 15 s),
`DECISION_GUARD_KEEP_ALIVE` / `keep_alive` (sent to your own service so a local model stays loaded), `DECISION_GUARD_READONLY` / `readonly` (read-only fast path, on by default; `0`/`false` turns it off, the variable wins). `ask_p` / `user_p` / `timeout_ms` / `budget_ms` / `keep_alive` / `readonly` also live in `config.json`.
Out-of-range values fall back to the default.

## Steps

1. Read `scripts/install.sh --dry-run` output first. With no target the script sets up everything the machine has: shared files,
   the skill link, and a hook or extension for each agent found (`~/.omp`/`~/.pi`, `~/.claude`, `~/.codex`, `~/.copilot`, `~/.config/opencode`).
   Named targets install only those: `files skill pi opencode claude codex copilot`, plus `opencode-ask` and `archive`
   (never automatic: one changes how OpenCode prompts, the other schedules a weekly job).
2. Run `scripts/install.sh` (or name targets). The installer edits user-level agent config (`~/.claude/settings.json`,
   `~/.codex/hooks.json`) and backs up each existing file as `*.bak-decision-guard`. Show the dry run and get the user's
   go-ahead before editing agent config they did not name. Claude and Codex get two hooks: `PreToolUse` (judge) and
   `UserPromptSubmit` (remember what the user asked). The installer verifies the prebuilt binary's checksum before copying it,
   removes the old Node copies from `~/.decision-guard/`, and ends with a self-check; a failed check exits non-zero.
3. Verify after writing: re-run with `--dry-run` and expect `already wired`; run `cargo test` in `rust/`.
4. Codex only: tell the user to open `/hooks` and trust the new hook(s); Codex skips unreviewed hooks.
5. Restart the agent (the OMP/Pi extension and OpenCode plugin keep the old adapter in memory until then), then trigger one `rm -rf <dir>` and confirm the prompt or rejection.

## Verification points

- `cargo test` in `rust/` passes (offline, no key needed; it runs the real binary against stand-in servers and a private `HOME`).
- `dist/SHA256SUMS` matches the source: after any change under `rust/src`, run `rust/scripts/build-dist.sh` and commit `dist/`.
- Hook output per agent: Claude/Codex `hookSpecificOutput.permissionDecision`; Copilot top-level `permissionDecision`.
- A malformed payload must exit 0 silently: Copilot treats any non-zero `preToolUse` exit as a deny.
- With a service configured, repeat a model-judged command in a session where the prompt hook recorded "force push main now":
  the exact command must not ask, a similar one (another branch) must.
- A custom service answers the System One shape; OpenAI and a local Ollama with `nimble` have been called live, any other endpoint should be tried once.

## Stop conditions

- No decision service configured and the user wants model judgement: stop and ask for an OpenAI key or the URL of their own
  service; do not paste a key into chat logs or files in the repo.
- The user's own service is a remote host: the command, its directory and recent user messages go there. Say so before
  configuring it; a local server avoids this. Never lower the `https` requirement for a remote host.
- An existing agent config file is not valid JSON: stop, do not repair it. A missing one is created when the agent's directory exists.
- Copilot CLI is not installed: the hook file can be written, but report it as untested.
- `opencode-ask` changes how OpenCode prompts for every bash command: only run it when the user asked for real OpenCode prompts.
- `install.sh files` says "no prebuilt binary" (any machine other than Apple Silicon macOS) or "checksum mismatch": stop. Build the
  binary for that machine with `rust/scripts/build-dist.sh` (needs a Rust toolchain) or restore `dist/` from git; never copy a binary around the check.

## Known limits

- Not a security boundary. A model verdict can be wrong, and agents have other write paths (`apply_patch`, edit
  tools, `find -delete`, `rsync --delete`) that are not covered.
- The cache ignores the working directory, so a relative-path command can reuse a verdict from another directory.
- Delete targets do not follow a preceding `cd`; the prompt shows paths resolved against the session cwd.
- `git rm -r` and `rm -r` inside a quoted string also trigger the delete rule (over-asking is deliberate).
- "The user asked for it" is only as good as the recorded prompts: agents without a prompt hook installed never
  skip the question. The two deterministic rules ignore it on purpose.
- The exfiltration rule is pattern based: it misses a secret behind a variable or a combined flag such as `curl -sd`.
  Indirect deletes (`find -delete`, `rsync --delete`) and other secret leaks are left to the model, which judged them
  correctly most of the time but not always (it scored `env | curl -d @-` at 0.46 before the rule existed).
- The deny list is pattern based and anchored to command position: it misses a command built through a variable or `eval`.
  It is short on purpose (disk erase, raw device writes, `mkfs`, fork bomb) and is never overridden by the user's words.
- Your own allow list only applies to a command with no chain/substitution/redirection characters, by design, so an
  allow pattern cannot widen into a chained command; if you need to allow such a command, allow it unchained.
- The read-only fast path is pattern based, not a sandbox: it proves a short table of tools (`rg`, `sed -n`, `cat`, `ls`,
  `git` reads, read-only `python3` scripts, ...) and sends everything else to the model. It only skips the model, never
  overrides a rule above it, and its coverage (49.3% of the model's `safe` commands) was measured on one user's log.
