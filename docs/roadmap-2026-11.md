# Roadmap: 2026-11 → 2027-02

Status: proposal, written 2026-10-22 against `main` @ `841a049`. Nothing below is implemented yet.
Everything marked *(measured)* was taken from this repository or a live `decisions.db`, not estimated.

## Where we are (facts first)

The engine decides in this order: built-in deny list → user deny → recursive delete → exfiltration → user
allow → read-only proof → cache → model. Only the last stage is probabilistic.

| Stage | Latency *(measured)* | Notes |
|---|---|---|
| built-in deny (4 entries), user deny, delete, exfiltration | 0–4 ms | `rules.rs`, 781 lines incl. tests |
| read-only proof | 1–4 ms | `readonly.rs` 1490 lines + `pyproof.rs` 1572 lines (tree-sitter Python) |
| verdict cache | 1–4 ms | exact-command key, ignores cwd |
| local decision model, `laya` (ModernBERT-large) | **61–100 ms** | Jev on `127.0.0.1:11435` |
| local decision model, `pplx-decider` (27B MLX) | **1032–1063 ms** | oMLX Python server on `:8092` |
| timeout path | 12000 ms | then fail-open with a warning |

Coverage *(measured, from the pre-Rust audit log of 3174 distinct `(command, cwd)` pairs)*: the read-only
proof alone allows **49.4% of the commands the model called `safe`** without a model call. 83% of all model
calls come back `safe`.

Local `decisions.db` (189 rows, this machine, biased because most were written while testing the model path):

| source | n | avg ms |
|---|---|---|
| `api` (model) | 131 | 745 |
| `rule` / `readonly` | 33 | 2 |
| `rule` / `dir-delete` | 13 | 1 |
| `cache` | 5 | 2 |
| `error` (timeout, unreachable) | 5 | 7318 |
| `no_service` | 1 | 3 |

## Verdict on the proposed priorities

| # | Proposal | Verdict | Why |
|---|---|---|---|
| P0-1 | Benchmark corpus | **Agree, but redefine the output** | It is the only thing that makes any later claim testable. But we are not a binary allow/deny guard: reporting accuracy alone would hide the fact that behaviour is driven by `ask_p`. See "What the numbers must contain". |
| P0-2 | Protocol matrix + fail-open/closed | **Agree, but it is half done and mis-scoped** | `rust/tests/hook.rs` already has 22 cases including the exact dcg#183 failure (model-judged ask on Codex becomes a warning). What is actually missing is not more cases but (a) a parameterised matrix pinned per agent, and (b) **visibility** of the fail-open path. |
| P1-3 | Pack structure; import dcg's 50+ packs | **Split.** Pack structure: yes. Importing dcg content: **no, and this is not negotiable as written** | dcg is not MIT; it is "MIT with an OpenAI/Anthropic rider" that also lists *benchmarking, testing, analysing* as restricted "use" for those parties. Vendoring it re-licenses our whole repo. Details in "The dcg question". |
| P1-4 | Hash-chained audit log | **Demote to P2, and only as an option** | It defends against log tampering, but the threat model here is honest mistakes (same as dcg's own README). Anyone who can rewrite `decisions.db` can also replace the binary. It buys compliance optics, not safety. |
| P2-5 | Model backend abstraction: MLX / Ollama / LM Studio / OpenAI | **The premise is wrong — three of the four already work** | `judge.rs` speaks two wire formats and `config.json` now names services, so *any* SystemOne endpoint already works: Ollama ≥0.35, llama.cpp, SGLang, Jev, and our own `server.py`. Only **LM Studio** is missing, and it is missing because it has no `/v1/systemone` at all *(measured: `{"error":"Unexpected endpoint or method. (POST /v1/systemone)"}`)*. So this is one adapter, not an abstraction layer. |
| P2-6 | Approval UX: diff view + explain | **Reject as scoped** | The hook has no UI: `permissionDecisionReason` is plain text and the agent renders it. A diff view belongs in `decision-guard web`, which is a different surface with a different user. Explain-in-the-terminal would mean spending model calls on presentation. |

## What the list missed

**1. Latency is a model-choice problem, not a coverage problem.** A 30-command agent session at the current
59% model-call rate costs **17.7 s of cumulative stall with `pplx-decider`** and **1.1 s with `laya`**. Adding
packs would have to cut model calls by 6× to match simply switching model. Both matter; the model is the
cheaper lever and the benchmark must report accuracy *and* P95 latency per backend, not accuracy alone.

**2. A cascade is the obvious answer and nobody has written it down.** `laya` at 61 ms is comfortable;
`pplx-decider` at 1 s is accurate. Route the uncertain band (`0.3 ≤ p_destructive ≤ 0.7`) to the big model and
the rest to the small one. Blocked by calibration: the two models' probabilities are not on the same scale
(`laya` gave 0.442 where `pplx` gave 0.9987 for the same command). Needs a per-model calibration step first.

**3. Fail-open is invisible, and that is the real dcg#183 lesson.** On this machine **6 of 189 decisions
(3.2%) were never judged** — 5 timeouts averaging 7.3 s and 1 `no_service` — and all six were allowed. The only
trace is a row in SQLite. Nobody watching the agent sees it. Options: a per-agent `DECISION_GUARD_FAIL_CLOSED`,
a viewer banner, and a "this command ran unjudged" counter in `decision-guard web`'s summary.

**4. The read-only fast path has the same adversarial weakness as dcg's rules.** GuardFall's finding — 10 of 11
agents bypassed by argv expansion, quoting, flag semantics, script files — applies to *any* pattern-based
layer, including ours. `readonly.rs` proves "every segment is read-only" by matching a tool/flag table; a
construction it fails to recognise goes to the model (safe), but a construction it *misreads* as read-only is
an allow with no model call. We have never adversarially tested it. This must be a benchmark category, not an
afterthought, and the README should stop implying the fast path is safe against a hostile command author.

**5. Windows is build-only.** We now ship a `.exe` from CI, but `install.sh` is bash and every hook path in it
is POSIX. Either write a PowerShell installer or label the artifact build-only in `dist/README.md`.

**6. No fallback service.** `active` selects one service; if it dies every command fails open. A second entry
used only when the first errors would cost ~20 lines in `resolve_service`.

**7. The cache ignores cwd (known, documented `shortcut:`).** `rm -rf build` judged in one directory is reused
in another. Fine for the current threat model, but the benchmark should report how often that key collides.

## What the numbers must contain

Not "precision and recall". The decision rule is `p_destructive ≥ ask_p`, so the honest report is:

- **PR curve over `ask_p` ∈ [0.3, 0.7]**, plus the operating point in force, so a threshold change can be
  argued from data.
- **Calibration**: reliability diagram and Brier score per model. Without this, "0.442 vs 0.9987" on the same
  command is uninterpretable.
- **Per-stage attribution**: recall of the rule layer alone, the read-only layer alone, and the model alone.
  GuardFall's point is that a single aggregate number hides which layer is carrying the result.
- **Latency P50/P95/P99 and cold-start**, per backend, including the timeout path as a real outcome.
- **Slices**: the 5 GuardFall bypass classes, plus "benign but scary-looking" (`grep 'rm -rf'`, `echo "mkfs"`)
  to measure false asks.

## Benchmark corpus: where the ground truth comes from

This is the expensive part and it is not a coding problem.

| Source | Use | Why / why not |
|---|---|---|
| **Our own `decisions.db`** (3174 distinct commands) | primary | Real commands from real sessions, already deduplicated. Needs human labels: `0 / 0.5 / 1` for `p_destructive`, plus a `bypass_class` tag where it applies. Sample ~600, stratified by the model's original label so `destructive` is not underrepresented. |
| **Hand-built bypass set** (50–80 cases) | primary | The only way to test the adversarial axis. Build each GuardFall class against *our* parser: `$(...)`, backticks, `bash -c`, quoted command words, flag aliases (`-fr` vs `-rf`), wrapper prefixes (`env`, `command`, `time`), heredoc and `python -c`. Each case states the expected class and whether the rule layer is allowed to miss it (many should reach the model, not be caught). |
| Public corpora (CyberSecEval, semgrep/shellcheck fixtures, OWASP command-injection payloads) | diversity for benign | Cheap volume, but they are injection payloads for *web* sinks, not agent shell habits. Cap their weight. |
| Generated by a model | **avoid** | We judge with a model; grading with model-written labels makes the benchmark circular. If used at all, for *variety only*, and every generated case needs a human yes/no before it counts. |
| dcg's `tests/corpus/canonical.toml` | **do not use** | See the next section. Its schema is worth copying; its content is not ours to take. |

Ground-truth cost is real: ~600 labels × ~40 s each ≈ **6–7 hours of one person's attention**, and the
`risky`/`destructive` boundary will disagree with itself unless the rubric is written first. Write the rubric
(six bullet rules with examples) *before* labelling, and label 50 cases twice to measure self-agreement.

## The dcg question: license blocks vendoring

dcg is **not MIT**. Its `LICENSE` is "MIT License (with OpenAI/Anthropic Rider)". The rider:

- grants **no rights at all** to OpenAI, Anthropic, their affiliates, or anyone acting on their behalf;
- defines "use" to include *benchmarking, testing, analysing, indexing, or incorporating into any dataset,
  training corpus, evaluation harness* — for those parties.

We are not a restricted party, so the MIT half applies to us. The problem is downstream: vendoring dcg packs
or its corpus into this repo would attach that rider to **every user of decision-guard**, including any who
work at those companies. That is a poison pill in an otherwise permissive project, and it also forbids using
their corpus inside our evaluation harness if a contributor happens to be in scope.

**Decision for the roadmap: take structure, not content.** What is worth copying is the *shape*, and that is
not copyrightable:

- pack registry with per-domain enable/disable, declared in data not code;
- a stable `rule_id` of `pack:pattern`, an explicit `mode` (`deny` / `ask` / `warn` / `log`) per rule;
- a TOML case schema with `id`, `category`, `input_kind`, `expected_decision`, `expected_log`;
- a `known_failing` field, scoped to dialects, that fails the suite when a marked case starts passing.

The pack *content* gets written here, from the benchmark's false-negative list, which is a better source
anyway: our misses are the packs we actually need, not another project's 177 files.

## Protocol matrix: how to organise the fixtures

Today: 22 cases in one file, each covering several agents. That reads well but cannot answer "did the Codex
contract change?".

Proposed shape:

```
rust/tests/
  protocol/
    matrix.rs            # one loop: for each (scenario, agent) assert the exact response
    fixtures/
      claude.json        # payload shape + expected stdout JSON / exit code / stderr
      codex.json
      copilot.json
      opencode.json
      pi.json
```

Scenarios: `allow`, `ask`, `deny`, `unjudged` (fail-open), `unjudged+fail_closed`, `malformed payload`,
`missing fields`, `unknown extra fields`, `prompt event`, `non-Bash tool`.
Assertions are **snapshot tests** (`insta`), so any contract change shows up as a diff rather than a silent
pass, and `cargo insta review` decides whether the change was intended.

Three rules for the matrix:

1. **Unknown fields must never change the decision** — a new field in an agent's payload is the likely shape
   of the next dcg#183.
2. **A missing field must fall back to a documented default, not a crash** — and the default must be tested.
3. **The adapter layer is tested separately** (`scripts/adapters/*.ts|js` under `node --test`), because the
   Rust tests cannot see what the wrapper does with `stdout.trim() === ""`.

## Phased plan

Estimates are one experienced person with agent assistance; "d" = focused days.

### Phase 0 — Evidence (2 weeks) · no production code changes

| Task | Commit | d | Depends |
|---|---|---|---|
| Rubric for `0 / 0.5 / 1` plus bypass classes | `docs/benchmark-rubric.md` | 1 | — |
| Label tool: read `decisions.db`, emit TOML cases, resume where you stopped | `bench/label.py` | 1.5 | rubric |
| Export + sampling (stratified, dedup, secret-masked) | `bench/cases/*.toml` | 1 | label tool |
| Hand-built bypass set, one file per class | `bench/cases/bypass-*.toml` | 2 | rubric |
| Runner: per-stage attribution, PR over `ask_p`, calibration, latency quantiles | `rust/src/bin/bench.rs` + `bench/run.py` | 3 | cases |
| First report | `docs/benchmark-2026-11.md` | 1 | runner |
| Human labelling, 600 cases (parallel, the long pole) | — | 5–6 | export |

**Acceptance:** `bench/run.py` reproduces the report on a clean checkout; the report states per-stage recall,
the PR curve, calibration per backend, and P50/P95/P99 for `laya`, `pplx-decider` and the timeout path. The
labelled set is committed (commands masked) so the number is reproducible by someone else.

### Phase 1 — Protocol matrix and fail-open visibility (3 weeks)

| Task | Commit | d | Depends |
|---|---|---|---|
| Extract fixtures per agent from the 22 existing cases | `tests/protocol/fixtures/*.json` | 2 | — |
| Matrix runner + snapshots for the 10 scenarios | `tests/protocol/matrix.rs` | 2.5 | fixtures |
| "Unknown field / missing field" cases per agent | same | 1 | matrix |
| `fail_open` reason column in `decisions.db` (`timeout` / `unreachable` / `no_service` / `parse`) | migrate + `store.rs` | 1.5 | — |
| Viewer: unjudged count in the summary + filter | `web.rs` | 1.5 | column |
| Per-agent `fail_closed` in `config.json` | `judge.rs`, `hook.rs` | 1.5 | — |
| Adapter contract tests (`node --test`) | `scripts/adapters/*.test.ts` | 2 | — |
| README: the unjudged path and the per-agent switch | `README.md` | 1 | all |

**Acceptance:** breaking one agent's fixture makes exactly one matrix case fail; a forced timeout is visible
in the viewer summary and filterable; `fail_closed` per agent is covered by a test that asserts a deny.

### Phase 2 — Rule layer as packs (3 weeks)

| Task | Commit | d | Depends |
|---|---|---|---|
| Pack trait + registry + per-domain enable/disable in `config.json` | `rust/src/packs/mod.rs` | 3 | Phase 0 report |
| Port the 4 deny entries, exfiltration and delete rules into packs (behaviour identical, proven by the 97 existing tests) | `rust/src/packs/{core,filesystem}.rs` | 2 | registry |
| Packs for the top false-negative clusters from Phase 0 | `rust/src/packs/{git,containers,cloud,database}.rs` | 5 | report |
| Pack-level benchmark slice | `bench/run.py --by-pack` | 1.5 | runner |
| Docs: pack schema, how to add one | `docs/packs.md` | 1 | packs |

**Acceptance:** model-call rate on the benchmark drops from ~59% to ≤35% with **no loss of destructive recall**;
each pack can be disabled individually and the drop is measured; the existing 97 tests still pass unchanged.

### Phase 3 — Audit integrity and approval surface (1.5 weeks)

| Task | Commit | d | Depends |
|---|---|---|---|
| Optional hash chain over `decisions` (`--chain`, off by default) | `store.rs` | 2 | — |
| `decision-guard verify-chain` subcommand | `main.rs` | 1 | chain |
| Viewer: "why" panel rendering the full decision path (rules → cache → model → threshold) | `web.rs` | 3 | Phase 1 column |
| README: threat model section, explicitly out-of-scope | `README.md` | 1 | — |

**Acceptance:** a hand-edited row is reported by `verify-chain`; the viewer shows every stage that was skipped
and why, for a real command.

### Phase 4 — Backends, cascade, fallback (2.5 weeks)

| Task | Commit | d | Depends |
|---|---|---|---|
| LM Studio chat-completions adapter (`Format::Chat`, JSON-schema output, `max_completion_tokens`) | `judge.rs` | 3 | — |
| Fallback service in `resolve_service` (used only when the active one errors) | `judge.rs` | 1 | — |
| Per-model calibration table from Phase 0, so probabilities are comparable | `judge.rs`, `docs/` | 2 | Phase 0 |
| Cascade: small model, escalate the `0.3–0.7` band to the configured large one | `judge.rs` | 3 | calibration, fallback |
| Backend comparison in the benchmark | `bench/run.py --by-backend` | 2 | adapter |
| PowerShell installer **or** explicit build-only note | `scripts/install.ps1` / `dist/README.md` | 2 | — |

**Acceptance:** the same 600-case set runs against all four backends and reports (accuracy, P95); the cascade's
mean latency is under 150 ms at equal recall to `pplx-decider` alone; killing the active service falls back
instead of failing open, proven by a test.

**Total: ~12 weeks** (Phase 0–1 are the critical path; Phases 2 and 4 can overlap once the benchmark exists).

## Risks and open questions

**R1 — dcg's license is a blocker, not a detail.** The rider forbids use by OpenAI/Anthropic and their agents
and names benchmarking as "use". Vendoring its packs or corpus would attach that to every user of this
project. *Position: structure only, no content.* If you disagree, get a written answer from the author first.

**R2 — The benchmark's ground truth is the schedule risk.** 600 labels is 6–7 hours of one person, and the
`risky`/`destructive` line is genuinely fuzzy. If labelling stalls, the whole roadmap stalls, because Phase 2's
acceptance criterion depends on it. Mitigation: start labelling in week 1, in parallel with the tooling.

**R3 — 1 s per model call is too slow for real sessions.** At the current 59% model-call rate a 30-command
session stalls 17.7 s. Two ways out: cut the rate (Phase 2) or cut the per-call cost (cascade / `laya`). The
cascade needs per-model calibration, which is why it sits in Phase 4 and not Phase 1.

**R4 — The read-only fast path is pattern-based and we have never attacked it.** Its proof is a tool/flag
table; a construction it misreads becomes a silent allow. This is the same class of weakness GuardFall found
in every agent it tested. Until the bypass set covers `readonly` specifically, the README's "proven read-only"
should be read as "proven against the patterns we know".

**R5 — Pack-ification may not pay.** `readonly.rs` (1490 lines) and `pyproof.rs` (1572) are the thick part of
the rule layer, not the 4-entry deny list. Turning 4 entries into packs is easy and buys little; the gain only
arrives if the new packs (git, containers, cloud) actually catch what the model currently decides. Phase 0's
false-negative list decides whether Phase 2 is worth 3 weeks — so the plan is written to be cut after Phase 0
if the list is thin.

**R6 — Windows remains half-supported.** The CI produces a `.exe`, `install.sh` is bash, and no hook path here
was tested on Windows. Publishing an artifact invites the assumption that it works.

**R7 — Per-agent `fail_closed` can break workflows.** Denying on a timeout means a slow model blocks work. It
must default to off, be per-agent, and be documented with the latency consequence.

**R8 — Model-based labelling would make the benchmark circular.** Any generated corpus needs a human pass;
otherwise we are grading the model with the model.

## Open questions for the user

1. Is vendoring dcg content acceptable to you at all, given R1? (My recommendation: no.)
2. Do you want the cascade (Phase 4) to be the default once calibrated, or an opt-in?
3. Windows: PowerShell installer, or drop the artifact and publish darwin+linux only?
4. Is 600 labelled cases the right size, or do you want the first pass at 200 to prove the tooling?
