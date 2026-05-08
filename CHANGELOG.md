# Changelog

All notable changes to Modus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 0.1.0. Pre-0.1.0 versions are not stable; the CLI
surface, action vocabulary, and corpus interface may change without
notice.

## [Unreleased]

## [0.4.0] — 2026-05-08

First non-pre-release tag. **Modus's autonomous loop closes the
full hypothesize → Quarry-persisted Candidate → Finding lifecycle
inside a single `run_autonomous_session` call, severity-gated.**
Operators drive the seeded-corpus autonomous flow from any
MCP host (Claude Desktop primarily) with zero Python driver
scripts and zero arguments beyond `target` and `bug_classes`.

The four invariants from ADR-0001 still hold under the new shape:
typed actions, formal Z3 consistency check, Quarry-backed corpus,
storage-enforced submission line. What changes from 0.3.0a1: the
agent now closes the Candidate→Finding promotion lifecycle that
operators previously had to drive via the Quarry CLI.

Live-verified end-to-end on OWASP Juice Shop with phi4:14b on
local Ollama (M1 Pro, 16 GB unified): 22-step run produced 5
Candidates and 4 auto-promoted Findings (high / high / medium
/ high). Severity gating verified live — the severity-info
Candidate correctly stayed un-promoted per the threshold rule.
The deterministic fallback proposer fired once at step 5 to
unblock the LLM's commitment gap; phi4 emitted four more
hypothesizes and three promotions on its own afterward.

What 0.4.0 ships with that 0.3.0a1 didn't:

- **Autonomous Candidate→Finding promotion.**
  `corpus.promote_finding` builtin in the default tool registry
  (9 default builtins, was 8). Severity-gated: medium/high/critical
  Candidates auto-promote inside the run; low/info stay
  un-promoted for operator review.
- **Agent-authored Candidates persist to Quarry.** The
  `hypothesize` action funnels into `db.upsert_candidate` via
  Quarry's new `candidate_create` MCP write tool. Module name
  `agent_hypothesize`; dedup key
  `<bug_class>:<sorted_evidence_refs>`; score derived
  monotonically from `severity_hint`.
- **Pattern-driven fallback proposer.** Per-bug-class detectors
  (`info_disclosure` / `auth_bypass` / `idor` / `sqli`) match
  against the run's observations and synthesize `Hypothesize`
  plus `corpus.promote_finding` proposals when the LLM keeps
  abdicating. Frontier models commit on their own — the fallback
  only fires for mid-size open-weight models hitting the
  decisiveness gap.
- **Auto-load run pool from Quarry corpus** (default
  `seed_from_corpus=True`). When the operator has run
  `quarry ingest --target X --source responses ...`, Modus
  pulls the ingested evidence back as structured records via
  Quarry's new `list_response_artifacts` MCP read tool and
  seeds the run's evidence pool automatically. From the MCP
  host it's just `run_autonomous_session(target=..., bug_classes=[...])`.
- **`recon_jsonl_path` argument** on the autonomous-session
  MCP tools for layering additional recon JSONL on top of the
  corpus auto-load (operators with recon they didn't ingest).
  Both sources combine, deduped by observation id.
- **`findings_promoted` in the result payload** — list of
  Findings the autonomous loop auto-promoted this run, in
  Quarry's `finding_promote` shape. Operators see the Findings
  landed without round-tripping through Quarry's CLI.
- **Submission policy revised.** ADR-0002 §4 / 0003 §6 / 0004
  amended; persistent `submission_line.md` memory updated. The
  structural firewall on *external submission* (no `submit` /
  `publish` / `post` / `report` / `report-to-h1` tool in the
  registry, adding one is off-limits) is preserved unchanged.
  The earlier "promotion is operator-only via the Quarry CLI"
  stance is dropped — Candidate→Finding is corpus-internal,
  not an outbound action against a third party.

Quarry compatibility: requires Quarry main as of 2026-05-08
(post pb3ck/quarry#109 finding_promote, #111 candidate_create,
#113 list_response_artifacts). Older Quarry servers connect
fine but the auto-load and promotion paths skip with INFO
warnings — the loop falls back to whatever
`recon_jsonl_path` JSONL or `initial_observation_ids` the caller
provided.

### Test posture

312 tests pass, 5 deselected (integration tests requiring
`amass`, `nuclei`, or a `quarry` binary). ruff format/check
clean, mypy strict clean across all 16 source modules.

### What v0.4.0 doesn't include

The external-operator-without-hand-holding human-test that's
been gating every prior tag. Modus's structural pieces are all
in place and verified live on local hardware; what's missing is
a third-party operator following `docs/quickstart.md` from a
clean machine. The doc-following dry-run we did before tagging
caught five friction points (stale tool count, missing
`quarry target add` step, payload field mismatches) and fixed
them — but a real external user is still the unwritten test.
The non-pre-release tag commits to the current API shape;
breaking changes will land at v0.5.0+ in the usual semver way.

### Issues closed at 0.4.0

- v0.4.0: #12, #13, #14, #16, #18, #21, #23, #26
- Plus alphas: 0.4.0a1 (#12, #13, #14, #16, #18), 0.4.0a2 (#21, #23)

For the alpha-by-alpha narrative see the [0.4.0a1] and [0.4.0a2]
sections below; both alphas predated this release on
2026-05-08.

## [0.4.0a2] — 2026-05-08

Operator-UX bridge alpha. Closes the gap between the v0.4.0a1
chain-closure work (autonomous Candidate→Finding loop verified
live) and a real external-operator-without-hand-holding flow:
the autonomous-session MCP tools now accept the operator's
recon as input — either via an explicit JSONL path or auto-loaded
from the Quarry corpus the operator already ingested into.

What 0.4.0a2 ships with that 0.4.0a1 didn't:

- **Auto-load from Quarry corpus** (default behaviour). When the
  operator has run `quarry ingest --target X --source responses
  /path/to/recon.jsonl`, Modus's autonomous loop pulls the
  ingested evidence back as structured records via Quarry's new
  `list_response_artifacts` MCP read tool and seeds the run's
  evidence pool automatically. From the MCP host it's just
  `run_autonomous_session(target=..., bug_classes=[...])` —
  no path arguments needed.
- **`recon_jsonl_path` argument** for layering additional
  recon JSONL on top of the corpus auto-load (operators with
  recon they didn't ingest, or who want the seeded-corpus run
  without the ingest step). Both sources combine, deduped by
  observation id.
- **`seed_from_corpus: bool` argument** (default `true`) so
  operators who explicitly want a cold-start run can opt out.
- **`docs/quickstart.md` §4 rewritten** with the recon →
  ingest → autonomous workflow. Operator-friendly default:
  one `quarry ingest` call, then a sentence to Claude Desktop.

What's new since 0.4.0a1 (full detail under "Added"/"Changed"
below):

- `corpus.list_response_artifacts` Quarry MCP read tool
  (Quarry-side, see Quarry CHANGELOG).
- `QuarryMcpClient.list_response_artifacts(...)` async method.
- `ResponseArtifact` dataclass.
- `AgentLoop.run(seed_from_corpus=True, initial_observation_ids=...)`
  — both new parameters.
- `_seed_observations_from_jsonl` server-side helper that
  materialises a `responses`-shape JSONL into SessionObservations
  for the autonomous-loop run pool.
- 17 new tests across `test_corpus.py`, `test_agent.py`, and
  `test_server.py`. 309 pass total (was 294 in 0.4.0a1).

### Added

- **`seed_from_corpus` argument on `run_autonomous_session` /
  `start_autonomous_session` MCP tools** (default `true`). When
  enabled, the autonomous loop calls Quarry's
  `list_response_artifacts` MCP read tool at the start of each
  run, materializes the structured records into
  `SessionObservation`s, and folds their ids into
  `initial_observation_ids` — so any responses-shape evidence
  the operator has already ingested into Quarry as a `responses`
  source becomes citable in `hypothesize` actions automatically.
  Operator UX: "if you ingested recon into Quarry, the agent
  uses it." No JSONL path argument required. Older Quarry
  versions that don't expose `list_response_artifacts` skip the
  auto-load (soft-warned via INFO log) and the loop proceeds
  with whatever pool the caller provided. The `recon_jsonl_path`
  argument still works and combines with the corpus auto-load
  (deduped by observation id) for operators who want both.
- **`QuarryMcpClient.list_response_artifacts(target, limit?,
  max_body_bytes?)`** — async method wrapping Quarry's MCP read
  tool (Quarry main as of 2026-05-08, post pb3ck/quarry#114).
  Returns `list[ResponseArtifact]`. `list_response_artifacts`
  joins `OPTIONAL_TOOLS`.
- **`ResponseArtifact` dataclass** in `modus.corpus`
  (`observation_id`, `url`, `status`, `response_headers`,
  `response_body`, `body_truncated`, `body_full_len`,
  `ingested_at`, `sha256`).
- **`AgentLoop.run(seed_from_corpus=True)`** parameter that
  drives the auto-load. `_seed_from_corpus(target_name)` opens
  a Quarry MCP client via `session.with_quarry()`, materializes
  artifacts as observations, and returns the seeded id set.
  Failures (older Quarry, target not found, Quarry binary
  missing) are logged at INFO/WARNING and treated as
  empty-pool — never raise.
- **`docs/quickstart.md` §4b** updated to reflect auto-load as
  the default — operators don't need to pass any path argument
  if they've already ingested recon into Quarry.

### Changed

- **`run_autonomous_session` result payload** gains
  `seed_from_corpus` (echoes the operator's choice) alongside
  the existing `seeded_observation_count` (count from the
  optional `recon_jsonl_path` JSONL). The two fields disambiguate
  the two seeding paths.

- **`recon_jsonl_path` argument on `run_autonomous_session` /
  `start_autonomous_session` MCP tools.** Operators driving
  Modus from an MCP host (Claude Desktop, etc.) can now pass
  the path to a `responses`-shape JSONL file (records of
  `{url, status, headers, body}` — same shape Quarry's
  `responses` ingest adapter accepts) and Modus will materialize
  each record into a `SessionObservation`, populate the
  autonomous loop's `initial_observation_ids`, and proceed —
  no Python driver script needed. The seeded observations are
  citable in `hypothesize` actions in the same run and feed the
  deterministic fallback proposer. Closes the operator-UX gap
  surfaced during the v0.4.0a1 live verification: the autonomous
  loop's per-run-pool firewall meant operators couldn't drive
  the seeded-corpus flow over MCP without bypassing the tool
  surface entirely. The result payload reports
  `seeded_observation_count` and (on failure) a `recon_warning`
  string with a human-readable diagnosis. Empty / missing path
  is a no-op, preserving prior behavior.
- **`docs/quickstart.md` §4** rewritten with the recon →
  ingest → autonomous workflow, including a 30-line Python
  recon driver an operator can copy-paste against any HTTP
  target.

## [0.4.0a1] — 2026-05-08

Autonomous Candidate→Finding alpha. The autonomous loop now
closes the full hypothesize → Quarry-persisted Candidate →
Finding lifecycle inside a single `run_autonomous_session`
call, severity-gated per the v0.4.0 promotion policy. The
external-submission firewall (no `submit`/`publish`/`post`/
`report` tool in the registry, adding one is off-limits) is
preserved.

Live-verified end-to-end on OWASP Juice Shop with phi4:14b on
local Ollama, against a corpus seeded with 38 recon evidence
chunks: 22 steps, 5 Candidates landed, 4 auto-promoted to
Findings (high / high / medium / high), 1 severity=info
Candidate correctly stayed un-promoted per the threshold rule.
The deterministic fallback proposer fired exactly once at step
5 to unblock the LLM's commitment gap; phi4 emitted four more
hypothesizes and three promotions on its own afterward.

What 0.4.0a1 ships with that 0.3.0a1 didn't:

- **`corpus.promote_finding` builtin** in the default tool
  registry (9 default builtins, was 8 in 0.3.0a1). Backed by
  Quarry's MCP `finding_promote` write tool.
- **Agent-authored Candidates persist to Quarry** via the new
  `candidate_create` MCP write tool (Quarry-side, see Quarry
  CHANGELOG). The `hypothesize` action handler funnels into
  `db.upsert_candidate` so the resulting row is byte-identical
  to what `analyze_*` would have produced for the same inputs.
  Module name `agent_hypothesize`; dedup key
  `<bug_class>:<sorted_evidence_refs>`; score derived
  monotonically from `severity_hint`.
- **Severity-gated auto-promotion**: medium/high/critical
  Candidates auto-promote inside the run; low/info stay
  un-promoted for operator review.
- **Pattern-driven fallback proposer** that closes the
  decisiveness gap mid-size open-weight models hit on the
  autonomous loop. Per-bug-class detectors
  (info_disclosure / auth_bypass / idor / sqli) match against
  the run's observations and synthesize `Hypothesize` plus
  `corpus.promote_finding` proposals when the LLM keeps
  abdicating. Frontier models reach the lifecycle on their
  own — the fallback only fires for local models.
- **`AgentLoop.run(initial_observation_ids=...)`** parameter
  to seed the run pool from operator recon.

### Added

- **Pattern-driven fallback proposer** (`modus.evidence_patterns.detect_evidence_patterns`
  + `AgentLoop._fallback_proposals`). Mid-size open-weight models
  (gemma2:9b, qwen2.5-coder:14b, phi4:14b) reliably hit a
  "decisiveness gap" in the autonomous loop — they explore
  competently but won't emit `hypothesize` even when their own
  action history contains textbook evidence, terminating
  `empty_pruning_streak` instead of producing Candidates. The
  fallback proposer closes that gap deterministically: per-bug-
  class detectors (info_disclosure version banners and secret
  hints; auth_bypass same-path status differentials; idor
  enumerable-id user-data dumps; sqli DB-error and tainted-input
  result-shape divergence) match against the run's observations
  and synthesize `Hypothesize` proposals when the LLM keeps
  abdicating. A second fallback layer synthesizes
  `corpus.promote_finding` `Tool` proposals against pending
  medium/high/critical Candidates the LLM didn't auto-promote on
  schedule. Both fallbacks flow through the same Z3-prune-rank-
  execute pipeline as the LLM's batch; fallback proposals are
  prepended so the deterministic safety net wins ranking when it
  fires. The LLM proposer keeps primacy — the fallback only
  emits when activation gates (warmup steps, quiet-after-hypothesize
  window, single-fire dedup) are satisfied. Live-tested on Juice
  Shop with phi4:14b: prior runs produced 0 Candidates; with the
  fallback, the loop produces multiple Candidates across
  info_disclosure / idor / auth_bypass and auto-promotes the
  severity-medium-or-higher ones to Findings.
- **`AgentLoop.run(initial_observation_ids=...)`** — parameter
  to seed the run's evidence pool with operator-provided
  observation ids. The autonomous loop's `Hypothesize`
  precondition gates `evidence_refs` to "this run's pool only"
  to prevent cross-run bleed between sequential autonomous
  sessions. Treating operator recon as part of *this* run's
  starting state keeps the firewall meaningful while letting the
  agent cite the recon data the operator did up front (typically
  httpx, katana, or `responses`-shape JSONL ingested into Quarry
  by the operator before the autonomous run starts).
- **Autonomous Candidate→Finding promotion.** New
  `corpus.promote_finding` builtin in the default tool registry,
  dispatching to `modus.builtins.corpus.promote_finding`, which
  calls Quarry's MCP `finding_promote` write tool (Quarry ≥ 0.2 —
  older Quarry servers connect but surface
  `CorpusToolsMissingError` at promote-call time with a clear
  upgrade message). Per-tool precondition gates the Candidate id
  on this run's observation pool (`state.known_evidence`) so
  cross-run promotion is structurally impossible — that remains
  the operator's `quarry finding promote` CLI verb.
- **Severity-gated proposer rule.** The system prompt instructs
  the LLM to emit `corpus.promote_finding` on the step after a
  `hypothesize` whose `severity_hint` was `medium`, `high`, or
  `critical`. Severity-`low` and severity-`info` Candidates stay
  un-promoted for operator review. Promoting a low/info Candidate
  is a policy violation surfaced in the closing-rule block.
- **`Finding` dataclass** in `modus.corpus` mirroring Quarry's
  `finding_promote` response (`id`, `candidate_id`, `target_id`,
  `severity`, `title`, `status`, `created_at`).
- **`QuarryMcpClient.promote_finding(...)`** — async method
  wrapping the MCP call. Added to the `CorpusClient` Protocol;
  `StubCorpusClient` returns a deterministic `Finding` for tests.
- **`modus.builtins` package** — new module hierarchy hosting
  the first-party builtin callables. Currently ships
  `modus.builtins.corpus.promote_finding`; the six typed-action
  callables (`probe`, `request`, etc.) remain stub paths
  pending the registry-dispatch migration.
- **`hypothesize` action persists to Quarry.** The action
  handler in `ModusServer._execute_action` now writes the
  agent-authored Candidate to Quarry's corpus via the new
  `QuarryMcpClient.create_candidate` (Quarry MCP write tool
  `candidate_create`, requires Quarry ≥ candidate_create). The
  Candidate's `module` is `agent_hypothesize`; the dedup `key`
  is `<bug_class>:<sorted_evidence_refs>` so re-emitting the
  same hypothesis upserts in place; the `score` maps the
  `severity_hint` onto a monotone scale (info=0.1 … critical=0.95)
  for sort order within the module's output. The action result
  now includes `candidate_id` (Quarry-resolvable UUID), enabling
  next-step `corpus.promote_finding`. Older Quarry servers
  return `candidate_id=null` and a `persistence_error` field
  rather than failing the action.
- **`QuarryMcpClient.create_candidate(...)`** — async method
  wrapping the MCP `candidate_create` call. Added to the
  `CorpusClient` Protocol; `StubCorpusClient.create_candidate`
  returns a deterministic `Candidate` for tests.
  `candidate_create` joins `OPTIONAL_TOOLS`.
- **`CorpusState.run_candidates`** — frozenset of Candidate ids
  produced by `hypothesize` actions in the current autonomous
  run. Populated by `AgentLoop.run` from each step's result
  payload; consumed by `_promote_finding_preconditions` (now
  fixed to gate on the right pool — was checking
  `state.known_evidence`, which `hypothesize` doesn't populate).

### Changed

- **Default registry size: 8 → 9.** The `corpus.promote_finding`
  builtin joins the six typed-action builtins and the two recon
  shells (`amass.enum`, `nuclei.scan`).
- **Submission policy** (ADR-0002 §4, ADR-0003 §6, ADR-0004
  "Submission line"): the structural firewall on *external
  submission* (no `submit`/`publish`/`post`/`report`/
  `report-to-h1` tool in the registry, adding one is off-limits)
  is unchanged. The earlier "promotion is operator-only via the
  Quarry CLI" stance is dropped — promotion is now a corpus-
  internal action the autonomous loop performs. Submission to
  bug-bounty programmes remains the operator's, performed
  outside Modus.
- **README, ROADMAP, ADRs 0002/0003/0004, `docs/quickstart.md`,
  proposer system prompt** all amended to reflect the new
  promotion policy. ROADMAP gains a Milestone 7 entry.

## [0.3.0a1] — 2026-05-07

Tools-first alpha. The closed v0.1 typed-action vocabulary is
extended with an open `ToolRegistry` per ADR-0004; the agent
reaches recon shells (`amass.enum`, `nuclei.scan`), the typed-
action surface (`probe`, `request`, `compare`, `differential`,
`annotate`, `hypothesize`), Quarry's analytical and read tools,
and any operator-declared shell or MCP-passthrough tool. The
autonomous loop covers recon → exploit → evidence in one
unbroken run.

The four invariants from ADR-0001 still hold under the new
shape: typed actions (every emission validated by Pydantic),
formal consistency check (Z3 dispatches via per-tool
preconditions), Quarry-backed corpus (default storage; tools
register as `corpus.*` entries), storage-enforced submission
line (no `submit`-shaped *tool* in the registry; adding one is
project-policy off-limits). What changes: the trust boundary
moves from the action union's discriminator to the registry's
contents.

Verified live against OWASP Juice Shop on local hardware: full
recon → exploit → hypothesize cycle through gemma2:9b producing
seven distinct Candidates with four-section rationales
(Vulnerability / Exploit / Evidence / Impact) and accurate
severity_hint selection.

What 0.3.0a1 ships with that 0.1.0a1 didn't:

- 21 always-present MCP tools (was 18) — adds
  `start_autonomous_session`, `poll_autonomous_session`,
  `cancel_autonomous_session` (the async session pattern from
  #1) plus the generic `tool` dispatch surface.
- Open `ToolRegistry` with eight default builtins (six typed-
  action + two recon shell), loadable extensions from the scope
  file's `tools` block.
- `ToolExecutor` dispatching shell / builtin / mcp-stub backends
  with output capping, per-tool timeouts, scoped env, and full
  audit-grade `ToolObservation` records.
- Per-run observation-id gating on `Hypothesize.evidence_refs`
  (no cross-run bleed).
- Strict dedup in the agent loop (duplicate-survivor steps
  skipped, not re-executed).
- Pre-warm proposer LLM at server startup (cold-load tax moves
  out of the operator's first call).
- Bug-class evidence pattern library covering eight classes with
  per-class canonical severity defaults — fixes smaller models
  defaulting to `severity_hint="info"` on clear `critical`
  findings.
- Submission policy revised: structural firewall stays, verbal
  ban dropped — rationales may recommend operator promotion.

The full change set since 0.1.0a1 is catalogued below.

### Architecture

- **Tools-first action grammar (ADR-0004).** The closed v0.1
  typed-action vocabulary is extended with a single open
  primitive — `Tool(name, args)` — backed by an operator-
  configurable `ToolRegistry`. The agent reaches recon shells
  (`amass.enum`, `nuclei.scan`), Modus's typed-action builtins
  (`probe`, `request`, `compare`, `differential`, `annotate`,
  `hypothesize`), and any custom shell or MCP tool the operator
  declares in their scope file's `tools` block. Closes #6, #7, #8,
  #9, #10.
  - **Six small-fix milestones land here** that together pivot
    Modus from "autonomous within the focused-attack stage" to
    "autonomous across recon → exploit → evidence":
    1. `Tool` action variant in the typed grammar (#6).
    2. `ToolRegistry` + `ToolSpec` with three invocation
       backends (`shell` / `mcp` / `builtin`) and a JSON-Schema-
       declared args shape; loadable from the scope file's
       `tools` block (#7).
    3. Generic `ToolExecutor` dispatching shell (asyncio
       subprocess with placeholder-substituted argv, 64 KB
       output cap, per-tool timeout, scoped env), builtin
       (dotted-path resolution + invocation), and MCP-passthrough
       (stub for v0.3.0; real client-side implementation
       deferred) (#8).
    4. Consistency layer dispatches `Tool` actions through the
       registry's per-tool preconditions; `tool_registered:<name>`,
       `tool_args_missing_required:<tool>:<arg>`, and
       `tool_args_unknown_field:<tool>:<arg>` join the
       precondition-label vocabulary (#9).
    5. `amass.enum` and `nuclei.scan` first-party builtins with
       scope-gating preconditions; `tool` MCP surface lets
       operators dispatch any registered tool from the
       verified-action conversation; `ModusServer` constructed
       with a `ToolExecutor` that routes through the registry
       (#10).
    6. README / ADR-0002 §4 / ADR-0003 §6 amended to reflect the
       agent-first / tools-first framing; ADR-0004 published as
       the load-bearing decision record (#11).
- **Submission line stays structural under the new grammar.** No
  `submit`/`publish`/`post`/`report` *tool* is registered in the
  default registry, and adding one is project-policy off-limits.
  The agent can emit a `Tool` action with any name, but the
  consistency layer rejects with `tool_registered:<name>` if it
  isn't in the registry. Same firewall guarantee as the closed-
  grammar version, surfaced through registry membership rather
  than the action-union discriminator.

### Changed

- **Submission policy revised.** The structural firewall (no
  `submit`/`publish`/`post` action in the grammar, terminal state
  is a Candidate in storage, promotion to Finding is the operator's
  `quarry finding promote`) is unchanged and remains a committed
  invariant. The verbal ban — "Modus never tells the operator to
  submit" — is dropped. A `hypothesize` rationale, a session
  summary, or any operator-facing output may now legitimately
  recommend the operator promote a Candidate or submit it to a
  bug-bounty programme. The agent's gate is structural (no outbound
  action exists), not communicative. Affects: README, ROADMAP,
  proposer system prompt, ADR-0002 §4, ADR-0003 §6, quickstart,
  `SessionCandidate` docstring.
- Pulled `qwen2.5-coder:7b`, `qwen2.5-coder:14b`, `qwen3:8b`,
  `phi4:14b`, and `gemma2:9b` against the proposer's prompt; landed
  on `gemma2:9b` as the practical sweet spot for local autonomous
  loops on M1 Pro / 16 GB unified memory (4/4 sections in rationale,
  severity=critical, ~19s warm inference per step).

### Added

- Closing-rule block in proposer's per-step prompt: when bug_classes
  is non-empty, instructs the model to emit `hypothesize` once
  recent observations evidence one of them, with the four-section
  rationale shape (Vulnerability / Exploit / Evidence / Impact) and
  deliberate `severity_hint` selection.
- `request_body` excerpt in step history summaries so the proposer
  can tell SQLi from a normal login (`response_body` excerpt alone
  is not enough — the contrast lives in the *request*).
- `(host, port, tls)` triples rendered explicitly in the proposer's
  scope block. Smaller models stop emitting URL-form `target` values
  and dropping `port`/`tls`.
- Defensive clause: `rationale` field MUST be non-empty.

## [0.1.0a1] — 2026-05-07

First alpha. Modus is an autonomous offensive agent delivered as
an MCP server; the operator drives it from any MCP-aware host
(Claude Desktop primarily). The propose-prune-rank-execute loop
runs end-to-end inside the autonomous-session MCP tool. The
verified-action surface, Quarry passthroughs, and
autonomous-session tools are all always-present in the tool list
per ADR-0003. Verified live against OWASP Juice Shop:
end-to-end recon, IDOR-shaped differentials, the submission line
held across every run.

The four invariants — typed action vocabulary, formal
consistency checking, Quarry-backed corpus, storage-enforced
submission line — are committed surfaces. Everything else may
shift between alpha releases until 1.0.

The full change set since the empty-skeleton commit is
catalogued in the section below.

## Pre-release work (rolled into 0.1.0a1)

### Added

- Initial repository skeleton: README, ROADMAP, LICENSE, CONTRIBUTING,
  SECURITY, CHANGELOG, AUTHORS.
- Python package layout under `src/modus/`.
- `pyproject.toml` with `uv`-managed dependencies.
- Documentation scaffolding under `docs/`.
- Architectural decision records:
  [`docs/adr/0001-typed-action-vocabulary.md`](./docs/adr/0001-typed-action-vocabulary.md)
  and
  [`docs/adr/0002-autonomous-loop-and-verifier-driven-search.md`](./docs/adr/0002-autonomous-loop-and-verifier-driven-search.md).
- Corpus interface contract pinned to Quarry's MCP surface:
  [`docs/corpus-interface.md`](./docs/corpus-interface.md).
- Typed action vocabulary as a Pydantic discriminated union:
  `Probe`, `Request`, `Compare`, `Differential`, `Annotate`,
  `Hypothesize` (`src/modus/actions.py`).
- Z3-backed consistency layer with batch pruning
  (`src/modus/consistency.py`).
- `ScopePolicy` model for operator-defined scope envelopes
  (`src/modus/scope.py`).
- `CorpusClient` protocol, real `QuarryMcpClient` (drives
  `quarry mcp` over MCP stdio JSON-RPC, verifies the required tool
  surface on connect, parses every tool result into pinned Python
  types where Quarry's schema is stable and into raw dicts where
  it's flagged as in-flux), and `StubCorpusClient` for tests
  (`src/modus/corpus.py`). Includes the full corpus error
  hierarchy: `CorpusUnavailableError` for spawn failures,
  `CorpusToolsMissingError` for schema mismatches,
  `CorpusToolError` for tool-side failures, `CorpusTimeoutError`
  for per-call timeouts, `CorpusSchemaError` for malformed
  payloads.
- `Proposer` protocol + `AnthropicProposer` skeleton (cache zones
  pinned) + deterministic `FixedProposer` for tests
  (`src/modus/proposer.py`).
- `AgentLoop` skeleton with budget, audit-record types, and
  per-step context wiring (`src/modus/agent.py`).
- `modus action validate` CLI subcommand wired to the consistency
  layer; runs end-to-end on a JSON spec file.
- `modus corpus status` CLI subcommand: opens a Quarry MCP
  session, prints schema version and per-entity counts, exits
  with distinct codes for each corpus failure category.
- `modus run` CLI subcommand stubbed pending Milestone 4.
- Tests for action vocabulary, consistency layer, scope policy,
  CLI surface, and the corpus client. The corpus contract tests
  drive a duck-typed fake `mcp.ClientSession` through the same
  code path the real session flows through, exercising tool
  verification, payload parsing, error mapping, and timeout
  behaviour without requiring Quarry to be installed.
- `pytest -m integration` opt-in test marker for tests that
  drive a real `quarry mcp` subprocess against a tmpdir corpus.
  Skipped by default; documented in `CONTRIBUTING.md`.

### Architecture

- **Modus is delivered as an MCP server.** The agent's
  autonomous loop runs end-to-end inside Modus when the host
  invokes its autonomous-session tool; Modus also exposes a
  per-action verified-tool surface for hosts/operators who want
  to drive each step explicitly. Both surfaces are always
  present in the MCP tool list. The operator drives Modus from
  any MCP-aware host (Claude Desktop primarily). README and
  ROADMAP rewritten around this shape.
- ADR-0003
  ([`docs/adr/0003-host-driven-loop-mcp-server-boundary.md`](./docs/adr/0003-host-driven-loop-mcp-server-boundary.md))
  documents the new architecture. ADR-0002 is extended (not
  superseded) — the autonomous loop's internals
  (N-sampling, Z3 pruning, ranking, budget-bounded execution,
  cache-zone discipline) still apply; what changes is that the
  loop runs inside an MCP tool handler rather than a CLI.
- New `docs/mcp-host-integration.md` covers operator-facing
  setup for Claude Desktop, Claude Code, and other MCP-aware
  hosts.
- M3 (MCP server with verified-action surface, Quarry
  passthroughs, and registered-but-not-yet-implemented
  autonomous-session tools) lands. New modules:
  - `src/modus/server.py` — the MCP server, registering 18
    tools (6 verified-action + 10 Quarry-passthrough + 2
    autonomous-session). Each verified-action call is Z3-gated
    before any side effect; rejection surfaces the failed
    precondition names back to the host.
  - `src/modus/session.py` — per-MCP-server state:
    `LlmProviderConfig.from_env`, `ServerSession` (immutable
    scope, lazy Quarry connection, in-memory observation and
    Candidate pools), `SessionObservation`, `SessionCandidate`.
    Quarry's MCP surface is read-only at v0.1, so observations
    Modus produces during a session live in this in-memory
    pool until the operator ingests them out of band.
  - `src/modus/executor.py` — async HTTP executor for the
    `Request` action. Handles network-level failures defensively
    (captures into the observation's `error` field) and
    truncates non-text response bodies at 64 KB so MCP results
    stay reasonable.
- New `modus mcp --scope <path>` CLI subcommand replaces the
  old `modus run` stub. Accepts `MODUS_SCOPE_PATH` from env as
  an alternative to the flag.
- New `pytest -m integration` marker scope covers the corpus
  client; the M3 server's contract tests run against a fake
  corpus and a recording HTTP transport without standing up an
  MCP transport.

### Removed

- The `modus run` CLI subcommand stub, replaced by `modus mcp`.
  Operators no longer drive Modus from the CLI; they drive it
  through their MCP host (Claude Desktop primarily).

### Added (M4 — autonomous-session loop)

- `src/modus/proposer.py` re-targeted from a stub to two real
  provider-portable implementations: `AnthropicProposer` (Messages
  API with prompt-cache control on the system prefix) and
  `OpenAICompatibleProposer` (Chat Completions API with optional
  `base_url` for OpenAI / Ollama / vLLM / OpenRouter and graceful
  fallback when the upstream rejects `response_format`). Shared
  prompt construction and response parsing in `_LlmProposerBase`;
  malformed model output returns `[]` rather than crashing the
  loop. New `make_proposer(llm, scope)` factory dispatches on
  provider config.
- `src/modus/agent.py` re-targeted from a skeleton to the full
  propose-prune-rank-execute loop. `AgentLoop.run(target_name,
  bug_classes, objective?)` runs end-to-end with a `Budget`
  (max_steps, max_wall_seconds, max_consecutive_empty_steps)
  and returns a `SessionRecord` with every sampled proposal,
  every Z3 verdict, and every executed action. v0.1 ranking
  heuristic is "first survivor wins"; the ranking surface is
  in place for richer heuristics in v0.2+.
- The `run_autonomous_session` and `propose_actions` MCP tool
  handlers in `src/modus/server.py` are wired to the loop. The
  autonomous session shares the verified-action surface's
  executor (`_execute_action`) by dependency injection, so the
  same Z3 → executor path runs whether the action was emitted
  by Modus's own proposer or by the host's LLM.
- The HTTP executor's User-Agent is now operator-configurable
  via `ScopePolicy.user_agent` (default conservative
  `Modus/{version}`, no project URL). Per-request action headers
  override the scope default.
- New tests: `tests/test_proposer.py` (parser robustness,
  Anthropic + OpenAI-compatible round-trips with fake clients,
  factory dispatch), `tests/test_agent.py` (happy path, empty
  streak termination, step budget cap, executor error handling,
  session-record serialisation), plus expanded
  `tests/test_server.py` coverage of the autonomous tool
  handlers.

140 tests pass, 3 integration tests deselected. ruff clean, mypy
strict clean.

### Changed

- `README.md` and `ROADMAP.md` rewritten around the autonomous
  agent framing. Modus is no longer documented as "session at a
  time, with the operator present"; the loop is autonomous within
  scope, and the only hard human gate is on the output side
  (Quarry's `quarry finding promote`, never Modus). The
  submission line — "never submit, never tell the operator to
  submit" — is the explicit invariant.

- `.github/` workflows for lint and test on push.
- `.gitignore` covering Python, editor, and OS artifacts.
