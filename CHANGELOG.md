# Changelog

All notable changes to Modus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 0.1.0. Pre-0.1.0 versions are not stable; the CLI
surface, action vocabulary, and corpus interface may change without
notice.

## [Unreleased]

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
