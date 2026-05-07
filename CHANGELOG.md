# Changelog

All notable changes to Modus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 0.1.0. Pre-0.1.0 versions are not stable; the CLI
surface, action vocabulary, and corpus interface may change without
notice.

## [Unreleased]

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
