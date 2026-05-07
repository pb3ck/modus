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
- `CorpusClient` protocol + `QuarryMcpClient` stub +
  `StubCorpusClient` for tests (`src/modus/corpus.py`).
- `Proposer` protocol + `AnthropicProposer` skeleton (cache zones
  pinned) + deterministic `FixedProposer` for tests
  (`src/modus/proposer.py`).
- `AgentLoop` skeleton with budget, audit-record types, and
  per-step context wiring (`src/modus/agent.py`).
- `modus action validate` CLI subcommand wired to the consistency
  layer; runs end-to-end on a JSON spec file.
- `modus run` CLI subcommand stubbed pending Milestone 4.
- Tests for action vocabulary, consistency layer, scope policy,
  and CLI surface.

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
