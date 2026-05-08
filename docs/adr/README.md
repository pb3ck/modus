# Architectural Decision Records

ADRs document significant design choices for Modus.

## Format

Each ADR is a single Markdown file named `NNNN-short-slug.md` where
`NNNN` is a four-digit sequential number and `short-slug` is a
hyphenated description.

Every ADR has the following sections:

- **Status** — proposed, accepted, deprecated, superseded.
- **Date** — YYYY-MM-DD when the ADR was last updated.
- **Supersedes / Superseded by** — links to related ADRs.
- **Context** — what problem the decision addresses, including
  any relevant prior state.
- **Decision** — what was decided, in enough detail that a future
  contributor can understand the choice without reading a wiki.
- **Consequences** — positive, negative, and neutral effects of
  the decision.
- **Alternatives considered** — what else was on the table and
  why it was rejected.
- **References** — links to papers, prior art, or related
  documents.

## Index

- [`0001-typed-action-vocabulary.md`](./0001-typed-action-vocabulary.md)
  — actions are drawn from a typed grammar and validated by an
  SMT solver before dispatch.
- [`0002-autonomous-loop-and-verifier-driven-search.md`](./0002-autonomous-loop-and-verifier-driven-search.md)
  — the autonomous loop's shape: N-sampling with SMT pruning,
  prompt-cache-aware context. Extended by ADR-0003 (the loop
  now runs inside an MCP tool handler).
- [`0003-host-driven-loop-mcp-server-boundary.md`](./0003-host-driven-loop-mcp-server-boundary.md)
  — Modus is an autonomous agent exposed as an MCP server. The
  autonomous-session tools and verified-action tools are both
  always present. Extends ADR-0002.
- [`0004-tools-first-action-grammar.md`](./0004-tools-first-action-grammar.md)
  — open registry-keyed action vocabulary with shell, MCP-passthrough,
  and builtin backends. The closed typed-action union from ADR 0001
  becomes a fast path inside the open grammar.
- [`0005-recon-mode-scope-and-two-phase-autonomous-session.md`](./0005-recon-mode-scope-and-two-phase-autonomous-session.md)
  — recon-mode scope (read-only OSINT under wildcard authorization)
  + two-phase autonomous session (agent proposes Tier A/B/C
  expansion, operator commits in one bounded review). Status:
  proposed.
- [`0006-engagement-coordinator-session-of-sessions.md`](./0006-engagement-coordinator-session-of-sessions.md)
  — engagement coordinator: deterministic state machine driving
  LLM decisions within bounded transitions; persisted in Quarry;
  parallel CLI + MCP surfaces. Generalises the autonomy claim
  from "within a session" (ADR 0001/0002) to "across a multi-
  cycle engagement." Depends on ADR 0005. Status: proposed.

## When to write an ADR

Write an ADR when the decision:

- Changes the action vocabulary, the consistency checker, the
  corpus interface, or the promotion lifecycle.
- Adds or removes a major dependency.
- Changes how Modus interacts with LLM providers, MCP servers,
  or external tools at the architectural level.
- Resolves a question that was previously contested.

Don't write an ADR for:

- Routine refactoring.
- Bug fixes.
- Documentation updates.
- Choices that are obviously reversible without consequence.

When in doubt, write the ADR. They're cheap to produce and
expensive to omit.
