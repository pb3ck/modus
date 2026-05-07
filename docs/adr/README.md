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
