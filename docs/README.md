# Modus Documentation

This directory holds Modus's design documentation. Documents are
roughly grouped as follows:

- **Architectural Decision Records (ADRs)** under [`adr/`](./adr/).
  These document significant design choices with their context,
  alternatives considered, and consequences. ADRs are immutable
  once accepted; later decisions that supersede them get their
  own ADR.
- **Reference documentation** at the top level. The action
  vocabulary, the corpus interface, and the consistency-check
  semantics will each have a reference document once the
  corresponding code lands.
- **Operator documentation** for installing, configuring, and
  running Modus, also at the top level. Targeted at someone who
  wants to use Modus rather than work on it.

## Current documents

- [`adr/0001-typed-action-vocabulary.md`](./adr/0001-typed-action-vocabulary.md)
  — the foundational architectural decision: actions are typed
  rather than free-form.
- [`adr/0002-autonomous-loop-and-verifier-driven-search.md`](./adr/0002-autonomous-loop-and-verifier-driven-search.md)
  — the loop shape: autonomous, verifier-driven N-sampling with
  SMT pruning, prompt-cache-aware context engineering.
- [`corpus-interface.md`](./corpus-interface.md) — the contract
  Modus places on its corpus substrate, pinned to Quarry's MCP
  surface.

## Planned documents

The following documents are referenced from the README or the
roadmap and will be written as the corresponding code lands:

- `action-vocabulary.md` — reference for every action type, its
  preconditions, its effect on the corpus, and its consistency
  rules.
- `consistency-checks.md` — the SMT formulation Modus uses to
  validate proposed actions, with worked examples per action
  type.
- `proposer.md` — the verifier-driven sampling loop in detail:
  prompt zones, sample budget, pruning, value heuristics.
- `quickstart.md` — operator-facing install and first-run guide,
  including how to point Modus at an existing Quarry corpus.
- `methodology.md` — how Modus expects to fit into a real bounty
  workflow, including the operator's review loop after a session
  ends.
