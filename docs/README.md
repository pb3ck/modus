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

## Planned documents

The following documents are referenced from the README or the
roadmap and will be written as the corresponding code lands:

- `corpus-interface.md` — specification of the MCP tool surface
  Modus expects from a corpus substrate.
- `action-vocabulary.md` — reference for every action type, its
  preconditions, its effect on the corpus, and its consistency
  rules.
- `consistency-checks.md` — the SMT formulation Modus uses to
  validate proposed actions.
- `quickstart.md` — operator-facing install and first-run guide.
- `methodology.md` — how Modus expects to be used in a real
  bounty workflow, including the human-in-the-loop seam.
