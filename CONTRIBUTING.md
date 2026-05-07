# Contributing to Modus

Modus is in pre-alpha. PRs are not yet open; the architecture and
the v0.1 scope are still being established. Issues, design
discussion, and questions are welcome.

If you are reading this and considering contributing once the
project opens up: thank you. The notes below describe how
contributions will work once they are accepted.

## What Modus needs

In rough priority order:

1. Working code for the v0.1 milestones (see [`ROADMAP.md`](./ROADMAP.md)).
2. Adversarial review of the typed action vocabulary — places where
   the grammar is too permissive, places where the consistency
   checker can be fooled, action types that should exist but don't.
3. Adapter coverage for offensive tools whose output Modus reads
   (likely the same tools Quarry's adapters cover, plus whatever
   the action vocabulary needs to dispatch).
4. Documentation. Especially the corpus interface specification
   and the action vocabulary reference.
5. Adversarial testing on lab targets. Modus needs to be exercised
   against deliberately vulnerable applications before it touches
   real bounty programs.

## What Modus doesn't need

- New bug classes beyond the v0.1 scope, until v0.1 ships.
- New LLM provider integrations beyond Anthropic, OpenAI, and
  the OpenAI-compatible path, until v0.1 ships.
- A web UI.
- Marketing.

## Code style

- Python 3.12+. Use modern type hints; `from __future__ import
  annotations` is fine.
- `ruff` for linting and formatting. The `pyproject.toml` config
  is authoritative.
- `mypy --strict` passes on all code under `src/modus/`. Tests
  may be looser but should be type-checked.
- Tests use `pytest`. Every action type has at least one positive
  test and one negative test. Every consistency-check rule has
  at least one test that demonstrates the rule firing and at least
  one that demonstrates it not firing on a similar-but-valid case.

## Commit style

Conventional commits are encouraged but not enforced. Keep the
subject line under 72 characters; explain the why in the body.

## Architectural changes

Anything that changes the action vocabulary, the consistency
checker, the corpus interface, or the promotion lifecycle requires
an ADR (architectural decision record) under `docs/adr/`. The first
ADR is [`0001-typed-action-vocabulary.md`](./docs/adr/0001-typed-action-vocabulary.md);
follow that template.

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md). Do not file public issues for
security vulnerabilities in Modus itself.

## Code of conduct

Be decent. Disagree on the substance, not the person. Adversarial
review is welcome; ad hominem isn't. The maintainer reserves the
right to remove comments or block contributors for behavior that
makes the project less productive to participate in.

## License

By contributing to Modus you agree that your contributions will
be licensed under AGPL-3.0-or-later. Modus does not use a CLA —
contributions are inbound=outbound under the AGPL. There is no
commercial-license offering and no plan to add one.
