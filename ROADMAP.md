# Modus Roadmap

This roadmap is aspirational and will be revised as v0.1 proves
out or fails to. Dates are deliberately absent — milestones are
gated by working code, not calendars.

The throughline: Modus is an autonomous offensive agent that
runs end-to-end without per-step operator approval. The single
hard human gate is on the way out — the agent writes Candidates
and stops, and the operator promotes them to Findings via
Quarry. Every milestone is read against that target shape.

## Milestone 0 — Skeleton (in progress)

Repository layout, packaging, documentation scaffolding, license,
governance files. The README, ROADMAP, ADR-0001, and ADR-0002 are
in place; the corpus-interface document pins Modus's contract on
Quarry. No agent loop yet, but the package imports, the CLI
runs, and the test suite is green.

Exit criteria: a developer can clone the repo, read the docs,
understand what Modus is intended to be without running anything,
and run `pytest` to a green result.

## Milestone 1 — Action vocabulary and consistency check

The typed action grammar is specified and implemented. The v0.1
action set (`Probe`, `Request`, `Compare`, `Differential`,
`Annotate`, `Hypothesize`) round-trips through the consistency
checker. Each action type has a Pydantic model with its
preconditions, an SMT encoding of those preconditions, and a
deterministic accept/reject from the Z3 layer.

The consistency layer is built as a *pruner over sampled
proposals*, not a yes/no gate against a single proposal.
Verifier-driven beam search is the contract; the proposer side
of that contract is stubbed at this milestone but the
consistency side is real.

Exit criteria: `modus action validate <spec.json>` returns a
deterministic accept/reject with rationale; the test suite covers
each action type, at least one negative case per type, and at
least one batch-pruning case (N proposals in, K survive).

## Milestone 2 — Quarry corpus client

Modus consumes Quarry's MCP surface as a client. `quarry mcp` is
a process Modus launches (or attaches to) and drives via JSON-RPC
over stdio. Modus reads corpus state via Quarry's read-only tools
(`search`, `list_targets`, `status`, `diff`, `coverage`,
`list_assets`, `recall`) and writes Candidates back via Quarry's
analytical / promotion-eligible surfaces.

Exit criteria: `modus corpus status` resolves a Quarry corpus
and reports current state; a Candidate written by Modus in one
session is visible to `quarry finding list` and to the next
Modus session's retrieval. Modus reimplements no Quarry
functionality.

## Milestone 3 — Verifier-driven proposer

The LLM proposer is real. At each step, the proposer samples N
candidate actions in parallel from the LLM (provider-native tool
use / structured output, so the output is grammatical by
construction), the consistency layer prunes them, and a value
heuristic ranks the survivors by expected information gain.
Anthropic is the primary provider; the prompt is designed for
prompt-cache friendliness — vocabulary, scope, and stable
context live in the cached prefix, only per-step retrieval flows
in fresh.

Exit criteria: a single propose-prune-rank-execute step runs
end-to-end against a lab target, produces an executed action and
a corpus row, with both the proposer's full sample set and the
consistency layer's verdicts persisted for audit.

## Milestone 4 — Autonomous loop

The propose-prune-rank-execute step is run in a loop with a
budget (steps, time, token cost). The agent runs end-to-end
against a single bug class on a controlled lab target (a
deliberately vulnerable application, not a real bounty target),
without per-step operator approval, and produces Candidates the
operator reviews afterward in Quarry.

Exit criteria: Modus completes a session against a lab target
and produces at least one true-positive Candidate that survives
the operator's later review and would be a defensible Finding
under standard bounty triage. The session is reproducible from
the corpus alone.

## Milestone 5 — v0.1 release

The v0.1 bug-class scope is implemented end-to-end. Documentation
is complete enough for an external operator to install Modus,
configure scope against a Quarry target, run a session, and have
the resulting Candidates land in Quarry for promotion. The audit
surface (every action sampled, every Z3 verdict, every executed
action, every Candidate) is queryable from Quarry.

Exit criteria: an external user (someone who is not the
maintainer) runs Modus against a lab environment and produces a
session summary without operator hand-holding.

## Beyond v0.1

Out of scope for v0.1 and intentionally deferred:

- **Hypothesis ledger with Bayesian action selection.** Each
  session opens with explicit hypotheses ("this endpoint has
  IDOR"), each carrying a probability that gets updated by
  every observation; the proposer chooses actions that maximize
  expected information gain across competing hypotheses.
  Belongs after the autonomous loop is real and we have data on
  what value heuristics actually work.
- **Plan-then-verify multi-step actions.** The LLM emits a DAG
  of typed actions with data dependencies; Z3 verifies the whole
  plan before any of it runs. Interesting; deferred until we've
  seen where single-step beam search actually fails.
- **Process-reward fine-tuning from Quarry promotion history.**
  Implicit feedback (which Candidates the operator promoted) as
  a training signal for the proposer. Requires Quarry-side
  promotion volume that doesn't exist yet.
- **Additional bug classes beyond the v0.1 set.**
- **Local-model-only operation.** Waits on local agentic
  capability reaching parity with frontier models on the
  relevant tasks.
- **Adapter coverage for additional corpus substrates.** The
  corpus interface is documented; in principle any MCP server
  matching it works. In practice we are coupled to Quarry until
  someone needs otherwise.
- **Submission automation.** Stays a non-goal at every
  milestone, as a hard rule, not a deferred feature.

## What's deliberately not on the roadmap

- An auto-promotion mode. Promotion of a Candidate to a Finding
  is always a human action via Quarry's CLI. Modus has no such
  surface and will not.
- A Modus-side report-generation feature. Submission-ready text
  is the operator's job; Modus produces structured Candidates
  in Quarry.
- A web UI. Modus is a CLI tool. If a UI is wanted, build it
  against the Quarry corpus, not against Modus.
- A SaaS offering. Modus runs locally; the corpus runs locally
  via Quarry.
