# Modus Roadmap

This roadmap is aspirational and will be revised as v0.1 proves out
or fails to. Dates are deliberately absent — milestones are gated by
working code, not calendars.

## Milestone 0 — Skeleton (in progress)

Repository layout, packaging, documentation scaffolding, license,
governance files. No working code. Exit criteria: a developer can
clone the repo, read the docs, and understand what Modus is intended
to be without running anything.

## Milestone 1 — Action vocabulary and consistency check

The typed action grammar is specified and implemented. A small
set of v0.1 actions (probe, request, compare, annotate) round-trip
through the consistency checker. The checker rejects actions whose
preconditions are not satisfied by current corpus state. No agent
loop yet; actions are exercised by hand or by tests.

Exit criteria: `modus action validate <spec.json>` returns a
deterministic accept/reject with rationale; the test suite covers
each action type and at least one negative case per type.

## Milestone 2 — Corpus interface

The corpus interface is specified as an MCP tool surface. A
reference adapter against the v0.1 reference substrate is working.
Modus can read corpus state, write Candidates, and read back its
own previous actions across sessions.

Exit criteria: `modus corpus status` reports current state; a
Candidate written in one session is visible to a query in the next.

## Milestone 3 — Agent loop

The propose-validate-execute-record loop runs end-to-end against
a single bug class on a controlled lab target (a deliberately
vulnerable application, not a real bounty target). The loop
produces Candidates that a human can review and promote.

Exit criteria: Modus completes a session against a lab target
and produces at least one true-positive Candidate that survives
the 7-Question Gate and would be a defensible Finding under
standard bounty triage.

## Milestone 4 — v0.1 release

The v0.1 bug-class scope is implemented end-to-end. Documentation
is complete enough for an external operator to install Modus,
configure scope, run a session, and promote findings. The audit
surface (every action, every consistency-check result, every
Candidate, every promotion) is queryable.

Exit criteria: an external user (someone who is not the maintainer)
runs Modus against a lab environment and produces a session
summary without operator hand-holding.

## Beyond v0.1

Out of scope for v0.1 and intentionally deferred:

- Additional bug classes beyond the v0.1 set.
- Local-model-only operation (waits on local agentic capability
  reaching parity with frontier models on the relevant tasks).
- Adapter coverage for additional corpus substrates.
- IRL-based action selection (this is a separate research thesis;
  Modus v0.1 uses LLM-driven proposal with formal consistency
  checks, not learned policy).
- Any form of submission automation. This stays a non-goal at
  every milestone.

## What's deliberately not on the roadmap

- An autopilot mode. Modus runs a session at a time, with the
  operator present.
- A scoring or ranking system that auto-promotes Candidates.
  Promotion is always a human action.
- A web UI. Modus is a CLI tool. If a UI is wanted, it can be
  built against the corpus, not against Modus.
- A SaaS offering. Modus runs locally; the corpus runs locally
  or in the operator's own infrastructure.
