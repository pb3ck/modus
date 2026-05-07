# Modus

> Autonomous offensive agent built on a typed action vocabulary,
> formal consistency checking, and a Quarry-backed corpus.

Modus is an autonomous offensive security agent for authorized bug
bounty and penetration-testing work. It reasons over a Quarry corpus,
proposes typed actions against in-scope targets, formally verifies
each action before execution, and writes its findings as Candidates
into the corpus. Modus runs the loop end-to-end without per-step
operator approval. The single hard human gate is on the way out:
**Modus never submits. Modus never tells the operator to submit.**

> **Status: pre-alpha (0.0.0).** The v0.1 skeleton is being laid
> down. Nothing here runs end-to-end yet; expect every file to
> change.

## What this is

- An autonomous agent loop that reasons over an existing Quarry
  corpus, proposes typed actions from a defined grammar, validates
  each proposal against current corpus state via an SMT consistency
  check, and executes the actions that pass.
- A verifier-driven proposer: the LLM samples N candidate actions
  per step in parallel, the Z3 layer prunes the inconsistent ones,
  and a value heuristic picks what runs. The SMT layer is a
  search-space pruner, not a yes/no gate.
- A Quarry-native tool: the corpus, the retrieval surface, the
  analytical modules, the Candidate/Finding lifecycle, and the
  cross-engagement memory all live in Quarry. Modus depends on
  Quarry's MCP surface; it does not reimplement any of it.
- A submission firewall enforced by storage: the agent's terminal
  state is "wrote a Candidate to the Quarry corpus." Nothing in
  Modus produces submission-ready report text or anything that
  reads as a recommendation to submit.

## What this isn't

- Not a scanner. Modus reasons about what to do next given current
  corpus state. Recon and traffic harvesting belong upstream of
  Quarry's ingest layer; Modus consumes what they produced and
  generates targeted active traffic of its own.
- Not a corpus. Quarry is the corpus. Modus stores nothing about
  evidence, assets, or findings outside what Quarry already
  models.
- Not a methodology framework. Modus assumes the operator has
  already authorized scope and chosen which engagements to feed
  it. Pick your battles upstream; Modus runs the engagement.
- Not a submitter. Ever. The line between observation and
  recommendation is enforced by storage, not by prompt: there is
  no "publish" path in Modus, and there will not be one.

## Why this exists

The autonomous offensive tooling space has converged on a pattern:
LLM in a free-form ReAct loop, shell-string tool dispatch,
session-scoped memory, chain-of-thought traces as the audit
surface, operator approval per step as the safety gate. That
shape works for demos. It doesn't compose with professional
operator discipline, because the agent's reasoning is locked
inside the model, the system of record is a flat log file, and
the safety gate is the same person whose attention the agent is
supposed to multiply.

Modus takes a different bet, in four parts.

- The action vocabulary is **typed**. The agent proposes actions
  drawn from a defined grammar, not arbitrary shell commands. The
  LLM emits proposals via constrained decoding (provider-native
  tool use, structured output) so the proposer's output is
  grammatical by construction.
- The consistency check is **formal**. Each proposed action is
  validated against preconditions and current corpus state via an
  SMT solver. Used as a *pruner over sampled proposals*, the
  solver eliminates whole classes of invalid action before any
  network traffic is generated.
- The corpus is **Quarry**. Every action, result, and Candidate is
  a typed row in Quarry's storage layer, accessed over MCP.
  Reviewing what Modus did last Tuesday is `quarry session show`
  or a SQLite query, not a log scrape. Sessions across engagements
  share a single substrate.
- The submission line is **storage-enforced**. Modus's terminal
  state is a Candidate in Quarry. Promotion to a Finding is
  Quarry's `quarry finding promote`, run by the operator. There
  is no Modus-side path that produces submission text or a
  recommendation to submit.

These four commitments are the invariants. The LLM provider, the
specific Z3 encoding, the bug classes in v0.1 scope — all of
that can change. The invariants don't.

## How it fits with Quarry

Quarry is the upstream dependency. It already ships:

- A local corpus (SQLite) for evidence, assets, candidates, and
  findings, with provenance preserved on every row.
- An MCP server (`quarry mcp`) exposing read-only retrieval
  (`search`, `list_targets`, `status`, `diff`, `coverage`,
  `list_assets`, `recall`) and analytical modules
  (`analyze_regression`, `analyze_jsdelta`, `analyze_interesting`).
- A Candidate/Finding lifecycle with operator-driven promotion
  (`quarry finding promote`).
- Cross-engagement memory via `quarry recall`.

Modus runs as an MCP client of `quarry mcp`. The agent's
"what is the current state of the world" is whatever Quarry's
retrieval layer returns. The agent's "what did I find" is a row
Modus writes back into Quarry's Candidate table. Modus does not
duplicate any of Quarry's functionality, and Modus's contract on
Quarry is documented separately as the corpus interface (see
[`docs/corpus-interface.md`](./docs/corpus-interface.md)).

What Modus adds on top of Quarry:

- The autonomous agent loop and its proposer.
- The typed action vocabulary and its Z3 consistency layer.
- Active HTTP execution against in-scope targets. Quarry ingests
  output from external tools; Modus is the thing that produces
  traffic of its own, under formal scope constraints.
- LLM provider plumbing with prompt-cache-aware context
  engineering.
- Scope enforcement encoded as preconditions in the SMT layer.

## Architecture (v0.1, planned)

```
operator
   │
   │  modus run --target <quarry-target> --classes idor,ssrf
   ▼
modus
   │
   ├── proposer ─── samples N candidate actions per step (LLM, parallel)
   │                                │
   │                                ▼
   ├── consistency ── Z3 prunes proposals violating scope or
   │                    preconditions against corpus state
   │                                │
   │                                ▼
   ├── value heuristic ── picks the K survivors with highest
   │                       expected information gain
   │                                │
   │                                ▼
   ├── executor ─── runs surviving actions
   │                  (HTTP requests, Quarry tool calls, both)
   │                                │
   │                                ▼
   └── corpus ──────► quarry mcp ◄──────► Quarry (SQLite)
                                │
                                ▼
                          Candidates
                                │
                                ▼
       (operator runs `quarry finding promote` to lift to Finding —
        outside Modus, by design)
```

The loop is autonomous within an authorized scope. It runs until
its budget (steps, time, or token cost) is exhausted, until no
proposal survives the consistency check, or until it has nothing
left to learn. The operator returns to a corpus full of Candidates
to triage at their own cadence.

## Scope

### v0.1 bug classes

To be confirmed and pinned in a follow-up ADR. Likely candidates:
IDOR, SSRF, auth bypass, plus one of (open redirect chains,
business logic on financial flows, SQLi on parameterized
endpoints). Modus is web-only at v0.1. No binary exploitation,
no priv-esc, no smart contracts.

### v0.1 LLM providers

Anthropic primary, with prompt-cache-aware context engineering as
a first-class concern. OpenAI secondary, OpenAI-compatible
(Ollama, vLLM, OpenRouter) tertiary. Local-only support is a
v0.3+ goal, gated on local agentic capability catching up.

### v0.1 corpus

Any MCP server that implements the documented corpus interface.
The reference dependency is Quarry; see
[`docs/corpus-interface.md`](./docs/corpus-interface.md) for the
exact tool surface Modus consumes.

## Non-goals

- Competing with commercial autonomous pentesters on benchmark
  scores. Modus is a different bet on the agent's *shape*, not
  on raw recall.
- Submitting reports. Ever. At any milestone. Under any flag.
- Generating submission-ready report text. The agent's output
  is structured Candidates in Quarry; the operator's report is
  the operator's job.
- Running outside operator-defined scope. Scope is encoded as
  preconditions in the consistency layer; the agent cannot
  propose, much less execute, an action against an out-of-scope
  asset.
- Replacing Quarry. Modus depends on Quarry; it does not
  duplicate ingestion, retrieval, analytical modules, or the
  Finding lifecycle.

## Status and roadmap

The v0.1 skeleton is being laid down. The action vocabulary,
consistency layer, MCP client, and proposer abstractions are
landing first; the autonomous loop closes once those are real.
See [`ROADMAP.md`](./ROADMAP.md) for milestone planning and
[`docs/adr/`](./docs/adr/) for the architectural decisions that
got us here.

## License

AGPL-3.0-or-later. See [`LICENSE`](./LICENSE).

The AGPL choice is deliberate: Modus is offensive security
infrastructure, and modifications that get deployed as services
should be returned to the community. If the AGPL is incompatible
with your use case, contact the maintainer about commercial
licensing.

## Contributing

Not yet. The repository is in initial layout; PRs will be
welcomed once v0.1 has a working baseline. Issues and design
discussion are welcome in the meantime.

## Authorized use only

Modus is built for authorized security testing — bug bounty
programs with written safe-harbor terms, penetration tests with
written authorization, and your own infrastructure. Using Modus
against systems you don't have explicit permission to test is
illegal in most jurisdictions and is not supported by this
project.
