# Modus

> Offensive agent built on a typed action vocabulary, formal consistency
> checking, and human-promoted findings.

Modus is an offensive security agent for authorized bug bounty and
penetration-testing work. It proposes typed actions against a target
corpus, checks each action for formal consistency before execution,
and surfaces results as Candidates the operator promotes to Findings
by hand.

> **Status: pre-alpha (0.0.0).** Nothing here is shippable yet. The
> repository is being populated with the v0.1 skeleton; expect every
> file in here to change.

## What this is

- An agent loop that proposes typed actions (a constrained vocabulary,
  not free-form shell), validates each action against the current
  corpus state via an SMT consistency check, and executes only the
  actions that pass.
- A persistence model where every action, every result, and every
  agent decision is durable, queryable, and reviewable after the
  session ends. The session is not the system of record; the corpus is.
- A promotion lifecycle: agent output is always a Candidate. Promotion
  to a Finding is an explicit human action. The agent never submits,
  never publishes, never crosses the observation/recommendation line
  on its own.

## What this isn't

- Not an autopilot. Modus does not run unattended against new targets,
  does not submit reports, and does not take destructive actions
  without explicit approval per session.
- Not a scanner. Modus reasons about what to do next given current
  corpus state; it doesn't replace nuclei, httpx, katana, or any
  other recon tool. It uses their output.
- Not a methodology framework. Modus assumes the operator already
  knows what they're doing and wants leverage on the parts of the
  workflow that benefit from a structured agent — hypothesis
  generation, action sequencing, evidence accumulation.
- Not a SaaS. Local-first, BYOK for any model provider, no telemetry.

## Why this exists

The autonomous offensive tooling space has converged on a pattern:
LLM agent loop, free-form tool dispatch, session-scoped memory,
chain-of-thought traces as the audit surface. That pattern works
for demos and benchmarks. It doesn't compose well with professional
operator discipline because the agent's reasoning is locked inside
the model and the system of record is a flat log file.

Modus takes a different bet:

- The action vocabulary is **typed**. The agent proposes actions
  drawn from a defined grammar, not arbitrary shell commands. New
  action types are additions to the grammar, not new prompt text.
- The consistency check is **formal**. Each proposed action is
  validated against preconditions and corpus state via an SMT
  solver before it executes. Inconsistent actions are rejected
  before they hit the network.
- The audit surface is the **corpus**, not the trace. Every action,
  result, candidate, and promotion is a typed row in persistent
  storage. The session ends; the corpus survives. Reviewing what
  the agent did last Tuesday is a query, not a log scrape.
- The promotion lifecycle is **human-driven**. Modus produces
  Candidates. The operator promotes them to Findings. The line
  between observation and recommendation is enforced by storage,
  not by prompt.

These four commitments are the invariants. Everything else — which
LLM provider, which substrate the corpus runs on, which bug classes
are in scope for v0.1 — can change. The invariants don't.

## Architecture (v0.1, planned)

```
operator
   │
   ▼
modus CLI ──► agent loop ──► action proposer (LLM)
                  │              │
                  │              ▼
                  │         typed action (pydantic)
                  │              │
                  │              ▼
                  │         consistency checker (Z3)
                  │              │
                  │              ▼
                  │         execution dispatch
                  │              │
                  │              ▼
                  └─────────► corpus (MCP-backed)
                                 │
                                 ▼
                            Candidates ──► (human promotes) ──► Findings
```

The corpus is accessed over MCP. The v0.1 reference substrate runs
locally; the corpus interface is what Modus depends on, not any
specific implementation. Any MCP server that exposes the required
tool surface can be a corpus.

## Scope

### v0.1 bug classes

To be confirmed. Likely candidates: IDOR, SSRF, auth bypass, plus
one of (open redirect chains, business logic on financial flows,
SQLi on parameterized endpoints). Modus is web-only at v0.1. No
binary exploitation, no priv-esc, no smart contracts.

### v0.1 LLM providers

Anthropic primary, OpenAI secondary, OpenAI-compatible (Ollama,
vLLM, OpenRouter) tertiary. Local-only support is a v0.3+ goal
once local model agentic capability has caught up.

### v0.1 corpus

Any MCP server that implements the documented corpus interface.
The reference implementation is documented separately (see
`docs/corpus-interface.md`, planned).

## Non-goals

- Competing with commercial autonomous pentesters on benchmark
  scores. Modus is a different bet.
- Submitting reports automatically. Ever.
- Running without scope enforcement. Modus refuses to act outside
  the operator-defined scope, full stop.
- Supporting every offensive tool. Modus integrates a small set
  of high-quality tools well; it does not aspire to be a swiss
  army knife.

## Status and roadmap

This README is being written before the code. The v0.1 skeleton
is being laid down now; nothing here runs yet. See
[`ROADMAP.md`](./ROADMAP.md) for milestone planning.

## License

AGPL-3.0-or-later. See [`LICENSE`](./LICENSE).

The AGPL choice is deliberate: Modus is offensive security
infrastructure, and modifications that get deployed as services
should be returned to the community. If the AGPL is incompatible
with your use case, contact the maintainer about commercial
licensing.

## Contributing

Not yet. The repository is in initial layout; PRs will be welcomed
once v0.1 has a working baseline. Issues and design discussion
are welcome in the meantime.

## Authorized use only

Modus is built for authorized security testing — bug bounty
programs with written safe-harbor terms, penetration tests with
written authorization, and your own infrastructure. Using Modus
against systems you don't have explicit permission to test is
illegal in most jurisdictions and is not supported by this project.
