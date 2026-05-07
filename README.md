# Modus

> Autonomous offensive agent — typed action vocabulary, formal
> consistency checking, Quarry-backed corpus, delivered as an MCP
> server.

[![CI](https://github.com/pb3ck/modus/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pb3ck/modus/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](./pyproject.toml)

Modus is an autonomous offensive security agent for authorized bug
bounty and penetration-testing work. The agent reasons over a Quarry
corpus, proposes typed actions against in-scope targets, formally
verifies each action before execution, and writes its findings as
Candidates into the corpus. Modus is delivered as an **MCP server**:
the operator drives it from any MCP-aware host (Claude Desktop,
Claude Code, Cursor, anything that speaks the Model Context Protocol).
The agent's autonomous loop runs end-to-end inside Modus — the host
just kicks it off and reads the result. The single hard human gate
is on the way out: **Modus never submits.** No `submit`, `publish`,
or `post` action exists in the grammar; promotion of a Candidate to
a Finding is the operator's `quarry finding promote`, run outside
Modus. Modus may *recommend* submission in a Candidate's rationale —
the decision and the act remain the operator's.

> **Status: alpha (0.1.0a1).** The autonomous loop runs end-to-end
> against authorized targets — see [`docs/quickstart.md`](./docs/quickstart.md).
> The action vocabulary, the consistency check, the corpus
> interface, and the submission-line invariant are committed
> surfaces; everything else may shift between alpha releases until
> 1.0.

## What this is

- **An autonomous agent**, primarily. The operator points their
  MCP host at Modus and invokes the autonomous-session tool.
  Modus runs the propose-prune-rank-execute loop internally —
  sampling N candidate actions from its own LLM provider per
  step, pruning the inconsistent ones via the Z3 consistency
  check, ranking the survivors by expected information gain,
  and executing the top-K under a budget. The host never sees
  the inner loop; it sees a single tool call that returns a
  batch of Candidates.
- **An MCP server**, in delivery. Both the autonomous session
  tools and the underlying typed-action tools (probe, request,
  compare, differential, annotate, hypothesize) are exposed
  over MCP. So is Quarry's read surface — Modus proxies Quarry
  through the same server, so the operator configures one MCP
  endpoint, not two. Operators who want full transparency can
  drive the typed-action tools step-by-step from the host;
  operators who want agency invoke the autonomous-session tool.
- **A Quarry-native agent.** The corpus, the retrieval surface,
  the analytical modules, the Candidate/Finding lifecycle, the
  cross-engagement memory all live in Quarry. Modus depends on
  Quarry's MCP surface; it does not reimplement any of it.
- **A submission firewall enforced by storage.** Every action
  Modus emits — autonomous loop or single tool call — terminates
  in a Quarry row (observation, comparison, annotation,
  Candidate). No `submit`, `report`, or `publish` tool exists in
  Modus's MCP surface, and none will be added. Promotion to a
  Finding is the operator's `quarry finding promote`, run outside
  Modus, after the session ends. Modus's rationales may *recommend*
  promotion or external submission — the structural firewall is the
  absence of a submission action, not a ban on operator-facing
  recommendations.

## What this isn't

- Not a scanner. Modus reasons about what to do next given
  current corpus state. Recon and traffic harvesting belong
  upstream of Quarry's ingest layer; Modus consumes what they
  produced and generates targeted active traffic of its own.
- Not a corpus. Quarry is the corpus. Modus stores nothing
  about evidence, assets, or findings outside what Quarry
  already models.
- Not a model wrapper. Modus has its own LLM provider for the
  autonomous loop, but it is provider-portable
  (Anthropic / OpenAI / OpenAI-compatible: Ollama, vLLM,
  OpenRouter). The host's LLM and Modus's LLM are independent
  choices the operator makes separately.
- Not a chatbot. Modus's autonomous tool returns a structured
  batch of Candidates, not a narrative response. The host's
  conversation is between the operator and the host's LLM;
  Modus is the offensive engine bolted to the side.
- Not a submitter. Ever. The line between observation and
  recommendation is enforced by storage, not by prompt: there
  is no "publish" path in Modus, and there will not be one.

## Why this exists

The autonomous offensive tooling space has converged on a shape:
LLM in a free-form ReAct loop, shell-string tool dispatch,
session-scoped memory, chain-of-thought traces as the audit
surface, operator approval per step as the safety gate. That
shape works for demos. It doesn't compose with professional
operator discipline because the agent's reasoning is locked
inside the model, the system of record is a flat log file, and
the safety gate is the same person whose attention the agent is
supposed to multiply.

Modus takes a different bet, in five parts.

- The action vocabulary is **typed**. The agent (Modus's own,
  inside the autonomous loop; or the host's, when driving Modus
  step-by-step) emits actions drawn from a defined grammar, not
  arbitrary shell commands. The vocabulary maps to an MCP tool
  surface, so any MCP-aware host's LLM produces grammatical
  proposals by construction.
- The consistency check is **formal**. Each proposed action is
  validated against preconditions and current corpus state via
  an SMT solver before any side effect. Used as a *pruner over
  sampled proposals* in the autonomous loop, the solver
  eliminates whole classes of invalid action before any network
  traffic is generated.
- The corpus is **Quarry**. Every action, result, and Candidate
  is a typed row in Quarry's storage layer, accessed over MCP.
  Reviewing what Modus did last Tuesday is `quarry session show`
  or a SQLite query, not a log scrape. Sessions across
  engagements share a single substrate.
- The agent is **delivered through MCP**. The operator picks
  the host (Claude Desktop, Claude Code, Cursor, any MCP-aware
  host); the host picks the model the *host* runs. Modus's own
  internal LLM (used by the autonomous loop) is a separate,
  provider-portable choice the operator makes via env vars.
  Modus is not locked to any provider on either side.
- The submission line is **storage-enforced**. Modus's terminal
  state is a Candidate in Quarry. Promotion is Quarry's
  `quarry finding promote`, run by the operator. No `submit`,
  `publish`, or `post` action exists in Modus's grammar; the
  structural firewall is the absence of an outbound action, not
  a ban on the agent's rationale recommending the operator
  promote or submit.

These five commitments are the invariants. The specific MCP
host, the specific LLM provider, the specific Z3 encoding, the
bug classes in v0.1 scope — all of that can change. The
invariants don't.

## How it fits

```
              operator
                 │
                 ▼
        ┌────────────────────┐          ┌──────────────────┐
        │  MCP host          │          │  modus-side LLM  │
        │  (Claude Desktop,  │          │  (Anthropic,     │
        │   Claude Code,     │          │   OpenAI,        │
        │   Cursor, ...)     │          │   Ollama, ...)   │
        └────────┬───────────┘          └────────▲─────────┘
                 │                               │
                 │ MCP (stdio, JSON-RPC)         │ used inside
                 ▼                               │ autonomous loop
        ┌────────────────────────────────────────┴─────────┐
        │                  modus mcp                       │
        │                                                  │
        │  ┌──────────────────────┐  ┌─────────────────┐   │
        │  │ autonomous-session   │  │ verified-action │   │
        │  │ tools (loop inside)  │  │ tools (one-shot)│   │
        │  └──────────┬───────────┘  └────────┬────────┘   │
        │             │                       │            │
        │             ▼                       ▼            │
        │       ┌────────────────────────────────────┐     │
        │       │ Z3 consistency check + scope       │     │
        │       └─────────────────┬──────────────────┘     │
        │                         │                        │
        │             ┌───────────┴────────────┐           │
        │             ▼                        ▼           │
        │       ┌────────────────┐     ┌────────────────┐  │
        │       │ HTTP executor  │     │ Quarry MCP cli │  │
        │       └───────┬────────┘     └───────┬────────┘  │
        └───────────────┼──────────────────────┼───────────┘
                        ▼                      ▼
                 in-scope target          quarry mcp
                                              │
                                              ▼
                                    Quarry corpus (SQLite)
                                              │
                                              ▼
                                         Candidates
                                              │
                                              ▼
                            (operator runs `quarry finding promote`
                             to lift to Finding — outside Modus)
```

The operator configures Modus as an MCP server in their host's
settings:

```json
{
  "mcpServers": {
    "modus": {
      "command": "modus",
      "args": ["mcp", "--scope", "/path/to/scope.json"],
      "env": {
        "QUARRY_HOME": "/path/to/quarry/home",
        "MODUS_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

The host then sees Modus's tool surface — autonomous-session
tools and verified-action tools — and the operator drives via
ordinary host conversation. See
[`docs/mcp-host-integration.md`](./docs/mcp-host-integration.md)
for full setup.

## Scope

### v0.1 bug classes

To be confirmed and pinned in a follow-up ADR. Likely
candidates: IDOR, SSRF, auth bypass, plus one of (open redirect
chains, business logic on financial flows, SQLi on parameterized
endpoints). Modus is web-only at v0.1. No binary exploitation,
no priv-esc, no smart contracts.

### v0.1 MCP hosts

Claude Desktop is the primary host target — that's the shape
Modus is designed against. Any other MCP-aware host (Claude
Code, Cursor, Continue, Zed) works to the extent that it
implements the standard MCP stdio transport. Setup snippets for
the common ones are in
[`docs/mcp-host-integration.md`](./docs/mcp-host-integration.md).

### v0.1 LLM providers (Modus-internal, for autonomous sessions)

Anthropic primary, OpenAI secondary, OpenAI-compatible (Ollama,
vLLM, OpenRouter via `base_url`) tertiary. The provider-portable
proposer is the only Modus-internal LLM choice; the host's LLM
choice is separate and outside Modus's control. Local-only
support is a v0.3+ goal, gated on local agentic capability
catching up.

### v0.1 corpus

Any MCP server that implements the documented corpus interface.
The reference dependency is Quarry; see
[`docs/corpus-interface.md`](./docs/corpus-interface.md) for the
exact tool surface Modus consumes.

## Non-goals

- Competing with commercial autonomous pentesters on benchmark
  scores. Modus is a different bet on the agent's *shape*, not
  on raw recall.
- Submitting reports automatically. Ever. At any milestone.
  Under any flag. There is no outbound action in the grammar;
  promotion is the operator's `quarry finding promote`. Modus's
  rationale may *recommend* the operator submit a Candidate, but
  the act is theirs.
- Generating finished, submission-ready report text without
  operator review. Candidates are structured rationales the
  operator triages; turning a triaged set into a programme-ready
  submission package is the operator's job.
- Running outside operator-defined scope. Scope is encoded as
  preconditions in the consistency layer; the agent cannot
  propose, much less execute, an action against an out-of-scope
  asset.
- Replacing Quarry. Modus depends on Quarry; it does not
  duplicate ingestion, retrieval, analytical modules, or the
  Finding lifecycle.
- Replacing the host. Modus does not implement a chat UI, an
  approval-prompt UX, or a model-selection menu. Those are the
  host's job.

## Status and roadmap

The v0.1 skeleton is being laid down. The action vocabulary,
consistency layer, MCP corpus client, and proposer abstractions
are landing first; the MCP server and the autonomous-session
tool close the loop. See [`ROADMAP.md`](./ROADMAP.md) for
milestone planning and [`docs/adr/`](./docs/adr/) for the
architectural decisions that got us here.

## License

AGPL-3.0-or-later. See [`LICENSE`](./LICENSE).

The AGPL choice is deliberate: Modus is offensive security
infrastructure, and modifications that get deployed as services
should be returned to the community. Modus is pure FOSS — there
is no dual-license model and no commercial-license offering.

## Contributing

Not yet. The repository is in initial layout; PRs will be
welcomed once v0.1 has a working baseline. Issues and design
discussion are welcome in the meantime. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Authorized use only

Modus is built for authorized security testing — bug bounty
programs with written safe-harbor terms, penetration tests with
written authorization, and your own infrastructure. Using Modus
against systems you don't have explicit permission to test is
illegal in most jurisdictions and is not supported by this
project.
