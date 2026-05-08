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
just kicks it off and reads the result. The autonomous loop closes
the Candidate→Finding lifecycle inside the corpus: severity-medium-
or-higher Candidates auto-promote to Findings via `corpus.promote_finding`,
backed by Quarry's MCP `finding_promote` write tool. The single hard
human gate is on bug-bounty submission: **Modus never submits to a
bounty programme.** No `submit`, `publish`, `post`, `report-to-h1`,
or equivalent tool exists in the registry, and adding one is
off-limits. Submission of a Finding to a programme is the operator's,
performed outside Modus.

> **Status: 0.4.0 (early release).** The autonomous loop runs
> end-to-end against authorized targets *and* closes the
> Candidate→Finding lifecycle inside the run — see
> [`docs/quickstart.md`](./docs/quickstart.md). The action
> vocabulary (open `ToolRegistry` per ADR-0004), the formal
> consistency check, the corpus interface, the submission-line
> invariant, and the autonomous-session MCP tool surface are
> committed surfaces; everything else may shift between minor
> releases until 1.0. v0.4.0 is the first non-pre-release tag —
> alphas precede it back to 0.1.0a1.

## What this is

- **An autonomous agent with an open tool registry.** The operator
  points their MCP host at Modus and invokes the autonomous-session
  tool. Modus runs the propose-prune-rank-execute loop internally,
  reaching every tool the operator's registered: recon shells
  (`amass`, `nuclei`), the typed-action surface (`probe`,
  `request`, `compare`, `differential`, `annotate`, `hypothesize`),
  Quarry's corpus tools, host-side MCP servers, and any custom
  shell or MCP tool the operator declares in their scope file's
  `tools` block. The agent isn't bounded by a closed grammar; it's
  bounded by what the registry exposes. (See ADR-0004 for the
  pivot from the closed v0.1 vocabulary.)
- **An MCP server**, in delivery. The full tool surface — typed
  actions, the generic `tool` dispatch, Quarry passthroughs,
  autonomous-session controls (start / poll / cancel /
  run / propose) — is registered as MCP tools. Operators who want
  full transparency drive individual tools step-by-step from the
  host; operators who want agency invoke `start_autonomous_session`
  and let the loop run.
- **Quarry-aware, not Quarry-native.** Quarry's analytical modules
  and read surface are first-party tool registrations
  (`corpus.search`, `analyze_jsdelta`, etc., proxied through
  Modus's MCP server). Quarry is the default storage backend and
  the cross-engagement memory; Modus depends on it but isn't
  subordinate to its data model. Other tools' observations live
  alongside Quarry rows in the same in-session pool.
- **A submission firewall enforced by registry membership.** No
  `submit`, `report`, `publish`, `post`, or `report-to-h1` tool
  is registered in the default registry, and adding one is
  project-policy off-limits. The agent can emit a `Tool` action
  with any name, but the consistency layer rejects with
  `tool_registered:<name>` if it isn't in the registry. The
  firewall covers *external submission* (to bug-bounty
  platforms), not internal promotion: the
  `corpus.promote_finding` builtin closes the Candidate→Finding
  lifecycle inside the local corpus on severity-medium-or-higher
  Candidates, which is corpus-internal, not an outbound action.
  Submission of a Finding to a programme is the operator's,
  performed outside Modus.

## What this isn't

- Not a scanner. Modus reasons about what to do next given
  current corpus state, and it can drive scanners as registered
  tools (`nuclei.scan`, `amass.enum`, anything operator-declared).
  The scanner is the *muscle*; Modus's autonomous loop is the
  *direction*. Without the loop, a scanner just generates noise.
- Not a corpus. Quarry is the default storage backend; Modus's
  in-session observation pool flushes to Quarry for cross-session
  memory. Modus does not duplicate Quarry's ingestion or its
  Finding lifecycle.
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

- The action surface is a **typed registry**. Every action the
  agent emits is a Pydantic-validated `Tool(name, args)` (or one
  of the typed-action fast paths — `Probe`, `Request`, etc.).
  The registry declares what `name` values are dispatchable and
  what each tool's `args` shape is; adding a new capability is
  one operator-authored entry in the scope file's `tools` block.
  The closed v0.1 vocabulary is gone; the trust boundary is the
  registry's contents.
- The consistency check is **formal and per-tool**. Each proposed
  action is validated against scope and corpus state via an SMT
  solver before any side effect. Each tool spec declares its own
  preconditions function (the registry is the dispatch table for
  Z3); built-in tools ship scope-gating preconditions
  (`amass.enum` requires the domain in scope, `nuclei.scan`
  requires the URL's `(host, port, tls)` in
  `allowed_endpoints`). The autonomous loop uses Z3 as a *pruner
  over sampled proposals*.
- The corpus is **Quarry**. Cross-engagement memory, structured
  storage, and the analytical modules
  (`analyze_regression` / `analyze_jsdelta` / `analyze_interesting`)
  live in Quarry, exposed through Modus's tool registry as
  `corpus.*` entries. Reviewing what Modus did is
  `quarry session show` or a SQLite query, not a log scrape.
- The agent is **delivered through MCP**. The operator picks
  the host (Claude Desktop, Claude Code, Cursor, any MCP-aware
  host); the host picks the model the *host* runs. Modus's own
  internal LLM (used by the autonomous loop) is a separate,
  provider-portable choice the operator makes via env vars.
  Modus is not locked to any provider on either side.
- The submission line is **structural**. No `submit`, `publish`,
  `post`, `report`, or `report-to-h1` tool is registered in the
  default registry, and adding one is project-policy off-limits.
  The agent can emit a `Tool` action with any name, but the
  consistency layer rejects with `tool_registered:<name>` if it
  isn't in the registry. The firewall covers *external
  submission* (to bug-bounty platforms), not internal promotion:
  Candidate→Finding promotion is corpus-internal and the
  autonomous loop closes it via `corpus.promote_finding` on
  severity-medium-or-higher Candidates. Submission to a
  programme is the operator's, performed outside Modus.

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
        │                   modus mcp                      │
        │                                                  │
        │  autonomous-session tools          typed-action  │
        │  (start / poll / cancel / run /     surface +    │
        │   propose)                          generic tool │
        │             │                       │            │
        │             ▼                       ▼            │
        │       ┌────────────────────────────────────┐     │
        │       │  Z3 consistency check  ──┐         │     │
        │       │  (per-tool preconds)     ▼         │     │
        │       │                  ┌──────────────┐  │     │
        │       │                  │ ToolRegistry │  │     │
        │       │                  └──────┬───────┘  │     │
        │       └─────────────────────────┼──────────┘     │
        │                                 ▼                │
        │                         ┌─────────────────┐      │
        │                         │  ToolExecutor   │      │
        │                         └─┬──────┬──────┬─┘      │
        │                           │      │      │        │
        │                           ▼      ▼      ▼        │
        │                       shell  builtin   mcp       │
        │           (amass, nuclei, …) (request, hypoth) (host MCP)
        └───────────────┬──────────────────┬───────────────┘
                        ▼                  ▼
                 in-scope target       quarry mcp
                                          │
                                          ▼
                                  Quarry corpus (SQLite)
                                          │
                                          ▼
                                      Candidates
                                          │
                                          ▼
                                  corpus.promote_finding
                                  (severity ≥ medium, in-loop)
                                          │
                                          ▼
                                       Findings
                                          │
                                          ▼
                       (operator submits to programme — outside Modus)
```

Every action — typed-action fast path or generic `tool` dispatch —
flows through the same registry-driven Z3 check, then through the
`ToolExecutor`, then to one of three backends. Quarry is one
backend (`builtin` invocations targeting `corpus.*` registry
entries) among many; recon shells (`amass`, `nuclei`) and any
operator-declared tools share the path. ADR-0004 documents the
pivot from the closed v0.1 vocabulary to this shape.

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
- Submitting Findings to bug-bounty programmes automatically.
  Ever. At any milestone. Under any flag. No `submit`, `publish`,
  `post`, `report`, or `report-to-h1` tool exists in the
  registry, and none will be added. The submission line is
  *external* — Modus closes the Candidate→Finding lifecycle
  inside the local corpus on severity-medium-or-higher
  Candidates, but submission of a Finding to a programme is the
  operator's, performed outside Modus.
- Generating finished, submission-ready report text without
  operator review. Findings carry the structured rationale the
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
