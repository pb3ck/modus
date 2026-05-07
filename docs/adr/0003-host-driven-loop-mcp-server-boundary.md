# ADR 0003: Modus is an autonomous agent exposed as an MCP server

- **Status:** accepted
- **Date:** 2026-05-06
- **Supersedes:** —
- **Superseded by:** —
- **Extends:** [`0001-typed-action-vocabulary.md`](./0001-typed-action-vocabulary.md)
  and [`0002-autonomous-loop-and-verifier-driven-search.md`](./0002-autonomous-loop-and-verifier-driven-search.md).

## Context

ADR-0002 committed Modus to running its own LLM proposer in a
verifier-driven sampling loop. The intent was an autonomous
agent that drives an LLM API directly, samples N candidate
actions per step, prunes via Z3, and executes the survivors.

Reframing Modus as "an MCP server consumed by Claude Desktop"
risks reducing it to a passive tool collection — the host's LLM
becomes the agent, and Modus's contribution shrinks to whatever
the host's tool-use loop happens to do. That's not what the
project is. **Modus is an autonomous offensive agent. The MCP
server is its delivery mechanism, not its identity.** The typed
action vocabulary and the formal consistency check are
infrastructure for that agency, not an end in themselves.

The right boundary is one level out: **Modus is an autonomous
agent exposed through an MCP server.** The agent's autonomous
loop is the load-bearing surface — when the host invokes
Modus's autonomous-session tool, Modus runs the full ADR-0002
loop end-to-end inside that one MCP call and returns
Candidates. Per-action verified tools are a secondary,
transparency-oriented surface for operators who want to watch
Modus work step by step, but they're not what Modus *is* — they
share the same vocabulary, same Z3 layer, same executor as the
autonomous loop, and they always sit beneath the autonomous
tools in importance.

The operator picks the host (Claude Desktop, Claude Code,
Cursor, anything MCP-aware). The host picks how to use Modus.
Modus owns the parts neither the host nor the corpus can:
formally checked actions, autonomous multi-step search under
formal scope, the HTTP executor.

## Decision

### 1. Modus is an MCP server with the autonomous tools at the centre

The `modus mcp` CLI subcommand starts an MCP server over stdio.
The host connects to it like any other MCP server. Modus
exposes two tool surfaces, both **always registered**:

#### A. Autonomous-session tools (the load-bearing surface)

The set of high-level tools that take an objective and a budget,
then run the full ADR-0002 loop internally:

- `run_autonomous_session(target, bug_classes, budget)` — runs
  the propose-prune-rank-execute loop against a Quarry target
  for a bounded budget. Returns the Candidates produced.
- `propose_actions(context, sample_count)` — returns N candidate
  actions for the current corpus state with each one's Z3
  verdict. Useful when the host wants to delegate proposal
  generation but keep execution on its side.

These tools are **always present** in `list_tools` output —
they are what Modus *is*. If a host invokes one of them while
Modus's own LLM provider isn't configured, the call returns
`isError=True` with a clear message naming the missing
configuration. This makes the requirement discoverable through
the natural MCP error path rather than hiding the autonomous
tools behind a feature flag.

Modus's internal LLM is provider-portable: `AnthropicProposer`,
`OpenAICompatibleProposer` (covering OpenAI, Ollama, vLLM,
OpenRouter via `base_url`). Provider choice is independent of
the MCP host's choice — the operator may want the host on Claude
Sonnet for the conversation and Modus internally on a local
Ollama for the autonomous search. The provider is selected via
env (`MODUS_LLM_PROVIDER` + provider-specific keys/URLs); the
server start-up logs the resolved provider to stderr for
operator visibility, and warns to stderr if none is configured.

#### B. Verified-action tools (the transparency surface)

One MCP tool per Action variant in `modus.actions` (`probe`,
`request`, `compare`, `differential`, `annotate`, `hypothesize`),
plus passthroughs for Quarry's read tools (`search`,
`list_targets`, `corpus_status`, `list_assets`, `diff`,
`coverage`, `recall`, `analyze_*`). Each call passes through
:class:`ConsistencyChecker.check`; rejected calls return
`isError=True` with the failed precondition names. Host LLMs
that want to drive Modus step-by-step — or operators who want
full transparency over each action — use this surface.

This is ADR-0001's original single-proposal shape. It works
without a Modus-side LLM provider, since the host's LLM is
proposing each action. So even an operator who hasn't yet
configured a provider can exercise the verified-action surface
end-to-end through Claude Desktop.

### 2. ADR-0002's loop runs inside the autonomous-session tools

ADR-0002 stays intact for the autonomous-session path:

- N-sampling from the configured proposer.
- Z3 pruning of the sampled batch.
- Value-heuristic ranking of the survivors.
- Top-K execution under budget.
- Prompt-cache-aware context engineering on providers that
  support caching (Anthropic); structural prompt discipline
  on providers that don't.

The verified-action tools (surface A) don't use the proposer at
all — the host's LLM is the proposer for that path. So `proposer.py`
and `agent.py` are *not* deleted; they're scoped to the
autonomous-session path and invoked from inside the MCP tool
handlers for surface B.

### 3. The Z3 consistency check is the load-bearing primitive

Both surfaces share the consistency layer. In surface A, the Z3
check gates each MCP tool call from the host. In surface B, the
Z3 check prunes the proposer's sampled batch on each step. The
Z3 layer doesn't know or care which surface called it — it just
takes an Action and a CorpusState and returns a Verdict.

This is the symmetry that makes the dual-mode design coherent.
The vocabulary and the verifier are universal; the loop is
optional and pluggable.

### 4. The HTTP executor lives inside Modus

Quarry doesn't make HTTP requests; it ingests their results.
Modus is the thing that produces traffic of its own under formal
scope constraints. When the host calls Modus's `request` tool —
or when Modus's autonomous loop emits a `Request` action —
Modus's executor performs the HTTP request inside the MCP server
process and persists the request/response as an observation
Quarry can later index.

The executor is the same code path for both surfaces. Surface A
gets one verified request per host tool call; surface B may make
many during a single autonomous-session tool call.

### 5. Scope is loaded at server start

The `modus mcp` command takes a scope policy (a JSON file path
via `--scope` or `MODUS_SCOPE_PATH`). Parsed once at startup,
held immutably for the server's lifetime, consulted by the
consistency layer on every tool call (surface A and surface B).

### 6. The submission line is unchanged

Modus has no `submit`, `report`, or `publish` tool on either
surface. The terminal effect of every action — verified or
autonomous — is a Candidate row (or an annotation, observation,
or comparison) in Quarry. Promotion is the operator's
`quarry finding promote`, run outside Modus, after the session
ends. The autonomous-session tools cannot escape this; they're
implemented on top of the same action vocabulary that has no
submission verb in it.

### 7. "Autonomous within scope" is delivered by surface A

The operator who wants real agency calls Modus's
`run_autonomous_session` tool from their host and lets Modus run
the multi-step loop end-to-end. The host's UX during that call
is "tool in progress for N seconds"; the result is a structured
batch of Candidates the operator reviews afterward. This is the
shape Modus is supposed to deliver — autonomous, scope-bound,
audit-trailed in Quarry, terminating in Candidates the operator
promotes by hand.

The operator who wants per-step transparency uses surface B
instead, accepting that they're trading agency for visibility.
Both surfaces are always present in Modus's tool surface; the
operator (or the operator's host) chooses which to invoke.

### 8. Unified facade for the corpus

The host configures one MCP server (Modus). Modus internally
holds a `QuarryMcpClient` and proxies Quarry's read tools
through its own MCP surface. Operator setup is one stanza in
Claude Desktop's settings rather than two.

Cost: Modus tracks Quarry's MCP surface as it evolves and adds
passthroughs for new tools. Quarry's M2.5 analytical tools are
flagged as in-flux in Quarry's own README; Modus accepts that
maintenance burden.

## Consequences

### Positive

- **Modus is what it claims to be: an autonomous offensive
  agent.** Surface A is the load-bearing surface — the same
  agency ADR-0002 committed to, just exposed as an MCP tool the
  host can invoke rather than a CLI the operator runs directly.
- **Two operator profiles are first-class.** Operators who want
  agency get surface A. Operators who want transparency get
  surface B. Same install, same vocabulary, same verifier; both
  surfaces are always present.
- **Provider portability stays.** The host picks the host's
  model (Claude Desktop ⇒ Claude). Modus's autonomous loop picks
  Modus's model (configurable; the operator sets
  `MODUS_LLM_PROVIDER` independently of whatever model their
  host is using). The two are independent.
- **The codebase shape is unchanged from M0–M2.** The proposer
  and agent loop we already started building are exactly what
  surface A needs; they get re-targeted from "CLI-driven loop"
  to "MCP-tool-handler-driven loop" but the internals stay.

### Negative

- **The MCP server has more state than a pure tool surface
  would.** Surface B has long-running tool calls, streaming
  progress notifications, an internal budget tracker, and
  cancellation semantics. That's real complexity inside the
  server.
- **There are now two ways to do the same thing.** A host could
  drive surface A through ten verified tool calls or call
  surface B's autonomous-session tool with `budget=10`. Same
  outcome, different cost profile. Documentation has to make
  the choice clear.
- **Two LLMs in the operator's monthly bill** for the
  autonomous-session path. The host's model consumption plus
  Modus's autonomous-loop consumption. Operators have to budget
  for both. Not different from running any agentic tool stack,
  but worth being honest about. (The verified-action surface
  has no Modus-side LLM cost at all — only the host's.)
- **Surface A's autonomous tools fail meaningfully when no
  Modus-side LLM is configured.** The error path is
  discoverable via the natural MCP tool-call result, not a
  startup failure or hidden tool. Operators who try the
  autonomous tool without setting `MODUS_LLM_PROVIDER` learn
  what they need from the error message, then configure and
  retry.

### Neutral

- The action vocabulary doesn't change. ADR-0001's grammar still
  holds; the consistency layer still applies; surfaces A and B
  share both.
- The corpus-interface contract on Quarry doesn't change. Modus
  is still a Quarry MCP client; the same tool surface from
  `docs/corpus-interface.md` applies.

## Alternatives considered

- **Modus as a pure passive verifier (the original ADR-0003
  draft).** Rejected after operator feedback: reduces Modus to a
  tool collection, delegates all agency to the host. The whole
  reason the project exists is to *be* an autonomous offensive
  agent, not to wrap one.
- **Modus as a pure CLI agent with no MCP surface.** Rejected:
  the operator wants to drive Modus through their existing host
  (Claude Desktop). Forcing a separate CLI is friction without
  benefit.
- **MCP "sampling" capability for the autonomous loop** —
  letting Modus call back into the host's LLM for proposal
  generation. Considered: fits the model-portability story
  cleanly. Rejected for v0.1: not all hosts support sampling,
  Claude Desktop's support is partial and evolving, and we'd be
  betting on a feature still in flux. Surface B uses Modus's own
  LLM provider for now; sampling is a v0.2+ add if hosts
  converge on robust support.
- **Separate Modus and Quarry MCP servers.** Rejected: heavier
  host configuration, no consistency layer over composed Quarry
  calls. Same reasoning as the unified-facade decision.

## References

- ADR 0001 — typed action vocabulary, the substrate this ADR
  builds on.
- ADR 0002 — the autonomous-loop / verifier-driven-search ADR
  this one extends; surface A runs ADR-0002's loop inside an
  MCP tool handler.
- The Model Context Protocol specification
  (https://modelcontextprotocol.io).
- Quarry's `docs/mcp.md` — Quarry's MCP surface, which Modus
  proxies through the unified facade.
