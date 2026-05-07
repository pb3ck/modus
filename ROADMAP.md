# Modus Roadmap

This roadmap is aspirational and will be revised as v0.1 proves
out or fails to. Dates are deliberately absent — milestones are
gated by working code, not calendars.

The throughline: Modus is an autonomous offensive agent
delivered as an MCP server. The agent's autonomous loop runs
end-to-end inside Modus when invoked via its autonomous-session
MCP tool. The operator drives Modus from any MCP-aware host
(Claude Desktop primarily). The single hard human gate is on
the way out — Modus writes Candidates and stops, and the
operator promotes them to Findings via Quarry. Every milestone
is read against that target shape.

## Milestone 0 — Skeleton (done)

Repository layout, packaging, documentation scaffolding,
license, governance files. The README, ROADMAP, ADR-0001,
ADR-0002, ADR-0003 are in place; the corpus-interface document
pins Modus's contract on Quarry; the MCP host-integration doc
is in place. The package imports, the CLI runs, the test suite
is green.

## Milestone 1 — Action vocabulary and consistency check (done)

The typed action grammar is specified and implemented. The v0.1
action set (`Probe`, `Request`, `Compare`, `Differential`,
`Annotate`, `Hypothesize`) round-trips through the consistency
checker. Each action has a Pydantic model with its
preconditions, an SMT encoding of those preconditions, and a
deterministic accept/reject from the Z3 layer.
`modus action validate <spec.json>` returns a deterministic
verdict; the test suite covers each action type and at least
one negative case per type.

## Milestone 2 — Quarry corpus client (done)

Modus consumes Quarry's MCP surface as a client. `quarry mcp` is
a process Modus launches (or attaches to) and drives via JSON-RPC
over stdio. Modus reads corpus state via Quarry's read-only tools
(`status`, `list_targets`, `search`, `list_assets`, `diff`,
`coverage`, `recall`) and the analytical tools (`analyze_*`).
`modus corpus status` resolves a Quarry corpus and reports
current state. Modus reimplements no Quarry functionality.

## Milestone 3 — MCP server with verified-action surface (done)

Modus is itself an MCP server. `modus mcp` starts the server
over stdio. The server registers:

- **Verified-action tools**: one per Action variant
  (`probe`, `request`, `compare`, `differential`, `annotate`,
  `hypothesize`). Each tool's input schema is derived from the
  Pydantic model so the host's LLM emits grammatical calls by
  construction. Every call passes through the Z3 consistency
  check; rejected calls return `isError=True` with the failed
  precondition names.
- **Quarry passthroughs**: every Quarry MCP read tool plus the
  three analytical tools, proxied through Modus so the host
  configures one MCP server. Tools come straight from Modus's
  `QuarryMcpClient`.
- **Autonomous-session tools (registered, not yet implemented)**:
  `run_autonomous_session(...)` and `propose_actions(...)` are
  registered in the tool list with their schemas, but invoking
  them returns `isError=True` with "not yet implemented at
  Milestone 3 — see ROADMAP.md M4" until M4 lands. They are
  always present in the tool surface from M3 onward — that's
  what Modus *is*.

The HTTP executor lands here too: when the host calls Modus's
`request` tool, Modus performs the HTTP request inside the MCP
server process and persists the request/response to Quarry.

Exit criteria: Modus appears as an MCP server in Claude
Desktop's tool surface; the host can call every verified-action
tool and every Quarry passthrough; rejected actions surface
their failed preconditions to the host; the autonomous-session
tools are listed but error with a clear pointer to M4.

## Milestone 4 — Autonomous-session tool (done)

The `run_autonomous_session` tool runs the full ADR-0002 loop
inside its handler:

- Modus's own LLM provider (Anthropic / OpenAI / OpenAI-
  compatible) samples N candidate actions per step.
- The Z3 consistency layer prunes the inconsistent ones.
- A value heuristic (information-gain-style) ranks the
  survivors.
- The top-K execute via the same HTTP executor and Quarry
  client used by the verified-action tools.
- The loop runs until the budget (steps, time, token cost) is
  exhausted, or three consecutive empty pruning rounds, or the
  host cancels the tool call.
- The tool returns a structured result: every sampled
  proposal, every Z3 verdict, every executed action, every
  Candidate produced, plus session metadata.

The proposer is provider-portable. The operator configures it
via `MODUS_LLM_PROVIDER` and provider-specific env. Without
provider config the tool returns a friendly error explaining
which env vars to set.

Exit criteria: Modus completes a session against a controlled
lab target (a deliberately vulnerable application, not a real
bounty target) without per-step operator approval, and produces
at least one true-positive Candidate that survives the
operator's later review and would be a defensible Finding under
standard bounty triage. The session is reproducible from the
corpus alone.

## Milestone 5 — v0.1 release

The v0.1 bug-class scope is implemented end-to-end across both
surfaces. Documentation is complete enough for an external
operator to install Modus, configure it in Claude Desktop,
configure their Modus-internal LLM provider, point it at a
Quarry target, and run a session — landing Candidates in Quarry
for promotion. The audit surface (every action sampled, every
Z3 verdict, every executed action, every Candidate) is
queryable from Quarry.

Exit criteria: an external user (someone who is not the
maintainer) sets up Modus + Claude Desktop + Quarry against a
lab environment and produces a session summary without operator
hand-holding.

## Beyond v0.1

Out of scope for v0.1 and intentionally deferred:

- **Hypothesis ledger with Bayesian action selection.** Each
  session opens with explicit hypotheses ("this endpoint has
  IDOR"), each carrying a probability that gets updated by
  every observation; the proposer chooses actions that maximize
  expected information gain across competing hypotheses.
  Belongs after M4 ships and we have data on what value
  heuristics actually work.
- **Plan-then-verify multi-step actions.** The LLM emits a DAG
  of typed actions with data dependencies; Z3 verifies the whole
  plan before any of it runs.
- **MCP "sampling" capability for the autonomous loop** —
  letting Modus call back into the host's LLM for proposal
  generation instead of using its own provider. Considered for
  v0.1 and rejected because host support is partial; revisit
  when sampling support converges across hosts.
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
- A Modus-side chat UI. Modus is an MCP server; the operator
  drives it from their host. If a UI is wanted, it lives in the
  host or in a separate tool that consumes the corpus directly.
- A SaaS offering. Modus runs locally; the corpus runs locally
  via Quarry.
