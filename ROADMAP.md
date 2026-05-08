# Modus Roadmap

This roadmap is aspirational and will be revised as v0.1 proves
out or fails to. Dates are deliberately absent — milestones are
gated by working code, not calendars.

The throughline: Modus is an autonomous offensive agent
delivered as an MCP server. The agent's autonomous loop runs
end-to-end inside Modus when invoked via its autonomous-session
MCP tool. The operator drives Modus from any MCP-aware host
(Claude Desktop primarily). The autonomous loop closes the
Candidate→Finding lifecycle inside the corpus: severity-medium-
or-higher Candidates auto-promote to Findings via
`corpus.promote_finding`. The single hard human gate is on bug-
bounty submission — Modus has no submit-shaped tool, none will
be added, and submission of a Finding to a programme is the
operator's, performed outside Modus. Every milestone is read
against that target shape.

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

## Milestone 5 — v0.1 alpha release (0.1.0a1 shipped)

First alpha is out. The v0.1 bug-class scope is implemented
end-to-end across both surfaces; docs are complete enough for an
external operator to set up Modus + Claude Desktop + Quarry and
run a session — see [`docs/quickstart.md`](./docs/quickstart.md).
The audit surface (every action sampled, every Z3 verdict, every
executed action, every Candidate) is queryable from Quarry.

What 0.1.0a1 ships with:
- 18 always-present MCP tools (verified-action + Quarry-passthrough
  + autonomous-session).
- Host-sampling proposer (`MODUS_LLM_PROVIDER=host`) routing
  proposals back through the MCP host, plus direct-API providers
  for hosts that don't support sampling.
- Scope encoded as `(host, port, tls)` triples; consistency layer
  gates Request actions on the full triple.
- HTTP executor with same-origin redirect following.
- Submission line storage-enforced across every action class.

Promoted from "exit criteria" to "polish targets for 0.1.0":
the external-operator-without-hand-holding test will gate the
non-pre-release `0.1.0` tag. 0.1.0a1 ships the docs that *enable*
that test; whether the docs are sufficient is what subsequent
alpha releases will refine.

## Milestone 6 — Tools-first pivot (0.3.0a1 shipped)

Three milestones — `v0.1.0`, `v0.2.0`, `v0.3.0` on GitHub — landed
in a single arc as 11 issues / 17 commits since `0.1.0a1`. The
through-line: Modus is now an autonomous agent with an open tool
registry, not a closed-grammar agent that handed off recon and
scanning to the operator. ADR-0004 documents the pivot.

What `0.3.0a1` ships:

- **Open tool registry** — `Tool(name, args)` action variant + a
  per-`ServerSession` `ToolRegistry` keyed by name. Three
  invocation backends: `shell` (`subprocess` with placeholder-
  substituted argv, output capping, per-tool timeouts, scoped
  env), `builtin` (Modus-internal callables resolved by dotted
  path), and `mcp` (stub for v0.3; full passthrough is a
  follow-up). Per-tool preconditions function declared on each
  spec dispatched through Z3 — adding a new tool is one
  registry entry, not a `_preconditions` switch edit. Closes
  v0.3.0 issues #6 / #7 / #8 / #9 / #10 / #11.
- **Reference shell tools** — `amass.enum` and `nuclei.scan`
  ship as first-party shell registrations with scope-gating
  preconditions (domain in `scope.hosts()`; URL's
  `(host, port, tls)` in `scope.allowed_endpoints`). The agent
  reaches recon and vuln scanning through the same registry it
  reaches typed actions.
- **Async session pattern** — `start_autonomous_session` /
  `poll_autonomous_session` / `cancel_autonomous_session`
  escape the host's per-tool-call timeout. Long unattended
  runs (overnight grinds, multi-step recon) now fit the
  architecture; the budget bounds wall time, not the
  transport. Closes v0.2.0 issue #1.
- **Per-run observation gating** — `Hypothesize.evidence_refs`
  is constrained to observations the current run produced;
  cross-run bleed from the process-lifetime observation pool
  is structurally impossible. Closes v0.1.0 issue #4.
- **Strict dedup** — duplicate-survivor steps skipped, not
  re-executed. Closes v0.1.0 issue #2.
- **Pre-warm LLM at server startup** — cold-load tax for
  local Ollama models moves out of the operator's first
  autonomous-session call. Closes v0.1.0 issue #3.
- **Bug-class evidence pattern library** — eight classes
  (auth_bypass, idor, info_disclosure, sqli, ssrf, xss, csrf,
  business_logic) with per-class recognition templates and
  canonical severity defaults rendered into the proposer's
  closing-rule block. Smaller models stop defaulting to
  `severity_hint="info"` on clear `critical` findings. Closes
  v0.2.0 issue #5.
- **Submission policy revised** — structural firewall stays
  (no `submit`-shaped *tool* in the registry, adding one is
  off-limits, terminal state is a Candidate in storage); the
  verbal ban on rationales recommending submission is dropped.

## Milestone 7 — Autonomous Candidate→Finding promotion (0.4.0 shipped)

The autonomous loop closes the full hypothesize → Quarry-
persisted Candidate → Finding lifecycle inside a single
`run_autonomous_session` call, severity-gated. ADR-0002 §4
amended; ADR-0003 §6 amended; ADR-0004's "Submission line"
amended.

What `0.4.0a1` ships:

- **`corpus.promote_finding` builtin** in the default
  `ToolRegistry`, dispatching to
  `modus.builtins.corpus.promote_finding` → Quarry's MCP
  `finding_promote` write tool. Per-tool precondition gates the
  Candidate id on this run's pool; cross-run promotion remains
  the operator's `quarry finding promote` CLI verb.
- **Agent-authored Candidates persist to Quarry.** The
  `hypothesize` action handler funnels the SessionCandidate
  into Quarry's `db.upsert_candidate` via the new
  `candidate_create` MCP write tool (Quarry-side), so the
  resulting row is byte-identical to what the analytical
  modules produce. Module name `agent_hypothesize`; dedup key
  `<bug_class>:<sorted_evidence_refs>`; score derived
  monotonically from `severity_hint`.
- **Severity-gated auto-promotion**: medium/high/critical
  Candidates auto-promote to Findings inside the run; low/info
  stay un-promoted for operator review.
- **Pattern-driven fallback proposer** that closes the
  decisiveness gap mid-size open-weight models hit on the
  autonomous loop. Per-bug-class detectors
  (info_disclosure / auth_bypass / idor / sqli) match against
  the run's observations and synthesize `Hypothesize` plus
  `corpus.promote_finding` proposals when the LLM keeps
  abdicating. Frontier models reach the lifecycle on their
  own — the fallback only fires when local models won't.
- **`AgentLoop.run(initial_observation_ids=...)`** parameter
  to seed the run pool from operator recon (typically `httpx`,
  `katana`, or `responses`-shape JSONL ingested into Quarry
  before the autonomous run starts).
- **Submission firewall: unchanged.** No `submit`/`publish`/
  `post`/`report`/`report-to-h1` tool exists in the registry;
  declaring one in a scope file's `tools` block is a policy
  violation. Submission to bug-bounty programmes remains the
  operator's, performed outside Modus.

Verified live 2026-05-08: phi4:14b on M1 Pro / 16 GB unified,
against an OWASP Juice Shop corpus seeded with 38 recon
evidence chunks, produced 5 Candidates and 4 auto-promoted
Findings (high / high / medium / high) end-to-end inside one
22-step autonomous run. The fallback fired exactly once at
step 5 to unblock the LLM; phi4 emitted four more
hypothesizes and three promotions on its own afterward. The
severity=info Candidate stayed un-promoted per the policy.

The non-pre-release `0.4.0` tag shipped 2026-05-08 once the
operator-UX gap closed: the autonomous-session MCP tools accept
`recon_jsonl_path` (#21) and auto-load from the Quarry corpus
via `seed_from_corpus=True` (#23), so MCP-host operators can
drive the full seeded-corpus autonomous flow with zero Python
driver scripts and zero arguments beyond `target` and
`bug_classes`. The doc-following dry-run before tagging surfaced
five friction points (#26) — stale tool count, missing
`quarry target add` step, payload field mismatches — all fixed
in the tagged release. The external-operator-without-hand-
holding human-test remains an unwritten test the v0.4.0 release
notes acknowledge openly; it's deferred to whatever real user
runs the docs first.

## Beyond v0.4

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
