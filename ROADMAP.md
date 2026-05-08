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

## Milestone 8 — Engagement-driven hardening + recon partition tooling (shipped 2026-05-08)

Real-target validation against Anduril's bug-bounty programme
surfaced three structural bugs and one operator-workflow gap.
All shipped in one arc:

- **Bug A — `ScopePolicy.default_headers` + merged-header audit
  capture.** Bug-bounty programmes commonly require an
  identifying header on every probe (HackerOne's
  `X-HackerOne-Research`, Bugcrowd equivalents). Pinned headers
  flow through the httpx client defaults and merge with
  per-request action.headers at send time. The executor's audit
  observation now records the *effective* header set (via
  `client.build_request` + `client.send`), not just the
  per-request slice — without this fix, the audit couldn't
  substantiate that the H1 header had actually gone on the wire.
  Shipped in 20b8bcc.
- **Bug B — same-host enforcement on auth_bypass / IDOR pattern
  detectors.** The detectors keyed by URL path only, so two
  unrelated services that happened to share a path got bucketed
  together; the 2026-05-08 Anduril run promoted an `auth_bypass
  HIGH` false positive comparing `foxglove.chaos.anduril.dev/`
  (200, deliberate health endpoint) to
  `cyberchef.security.anduril.dev/` (401, IP-allowlisted). Bucket
  key now includes hostname. Shipped in f89bf05.
- **Bug C — layered secret detection in info_disclosure
  pattern.** The bare-keyword substring detector fired on every
  HTML login form on the internet — including a stock Okta SAML
  login form because the form contained `<input name="password">`.
  Refactor splits detection into concrete-shape patterns (PEM
  keys, AWS access keys, GitHub/Slack tokens) with critical
  severity, keyword+value patterns with form-attribute exclusion
  + placeholder rejection at high severity, and bearer+token at
  high severity. Shipped in e7de124.
- **Issue #31 — `modus partition` CLI.** Closes the
  partition-slip class of bug from two consecutive engagements
  (`testsocom.anduril.com` 2026-05-02, `piv.usmc.anduril.com`
  2026-05-08). Maintained DO-NOT-TOUCH token list under
  `modus.partition._MARKERS` is the central place engagement
  learnings accrete: `.gov.` infix, 13 combatant commands
  (AFRICOM, CENTCOM, CYBERCOM, EUCOM, INDOPACOM, NORTHCOM, PACOM,
  SOCOM, SOUTHCOM, SPACECOM, STRATCOM, TRANSCOM, USFF), service-
  branch acronyms (USAF, USMC, USCG, USSF) with segment-boundary
  matching, defense agencies (Pentagon, DARPA), `piv.`/`cac.`
  prefix rule for credential-gated customer deployments.
  Verified live against the 2026-05-08 Anduril subfinder output
  (636 hosts → 29 Tier C / 7 ambiguous / 8 Tier B / 592 Tier A),
  catching `testsocom`, `piv.usmc`, plus three additional PIV
  military deployments the ad-hoc partition would have missed.
  Shipped in 56fae22.
- **ADR 0005 foundation slice.** Three new optional
  `ScopePolicy` fields with consistency-layer wiring:
  `scope_wildcards` (program-published wildcard authorization,
  validated `*.example.com` patterns), `recon_mode` (gates
  `Request` action unconditionally + `Tool` actions to `read`
  side-effect tier), `denied_patterns` (defence-in-depth deny
  check with substring/segment/prefix/infix match modes). Plus
  `default_tier_c_denied_patterns()` helper exposing the
  partition tool's deny set automatically. Backwards-compatible:
  every v0.4 scope file loads and behaves identically. Shipped
  in 76af8c8.

ADRs 0005 and 0006 also drafted in this arc (33e8d98, 02ed433),
proposing the recon-mode + two-phase-session design (#29) and
engagement-coordinator session-of-sessions design (#30).

Tests: 439 passing (was 312 at v0.4.0), ruff clean, mypy clean
on changed surface.

## Milestone 9 — ADR 0005 full implementation: agent-driven recon (#29)

Closes the recon-side operator-driven workflow that today
consumes ~30 minutes of operator time before Modus's autonomous
loop can usefully run on a fresh target. The two-phase
autonomous-session design from ADR 0005, with the data-model
foundation already shipped in M8. Three slices remaining:

- **`corpus.propose_scope_expansion` builtin.** Reads the
  current target's `host`-kind assets from Quarry, filters to
  those matching `scope_wildcards` and not already in
  `allowed_assets`, excludes `denied_patterns` matches, runs
  `modus.partition.partition_hosts` over the survivors, returns a
  structured proposal: `{tier_a, tier_b, tier_c, ambiguous}` with
  per-host `matched_tokens` and `rationale`.
- **AgentLoop integration.** The autonomous loop, on observing
  the propose-scope-expansion tool's result, marks the run as
  `expansion_proposed` in the SessionRecord and exits with
  `termination_reason="expansion_proposed"`. The
  `run_autonomous_session` payload gains a
  `scope_expansion_proposal` field surfacing the proposal to the
  MCP host.
- **`modus scope commit-expansion` CLI verb.** Operator reviews
  the proposal, accepts (typically Tier A entire, or
  cherry-picked subset), and the CLI rewrites the scope file
  with the expanded `allowed_assets` and clears `recon_mode`.
  The next `run_autonomous_session` call inherits the narrowed
  allow-list and probes normally. The session-resume mechanism
  is the existing `start_autonomous_session` /
  `poll_autonomous_session` pair — the operator's commit doesn't
  require Modus to maintain pause-and-resume state internally.

Exit criteria: a fresh-target engagement runs end-to-end with
exactly two operator decisions — scope-commit and findings-
review — instead of the ~20 decisions per engagement that the
2026-05-08 Anduril run required. The structural firewall property
(operator-curated allow-list at probe time) is preserved; what
changes is *who curates the candidate set* (the agent proposes,
the operator commits).

Estimate: ~2-3 weeks of focused work. Backwards compatible with
M8.

## Milestone 10 — ADR 0006 full implementation: engagement coordinator (#30)

Session-of-sessions orchestrator. Generalises the autonomy claim
from "within a session" (M3/M4) to "across a multi-cycle
engagement." Deterministic state machine driving LLM decisions
within bounded transitions; operator gates only at scope-commit
(per M9) and findings-review. Persisted in Quarry as new
`engagements` table (own Quarry-side ADR). Parallel CLI
(`modus engagement run`) and MCP tool
(`modus.coordinate_engagement` + `modus.engagement_advance`).

Three implementation surfaces:

- **Quarry-side**: schema migration adding `engagements` table,
  read tools (`engagement_get`, `engagement_list`,
  `engagement_decision_log`), write tools (`engagement_create`,
  `engagement_advance`, `engagement_pause`, `engagement_resume`).
  Own ADR on the Quarry side.
- **Modus-side core**: `modus.engagement` module with
  `EngagementState` enum (INIT, RECON, AWAITING_SCOPE_REVIEW,
  PROBE, DECIDING, AWAITING_FINDINGS_REVIEW, COMPLETE, PAUSED,
  FAILED), `Engagement` dataclass, `EngagementCoordinator` class
  with one method per transition,
  `LlmCoordinatorProposer` and
  `DeterministicCoordinatorProposer` (both implementing a
  `CoordinatorProposer` Protocol — same pattern fallback shape
  ADR 0002 introduced for the per-action proposer).
- **Modus-side surface**: `modus engagement` CLI subcommand
  (`run`, `pause`, `resume`, `status`, `replay`),
  `modus.coordinate_engagement` MCP tool,
  `modus.engagement_advance` follow-up tool for operator gates.

The DECIDING transition is the only multi-edge state — the LLM
picks among `widen` (more recon), `deepen` (more probe budget),
`stop` (calibration met), or `fail` (blocked) given corpus
state, prior session histories, the coordinator's own decision
log, and hard budgets (`max_engagement_wall_time`,
`max_engagement_api_cost`).

Cost containment: deterministic fallback at DECIDING when LLM
budget exhausted or by operator opt-out, decision-input digest
caching, hard cost budget that pauses the engagement when
reached.

Exit criteria: a multi-day Anduril-class engagement runs
unattended in a `tmux` session, surviving operator absences
through `PAUSED` state, with the operator returning only at
scope-commit and findings-review gates. Decision log
post-replay-able from the corpus alone.

Estimate: ~4-6 weeks of focused work after M9 lands. Depends on
M9; a coordinator can't drive a two-phase autonomous-session
loop that doesn't exist.

## Beyond M10 — Calibration for novel and creative findings

The bar shifts from *competent on medium-effort programmes*
(M9 + M10 reach this) to *creative on real targets*. Pattern
detectors find known shapes; novel findings, by definition,
don't fit known shapes. Calibrating for novelty is therefore
not about adding more `_detect_*` functions to
`evidence_patterns.py` — that path produces a faster lookup of
well-known bug patterns, not a richer creative process.

What actually drives novel findings in security research:
reading source / API contracts deeply for intent-vs-implementation
divergences; understanding the trust model holistically for
states the system assumed couldn't exist; composing primitives
across components into chains where each individual piece looks
benign; catching non-obvious side effects (race conditions,
time-of-check time-of-use, cache poisoning across users);
applying lessons from disclosed bugs in analogous systems;
persistent "what if" questioning with non-obvious branches;
reading code nobody else reads.

Modus does ~zero of these today. Six concrete avenues, ordered
by impact-per-effort:

1. **Wider corpus + RAG-over-corpus proposer.** The proposer's
   per-step prompt today sees action history, recent
   observations, scope, bug-class templates — and *not* relevant
   context retrieved from the larger corpus. That's the single
   biggest bottleneck on creative reasoning. Quarry adapters for
   git repos (source code), API documentation (OpenAPI / Swagger),
   prior bug-bounty disclosures (HackerOne disclosed reports,
   CVEs, post-mortems indexed by bug class + target type),
   operator notes. Modus tools for retrieval-augmented context —
   the proposer per-step asks "show me where this endpoint is
   implemented" or "find me bugs like this in similar systems"
   and gets relevant snippets. Most novel findings are old bugs
   in new contexts; this is the path to making that pattern
   reachable. ~6-10 weeks.
2. **Chain-aware proposer reasoning.** Today's proposer thinks
   in single actions. Real bug-bounty work thinks in
   *primitives → goals → bridges*. The action grammar already
   supports this (`Differential` takes many observations,
   `Hypothesize.evidence_refs` is a tuple); the per-step prompt
   doesn't structure thinking this way. Reframing the prompt to
   track primitives + goals + bridge candidates lets the LLM do
   chain-construction work the current prompt actively
   suppresses. ~2-3 weeks.
3. **Adversarial primitives as Tool actions.** `request.race(N,
   ...)` for race-condition probing, `request.smuggle(...)` for
   header-smuggling / cache-poisoning surface, `fuzzer.mutate_
   param(...)` for parameter mutation strategies. Operators
   declare in scope file's `tools` block; the agent uses them
   when the proposer thinks an adversarial probe makes sense.
   ~3-4 weeks for a useful starter set.
4. **Self-critique / proposal review.** A second LLM call per
   step that critiques the first: "is this proposal actually
   likely to find a bug, or am I confusing myself?" Penalty for
   false-positive class proposals; bonus for proposals that
   articulate concrete impact. The right shape is a layered
   proposer — cheap model proposes, expensive model reviews
   (Sonnet-then-Opus). ~2-3 weeks including prompt engineering.
5. **Operator-feedback calibration.** Every false-positive the
   operator marks teaches the proposer something. Persisted in
   Quarry as "things you got wrong on this engagement." Surfaced
   in the per-step prompt as "you previously over-flagged X; be
   more conservative on patterns like that." Over engagements,
   Modus calibrates to *this operator's* judgment of what counts
   as a real bug. ~3-4 weeks.
6. **Stronger model layering.** Three-tier proposer: pattern
   fallback (free, deterministic), Sonnet for routine action
   proposal (cheap, fast), Opus for chain construction +
   hypothesis evaluation + self-critique (slower, smarter). Each
   tier doing what it's best at. ~2-3 weeks.

Aggregate: ~9-12 months of focused work after M10 to reach
*creative for medium-effort programmes*. The frontier of what's
achievable for *creative on top-tier programmes* depends on LLM
capability that may or may not arrive on schedule; the
architecture should be ready for it. The honest read is that
novelty is upper-bounded by the proposer's reasoning capability,
and current frontier models still sit well below "frontier human
security researcher." Some of the gap closes when frontier
models get qualitatively better at multi-step adversarial
reasoning; some of the gap is fundamentally about *taste* (which
bugs are interesting vs. just technically valid) that's hard to
encode.

The single existence-proof milestone worth aiming at: a
RAG-augmented proposer surfaces a finding the operator agrees
is creative on a real target. One such run flips this section
from "probably possible" to "in hand."

## Long-horizon / speculative

Items that may belong on the roadmap eventually but aren't
ready to estimate:

- **Hypothesis ledger with Bayesian action selection.** Each
  session opens with explicit hypotheses ("this endpoint has
  IDOR"), each carrying a probability that gets updated by
  every observation; the proposer chooses actions that maximize
  expected information gain across competing hypotheses.
  Overlaps with chain-aware reasoning + operator-feedback
  calibration; would be the unified probabilistic substrate for
  both.
- **Plan-then-verify multi-step actions.** The LLM emits a DAG
  of typed actions with data dependencies; Z3 verifies the whole
  plan before any of it runs. Overlaps with chain-aware
  reasoning and self-critique; the formal-verification angle
  would be the differentiator.
- **Process-reward fine-tuning from Quarry promotion history.**
  Implicit feedback (which Candidates the operator promoted)
  as a training signal for the proposer. Requires Quarry-side
  promotion volume that doesn't exist yet (currently dozens of
  Findings across all engagements; useful fine-tuning needs
  thousands). Adjacent to operator-feedback calibration but
  distinct (training vs. prompting).
- **Adapter coverage for additional corpus substrates.** The
  corpus interface is documented; in principle any MCP server
  matching it works. In practice we are coupled to Quarry until
  someone needs otherwise.
- **MCP "elicitation" capability for the autonomous loop.**
  Letting Modus prompt the host's LLM mid-session for
  operator-via-host clarifications instead of the always-bounded
  operator-gate model from ADR 0006. Reconsidered if MCP host
  support converges and the operator-gate shape proves too
  rigid for some engagement classes.
- **A community-maintained partition-tokens repo.** Fetched by
  `modus partition` at run time, signed, validated. Addresses
  the ADR 0005 §Negative-consequences worry about
  `denied_patterns` source-of-truth lagging reality. Niche;
  nowhere near the critical path.

## What's deliberately not on the roadmap

- **Submission automation.** Stays a non-goal at every
  milestone, as a hard rule, not a deferred feature. Modus has
  no `submit` / `publish` / `post` / `report` /
  `report-to-h1`-shaped tool, declaring one in a scope file's
  `tools` block is a policy violation, and submission of a
  Finding to a bug-bounty programme remains the operator's,
  performed outside Modus. The autonomous loop closes the
  Candidate→Finding lifecycle inside the corpus (M7); the
  Finding→submitted-to-programme line is what stays absolute.
- **A Modus-side report-generation feature.** Submission-ready
  text is the operator's job; Modus produces structured
  Candidates and Findings in Quarry. Operators draft submission
  text from those.
- **A Modus-side chat UI.** Modus is an MCP server; the
  operator drives it from their host. If a UI is wanted, it
  lives in the host or in a separate tool that consumes the
  corpus directly.
- **A SaaS offering.** Modus runs locally; the corpus runs
  locally via Quarry. Multi-tenant hosting of an offensive
  agent is a different product with different risk posture; if
  it ever exists, it's somewhere else, not this repository.
