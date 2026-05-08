# ADR 0006: Engagement coordinator — session-of-sessions

- **Status:** proposed
- **Date:** 2026-05-08
- **Supersedes:** —
- **Extends:** ADR 0002 (autonomous loop), ADR 0003 (host-driven loop /
  MCP-server boundary), ADR 0005 (recon-mode scope and two-phase
  autonomous session)
- **Issue:** [#30](https://github.com/pb3ck/modus/issues/30)

## Context

ADR 0002 made *one autonomous session* fully self-directing within a
budget envelope. ADR 0005 makes one engagement *cycle* (recon → propose
→ commit → probe) fully autonomous within bounded operator review.
Neither addresses the layer above: an *engagement* in real bug-bounty
work is many cycles. Recon turns up infra; you probe it; the probe
results suggest more recon (different bug class, deeper paths, sister
deployments); you re-probe; eventually you exhaust the surface or
calibrate "this target is cold." Today, every transition between
those cycles is operator-driven — not because the structural firewall
requires it, but because we don't have a coordinator.

The 2026-05-08 Anduril engagement made the cost concrete. Five
autonomous sessions ran across the night, with ~20 operator decisions
between them: "widen scope?", "patch this bug now or file?", "Tier B
or C for this ambiguous host?", "stop or keep going?". Modus's
autonomous loop is autonomous; the engagement is not. The autonomy
claim ends up scoped to "within a session" — exactly the pattern ADRs
0004 and 0005 generalised away from for the action vocabulary and the
recon-vs-probe boundary respectively. This ADR generalises it for the
session boundary itself.

ADR 0005 is the prerequisite. Without it, an engagement coordinator
that wanted to drive recon → probe → re-recon would have to do the
scope expansion itself — and that's the operator-authorization step
that ADR 0005 specifically declined to automate. With ADR 0005 in
place, the coordinator's job becomes *deciding the next session's
parameters*, not *deciding scope*. Scope decisions remain operator-
gated through the propose-and-commit step ADR 0005 introduced. The
coordinator orchestrates everything *between* operator gates.

A note on scope. This ADR is design-only. The implementation is a
multi-week effort that depends on ADR 0005 being implemented first;
the coordinator can't drive a two-phase loop that doesn't exist yet.
Treat this as the architectural map, not the build plan.

## Decision

The engagement coordinator is **a deterministic state machine driving
LLM decisions within bounded transitions**, persisted in Quarry as a
new entity type, exposed via a new `modus engagement` CLI verb and a
parallel MCP tool. The state machine owns the *legal moves* between
sessions; the LLM picks *among legal moves* at decision points. The
operator's authorization gates remain exactly where ADR 0005 placed
them — scope commits and findings review — and nowhere else.

### State machine

An engagement is a finite-state machine with the following states:

```
              ┌────────────────────────┐
              │     INIT (operator)    │
              │  framing: program,     │
              │  scope_wildcards, ROE  │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │    RECON (autonomous)  │ ← recon-mode session per ADR 0005
              │  passive enumeration   │
              │  + ingest into Quarry  │
              └────────────┬───────────┘
                           │ propose_scope_expansion emitted
                           ▼
              ┌────────────────────────┐
              │ AWAITING_SCOPE_REVIEW  │ ← operator gate (ADR 0005)
              │  (operator commits     │
              │   Tier A subset)       │
              └────────────┬───────────┘
                           │ scope-commit
                           ▼
              ┌────────────────────────┐
              │    PROBE (autonomous)  │ ← probe-mode session per ADR 0002
              │  per-host probing,     │
              │  hypothesis, severity- │
              │  gated promotion       │
              └────────────┬───────────┘
                           │ session terminates
                           ▼
              ┌────────────────────────┐
              │       DECIDING         │ ← coordinator decision point
              │  read corpus state,    │
              │  pick next move        │
              └─────┬──────┬──────┬────┘
                    │      │      │
            widen   │      │ deep │ stop
                    ▼      ▼      ▼
                  RECON  PROBE  COMPLETE/AWAITING_FINDINGS_REVIEW
```

A second operator gate, **AWAITING_FINDINGS_REVIEW**, fires when the
coordinator reaches COMPLETE *and* the corpus has at least one
auto-promoted Finding the operator hasn't acknowledged. The
operator confirms, redirects (e.g. "the auto-promotion is wrong;
retract"), or terminates. This gate is bounded — one decision per
engagement-completion, not per Finding.

A third gate, **PAUSED**, isn't operator-authorization-load-bearing
— it's a budget/cost control. The operator can pause an engagement
mid-cycle (no API calls, no live traffic) and resume later. Implemented
as a flag on the engagement state row.

### LLM coordinator at the DECIDING transition

DECIDING is the only state with multiple legal next-state edges. The
state machine narrows the choice to the four edges in the diagram:
**widen** (more recon, e.g. new asset class — JS bundles, headers,
sister deployments), **deepen** (more probe budget against the
current scope, different bug classes), **stop** (calibration met, no
more findings expected), or **fail** (something blocking — quota,
auth, infrastructure). The LLM coordinator picks among them.

Inputs to the DECIDING LLM call:

- The engagement's framing (program, ROE, current scope_wildcards,
  current allowed_assets)
- The Quarry corpus state — current target's findings, candidates,
  evidence chunks per asset, last-run timestamps
- The session-record histories from prior PROBE phases — what was
  tried, what surfaced, what didn't
- The coordinator's own decision log — prior DECIDING outcomes and
  their downstream results (a primitive form of credit assignment)
- Hard budgets: max_engagement_wall_time, max_engagement_api_cost
  (declared by the operator at INIT)

The output is a structured choice (`widen` | `deepen` | `stop` |
`fail`) plus the parameters for the next session (bug_classes,
budget, objective text). The LLM never picks an *illegal* move —
the state-machine layer constrains the available choices. The LLM
*never* picks scope expansion — that's the operator gate from ADR
0005.

### Persistence: engagement entity in Quarry

Quarry's schema gains an `engagements` table (Quarry-side migration,
own ADR there). Columns:

```
engagements
├── id (UUID, primary key)
├── target_id (FK to targets — the engagement is per-target)
├── state (enum: INIT/RECON/AWAITING_SCOPE_REVIEW/PROBE/DECIDING/
│         AWAITING_FINDINGS_REVIEW/COMPLETE/PAUSED/FAILED)
├── framing (JSON: program rules, scope_wildcards, budgets)
├── decision_log (JSON array of {timestamp, state, decision,
│                 rationale} entries; append-only audit trail)
├── created_at, updated_at, completed_at
```

The decision_log is what makes the coordinator's reasoning auditable.
Every DECIDING outcome captures the LLM's rationale text, the
inputs it saw (digest of the corpus state at decision time), and
the chosen move. An operator can replay an engagement's decisions
post-hoc.

### Surface: CLI + MCP tool

Two parallel surfaces, mirroring ADR 0003's "verified-action +
autonomous-session both always present" pattern:

- **CLI verb** `modus engagement run --framing <yaml>` — for
  operators driving from the terminal. The framing YAML declares
  the program, scope_wildcards, budgets, ROE notes. The CLI streams
  state transitions and operator-gate prompts to stderr; on
  AWAITING_SCOPE_REVIEW or AWAITING_FINDINGS_REVIEW, it pauses with
  a structured prompt and resumes on operator input.

- **MCP tool** `modus.coordinate_engagement` — for MCP-host-driven
  engagements (Claude Desktop, Claude Code). Returns the current
  engagement state and the next operator-gate prompt; the host's
  LLM relays the prompt to the operator and feeds the response back
  via a follow-up tool call (`modus.engagement_advance`).

Both surfaces are thin shims over the same core coordinator. The
core lives at `modus.engagement` (new module).

### Decoupling LLM cost from engagement length

The coordinator's DECIDING calls accumulate over the engagement.
With a long-running engagement (days of background runs), unbounded
LLM cost is the operational risk. Three mitigations:

1. The DECIDING LLM call is bounded by `max_engagement_api_cost` —
   when the budget is consumed, the coordinator transitions to
   PAUSED with reason `api_cost_exhausted`. Operator decides
   whether to top up or stop.
2. The DECIDING input is digest-cached — same corpus state +
   framing produces the same decision deterministically (within
   sampling temperature). Repeated DECIDING transitions on the
   same state read from cache rather than re-prompting.
3. A non-LLM fallback DECIDING path: a deterministic policy that
   reads the same inputs and picks `widen` if the corpus has
   <N evidence chunks, `deepen` if <M findings have been promoted
   in the last K sessions, `stop` otherwise. Activated when LLM
   budget is exhausted *or* when the operator opts in via
   `--no-llm-coordinator`. Mirrors ADR 0002's pattern fallback for
   the proposer.

## Consequences

### Positive

- **The autonomy claim generalises across the engagement boundary.**
  ADR 0001 → "autonomous within a session." ADR 0005 → "autonomous
  within a recon-or-probe phase." This ADR → "autonomous across
  multiple cycles, with operator review only at authorization-
  load-bearing gates." Three nested generalizations of the same
  property.
- **Operator review remains bounded.** Scope commits + findings
  review per engagement = ~2-N decisions, where N is the number
  of recon-cycle iterations. For a typical engagement that's 1-3
  scope commits and 1 findings review. Not 20+ decisions per night.
- **Audit trail is uniform.** Every coordinator decision is a row
  in `engagements.decision_log`; every operator gate response is
  a row; every session-of-sessions transition is a row. The
  engagement is replayable post-hoc.
- **Composes with ADR 0005.** The coordinator is the layer that
  drives ADR 0005's two-phase loop on a schedule. Without the
  coordinator, ADR 0005 still works for one-shot engagements;
  with the coordinator, it works for ongoing ones too.
- **Composes with ADR 0002's pattern fallback.** The LLM-vs-
  deterministic-fallback split that closes the LLM commitment gap
  for the proposer (ADR 0002 §4 amendment) reappears here for the
  coordinator. Same pattern, same justification.
- **The engagement state survives crashes.** Persisting state in
  Quarry means an engagement paused at AWAITING_SCOPE_REVIEW for
  three days resumes correctly. No "this session timed out, start
  over" failure mode.

### Negative

- **Implementation surface area.** Quarry schema migration (new
  `engagements` table), new `modus.engagement` module (state
  machine + LLM coordinator + decision log), CLI verb, MCP tool,
  parallel test surface for every state transition, framing-YAML
  schema. Estimated 4-6 weeks of careful work *after* ADR 0005 is
  implemented (which is itself 2-3 weeks). This is a v0.6 deliverable
  at earliest.
- **Coordinator LLM is a second proposer-class component.** The
  proposer LLM (per ADR 0002) decides actions within a session. The
  coordinator LLM decides session transitions. Two LLM call sites
  with different prompts, different cost profiles, different
  failure modes. Operator config grows.
- **Decision-quality opacity.** The LLM coordinator's "widen vs
  deepen" choice is harder to evaluate than the proposer's
  per-action choice. We have no good metric for "was this
  engagement-strategy decision correct?" — the closest proxy is
  "did the next session find anything?", but that's lagging and
  noisy. The deterministic fallback gives us a baseline; comparing
  LLM vs fallback decision quality is its own research question.
- **Operator-trust concentration.** The coordinator is making
  *strategic* decisions on the operator's behalf — "is this target
  cold?" "should we look at JS bundles next?" An operator who
  trusts the per-session loop today might not trust the
  per-engagement strategy tomorrow. The operator can override at
  every gate, but the decision-trust-curve is steeper than
  per-session autonomy.
- **API cost surface.** Long-running engagements with LLM coordinator
  active accumulate cost between sessions. The mitigations above
  (budget cap, decision-cache, deterministic fallback) bound this
  but don't eliminate it.

### Neutral

- **Engagement state is a new corpus entity.** Quarry's schema gains
  `engagements`. Pulls Quarry-side complexity that wasn't there
  before — but engagements are the natural unit of bug-bounty work
  and Quarry already tracks targets, runs, evidence, findings.
  Engagements fit the model.
- **Two surfaces (CLI + MCP) is the existing pattern.** ADR 0003
  established that verified-action and autonomous-session tools are
  both always present. The coordinator follows the same shape —
  CLI for terminal-driven operators, MCP tool for host-driven ones.
- **Framing is operator-load-bearing forever.** This ADR doesn't
  automate the engagement *framing* step. Program rules, ROE,
  scope_wildcards — those come from the operator reading the bug-
  bounty program page. That's outside Modus's responsibility and
  stays that way.

## Alternatives considered

### Alternative A — host-LLM-as-coordinator

Instead of a Modus-internal coordinator, let the MCP host's LLM
(the Claude Code session, etc.) drive engagement strategy directly
using Modus's existing autonomous-session tools. The host's LLM
already has the operator, the conversation context, and access to
all of Modus's tools.

This is what we did during the 2026-05-08 Anduril engagement —
Claude-Code-as-coordinator, with the operator approving every
transition.

**Rejected.** Three reasons:

1. **Not deterministic across hosts.** A Claude Code engagement
   would coordinate differently from a Claude Desktop engagement
   from a Cursor engagement, because the host's LLM behaviour
   varies. The decision_log audit property only works if the
   coordinator is part of Modus, not part of the host.
2. **Host-context-bound.** The host's LLM holds engagement state
   in its conversation context, which doesn't survive a session
   restart. A 3-day engagement crosses many host conversations.
   Pinning state in Quarry decouples the engagement from the host's
   conversation lifecycle.
3. **Operator-trust pattern.** "Modus runs your engagement" is a
   different deal than "Claude Code (with Modus tools) runs your
   engagement." The first is an offering with a clear scope; the
   second is "your AI assistant with broad capabilities, doing
   whatever it decides." For an autonomous offensive agent, the
   bounded version is the only safe one.

### Alternative B — fully deterministic coordinator (no LLM)

Skip the LLM at DECIDING. The state machine plus a hand-coded
policy ("if no findings in last 2 sessions, widen scope; if 5
sessions without findings, stop") drives every transition.

**Rejected, with reservations.** This is what the deterministic
fallback in the chosen design does — and it's there for a reason.
The fallback is *cheaper* but *worse* than the LLM at engagement
strategy: the LLM can read corpus state qualitatively
("foxglove.bunker has version 0.0.97 and foxglove.chaos has
0.0.93, suggesting concurrent deployment lanes — let's check the
other anduril.dev sister hosts for additional version drift") in
ways the deterministic policy can't.

The right model is LLM-by-default with deterministic fallback, not
deterministic-only. We keep the fallback; we don't elevate it to
primary.

### Alternative C — operator-driven coordinator, no LLM, no state machine

Status quo. Operator manually orchestrates sessions. Modus offers
each session as a tool; the operator decides when and how to chain
them.

**Rejected.** This is the design space the engagement coordinator
ADR is *responding to*. The 2026-05-08 Anduril engagement showed
this scales linearly with operator attention — 20 decisions per
night for one target. For multi-target programmes (a hunter
working five bug-bounty programmes simultaneously), the operator
becomes the bottleneck. The coordinator is what removes that.

### Alternative D — coordinator-as-MCP-server-only

Same as the chosen design but skip the CLI surface. The coordinator
is only available via the MCP host's `modus.coordinate_engagement`
tool.

**Rejected.** The CLI surface is needed for headless operation —
a multi-day engagement running in a `tmux` session on a research
VM, no MCP host attached. This isn't a hypothetical — long-running
recon engagements (continuous monitoring, post-acquisition surface
re-survey) want exactly that shape. Both surfaces, parallel.

### Alternative E — coordinator decides scope expansion too

Promote the coordinator to authority over the ADR 0005 operator-gate.
The coordinator's LLM reads the propose_scope_expansion result and
decides whether to commit, with no human review.

**Rejected.** The slip-asymmetry argument from ADR 0005 §Alternatives
applies even more strongly here. An LLM-driven coordinator that
hallucinates a Tier A classification (or falls for prompt-injection
in a recon-tool's output) commits Modus to probing infrastructure
the operator never authorised. The human gate at scope-expansion is
load-bearing for *legal* authorization, not just safety. Removing it
would be removing the property that makes Modus a defensible
autonomous offensive agent rather than an unbounded scanner.

The coordinator decides *strategy*; the operator authorizes *scope*.
That separation is the load-bearing one.

## Implementation outline (sketch, not commitment)

For when implementation begins:

1. **Quarry-side**: schema migration adding `engagements` table,
   read tools (`engagement_get`, `engagement_list`,
   `engagement_decision_log`), write tools (`engagement_create`,
   `engagement_advance`, `engagement_pause`, `engagement_resume`).
   Own ADR on the Quarry side.
2. **Modus-side core**: `modus.engagement` module with
   `EngagementState` enum, `Engagement` dataclass mirroring the
   Quarry row, `EngagementCoordinator` class with one method per
   transition, `LlmCoordinatorProposer` and
   `DeterministicCoordinatorProposer` (both implementing a
   `CoordinatorProposer` Protocol).
3. **Modus-side surface**: `modus engagement` CLI subcommand
   (`run`, `pause`, `resume`, `status`, `replay`),
   `modus.coordinate_engagement` MCP tool +
   `modus.engagement_advance`.
4. **Test surface**: state-transition tests (every valid edge,
   every rejected invalid edge), coordinator-LLM deterministic-
   fallback parity tests (LLM and fallback agree on simple cases),
   end-to-end test with a mocked Quarry + Anthropic + a synthetic
   "5-host engagement" fixture.
5. **Migration**: ADR 0005 must be implemented first. The
   coordinator can't drive a two-phase autonomous-session loop
   that doesn't exist.

## References

- Issue [#30](https://github.com/pb3ck/modus/issues/30) — engagement
  coordinator design problem statement
- Issue [#29](https://github.com/pb3ck/modus/issues/29) and ADR 0005
  — recon-mode scope and two-phase autonomous session, the
  prerequisite this ADR builds on
- ADR 0002 §4 — autonomous loop's pattern-fallback split (the
  same LLM-vs-deterministic shape this ADR adopts for the
  coordinator)
- ADR 0003 — host-driven loop / MCP-server boundary (the parallel
  CLI + MCP surface pattern)
- 2026-05-08 Anduril engagement — the concrete operator-decision
  burden this coordinator removes (~20 decisions per night for one
  target)
