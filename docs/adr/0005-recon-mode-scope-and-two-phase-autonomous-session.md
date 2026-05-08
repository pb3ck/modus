# ADR 0005: Recon-mode scope and two-phase autonomous session

- **Status:** proposed
- **Date:** 2026-05-08
- **Supersedes:** —
- **Extends:** ADR 0001 (typed action vocabulary), ADR 0002 (autonomous
  loop), ADR 0003 (host-driven loop / MCP-server boundary)
- **Issue:** [#29](https://github.com/pb3ck/modus/issues/29)

## Context

`ScopePolicy.allowed_assets` is exact-match. `_parse_allowed_asset` in
`src/modus/scope.py` rejects wildcards (`*.example.com`) outright — the
operator must enumerate every host they want Modus to be able to reach
*before* the autonomous loop starts. That's the structural firewall:
the agent literally cannot generate traffic to a host the operator
hasn't pre-vetted. ADR 0001's "typed actions plus consistency check"
invariant gets its safety property from this allow-list shape.

The 2026-05-08 Anduril engagement made the cost of this property
concrete. The operator-driven workflow before Modus could do anything
was:

1. Run `subfinder` against the program's six wildcards (~3 minutes)
2. Hand-partition 636 hosts into Tier A/B/C (operator judgment, ~10
   minutes, slipped twice across two engagements)
3. `httpx` probe 419 Tier A new hosts (~45 seconds)
4. Author the scope file (manual JSON edit)
5. `quarry target add` + `quarry ingest`
6. *Now* Modus's autonomous loop can run

Steps 1–5 are ~30 minutes of operator workflow that the autonomous
agent was nominally supposed to absorb. The "autonomous" claim ends up
context-dependent: true inside one session, false across the engagement.
This is the same generalization step ADR 0004 took for the focused-
attack vs. recon split — the closed grammar made recon
structurally unreachable; this ADR makes the closed allow-list make
agent-driven recon structurally unreachable. Three of the v0.3
invariants — typed actions, formal consistency check, Quarry-backed
corpus — generalise cleanly to a richer scope shape; the fourth
(exact-match allow-list) is the one this ADR revisits.

A complicating recent fact: ADR 0004 made the action vocabulary open
via a tool registry. The operator can declare `subfinder` and `httpx`
as scope-file shell tools today and the agent could call them as `Tool`
actions. But the agent can't *use* the discovered hosts — anything
subfinder turns up that isn't already in `allowed_assets` is
unreachable for `Request`. So the open grammar without the open scope
gets us "agent runs subfinder" but stops short of "agent probes what
subfinder found." Half a workflow.

A second complicating recent fact: the maintained Tier A/B/C partition
landed in #31 (`modus partition` CLI) the same night this ADR is
written. That changes the implementation calculus for one of the
candidate designs (deny-pattern preconditions, Alternative C below) —
but two slips in two engagements (`testsocom` 2026-05-02,
`piv.usmc` 2026-05-08) is the evidence we have on whether deny lists
actually keep up with reality.

## Decision

Adopt a **two-phase autonomous session** with **recon-mode scope** as
the Phase-1 substrate. The operator authorizes a *wildcard* scope (the
program's published bug-bounty scope), the agent does recon under
read-only constraints, the agent proposes a Tier A/B/C partition using
the ADR-0004 tool registry plus the #31 partition logic, the operator
commits the proposal in one bounded review step, and the session
resumes with the now-narrowed exact-match allow-list. The operator
remains the load-bearing authorization for what the agent probes; the
operator's review is bounded to one decision per recon cycle rather
than N probes.

### `ScopePolicy` shape change

Three optional fields added to `ScopePolicy`. None are required; an
operator who wants the v0.4 exact-match-only behaviour just doesn't
set them.

```python
class ScopePolicy(BaseModel):
    target_name: str
    allowed_assets: frozenset[str] = frozenset()       # existing
    allowed_methods: frozenset[str] = ...              # existing
    user_agent: str = ...                              # existing
    default_headers: dict[str, str] = {}               # existing
    tools: tuple[ToolDeclaration, ...] = ()            # existing

    # NEW: program-published wildcard scope. Used in recon mode and as
    # the substrate from which scope-expansion proposals draw their
    # candidate hosts. Multiple entries supported (Anduril publishes
    # six wildcards). Each entry validated as a wildcard pattern of
    # the form `*.example.com` or `*.example.co.uk` — exactly one
    # leading wildcard label, no embedded wildcards.
    scope_wildcards: frozenset[str] = frozenset()

    # NEW: explicit recon-mode flag. When True, the consistency check
    # gates the `Request` action off entirely — only `read`-tier
    # tools (subfinder, crt.sh fetch, asset readback from Quarry) can
    # run. The agent can't generate live traffic to wildcard-matched
    # hosts in recon mode, only enumerate them via OSINT.
    recon_mode: bool = False

    # NEW: deny-pattern set, sourced from the maintained #31
    # partition `_MARKERS`. Even when an operator commits a
    # scope-expansion proposal, hosts matching these patterns are
    # rejected at the consistency layer as a defence-in-depth. Same
    # tokens that drive the partition CLI; reusing the list as the
    # deny set means engagement learnings flow into both surfaces.
    denied_patterns: frozenset[str] = frozenset()
```

### Phase 1: recon mode

When `recon_mode=True`:

- **`Request` action is rejected** by the consistency layer
  unconditionally. Recon mode is read-only OSINT; live HTTP probing
  is the operator-gated phase.
- **`Tool` actions are gated by side-effect tier**. `read` tier
  (subfinder, crt.sh fetch, dnsdumpster, search-engine OSINT,
  Quarry-passthrough reads) is allowed. `write` and `active` tiers
  are rejected. The tool registry's existing
  `ToolSpec.side_effect` attribute carries the tier (ADR 0004 §3).
- **Scope membership for tool argv substitution**. When a tool's
  `argv_template` includes `{target}` or similar, the substitution
  is checked against `scope_wildcards` (suffix match against any
  wildcard's parent zone) rather than `allowed_assets`. Lets the
  agent run `subfinder -d anduril.com` without `anduril.com`
  being in `allowed_assets`.

Recon mode produces one or more Quarry runs (subfinder output,
crt.sh fetches, asset rows). The agent's autonomous loop drives this
phase end-to-end. No human in the loop within Phase 1.

### Phase 2: scope-expansion proposal and commit

A new builtin tool `corpus.propose_scope_expansion` lives in
`modus.builtins.corpus`. It:

1. Reads the current target's `host`-kind assets from Quarry.
2. Filters to those matching any `scope_wildcards` entry's parent zone.
3. Excludes hosts already in `allowed_assets`.
4. Excludes hosts matching `denied_patterns`.
5. Runs `modus.partition.partition_hosts` over the survivors.
6. Returns a structured proposal: `{tier_a, tier_b, tier_c,
   ambiguous}` with per-host `matched_tokens` and `rationale`,
   plus a digest the operator hashes-checks before commit.

The autonomous-session loop, on observing this tool's result, marks
the run as **expansion-proposed** in the `SessionRecord` and exits
with `termination_reason = "expansion_proposed"`. The MCP host
surfaces the proposal to the operator (the existing
`run_autonomous_session` payload grows a `scope_expansion_proposal`
field).

The operator reviews the proposal — Tier A is the recommended
probe-eligible set, Tier B / Tier C / ambiguous are recommended
exclusions. The operator commits via:

```
modus scope commit-expansion --proposal-id <id> --accept-tier-a
```

This re-writes the scope file with the now-expanded `allowed_assets`
and clears `recon_mode`. The next `run_autonomous_session` call
inherits the narrowed allow-list and probes normally.

The session-resume mechanism is the existing
`start_autonomous_session` / `poll_autonomous_session` pair — the
operator's commit doesn't require Modus to maintain pause-and-resume
state internally. The agent's run terminates at proposal-emit; the
next run starts fresh with the new scope.

### Defence-in-depth: `denied_patterns` is a hard floor

Even when the operator accepts a Tier A proposal, the
`ConsistencyChecker` re-checks every probed host against
`denied_patterns` at action time. If the partition CLI's `_MARKERS`
list grows after the scope-expansion proposal was committed (e.g. a
new combatant-command marker is added in a Modus release between the
operator's commit and the next probe), the agent still gets blocked
from probing those hosts. The maintained list is the floor; the
operator-committed allow-list is the per-engagement ceiling.

This is the answer to the slip-asymmetry problem (Alternative C
below). Deny patterns alone aren't safe enough — they can lag
reality. But deny patterns *as a backstop* under an operator-curated
allow-list are strictly safer than the v0.4 allow-list-only model:
two filters, both must pass.

## Consequences

### Positive

- **Modus drives recon end-to-end.** The 30-minute pre-Modus operator
  workflow becomes a single autonomous session that emits a proposal,
  followed by one bounded operator review. The "autonomous" claim
  generalises across the engagement, not just the focused-attack
  stage. Resolves the gap raised in #29.
- **Operator review is bounded.** One scope-expansion decision per
  recon cycle, not N probe-by-probe approvals. The operator's
  attention scales with the *engagement*, not with the agent's
  per-step actions.
- **Structural firewall preserved.** The agent never expands its own
  allow-list. The operator does, in one bounded step. The exact-match
  allow-list invariant from ADR 0001 holds at probe time; recon-mode
  is its own gated surface.
- **Composes with #31.** The partition CLI's `_MARKERS` list is the
  source of truth for both `denied_patterns` and the partition logic
  inside `propose_scope_expansion`. One token list, two surfaces —
  engagement learnings (every slip caught at engagement time) flow
  into both deterministically.
- **Defence-in-depth.** `denied_patterns` as a consistency-layer
  floor under the operator's allow-list ceiling is strictly safer
  than v0.4 allow-list-only.
- **Backwards compatible.** Operators who don't set `scope_wildcards`
  or `recon_mode` get the v0.4 behaviour unchanged. The new path is
  opt-in.

### Negative

- **Implementation complexity.** Three new `ScopePolicy` fields, a
  new `corpus.propose_scope_expansion` builtin, a new CLI verb
  (`modus scope commit-expansion`), and a session-result field for
  the proposal payload. Estimated 2–3 weeks of careful work
  including the cross-cutting test surface (recon-mode behaves
  differently from probe-mode at every action's precondition layer).
- **Operator still in the loop.** A user who wants "fully agentic
  end-to-end recon → exploit" will see the bounded operator review
  as an interruption. The honest answer is that scope expansion is
  load-bearing for legal authorization (program rules, ROE) and
  isn't safely automatable; this ADR makes the unavoidable human
  step minimal rather than removing it. ADR 0006 (engagement
  coordinator, #30) is where "session-of-sessions" autonomy lives;
  this ADR enables but doesn't ship that.
- **`denied_patterns` source-of-truth coupling.** The Modus release
  cycle becomes a soft factor in deny-set freshness. If a new
  combatant-command marker emerges and `_MARKERS` isn't updated for
  three months, agent runs in those three months can't have it.
  Mitigation: `denied_patterns` is a frozenset, so an operator can
  override per-engagement via the scope file. Long-term mitigation:
  a community-maintained partition-tokens repo, fetched by `modus
  partition` at run time. Out of scope for this ADR.
- **Recon-mode tool side-effect tier dependency.** The `read`-tier
  gating in Phase 1 depends on tools being honestly labelled in their
  `ToolSpec.side_effect`. A maliciously- or carelessly-declared
  shell tool with `side_effect="read"` that actually fires HTTP
  requests would defeat the recon-mode constraint. The operator
  declares the tools, so this is the same trust-the-operator
  property the rest of the registry has — but worth surfacing.

### Neutral

- **Changes the scope-file shape.** Three new optional fields. JSON
  schema for the scope file gains a `scope_wildcards`, `recon_mode`,
  `denied_patterns` block. Documentation update; not a breaking
  change.
- **The partition CLI's role shifts.** Before this ADR: a
  recommendation tool the operator runs offline. After: also the
  source of truth for `propose_scope_expansion`'s ingest+filter
  pipeline. The CLI keeps existing as a manual operator surface
  (useful for one-off engagements where setting up recon-mode isn't
  worth it).
- **ADR 0004's "tools-first" framing is unchanged.** Recon-mode is
  a constraint *on which tools can run*, not a parallel grammar.
  The action vocabulary stays open. The consistency layer is where
  the constraint lives.

## Alternatives considered

### Alternative A — recon-mode scope without Phase 2

The original sketch in #29: add `scope_pattern` to `ScopePolicy`,
let the agent run subfinder under wildcard scope, but stop short of
the propose-and-commit handoff. The operator would manually inspect
the corpus and edit `allowed_assets` between sessions.

**Rejected.** This is half the workflow. The discovered hosts go
nowhere actionable; the operator still hand-curates the allow-list.
Doesn't move the operator-burden needle meaningfully — only saves the
subfinder run, not the partition step (which was the actually
expensive part of the 2026-05-08 workflow).

The recon-mode substrate from this alternative is preserved as
Phase 1 of the chosen design.

### Alternative B — two-phase autonomous session without recon-mode constraint

The opposite trim: keep the propose-scope-expansion handoff but skip
the recon-mode gating. Let the agent run any tool against
`scope_wildcards` (including live HTTP probing) before the operator
review.

**Rejected.** Recon mode's read-only constraint is the property that
makes the bounded operator review *bounded*. Without it, the agent
could pummel newly-discovered hosts with HTTP probes before the
operator has reviewed which ones are in scope. The operator would
then be reviewing the partition while traffic the agent already
generated sits in the audit trail. Recon mode separates "what could
exist" (passive enumeration, OSINT) from "what we touched" (probe-
mode). Both phases are agent-driven; only the second touches live
target infra.

### Alternative C — deny-pattern preconditions only

Encode the partition CLI's Tier C `_MARKERS` as
`ConsistencyChecker.denied_patterns`, add `scope_wildcards` to
`ScopePolicy`, and let the agent probe any wildcard-matching host
that doesn't trip a deny pattern. No two-phase split; no operator
review between recon and probe. Single continuous autonomous session.

**Rejected.** The slip data is the evidence. Two slips in two
engagements (`testsocom`, `piv.usmc`) caught only at engagement-time
shows the deny list lags reality even when actively maintained. The
asymmetry of error costs is the dispositive factor:

- *False positives* in the deny set silently exclude legitimate probe
  targets. Cost: missed bug-bounty findings. Recoverable on the next
  release.
- *False negatives* in the deny set let the agent probe military or
  customer-deployment infrastructure that the operator never
  authorised. Cost: program-rule violation, possible legal exposure
  per Anduril's "any testing involving physical approach to or
  proximity engagement with Anduril wireless networks, property,
  facilities, or personnel is strictly prohibited and may result in
  legal action" clause. Not recoverable.

The deny-pattern-only design has *no* second filter when the deny set
is wrong. The chosen design uses deny patterns as a defence-in-depth
floor under an operator-curated allow-list — wrong deny patterns
are still caught by the operator's commit step, and wrong commit
decisions are still caught by the deny patterns. Two filters, both
must fail to produce a violation.

### Alternative D — full LLM-driven scope decisions with operator notification

Let the agent's LLM proposer make the partition decision and silently
expand the allow-list during recon, with the operator notified
post-hoc.

**Rejected.** The submission line analogue: scope expansion is
authorization-load-bearing. An LLM proposer that hallucinates a
classification (or falls for prompt-injection from a recon tool's
output suggesting a host should be Tier A when it shouldn't) would
have committed Modus to probing infrastructure the operator never
saw. The operator's commit step is the firewall against that class
of failure. Notifying after the fact is too late.

## References

- Issue [#29](https://github.com/pb3ck/modus/issues/29) — recon-mode
  scope design problem statement
- Issue [#30](https://github.com/pb3ck/modus/issues/30) — engagement
  coordinator (depends on this ADR)
- Issue [#31](https://github.com/pb3ck/modus/issues/31) — partition
  CLI (composes with this ADR; closed 2026-05-08)
- ADR 0001 — typed action vocabulary (the structural firewall this
  ADR extends)
- ADR 0002 §6 — autonomous loop's pause/resume shape (the
  scope-expansion handoff uses this)
- ADR 0003 §4 — host-driven loop and async session lifecycle (the
  proposal-emit termination reason fits here)
- ADR 0004 — tools-first action grammar (the registry's
  `side_effect` tier is what gates Phase 1's read-only constraint)
- 2026-05-08 Anduril engagement memo — the concrete operator-burden
  data this ADR responds to
