# ADR 0002: Autonomous loop with verifier-driven sampling and prompt-cache-aware context

- **Status:** accepted
- **Date:** 2026-05-06
- **Supersedes:** —
- **Superseded by:** —
- **Extends:** [`0001-typed-action-vocabulary.md`](./0001-typed-action-vocabulary.md)
- **Extended by:** [`0003-host-driven-loop-mcp-server-boundary.md`](./0003-host-driven-loop-mcp-server-boundary.md)
  — the loop described here runs inside an MCP tool handler
  rather than as a standalone CLI loop. The loop's internals
  (N-sampling, Z3 pruning, ranking, budget-bounded execution,
  cache-zone discipline) are unchanged.

## Context

ADR-0001 commits to a typed action vocabulary validated by an SMT
solver before dispatch. It deliberately leaves the *loop shape*
unspecified — vocabulary and consistency are orthogonal to the
question of how the agent runs end-to-end.

That question is now load-bearing for the project, and the
default shape implied by typical agent literature — a single
LLM proposal per step, validated, executed, repeat, with the
operator approving each step — does not match Modus's intent.
Three things drive a different choice:

1. **Modus is intended to be autonomous.** The agent runs
   end-to-end without per-step operator approval. The hard human
   gate sits on the way *out*: Modus writes Candidates, and the
   operator promotes them via Quarry's `quarry finding promote`.
   That promotion happens after the session ends, not during it.
2. **The corpus is Quarry, accessed over MCP.** Long-term memory
   is durable in Quarry's SQLite; sessions bring in only the
   subset of the corpus relevant to the current step. The agent's
   working set is small and changing; the system prompt
   (vocabulary, scope, stable target context) is large and
   stable. Cache structure should reflect that asymmetry.
3. **The Z3 layer is wasted as a yes/no gate.** Validating one
   proposal at a time uses the solver as a filter; the solver
   is also a *pruner*, capable of eliminating whole classes of
   invalid action from a sampled batch in close to constant
   time relative to per-action proposal cost.

A free-form ReAct loop with operator-step approval would defeat
all three drivers: the agent isn't autonomous, retrieval isn't
cache-aware, and the solver is reduced to a binary gate. We need
a different loop shape, and we need to commit to it before the
proposer code lands.

## Decision

The Modus agent loop is an autonomous, verifier-driven,
prompt-cache-aware sampling loop. Concretely:

### 1. Verifier-driven sampling

At each step the agent does the following:

1. **Sample N proposals in parallel** from the LLM. The proposer
   uses provider-native tool use / structured output so each
   sampled proposal is grammatical against the typed action
   vocabulary by construction. N is a budget parameter
   (default candidate: N=8 for v0.1).
2. **Prune via the consistency layer.** Each proposal is encoded
   as Z3 constraints over current corpus state. Proposals
   whose preconditions are not entailed are rejected. The Z3
   layer's role is to eliminate proposals, not to bless one.
3. **Rank survivors** by a value heuristic. The v0.1 heuristic
   is *expected information gain*: how much does executing this
   action reduce uncertainty about live hypotheses? The
   heuristic is intentionally simple at v0.1; the architectural
   commitment is to the pruning-then-ranking shape, not to a
   specific heuristic.
4. **Execute the top K** survivors (K ≤ 1 at v0.1; raised
   later when concurrent execution is better understood).

The critical property: **proposals that fail the consistency
check are not just rejected, they're rejected before any
network or corpus side effect**. The cost of a bad sample is the
LLM token cost of generating it, which is bounded.

### 2. Autonomous loop with budget-bounded termination

The propose-prune-rank-execute step is run in a loop. The loop
terminates when:

- The step budget is exhausted (default: 50 steps).
- The wall-time budget is exhausted (default: 30 minutes).
- The token-cost budget is exhausted (default: a per-session
  cap configurable per provider).
- No proposal survives consistency checking three steps in a
  row (the agent has nothing left to do with the current
  corpus state).
- An operator interrupt is received.

The loop is otherwise autonomous: no per-step approval, no
"are you sure" prompt before executing a survived action. The
agent is trusted to operate within scope because scope is
encoded as preconditions in the consistency layer, not as a
prompt instruction.

### 3. Prompt-cache-aware context engineering

The Anthropic prompt cache has a 5-minute TTL and rewards
prompt prefixes that don't change. Modus's prompt is structured
in three zones, in this order:

1. **Cached prefix.** The system prompt, the action vocabulary
   (Pydantic schema rendered for the LLM), the scope policy,
   and the stable target context (Quarry `status` + a
   small fixed-size summary of the target's surface). This
   zone is built once per session and stays constant; it is
   marked for caching.
2. **Per-step retrieval.** The Quarry MCP tool results that
   inform the current step — `search` hits, `list_assets`
   filters, the most recent `diff` or `regression` candidates.
   This zone changes every step.
3. **Per-step instruction.** "Propose N actions to take next,
   given the above," with the agent's recent action/result
   history elided to a short summary the LLM doesn't need
   verbatim.

Cache misses are paid only on the per-step zones, not on the
vocabulary or scope. With a 50-step session this is a
cumulative ~5–10× cost reduction at no quality cost, provided
the cached prefix is genuinely stable.

### 4. The submission line is storage-enforced

The structural firewall: nothing in the agent loop produces an
outbound submission. The terminal effect of every action is a
Quarry corpus row. Promotion to a Finding is `quarry finding
promote`, run by the operator outside Modus. There is no
`submit`, `publish`, `post`, or `report` action in the vocabulary,
no submit-shaped tool exposed to the proposer, and none will be
added.

What the firewall does *not* do — superseded 2026-05-07: the
prior verbal ban ("the proposer is told it never tells the
operator to submit") is dropped. A Candidate's `rationale` may
recommend the operator promote it to a Finding or submit it to a
programme; that's an operator-facing recommendation, not an
outbound submission. The structural absence of a submit action
is what enforces the gate; the rationale's content is the
operator's tool, not the firewall's.

## Consequences

### Positive

- The Z3 layer earns its keep. Pruning N proposals is the right
  use of a solver; gating a single proposal is not.
- Session cost is bounded. The combination of N-sampling +
  Z3 pruning + budget termination gives the operator a
  predictable cost envelope.
- Prompt caching is structural, not incidental. The loop's
  shape forces the prompt structure that cache wants.
- Autonomy is real but bounded. The agent runs without
  per-step approval; scope and submission constraints are
  enforced by storage and grammar, not by attention.
- Audit is durable. Every sampled proposal, every Z3 verdict,
  and every executed action is a row in Quarry; the audit
  surface is the same surface a human reviewer queries.

### Negative

- N-sampling multiplies LLM cost per step by N. Cache
  effectiveness mitigates this but doesn't eliminate it.
  Budgets are necessary, not optional.
- The information-gain heuristic is research-y. v0.1 will
  ship with a stub heuristic that probably underperforms;
  the heuristic is replaceable but the *shape* is the
  commitment.
- Autonomous operation puts more weight on scope correctness.
  A bug in the scope encoding could let the agent act outside
  authorization, so the consistency layer's tests are
  load-bearing in a way they wouldn't be under per-step
  approval.
- Cache zones are a discipline, not a guarantee. A change to
  the vocabulary mid-session invalidates the cache and
  silently raises cost; tooling needs to make zone violations
  visible.

### Neutral

- The loop shape is a v0.1 commitment; the specific N, K,
  budget defaults, and value heuristic are not. Expect
  iteration on parameters as we learn what actually works
  against lab targets.
- The hypothesis-ledger / Bayesian action selection direction
  in `ROADMAP.md` is the natural extension of this shape, not
  a replacement of it. ADR-0002's commitments are upstream of
  it.

## Alternatives considered

- **Single-proposal-per-step with operator approval** (the
  default ReAct shape with a human gate). Rejected: contradicts
  Modus's autonomy intent and uses the SMT layer as a filter.
- **Single-proposal-per-step without approval** (autonomous
  but greedy). Rejected: doesn't use the solver as a pruner,
  inherits all the methodology-drift problems ADR-0001
  describes, and gives up the cost predictability that
  N-sampling-with-budget provides.
- **Multi-step plan generation** (LLM emits a DAG, solver
  validates the whole plan). Considered and deferred: a
  plausible direction once we have data on where single-step
  beam search fails. Listed in `ROADMAP.md` "Beyond v0.1."
- **Tree search / MCTS over action sequences.** Considered
  and rejected at v0.1 scope: the cost of expanding a tree
  per step is high, and the value of the deeper rollout is
  unclear without a reward signal richer than what Quarry's
  Candidate stream gives us. Belongs to a later milestone if
  the proposer plateaus.
- **Inverse RL on operator demonstrations** (the Praxis
  direction ADR-0001 references). Deferred: requires
  demonstration data we don't have. Listed in
  `ROADMAP.md` "Beyond v0.1."

## References

- ADR 0001 — typed action vocabulary, the substrate this ADR
  builds on.
- Anthropic prompt caching documentation, including the 5-minute
  TTL and prefix-stability requirements.
- Quarry's `docs/mcp.md` and `docs/findings.md` — the corpus
  and promotion lifecycle this loop terminates into.
