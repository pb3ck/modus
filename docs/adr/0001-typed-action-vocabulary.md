# ADR 0001: Typed action vocabulary with formal consistency checking

- **Status:** accepted
- **Date:** 2026-05-06
- **Supersedes:** —
- **Superseded by:** —

## Context

Modus is an offensive security agent. The dominant pattern in the
space (PentestGPT, hackingBuddyGPT, claude-bug-bounty, PentAGI,
the various MCP-skill-based agents) is a free-form ReAct loop:
the LLM proposes shell commands or tool invocations as text, a
harness parses and dispatches them, and the result feeds back
into the next LLM turn.

This pattern has known weaknesses:

1. **Methodology drift under model variance.** The same prompt
   produces different actions across runs, models, and context
   states. There is no structural constraint on what the agent
   can propose.
2. **Audit surface is the chain-of-thought trace.** Reviewing
   what the agent did requires reading model reasoning, which
   is verbose, sometimes confabulated, and not queryable.
3. **Prompt-injection failure mode is open.** Target-controlled
   content can convince the LLM to propose any action the
   harness will accept. The only defenses are operator approval
   gates and prompt-level sanitization, both of which fail in
   practice.
4. **No formal notion of action validity.** Actions that are
   logically inconsistent with current state (e.g., authenticate
   to a service Modus has never seen credentials for) are
   dispatched anyway and fail at execution.

## Decision

Modus does not use free-form actions. The agent proposes actions
drawn from a typed vocabulary, where each action type is:

1. **Defined as a Pydantic model** with explicit fields, types,
   and validation rules. New action types are additions to the
   vocabulary, not new prompt language.
2. **Annotated with preconditions** that must be satisfied by
   current corpus state before the action can be dispatched.
3. **Validated by an SMT solver (Z3)** before dispatch. The
   consistency check encodes preconditions as logical formulas
   over the corpus state and rejects actions whose preconditions
   are not entailed.

The action vocabulary is small at v0.1. The initial set is:

- `Probe(target, kind)` — passive observation of a target asset
  (read its current httpx record, fetch its current jsbundle,
  list its endpoints from the corpus). Effects: produces an
  observation in the corpus. Preconditions: target is in scope.
- `Request(target, method, path, headers?, body?)` — active HTTP
  request to a target asset. Effects: produces an observation
  with the request/response pair. Preconditions: target is in
  scope, method is in the operator-approved set for this session.
- `Compare(observation_a, observation_b, dimensions)` — structural
  diff between two observations. Effects: produces a comparison
  result. Preconditions: both observations exist in the corpus.
- `Annotate(target_or_observation, note)` — attach an operator-
  visible note to a corpus row. Effects: appends a note. No
  preconditions beyond the referent existing.
- `Hypothesize(class, evidence_refs, rationale)` — propose a
  Candidate of a given bug class with references to supporting
  evidence. Effects: writes a Candidate row. Preconditions:
  every evidence_ref exists in the corpus.

Additional action types are added via ADRs that supersede or
extend this one.

## Consequences

### Positive

- Methodology drift is bounded: the agent cannot propose actions
  outside the vocabulary, so inter-run variance is reduced to
  variance in which valid action is chosen, not what the action
  is.
- The audit surface is the corpus, not the trace. Every action
  is a typed row with a timestamp, a result, and a reference to
  the proposing session. Reviewing a session is `SELECT * FROM
  actions WHERE session_id = ?`, not log-grep.
- Prompt injection has a structural defense. An injected
  instruction cannot expand the action vocabulary; the worst it
  can do is convince the LLM to choose a different valid action,
  which is constrained by preconditions and visible in the
  corpus.
- Action validity is formally checkable. The Z3 consistency
  check rejects logically inconsistent actions before they hit
  the network, which improves both safety and quality of agent
  output.

### Negative

- The vocabulary is a constant maintenance surface. Every new
  bug class likely requires new action types or new precondition
  rules. The bound is more work than a free-form harness for the
  same coverage.
- Some legitimately useful agent behaviors (creative tool use,
  novel attack paths) are excluded by construction. Modus
  trades off agent expressiveness for agent auditability.
  This is intentional but it is a real cost.
- The Z3 consistency check is an extra component to maintain.
  Wrong consistency rules will reject valid actions
  (frustrating) or accept invalid ones (defeats the purpose).
  Test discipline on the consistency layer is important.
- Onboarding contributors is harder than for a free-form
  harness. Adding capability requires understanding the
  vocabulary, the precondition encoding, and the SMT layer,
  not just writing a new prompt.

### Neutral

- The vocabulary is an open question, not a closed answer. v0.1
  ships with five action types; v0.2 will likely refactor at
  least one of them based on what didn't work in practice.
- The relationship between the action vocabulary and the corpus
  schema is tight. Both will evolve together.

## Alternatives considered

- **Free-form ReAct loop** (the current default in the space).
  Rejected: see Context above.
- **Structured tool calling without consistency checking**
  (typed actions but no formal precondition validation).
  Rejected: this is what most agent frameworks do, and it
  catches the drift problem but not the validity problem.
  The Z3 layer is the differentiator.
- **Learned policy via inverse reinforcement learning** (the
  Praxis research direction). Deferred: this is a research
  thesis with its own data and benchmark requirements. Modus
  v0.1 uses LLM-driven proposal with formal consistency
  checks; an IRL-based proposer can be a later extension that
  swaps the proposer module without changing the vocabulary
  or the consistency layer.

## References

- Untila, "Emergent Formal Verification: How an Autonomous AI
  Ecosystem Independently Discovered SMT-Based Safety Across
  Six Domains," 2026. arXiv:2603.21149.
- Cobalt AI, "Broken by Default: A Formal Verification Study of
  Security Vulnerabilities in AI-Generated Code," 2026.
- The Pydantic documentation on discriminated unions, which is
  the planned shape of the action vocabulary in code.
