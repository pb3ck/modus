"""Autonomous agent loop.

The propose-prune-rank-execute step from ADR 0002, run inside a
single MCP tool handler per ADR 0003. The host calls Modus's
``run_autonomous_session`` tool with a target name, a list of bug
classes, and an optional budget; the loop runs until the budget is
exhausted or three consecutive empty pruning rounds happen, then
returns the accumulated audit record.

The loop's collaborators are dependency-injected:

* :class:`Proposer` — emits N candidate actions per step.
* :class:`ConsistencyChecker` — Z3-prunes the batch.
* ``execute_action`` callable — runs a single action and returns
  its result. The Modus server passes its own ``_execute_action``
  method here, so the autonomous loop and the per-step verified
  surface share one executor implementation.
* :class:`ServerSession` — the working corpus state, the
  in-memory observation/Candidate pool.

The loop's *value heuristic* is intentionally simple at v0.1:
"first survivor wins." The ranking shape is in place; the heuristic
is a research target for v0.2+.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from modus.proposer import StepContext

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from modus.actions import Action
    from modus.consistency import ConsistencyChecker, Verdict
    from modus.proposer import Proposer
    from modus.session import ServerSession


_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Budget:
    """Hard limits on what an autonomous session may consume."""

    max_steps: int = 50
    max_wall_seconds: float = 1800.0  # 30 minutes
    max_consecutive_empty_steps: int = 3


@dataclass
class StepRecord:
    """Audit row for one step of the loop.

    Every sampled proposal and every Z3 verdict is captured here.
    The session's :class:`SessionRecord` is what the autonomous-
    session tool returns to the host so the audit surface is
    queryable from the host's conversation transcript.
    """

    step_index: int
    started_at: datetime
    proposals: tuple[Action, ...]
    verdicts: tuple[Verdict, ...]
    executed: tuple[Action, ...] = field(default_factory=tuple)
    execution_results: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    finished_at: datetime | None = None


@dataclass
class SessionRecord:
    """Audit record for one whole agent session."""

    target_name: str
    bug_classes: tuple[str, ...]
    started_at: datetime
    steps: list[StepRecord] = field(default_factory=list)
    finished_at: datetime | None = None
    termination_reason: str | None = None

    def to_payload(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict for an MCP tool result."""
        return {
            "target_name": self.target_name,
            "bug_classes": list(self.bug_classes),
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at.isoformat() if self.finished_at else None),
            "termination_reason": self.termination_reason,
            "step_count": len(self.steps),
            "executed_count": sum(len(s.executed) for s in self.steps),
            "steps": [
                {
                    "step_index": s.step_index,
                    "started_at": s.started_at.isoformat(),
                    "finished_at": (s.finished_at.isoformat() if s.finished_at else None),
                    "proposal_count": len(s.proposals),
                    "rejected_count": sum(1 for v in s.verdicts if not v.accepted),
                    "executed": [a.model_dump() for a in s.executed],
                    "execution_results": list(s.execution_results),
                }
                for s in self.steps
            ],
        }


@dataclass
class AgentLoop:
    """Autonomous propose-prune-rank-execute loop.

    Use as a one-shot: construct, ``await loop.run(...)``, read the
    returned :class:`SessionRecord`. The loop is stateless across
    invocations — call it again to start a fresh session.
    """

    proposer: Proposer
    checker: ConsistencyChecker
    session: ServerSession
    execute_action: Callable[[Action], Awaitable[dict[str, Any]]]
    budget: Budget = field(default_factory=Budget)

    async def run(
        self,
        *,
        target_name: str,
        bug_classes: list[str],
        objective: str | None = None,
    ) -> SessionRecord:
        """Run the loop end-to-end and return the session record.

        ``objective`` is an optional natural-language framing the
        proposer can use to bias its sampling — typically the
        bug-class focus expressed as a sentence ("find IDOR on the
        ``demo`` target's user-scoped endpoints").
        """
        record = SessionRecord(
            target_name=target_name,
            bug_classes=tuple(bug_classes),
            started_at=_utcnow(),
        )
        objective_text = objective or self._default_objective(target_name, bug_classes)
        empty_streak = 0
        wall_started = time.monotonic()
        # Cumulative one-line summaries of executed actions and their
        # results, fed back to the proposer each step so it doesn't
        # re-propose actions that already ran. Capped at the most
        # recent ``HISTORY_TAIL`` entries to keep the prompt bounded.
        history: list[str] = []

        for step_index in range(self.budget.max_steps):
            if (time.monotonic() - wall_started) > self.budget.max_wall_seconds:
                record.termination_reason = "wall_time_exhausted"
                break

            step_started = _utcnow()
            context = self._step_context(
                objective_text, history=history, bug_classes=tuple(bug_classes)
            )

            # 1. Propose
            proposals = await self.proposer.propose(context)

            # 2. Prune
            verdicts = self.checker.prune(proposals, context.corpus_state)
            survivors = [(a, v) for a, v in verdicts if v.accepted]

            # 3. Rank — v0.1 heuristic: first novel survivor wins.
            #    Deduplicate against actions executed in the last
            #    ``DEDUP_TAIL`` steps so the agent doesn't re-run a
            #    failing action just because the proposer keeps
            #    putting it first.
            recently_executed = self._recent_action_keys(record.steps)
            chosen: Action | None = None
            for candidate, _ in survivors:
                if _action_dedup_key(candidate) not in recently_executed:
                    chosen = candidate
                    break
            all_duplicates = chosen is None and bool(survivors)
            if all_duplicates:
                # Every Z3-accepted survivor duplicates an action this
                # session already executed. Treat the step as empty
                # rather than re-running the duplicate — running it
                # again wastes budget and pollutes the corpus with a
                # near-identical observation row. The WARNING is
                # appended now (before the next step's _step_context
                # builds), so the proposer sees its stuckness in
                # recent_history on the very next iteration. If the
                # proposer keeps emitting only duplicates, the empty
                # pruning streak will terminate the loop.
                dup_keys = sorted({_action_dedup_key(c) for c, _ in survivors})
                sample = dup_keys[0]
                history.append(
                    f"step {step_index}: WARNING all {len(survivors)} Z3-accepted "
                    f"proposals duplicate actions executed earlier this session "
                    f"(e.g. `{sample}`). Step skipped — running the duplicate "
                    "again would waste budget. Try a different action kind, "
                    "path, parameter, or — if you have evidence — emit "
                    "`hypothesize` to close the loop."
                )

            # 4. Execute the top-K (K=1 at v0.1)
            executed: list[Action] = []
            execution_results: list[dict[str, Any]] = []
            if chosen is not None:
                try:
                    result = await self.execute_action(chosen)
                except Exception as exc:  # broad: don't kill the session on a tool error
                    _LOG.warning("execute_action raised: %s", exc)
                    result = {"error": f"executor raised: {exc}"}
                executed.append(chosen)
                execution_results.append(result)
                history.append(_summarise_step(step_index, chosen, result))
                empty_streak = 0
            else:
                if not all_duplicates:
                    # Distinct from the all-duplicates branch above:
                    # either Z3 rejected every survivor, or the
                    # proposer returned no actions at all. The
                    # all-duplicates branch already logged its own
                    # WARNING; don't double-log here.
                    history.append(
                        f"step {step_index}: all {len(proposals)} proposals rejected by Z3"
                    )
                empty_streak += 1

            step_record = StepRecord(
                step_index=step_index,
                started_at=step_started,
                proposals=tuple(proposals),
                verdicts=tuple(v for _, v in verdicts),
                executed=tuple(executed),
                execution_results=tuple(execution_results),
                finished_at=_utcnow(),
            )
            record.steps.append(step_record)

            if empty_streak >= self.budget.max_consecutive_empty_steps:
                record.termination_reason = "empty_pruning_streak"
                break

        if record.termination_reason is None:
            record.termination_reason = "step_budget_exhausted"
        record.finished_at = _utcnow()
        return record

    HISTORY_TAIL = 16  # how many recent steps to feed back to the proposer
    DEDUP_TAIL = 50  # how far back to look when deduplicating proposals
    # ^ DEDUP_TAIL is effectively "the whole session" at v0.1 budgets.
    # The proposer often re-emits the same URL after 8-10 steps even
    # though it failed earlier; full-session dedup makes the agent
    # spend budget on novel actions instead. If the agent legitimately
    # wants to retry an URL, it can vary the method, headers, or body.

    def _recent_action_keys(self, steps: list[StepRecord]) -> set[str]:
        """Set of dedup keys for actions executed in the last few steps.

        Used by the ranking step to skip survivors that are exact
        duplicates of recently-executed actions. Keeps the loop from
        stalling on a single proposal Claude keeps re-emitting.
        """
        keys: set[str] = set()
        for step in steps[-self.DEDUP_TAIL :]:
            for action in step.executed:
                keys.add(_action_dedup_key(action))
        return keys

    def _step_context(
        self,
        objective: str,
        *,
        history: list[str],
        bug_classes: tuple[str, ...] = (),
    ) -> StepContext:
        return StepContext(
            corpus_state=self.session.corpus_state(),
            scope=self.session.scope,
            objective=objective,
            bug_classes=bug_classes,
            recent_history=tuple(history[-self.HISTORY_TAIL :]),
            sample_count=8,
        )

    @staticmethod
    def _default_objective(target_name: str, bug_classes: list[str]) -> str:
        classes = ", ".join(bug_classes) if bug_classes else "any in-scope bug class"
        return (
            f"Find vulnerabilities of class(es) [{classes}] on Quarry target "
            f"{target_name!r}. Use the verified-action vocabulary to gather "
            f"evidence and end with one or more `hypothesize` actions when "
            f"you have a defensible Candidate."
        )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _action_dedup_key(action: Action) -> str:
    """Stable key for "is this the same action I just ran?".

    Identity-only: ignores headers, body, and other request-shaping
    fields — two requests to the same URL are the same action even if
    the body differs slightly. This is intentionally aggressive on the
    deduplication side; the proposer has plenty of room to vary the
    URL itself when it wants something distinct.
    """
    if action.kind == "request":
        scheme = "https" if getattr(action, "tls", True) else "http"
        port = getattr(action, "port", None)
        port_part = f":{port}" if port is not None else ""
        target = getattr(action, "target", "")
        return f"request:{action.method}:{scheme}://{target}{port_part}{action.path}"
    if action.kind == "probe":
        return f"probe:{action.target}:{action.aspect}"
    if action.kind == "compare":
        a, b = sorted([action.observation_a, action.observation_b])
        return f"compare:{a}:{b}"
    if action.kind == "differential":
        return f"differential:{action.bug_class}:{action.dimension}:{','.join(sorted(action.observations))}"
    if action.kind == "annotate":
        return f"annotate:{action.referent}:{hash(action.note)}"
    if action.kind == "hypothesize":
        return f"hypothesize:{action.bug_class}:{','.join(sorted(action.evidence_refs))}"
    return f"{action.kind}:{hash(action.model_dump_json())}"


def _summarise_step(step_index: int, action: Action, result: dict[str, Any]) -> str:
    """One-line history entry the proposer sees on the next step.

    Compact by design — the proposer doesn't need the full payload,
    just enough to know "I already tried X and it returned Y" so
    next-step proposals don't duplicate work. Long fields (response
    bodies, search hit lists) are summarised to a count or a length.
    """
    base = f"step {step_index}: {action.kind}"
    parts: list[str] = []
    # Action-specific identity fields the proposer cares about.
    target = getattr(action, "target", None) or getattr(action, "referent", None)
    if target:
        parts.append(f"target={target}")
    # Surface the observation_id in history so the proposer can cite it
    # in `evidence_refs` when it emits a `hypothesize` action. Without
    # this, the model has nothing to reference and can't close the loop.
    obs_id = result.get("observation_id") or result.get("id")
    if isinstance(obs_id, str) and obs_id:
        parts.append(f"obs={obs_id}")
    if action.kind == "request":
        method = getattr(action, "method", None)
        path = getattr(action, "path", None)
        port = getattr(action, "port", None)
        tls = getattr(action, "tls", None)
        # Carry the full URL shape through history so the proposer can
        # tell working transports from failing ones — plain ``GET /path``
        # hides whether port=13000 + tls=False were the difference.
        scheme = "https" if tls else "http"
        port_part = f":{port}" if port is not None else ""
        parts.append(f"{method} {scheme}://{target}{port_part}{path}")
        # Carry the request body excerpt too. Without it the proposer
        # sees "POST /login → 200 with JWT" but not what was POSTed —
        # it can't tell a successful SQLi from a successful normal
        # login, and won't recognise the bug-class evidence pattern.
        # Trimmed to 240 chars to match the response excerpt budget.
        req_body = getattr(action, "body", None)
        if isinstance(req_body, str) and req_body.strip():
            req_excerpt = req_body.replace("\n", " ").replace("\r", " ").strip()[:240]
            parts.append(f"req_body={req_excerpt!r}")
        status = result.get("status")
        if status is not None:
            parts.append(f"status={status}")
        body = result.get("response_body")
        if isinstance(body, str):
            parts.append(f"body_len={len(body)}")
            # Tail excerpt of the response body so the proposer can spot
            # win signals (auth tokens, error messages, version strings)
            # without us shipping kilobyte payloads back into the prompt.
            # 240 chars is plenty for a JWT prefix or a pithy 401 body.
            excerpt = body.replace("\n", " ").replace("\r", " ").strip()[:240]
            if excerpt:
                parts.append(f"body_excerpt={excerpt!r}")
    elif action.kind == "probe":
        aspect = getattr(action, "aspect", None)
        parts.append(f"aspect={aspect}")
        hits = result.get("hits")
        assets = result.get("assets")
        if hits is not None:
            parts.append(f"hits={len(hits) if isinstance(hits, list) else hits}")
        if assets is not None:
            parts.append(f"assets={len(assets) if isinstance(assets, list) else assets}")
    elif action.kind == "hypothesize":
        parts.append(f"bug_class={getattr(action, 'bug_class', '?')}")
    if "error" in result:
        parts.append(f"error={str(result['error'])[:120]}")
    return base + (" " + " ".join(parts) if parts else "")


__all__ = ["AgentLoop", "Budget", "SessionRecord", "StepRecord"]
