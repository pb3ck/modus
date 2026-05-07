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

        for step_index in range(self.budget.max_steps):
            if (time.monotonic() - wall_started) > self.budget.max_wall_seconds:
                record.termination_reason = "wall_time_exhausted"
                break

            step_started = _utcnow()
            context = self._step_context(objective_text)

            # 1. Propose
            proposals = await self.proposer.propose(context)

            # 2. Prune
            verdicts = self.checker.prune(proposals, context.corpus_state)
            survivors = [(a, v) for a, v in verdicts if v.accepted]

            # 3. Rank — v0.1 heuristic: first survivor wins
            # 4. Execute the top-K (K=1 at v0.1)
            executed: list[Action] = []
            execution_results: list[dict[str, Any]] = []
            if survivors:
                action, _verdict = survivors[0]
                try:
                    result = await self.execute_action(action)
                except Exception as exc:  # broad: don't kill the session on a tool error
                    _LOG.warning("execute_action raised: %s", exc)
                    result = {"error": f"executor raised: {exc}"}
                executed.append(action)
                execution_results.append(result)
                empty_streak = 0
            else:
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

    def _step_context(self, objective: str) -> StepContext:
        return StepContext(
            corpus_state=self.session.corpus_state(),
            scope=self.session.scope,
            objective=objective,
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


__all__ = ["AgentLoop", "Budget", "SessionRecord", "StepRecord"]
