"""Autonomous agent loop.

The propose-prune-rank-execute step from ADR 0002, run in a loop
under a budget. The operator launches the agent against a Quarry
target with a scope policy and a budget; the loop runs without
per-step approval and terminates on budget exhaustion or on three
consecutive empty pruning steps. The hard human gate sits *after*
the loop ends, in Quarry's own promotion lifecycle.

The loop is structured at Milestone 0 to expose the contract; the
load-bearing pieces (executor, value heuristic, retrieval policy)
land at Milestones 3 and 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from modus.consistency import ConsistencyChecker, CorpusState, Verdict
from modus.proposer import StepContext

if TYPE_CHECKING:
    from modus.actions import Action
    from modus.corpus import CorpusClient
    from modus.proposer import Proposer
    from modus.scope import ScopePolicy


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
    The session's :class:`SessionRecord` is what gets persisted to
    the corpus at session end so the audit surface is queryable
    after the fact.
    """

    step_index: int
    started_at: datetime
    proposals: tuple[Action, ...]
    verdicts: tuple[Verdict, ...]
    executed: tuple[Action, ...] = field(default_factory=tuple)
    finished_at: datetime | None = None


@dataclass
class SessionRecord:
    """Audit record for one whole agent session."""

    target_name: str
    started_at: datetime
    steps: list[StepRecord] = field(default_factory=list)
    finished_at: datetime | None = None
    termination_reason: str | None = None


@dataclass
class AgentLoop:
    """Autonomous propose-prune-rank-execute loop.

    Wiring is real; the executor and the value heuristic are stubs
    until Milestones 3 and 4. This class is the place where every
    piece of Modus comes together — vocabulary, consistency, corpus
    client, proposer, scope.
    """

    proposer: Proposer
    checker: ConsistencyChecker
    corpus: CorpusClient
    scope: ScopePolicy
    budget: Budget = field(default_factory=Budget)

    async def run(self) -> SessionRecord:
        """Run the loop until the budget is exhausted.

        Stub at Milestone 0 — the wiring is correct but the per-step
        retrieval, the value heuristic, and the executor are not yet
        connected. This raises until Milestone 4 lands.
        """
        raise NotImplementedError("autonomous loop lands at Milestone 4")

    def _initial_corpus_state(self) -> CorpusState:
        """Build the corpus state slice for step zero.

        The slice is small by design: scope-derived sets only. Each
        subsequent step extends the state with whatever the per-step
        retrieval pulled in. ADR 0002's prompt-zone discipline is
        what makes this efficient — the corpus state's *stable*
        portion (scope) is in the cached prefix, and only the deltas
        flow per step.
        """
        return CorpusState(
            in_scope_assets=self.scope.allowed_assets,
            allowed_methods=self.scope.allowed_methods,
        )

    def _step_context(self, state: CorpusState, retrieval: tuple[str, ...]) -> StepContext:
        return StepContext(
            corpus_state=state,
            scope=self.scope,
            retrieval=retrieval,
            sample_count=8,
        )


def utcnow() -> datetime:
    """Tiny convenience to keep the audit timestamps in one place."""
    return datetime.now(UTC)


__all__ = ["AgentLoop", "Budget", "SessionRecord", "StepRecord", "utcnow"]
