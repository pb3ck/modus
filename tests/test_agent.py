"""Tests for the autonomous agent loop.

These tests drive :class:`AgentLoop` with a :class:`FixedProposer`
and a recording ``execute_action`` so the loop's control flow,
budget enforcement, and audit-record shape can be verified
deterministically — no LLM, no network.
"""

from __future__ import annotations

from typing import Any

from modus.actions import Action, Probe
from modus.agent import AgentLoop, Budget
from modus.consistency import ConsistencyChecker
from modus.proposer import FixedProposer
from modus.scope import ScopePolicy
from modus.session import ServerSession


def _scope() -> ScopePolicy:
    return ScopePolicy(
        target_name="demo",
        allowed_assets=frozenset({"target.example.com", "evil.example.com"}),
        allowed_methods=frozenset({"GET"}),
    )


def _bare_session() -> ServerSession:
    return ServerSession(scope=_scope(), llm=None)


class _RecordingExecutor:
    """Captures every (action, result) pair the loop submits."""

    def __init__(self) -> None:
        self.calls: list[Action] = []

    async def __call__(self, action: Action) -> dict[str, Any]:
        self.calls.append(action)
        return {"executed": action.kind}


class TestLoopHappyPath:
    async def test_runs_step_and_executes_first_survivor(self) -> None:
        proposer = FixedProposer(
            [
                Probe(target="target.example.com"),
                Probe(target="evil.example.com"),
            ]
        )
        # Out-of-scope asset is NOT in the scope's allowed_assets — but
        # this scope has both, so all proposals pass. Use a scope with
        # only `target.example.com` to test rejection.
        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
        )
        session = ServerSession(scope=scope, llm=None)
        executor = _RecordingExecutor()
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=executor,
            budget=Budget(max_steps=1, max_consecutive_empty_steps=1),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        assert len(record.steps) == 1
        # First survivor (target.example.com) gets executed; the
        # evil.example.com proposal is rejected by Z3.
        assert len(executor.calls) == 1
        assert executor.calls[0].target == "target.example.com"


class TestEmptyStreakTermination:
    async def test_empty_streak_terminates_loop_early(self) -> None:
        # Every proposed action targets an out-of-scope asset, so all
        # are rejected by Z3 — empty pruning streak should fire.
        proposer = FixedProposer([Probe(target="evil.example.com")])
        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
        )
        session = ServerSession(scope=scope, llm=None)
        executor = _RecordingExecutor()
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=executor,
            budget=Budget(max_steps=20, max_consecutive_empty_steps=3),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        assert record.termination_reason == "empty_pruning_streak"
        assert len(record.steps) == 3
        assert executor.calls == []


class TestStepBudget:
    async def test_step_budget_caps_iterations(self) -> None:
        # Five distinct probes so the ranker can pick a fresh
        # (non-duplicate) action each step — without strict dedup
        # this test would have run the same action five times.
        proposer = FixedProposer(
            [
                Probe(target="target.example.com", aspect="httpx"),
                Probe(target="target.example.com", aspect="endpoints"),
                Probe(target="target.example.com", aspect="jsbundle"),
                Probe(target="target.example.com", aspect="tech"),
                Probe(target="evil.example.com", aspect="httpx"),
            ]
        )
        session = _bare_session()
        executor = _RecordingExecutor()
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=executor,
            budget=Budget(max_steps=5),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        assert len(record.steps) == 5
        assert record.termination_reason == "step_budget_exhausted"
        assert len(executor.calls) == 5
        # Each step should have executed a distinct action — the
        # ranker's first-novel-survivor heuristic skips duplicates.
        keys = {(c.kind, c.target, getattr(c, "aspect", None)) for c in executor.calls}
        assert len(keys) == 5


class TestStrictDedup:
    async def test_duplicate_survivors_skip_step_and_terminate_via_empty_streak(
        self,
    ) -> None:
        # Every step the proposer offers the SAME single action.
        # Step 0 executes it. From step 1 onward the only Z3-accepted
        # survivor is a recent duplicate, so strict dedup treats the
        # step as empty rather than re-executing. The empty pruning
        # streak should terminate the loop after
        # ``max_consecutive_empty_steps`` empty steps.
        proposer = FixedProposer([Probe(target="target.example.com")])
        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
        )
        session = ServerSession(scope=scope, llm=None)
        executor = _RecordingExecutor()
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=executor,
            budget=Budget(max_steps=20, max_consecutive_empty_steps=3),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        # Step 0 runs the action; steps 1, 2, 3 are empty (all
        # survivors duplicate step 0); empty_streak hits 3 and the
        # loop terminates as ``empty_pruning_streak``.
        assert len(executor.calls) == 1, (
            "strict dedup must skip duplicate-survivor steps; the same "
            "action should never run twice in a single session"
        )
        assert executor.calls[0].target == "target.example.com"
        assert record.termination_reason == "empty_pruning_streak"
        assert len(record.steps) == 4  # one executed + three empty
        # Verify each empty step recorded executed=() (not re-running
        # the duplicate).
        assert [len(s.executed) for s in record.steps] == [1, 0, 0, 0]


class TestExecutorErrorHandling:
    async def test_executor_exception_is_swallowed_per_step(self) -> None:
        async def boom(action: Action) -> dict[str, Any]:
            raise RuntimeError("network failed")

        proposer = FixedProposer([Probe(target="target.example.com")])
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=_bare_session(),
            execute_action=boom,
            budget=Budget(max_steps=2),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        assert len(record.steps) == 2
        # The failed execution is captured in the step record's
        # execution_results, not as a session-killing exception.
        assert "error" in record.steps[0].execution_results[0]


class TestSessionRecordSerialisation:
    async def test_to_payload_round_trips_minimally(self) -> None:
        proposer = FixedProposer([Probe(target="target.example.com")])
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=_bare_session(),
            execute_action=_RecordingExecutor(),
            budget=Budget(max_steps=1, max_consecutive_empty_steps=1),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        payload = record.to_payload()
        assert payload["target_name"] == "demo"
        assert payload["bug_classes"] == ["idor"]
        assert payload["step_count"] == 1
        assert payload["executed_count"] == 1
