"""Tests for the autonomous agent loop.

These tests drive :class:`AgentLoop` with a :class:`FixedProposer`
and a recording ``execute_action`` so the loop's control flow,
budget enforcement, and audit-record shape can be verified
deterministically — no LLM, no network.
"""

from __future__ import annotations

from typing import Any

from modus.actions import Action, Hypothesize, Probe
from modus.agent import AgentLoop, Budget
from modus.consistency import ConsistencyChecker
from modus.proposer import FixedProposer
from modus.scope import ScopePolicy
from modus.session import ServerSession, SessionObservation


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


class TestEvidenceRefsScopedToRun:
    """Per-run gating of ``Hypothesize.evidence_refs`` (#4).

    The ``ServerSession`` observation pool is process-lifetime, so
    observations from a prior ``run_autonomous_session`` call are
    visible in ``CorpusState.known_observations`` of the current
    run. The ``session_observations`` constraint added by #4 stops
    the proposer from citing those bleed-throughs as evidence; the
    citation must point at an observation produced *this* run.
    """

    async def test_hypothesize_citing_run_observation_is_accepted(self) -> None:
        # Step 0 produces an observation, step 1 hypothesizes
        # against it. The Z3 layer must accept because the cited
        # obs_id is in ``session_observations`` (this run's pool).
        produced_obs_id = "obs-step-0"

        async def executor(action: Action) -> dict[str, Any]:
            return {"observation_id": produced_obs_id, "kind": action.kind}

        proposer = FixedProposer(
            [
                Probe(target="target.example.com"),
                Hypothesize(
                    bug_class="idor",
                    evidence_refs=(produced_obs_id,),
                    rationale="**Vulnerability:** ... cites obs-step-0",
                ),
            ]
        )
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=_bare_session(),
            execute_action=executor,
            budget=Budget(max_steps=2),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        # Both steps executed, both their proposals accepted.
        assert record.steps[0].executed[0].kind == "probe"
        assert record.steps[1].executed[0].kind == "hypothesize"
        # No verdict on step 1 came back rejected.
        assert all(v.accepted for v in record.steps[1].verdicts)

    async def test_hypothesize_citing_prior_session_observation_is_rejected(
        self,
    ) -> None:
        # Bleed simulation: the session pool contains an observation
        # from a *prior* run_autonomous_session call. The proposer
        # tries to cite it from a fresh autonomous run that hasn't
        # produced any observations yet. The new
        # ``session_observations`` precondition must reject —
        # citing observations the agent didn't produce *this run*
        # is the bug class #4 fixes.
        bleed_obs_id = "obs-from-prior-run"
        session = _bare_session()
        # Pre-load the session pool with an observation as if a
        # prior run had produced it.
        session.observations.append(
            SessionObservation(
                id=bleed_obs_id,
                kind="request",
                payload={"status": 200},
            )
        )

        executor = _RecordingExecutor()
        proposer = FixedProposer(
            [
                Hypothesize(
                    bug_class="idor",
                    evidence_refs=(bleed_obs_id,),
                    rationale="cites a prior-session observation",
                )
            ]
        )
        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=executor,
            budget=Budget(max_steps=1, max_consecutive_empty_steps=1),
        )
        record = await loop.run(target_name="demo", bug_classes=["idor"])
        # The hypothesize survived the proposer but Z3 rejected it
        # because the evidence_ref isn't in this run's session
        # observations (which are empty — no actions have executed
        # yet that produced an observation).
        assert len(record.steps) == 1
        assert record.steps[0].executed == ()
        assert any(not v.accepted for v in record.steps[0].verdicts)
        # The unsat-core surface should name the offending obs_id.
        rejecting = next(v for v in record.steps[0].verdicts if not v.accepted)
        assert any(
            name.startswith("evidence_in_session:" + bleed_obs_id)
            for name in rejecting.failed_preconditions
        )
        # The recording executor never saw the action — Z3 rejected
        # it before execution.
        assert executor.calls == []
