"""Tests for the mining sub-agent — issue #38.

These tests cover three layers:

1. :class:`Miner` in isolation — running ``mine()`` against a stubbed
   Quarry session returns deduplicated :class:`MiningSignal` rows,
   and per-tool failures (older Quarry, transient errors) don't kill
   the pass.

2. Cadence — :class:`AgentLoop` fires mining every
   ``mining_cadence`` steps and the resulting signals show up in the
   next step's :class:`StepContext`.

3. Rendering — :func:`render_mining_block` produces a stable
   markdown block the proposer's system prompt can embed.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from modus.actions import Action, Probe
from modus.agent import AgentLoop, Budget
from modus.consistency import ConsistencyChecker
from modus.corpus import Candidate, CorpusToolsMissingError
from modus.mining import Miner, MiningSignal, render_mining_block
from modus.proposer import FixedProposer, StepContext
from modus.scope import ScopePolicy
from modus.session import ServerSession


def _scope() -> ScopePolicy:
    return ScopePolicy(
        target_name="demo",
        allowed_assets=frozenset({"target.example.com"}),
        allowed_methods=frozenset({"GET"}),
    )


class _FakeQuarry:
    """In-memory Quarry stub for mining tests."""

    def __init__(
        self,
        *,
        regression: list[Candidate] | None = None,
        interesting: list[Candidate] | None = None,
        jsdelta: list[Candidate] | None = None,
        recall_hits: dict[str, list[dict[str, Any]]] | None = None,
        coverage_report: dict[str, Any] | None = None,
        regression_raises: BaseException | None = None,
        interesting_raises: BaseException | None = None,
        jsdelta_raises: BaseException | None = None,
        coverage_raises: BaseException | None = None,
    ) -> None:
        self._regression = regression or []
        self._interesting = interesting or []
        self._jsdelta = jsdelta or []
        self._recall_hits = recall_hits or {}
        self._coverage_report = coverage_report
        self._regression_raises = regression_raises
        self._interesting_raises = interesting_raises
        self._jsdelta_raises = jsdelta_raises
        self._coverage_raises = coverage_raises
        self.call_counts: dict[str, int] = {
            "analyze_regression": 0,
            "analyze_interesting": 0,
            "analyze_jsdelta": 0,
            "recall": 0,
            "coverage": 0,
        }

    async def analyze_regression(self, *, target: str | None = None) -> list[Candidate]:
        self.call_counts["analyze_regression"] += 1
        if self._regression_raises is not None:
            raise self._regression_raises
        return list(self._regression)

    async def analyze_interesting(self, *, target: str | None = None) -> list[Candidate]:
        self.call_counts["analyze_interesting"] += 1
        if self._interesting_raises is not None:
            raise self._interesting_raises
        return list(self._interesting)

    async def analyze_jsdelta(self, *, target: str | None = None) -> list[Candidate]:
        self.call_counts["analyze_jsdelta"] += 1
        if self._jsdelta_raises is not None:
            raise self._jsdelta_raises
        return list(self._jsdelta)

    async def recall(
        self,
        *,
        value: str | None = None,
        tech: str | None = None,
        webserver: str | None = None,
    ) -> list[dict[str, Any]]:
        self.call_counts["recall"] += 1
        if value is None:
            return []
        return list(self._recall_hits.get(value, []))

    async def coverage(self, *, target: str | None = None) -> dict[str, Any]:
        self.call_counts["coverage"] += 1
        if self._coverage_raises is not None:
            raise self._coverage_raises
        # Default to an empty-but-shaped report so tests that don't
        # explicitly set coverage still exercise the parser without
        # surfacing signals.
        return self._coverage_report or {
            "target": target or "demo",
            "discovered": 0,
            "probed": 0,
            "unprobed_count": 0,
            "unprobed": [],
            "truncated": False,
            "note": None,
        }


def _session_with_quarry(fake: _FakeQuarry) -> ServerSession:
    session = ServerSession(scope=_scope(), llm=None)

    @asynccontextmanager
    async def _yield_fake():  # type: ignore[no-untyped-def]
        yield fake

    session.with_quarry = _yield_fake  # type: ignore[method-assign]
    return session


def _candidate(key: str, rationale: str, module: str = "regression") -> Candidate:
    return Candidate(
        id=f"cand-{key}",
        target_id="t-1",
        module=module,
        key=key,
        score=0.7,
        rationale=rationale,
        evidence_refs=(f"ev-{key}-1",),
        was_new=True,
    )


class TestMinerInIsolation:
    async def test_mine_collects_signals_from_all_three_analyzers(self) -> None:
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "200 -> 401 flip")],
            interesting=[_candidate("b.example.com", "tld-fingerprint")],
            jsdelta=[_candidate("c.example.com", "added admin.js")],
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine()

        assert {s.source for s in signals} == {"regression", "interesting", "jsdelta"}
        assert {s.key for s in signals} == {
            "a.example.com",
            "b.example.com",
            "c.example.com",
        }
        # All three analytical tools were called exactly once.
        for tool in ("analyze_regression", "analyze_interesting", "analyze_jsdelta"):
            assert fake.call_counts[tool] == 1

    async def test_mine_dedupes_stable_candidates_across_passes(self) -> None:
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "200 -> 401 flip")],
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        first = await miner.mine()
        second = await miner.mine()

        # First pass: one new signal. Second pass: same candidate
        # returned by Quarry, but Miner's _seen_keys suppresses it.
        assert len(first) == 1
        assert second == []

    async def test_mine_runs_recall_for_each_new_host(self) -> None:
        fake = _FakeQuarry(
            recall_hits={
                "target.example.com": [
                    {"target": "engagement-x", "kind": "httpx"},
                    {"target": "engagement-y", "kind": "katana"},
                ]
            }
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine(observed_hosts=frozenset({"target.example.com"}))

        recall_signals = [s for s in signals if s.source == "recall"]
        assert len(recall_signals) == 2
        assert all("target.example.com" in s.summary for s in recall_signals)
        assert fake.call_counts["recall"] == 1
        # A second pass with the same host doesn't re-recall.
        await miner.mine(observed_hosts=frozenset({"target.example.com"}))
        assert fake.call_counts["recall"] == 1

    async def test_mine_tolerates_missing_analyze_tool(self) -> None:
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "flip")],
            interesting_raises=CorpusToolsMissingError(
                missing=["analyze_interesting"], available=[]
            ),
            jsdelta=[_candidate("c.example.com", "added admin.js")],
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine()

        # interesting failed; regression + jsdelta survived.
        sources = {s.source for s in signals}
        assert sources == {"regression", "jsdelta"}

    async def test_mine_tolerates_unexpected_exception(self) -> None:
        fake = _FakeQuarry(
            regression_raises=RuntimeError("analytical engine exploded"),
            interesting=[_candidate("b.example.com", "tld-fingerprint")],
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine()
        assert {s.source for s in signals} == {"interesting"}


class TestCoverageSource:
    async def test_coverage_emits_signal_for_each_unprobed_asset(self) -> None:
        fake = _FakeQuarry(
            coverage_report={
                "target": "demo",
                "discovered": 5,
                "probed": 2,
                "unprobed_count": 3,
                "unprobed": [
                    "admin.example.com",
                    "api.example.com",
                    "internal.example.com",
                ],
                "truncated": False,
                "note": None,
            }
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine()
        coverage_signals = [s for s in signals if s.source == "coverage"]
        assert len(coverage_signals) == 3
        assert {s.key for s in coverage_signals} == {
            "admin.example.com",
            "api.example.com",
            "internal.example.com",
        }
        # Coverage was called exactly once this pass.
        assert fake.call_counts["coverage"] == 1

    async def test_coverage_respects_max_assets_per_pass(self) -> None:
        unprobed = [f"asset-{i}.example.com" for i in range(50)]
        fake = _FakeQuarry(
            coverage_report={
                "target": "demo",
                "discovered": 50,
                "probed": 0,
                "unprobed_count": 50,
                "unprobed": unprobed,
                "truncated": False,
                "note": None,
            }
        )
        session = _session_with_quarry(fake)
        miner = Miner(
            session=session,
            target_name="demo",
            coverage_max_assets_per_pass=5,
        )

        signals = await miner.mine()
        coverage_signals = [s for s in signals if s.source == "coverage"]
        # First-pass cap of 5 honoured even though Quarry returned 50.
        assert len(coverage_signals) == 5

    async def test_coverage_dedupes_across_passes(self) -> None:
        fake = _FakeQuarry(
            coverage_report={
                "target": "demo",
                "discovered": 1,
                "probed": 0,
                "unprobed_count": 1,
                "unprobed": ["admin.example.com"],
                "truncated": False,
                "note": None,
            }
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        first = await miner.mine()
        second = await miner.mine()
        # Same asset returned by Quarry on both passes; mining
        # surfaces it only once.
        assert sum(1 for s in first if s.source == "coverage") == 1
        assert sum(1 for s in second if s.source == "coverage") == 0

    async def test_coverage_tolerates_missing_tool(self) -> None:
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "flip")],
            coverage_raises=CorpusToolsMissingError(missing=["coverage"], available=[]),
        )
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine()
        # Regression survived; coverage gracefully absent.
        assert {s.source for s in signals} == {"regression"}

    async def test_coverage_tolerates_malformed_payload(self) -> None:
        # Quarry returns the dict but ``unprobed`` is the wrong shape
        # (e.g. an older server schema). The miner must not crash.
        fake = _FakeQuarry(coverage_report={"unprobed": "not a list"})
        session = _session_with_quarry(fake)
        miner = Miner(session=session, target_name="demo")

        signals = await miner.mine()
        assert all(s.source != "coverage" for s in signals)


class TestMiningCadence:
    async def test_agent_loop_fires_mining_at_cadence(self) -> None:
        """With ``mining_cadence=2`` and a 5-step budget, mining runs
        after step 1 and step 3 (i.e. (step_index+1) % 2 == 0)."""
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "200 -> 401 flip")],
        )
        session = _session_with_quarry(fake)
        proposer = FixedProposer([Probe(target="target.example.com", aspect="httpx")] * 5)
        executor_calls: list[Action] = []

        async def _execute(action: Action) -> dict[str, Any]:
            executor_calls.append(action)
            return {"executed": action.kind, "observation_id": f"obs-{len(executor_calls)}"}

        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=_execute,
            budget=Budget(max_steps=5, max_consecutive_empty_steps=10),
            mining_cadence=2,
        )

        await loop.run(target_name="demo", bug_classes=["idor"])

        # Mining should have fired after steps 1 and 3 -> 2 calls
        # to each analyze_* (regression is the only one with data).
        # interesting/jsdelta return [] so they still get called.
        assert fake.call_counts["analyze_regression"] == 2
        assert fake.call_counts["analyze_interesting"] == 2
        assert fake.call_counts["analyze_jsdelta"] == 2

    async def test_mining_disabled_when_cadence_zero(self) -> None:
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "flip")],
        )
        session = _session_with_quarry(fake)
        proposer = FixedProposer([Probe(target="target.example.com")] * 3)

        async def _execute(action: Action) -> dict[str, Any]:
            return {"executed": action.kind}

        loop = AgentLoop(
            proposer=proposer,
            checker=ConsistencyChecker(),
            session=session,
            execute_action=_execute,
            budget=Budget(max_steps=3, max_consecutive_empty_steps=10),
            mining_cadence=0,
        )
        await loop.run(target_name="demo", bug_classes=["idor"])

        assert fake.call_counts["analyze_regression"] == 0
        assert fake.call_counts["analyze_interesting"] == 0

    async def test_mined_signals_appear_in_next_proposer_context(self) -> None:
        """Cadence fires after step 0 (because (0+1) % 1 == 0); the
        proposer's *second* call must see the mined signals."""
        fake = _FakeQuarry(
            regression=[_candidate("a.example.com", "200 -> 401 flip")],
        )
        session = _session_with_quarry(fake)

        contexts_seen: list[StepContext] = []

        class _SpyProposer:
            async def propose(self, context: StepContext) -> list[Action]:
                contexts_seen.append(context)
                return [Probe(target="target.example.com", aspect="httpx")]

        async def _execute(action: Action) -> dict[str, Any]:
            return {"executed": action.kind}

        loop = AgentLoop(
            proposer=_SpyProposer(),
            checker=ConsistencyChecker(),
            session=session,
            execute_action=_execute,
            budget=Budget(max_steps=2, max_consecutive_empty_steps=10),
            mining_cadence=1,  # mine every step
        )
        await loop.run(target_name="demo", bug_classes=["idor"])

        assert len(contexts_seen) == 2
        # First propose call: no mining yet.
        assert contexts_seen[0].mining_signals == ()
        # Second propose call: mining ran between, signals present.
        assert len(contexts_seen[1].mining_signals) == 1
        assert contexts_seen[1].mining_signals[0].key == "a.example.com"


class TestRenderMiningBlock:
    def test_empty_signals_returns_empty_string(self) -> None:
        assert render_mining_block(()) == ""

    def test_renders_each_signal_as_a_bullet(self) -> None:
        sig = MiningSignal(
            source="regression",
            key="admin.example.com",
            summary="200 -> 401 flip",
            rationale="status flip",
            score=0.7,
            evidence_refs=("ev-1", "ev-2"),
        )
        out = render_mining_block((sig,))
        assert "Quarry analytical layer" in out
        assert "[regression]" in out
        assert "admin.example.com" in out
        assert "200 -> 401 flip" in out
        assert "ev-1" in out  # evidence_refs hint surfaces

    def test_warns_against_direct_evidence_ref_citation(self) -> None:
        sig = MiningSignal(
            source="recall",
            key="x@y",
            summary="seen elsewhere",
            rationale="seen",
            score=0.5,
            evidence_refs=(),
        )
        out = render_mining_block((sig,))
        # The block has to tell the LLM these refs aren't this-run
        # observations and it must re-probe before citing.
        assert "per-run isolation" in out or "re-probe" in out
