"""Tests for the Z3 consistency layer."""

from __future__ import annotations

from modus.actions import (
    Annotate,
    Compare,
    Differential,
    Hypothesize,
    Probe,
    Request,
)
from modus.consistency import ConsistencyChecker, CorpusState


def _scoped_state() -> CorpusState:
    return CorpusState(
        in_scope_assets=frozenset({"target.example.com", "admin.example.com"}),
        allowed_methods=frozenset({"GET", "HEAD"}),
        known_observations=frozenset({"obs-1", "obs-2", "obs-3"}),
        known_evidence=frozenset({"ev-1"}),
        known_referents=frozenset({"target.example.com"}),
    )


class TestProbeConsistency:
    def test_in_scope_target_accepted(self) -> None:
        verdict = ConsistencyChecker().check(Probe(target="target.example.com"), _scoped_state())
        assert verdict.accepted, verdict.rationale

    def test_out_of_scope_target_rejected(self) -> None:
        verdict = ConsistencyChecker().check(Probe(target="evil.example.com"), _scoped_state())
        assert not verdict.accepted
        assert any(name.startswith("target_in_scope:") for name in verdict.failed_preconditions)


class TestRequestConsistency:
    def test_allowed_method_accepted(self) -> None:
        verdict = ConsistencyChecker().check(
            Request(target="target.example.com", method="GET", path="/"),
            _scoped_state(),
        )
        assert verdict.accepted, verdict.rationale

    def test_disallowed_method_rejected(self) -> None:
        verdict = ConsistencyChecker().check(
            Request(target="target.example.com", method="DELETE", path="/"),
            _scoped_state(),
        )
        assert not verdict.accepted
        assert any(name == "method_allowed:DELETE" for name in verdict.failed_preconditions)

    def test_out_of_scope_target_rejected_even_with_allowed_method(self) -> None:
        verdict = ConsistencyChecker().check(
            Request(target="evil.example.com", method="GET", path="/"),
            _scoped_state(),
        )
        assert not verdict.accepted

    def test_endpoint_aware_check_rejects_wrong_port(self) -> None:
        # When CorpusState.allowed_endpoints constrains port + tls,
        # Request with a different (port, tls) tuple must be
        # rejected — even though the hostname IS in scope.
        from modus.scope import AllowedEndpoint

        state = CorpusState(
            in_scope_assets=frozenset({"localhost"}),
            allowed_endpoints=(AllowedEndpoint(host="localhost", port=13000, tls=False),),
            allowed_methods=frozenset({"GET"}),
        )
        verdict = ConsistencyChecker().check(
            Request(target="localhost", method="GET", path="/", port=3000, tls=False),
            state,
        )
        assert not verdict.accepted
        assert any(name.startswith("endpoint_in_scope:") for name in verdict.failed_preconditions)

    def test_endpoint_aware_check_accepts_matching_port(self) -> None:
        from modus.scope import AllowedEndpoint

        state = CorpusState(
            in_scope_assets=frozenset({"localhost"}),
            allowed_endpoints=(AllowedEndpoint(host="localhost", port=13000, tls=False),),
            allowed_methods=frozenset({"GET"}),
        )
        verdict = ConsistencyChecker().check(
            Request(target="localhost", method="GET", path="/", port=13000, tls=False),
            state,
        )
        assert verdict.accepted

    def test_endpoint_aware_check_rejects_wrong_tls(self) -> None:
        from modus.scope import AllowedEndpoint

        state = CorpusState(
            in_scope_assets=frozenset({"localhost"}),
            allowed_endpoints=(AllowedEndpoint(host="localhost", port=13000, tls=False),),
            allowed_methods=frozenset({"GET"}),
        )
        # Same host + port, but tls=True doesn't match the http-only
        # endpoint pattern.
        verdict = ConsistencyChecker().check(
            Request(target="localhost", method="GET", path="/", port=13000, tls=True),
            state,
        )
        assert not verdict.accepted


class TestCompareConsistency:
    def test_two_known_observations_accepted(self) -> None:
        verdict = ConsistencyChecker().check(
            Compare(
                observation_a="obs-1",
                observation_b="obs-2",
                dimensions=("status",),
            ),
            _scoped_state(),
        )
        assert verdict.accepted

    def test_unknown_observation_rejected(self) -> None:
        verdict = ConsistencyChecker().check(
            Compare(
                observation_a="obs-1",
                observation_b="obs-missing",
                dimensions=("status",),
            ),
            _scoped_state(),
        )
        assert not verdict.accepted

    def test_same_observation_rejected(self) -> None:
        verdict = ConsistencyChecker().check(
            Compare(
                observation_a="obs-1",
                observation_b="obs-1",
                dimensions=("status",),
            ),
            _scoped_state(),
        )
        assert not verdict.accepted
        assert "observations_distinct" in verdict.failed_preconditions


class TestDifferentialConsistency:
    def test_all_observations_known_accepted(self) -> None:
        verdict = ConsistencyChecker().check(
            Differential(
                observations=("obs-1", "obs-2"),
                dimension="identity",
                bug_class="idor",
            ),
            _scoped_state(),
        )
        assert verdict.accepted

    def test_unknown_observation_rejected(self) -> None:
        verdict = ConsistencyChecker().check(
            Differential(
                observations=("obs-1", "obs-missing"),
                dimension="identity",
                bug_class="idor",
            ),
            _scoped_state(),
        )
        assert not verdict.accepted


class TestAnnotateConsistency:
    def test_known_referent_accepted(self) -> None:
        verdict = ConsistencyChecker().check(
            Annotate(referent="target.example.com", note="checked"),
            _scoped_state(),
        )
        assert verdict.accepted

    def test_unknown_referent_rejected(self) -> None:
        verdict = ConsistencyChecker().check(
            Annotate(referent="ghost.example.com", note="checked"),
            _scoped_state(),
        )
        assert not verdict.accepted


class TestHypothesizeConsistency:
    def test_known_evidence_accepted(self) -> None:
        verdict = ConsistencyChecker().check(
            Hypothesize(
                bug_class="idor",
                evidence_refs=("ev-1", "obs-1"),
                rationale="200 leaks another tenant's record",
            ),
            _scoped_state(),
        )
        assert verdict.accepted

    def test_unknown_evidence_rejected(self) -> None:
        verdict = ConsistencyChecker().check(
            Hypothesize(
                bug_class="idor",
                evidence_refs=("ev-missing",),
                rationale="anything",
            ),
            _scoped_state(),
        )
        assert not verdict.accepted


class TestPruneBatch:
    def test_prune_returns_one_verdict_per_action(self) -> None:
        actions = [
            Probe(target="target.example.com"),
            Probe(target="evil.example.com"),
            Request(target="target.example.com", method="GET", path="/"),
        ]
        results = ConsistencyChecker().prune(actions, _scoped_state())
        assert len(results) == len(actions)

    def test_prune_isolates_failures(self) -> None:
        actions = [
            Probe(target="target.example.com"),
            Probe(target="evil.example.com"),
            Request(target="target.example.com", method="DELETE", path="/"),
        ]
        results = ConsistencyChecker().prune(actions, _scoped_state())
        survivors = [a for a, v in results if v.accepted]
        rejected = [a for a, v in results if not v.accepted]
        assert len(survivors) == 1
        assert len(rejected) == 2
