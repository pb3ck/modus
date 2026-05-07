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

    def test_in_session_evidence_accepted_when_session_pool_set(self) -> None:
        # Per-run constraint: when ``session_observations`` is a
        # frozenset (autonomous mode), Hypothesize must cite from
        # that subset. Here the cited observation IS in the session
        # pool, so the action passes.
        state = CorpusState(
            in_scope_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            known_observations=frozenset({"obs-prior-session", "obs-this-run"}),
            known_evidence=frozenset(),
            session_observations=frozenset({"obs-this-run"}),
        )
        verdict = ConsistencyChecker().check(
            Hypothesize(
                bug_class="auth_bypass",
                evidence_refs=("obs-this-run",),
                rationale="**Vulnerability:** ... etc",
            ),
            state,
        )
        assert verdict.accepted, verdict.rationale

    def test_prior_session_obs_rejected_when_session_pool_set(self) -> None:
        # The bug from the 2026-05-07 hunt: the proposer cites a
        # prior session's observation_id (which is in
        # ``known_observations`` because the ``ServerSession``
        # process-lifetime pool persists across runs). With the new
        # ``session_observations`` constraint, this MUST reject —
        # the agent can't cite evidence it didn't actually produce.
        state = CorpusState(
            in_scope_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            known_observations=frozenset({"obs-prior-session", "obs-this-run"}),
            known_evidence=frozenset(),
            session_observations=frozenset({"obs-this-run"}),
        )
        verdict = ConsistencyChecker().check(
            Hypothesize(
                bug_class="auth_bypass",
                evidence_refs=("obs-prior-session",),
                rationale="anything",
            ),
            state,
        )
        assert not verdict.accepted
        # The failed precondition surfaces the specific obs_id
        # that wasn't in the session pool — useful operator signal.
        assert any(
            name.startswith("evidence_in_session:obs-prior-session")
            for name in verdict.failed_preconditions
        )

    def test_autonomous_mode_with_empty_pool_rejects_all_citations(self) -> None:
        # ``session_observations=frozenset()`` is autonomous mode
        # before any actions have produced observations this run.
        # No citation is valid because nothing has been evidenced
        # yet — the proposer must produce an observation first
        # (Probe / Request / Compare) before it can hypothesize.
        state = CorpusState(
            in_scope_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            # known_observations populated from prior runs; visible
            # in the process-lifetime pool but NOT in this run.
            known_observations=frozenset({"obs-bleed"}),
            known_evidence=frozenset(),
            session_observations=frozenset(),  # autonomous, empty
        )
        verdict = ConsistencyChecker().check(
            Hypothesize(
                bug_class="auth_bypass",
                evidence_refs=("obs-bleed",),
                rationale="anything",
            ),
            state,
        )
        assert not verdict.accepted
        assert any(
            name.startswith("evidence_in_session:obs-bleed")
            for name in verdict.failed_preconditions
        )

    def test_verified_action_path_unchanged_when_session_pool_unset(self) -> None:
        # When ``session_observations`` is None (default), the
        # verified-action / CLI path uses the looser
        # ``evidence_known`` check — citing any
        # known_observation/known_evidence is fine. This guarantees
        # the new constraint doesn't break the operator-driven
        # surface (#4 design intent: hard reject in autonomous
        # mode, soft path in verified-action mode).
        state = CorpusState(
            in_scope_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            known_observations=frozenset({"obs-from-prior-call"}),
            known_evidence=frozenset(),
            # session_observations defaults to None.
        )
        verdict = ConsistencyChecker().check(
            Hypothesize(
                bug_class="idor",
                evidence_refs=("obs-from-prior-call",),
                rationale="cite from earlier in the verified-action chain",
            ),
            state,
        )
        assert verdict.accepted, verdict.rationale


class TestToolPlaceholder:
    """Tool actions are placeholder-rejected when the
    ``ConsistencyChecker`` has no registry/scope wired — the
    backward-compatible code path tests and the CLI go through.
    Verifies the agent loop can't accidentally execute a Tool
    emission against an unconfigured checker.
    """

    def test_tool_action_rejected_when_no_registry(self) -> None:
        from modus.actions import Tool

        verdict = ConsistencyChecker().check(
            Tool(name="amass.enum", args={"domain": "example.com"}),
            _scoped_state(),
        )
        assert not verdict.accepted
        assert "tool_dispatch_not_yet_implemented" in verdict.failed_preconditions


class TestToolRegistryDispatch:
    """Registry-driven dispatch (#9) — when the checker holds a
    scope and a registry, Tool actions go through the spec's
    per-tool preconditions instead of the placeholder rejection.
    """

    def _setup(
        self,
        *,
        preconditions=None,  # type: ignore[no-untyped-def]
        args_schema=None,  # type: ignore[no-untyped-def]
    ) -> tuple[ConsistencyChecker, object]:
        # Local imports keep the test module's top-level imports
        # narrow.
        from modus.scope import ScopePolicy
        from modus.tools import ShellInvocation, ToolRegistry, ToolSpec

        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
        )
        registry = ToolRegistry()
        spec = ToolSpec(
            name="amass.enum",
            kind="shell",
            description="recon",
            args_schema=args_schema
            or {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
            },
            side_effect="active",
            invocation=ShellInvocation(argv_template=("amass", "enum", "-d", "{domain}")),
            preconditions=preconditions or _accept_all,
        )
        registry.register(spec)
        return ConsistencyChecker(scope=scope, registry=registry), spec

    def test_registered_tool_with_passing_preconditions_accepts(self) -> None:
        from modus.actions import Tool

        checker, _spec = self._setup()
        verdict = checker.check(
            Tool(name="amass.enum", args={"domain": "target.example.com"}),
            _scoped_state(),
        )
        assert verdict.accepted, verdict.rationale

    def test_unregistered_tool_rejected(self) -> None:
        from modus.actions import Tool

        checker, _spec = self._setup()
        verdict = checker.check(
            Tool(name="not-registered", args={}),
            _scoped_state(),
        )
        assert not verdict.accepted
        assert "tool_registered:not-registered" in verdict.failed_preconditions

    def test_missing_required_arg_rejected_with_specific_label(self) -> None:
        from modus.actions import Tool

        checker, _spec = self._setup()
        verdict = checker.check(
            Tool(name="amass.enum", args={}),  # missing required `domain`
            _scoped_state(),
        )
        assert not verdict.accepted
        assert "tool_args_missing_required:amass.enum:domain" in verdict.failed_preconditions

    def test_unknown_field_rejected_when_additional_properties_false(self) -> None:
        from modus.actions import Tool

        checker, _spec = self._setup(
            args_schema={
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
                "additionalProperties": False,
            },
        )
        verdict = checker.check(
            Tool(
                name="amass.enum",
                args={"domain": "target.example.com", "rogue": "field"},
            ),
            _scoped_state(),
        )
        assert not verdict.accepted
        assert "tool_args_unknown_field:amass.enum:rogue" in verdict.failed_preconditions

    def test_per_tool_preconditions_evaluated(self) -> None:
        # The spec's preconditions function is called with
        # ``(args, scope, state)`` and its results are wired into
        # the Z3 layer. Use a fn that rejects when domain isn't in
        # scope.allowed_assets.
        from modus.actions import Tool

        def domain_in_scope(
            args: dict[str, object], scope: object, state: object
        ) -> list[tuple[str, bool]]:
            domain = str(args.get("domain", ""))
            return [(f"domain_in_scope:{domain}", domain in scope.allowed_assets)]  # type: ignore[attr-defined]

        checker, _spec = self._setup(preconditions=domain_in_scope)

        # In-scope domain → accepted.
        v_ok = checker.check(
            Tool(name="amass.enum", args={"domain": "target.example.com"}),
            _scoped_state(),
        )
        assert v_ok.accepted

        # Out-of-scope domain → rejected with the spec's label.
        v_bad = checker.check(
            Tool(name="amass.enum", args={"domain": "evil.example.com"}),
            _scoped_state(),
        )
        assert not v_bad.accepted
        assert "domain_in_scope:evil.example.com" in v_bad.failed_preconditions


def _accept_all(args: dict[str, object], scope: object, state: object) -> list[tuple[str, bool]]:
    """Per-tool preconditions stub for tests that don't care about
    the spec's specific gating — accepts everything."""
    return []


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
