"""Tests for the bug-class evidence pattern library (#5).

The pattern library is the prompt-side fix for two related papercuts
observed during the 2026-05-07 Juice Shop work: smaller proposers
defaulting ``severity_hint`` to ``info`` on clear ``critical``
findings, and the closing rule's recognition templates being shallow
(only auth_bypass / idor / info_disclosure had explicit "what does
the win look like" anchors).

These tests cover the library's contract:

  * Every entry has the four required fields populated.
  * ``render_patterns`` is scoped — it returns only the requested
    classes, in the order they were asked for.
  * Unknown bug classes are silently skipped (the closing rule still
    has its general guidance; the per-class block is a recognition
    aid, not a gate).
  * Severity defaults are deliberate — no canonical instance
    defaults to ``info``, which would be a regression of the bug we
    closed.
"""

from __future__ import annotations

from modus.evidence_patterns import PATTERNS, render_patterns


class TestPatternEntries:
    def test_every_pattern_has_required_fields_populated(self) -> None:
        for bug_class, pattern in PATTERNS.items():
            assert pattern.bug_class == bug_class, (
                f"PATTERNS key {bug_class!r} doesn't match "
                f"the entry's bug_class {pattern.bug_class!r}"
            )
            assert pattern.recognition.strip(), (
                f"{bug_class}: recognition template is empty — "
                "the closing rule has no anchor for this class"
            )
            assert pattern.severity_canonical in {
                "info",
                "low",
                "medium",
                "high",
                "critical",
            }
            assert pattern.severity_notes.strip()

    def test_no_canonical_instance_defaults_to_info(self) -> None:
        # ``info`` means "nothing actionable" per the severity
        # criteria. A canonical instance of any bug class in the
        # library is by definition actionable — defaulting to info
        # would re-introduce the regression #5 was filed to fix.
        for bug_class, pattern in PATTERNS.items():
            assert pattern.severity_canonical != "info", (
                f"{bug_class}: canonical-instance severity is "
                "'info', which contradicts the recognition "
                "template's premise of an actionable finding"
            )

    def test_v01_bug_classes_present(self) -> None:
        # The v0.1 likely-scope bug classes (per the README) all
        # have entries — operators hunting these get the per-class
        # template.
        required = {"auth_bypass", "idor", "info_disclosure", "sqli", "ssrf"}
        assert required <= set(PATTERNS), (
            f"missing v0.1 bug classes from library: {required - set(PATTERNS)}"
        )


class TestRenderPatterns:
    def test_renders_only_requested_classes(self) -> None:
        out = render_patterns(("auth_bypass", "sqli"))
        # Both requested classes appear.
        assert "**auth_bypass**" in out
        assert "**sqli**" in out
        # Other classes do NOT appear — the proposer's prompt stays
        # scoped to what the operator is actually hunting.
        assert "**idor**" not in out
        assert "**xss**" not in out
        assert "**ssrf**" not in out

    def test_empty_for_unknown_classes_only(self) -> None:
        # Unknown classes are silently skipped so an operator's
        # custom bug_class label doesn't crash the prompt build.
        out = render_patterns(("not-a-real-bug-class",))
        assert out == ""

    def test_partial_match_silently_skips_unknowns(self) -> None:
        out = render_patterns(("auth_bypass", "totally-fictional"))
        assert "**auth_bypass**" in out
        assert "fictional" not in out

    def test_renders_severity_default_per_class(self) -> None:
        out = render_patterns(("auth_bypass",))
        # Severity guidance is rendered with the canonical default
        # in the per-class block. Without this the model has no
        # specific cue to pick critical over the schema default.
        assert "`critical`" in out
        assert "Severity (canonical instance)" in out

    def test_rendered_block_is_substantive_for_each_class(self) -> None:
        # Every individual class's rendered block should be long
        # enough to actually anchor a small model — not a one-liner.
        # 200 chars is a generous floor that catches the case where
        # a recognition string is accidentally truncated.
        for bug_class in PATTERNS:
            out = render_patterns((bug_class,))
            assert len(out) > 200, (
                f"{bug_class}: rendered pattern is only {len(out)} chars; "
                "smaller models need a substantive recognition anchor"
            )


class TestProposerIntegration:
    def test_user_prompt_includes_per_class_recognition(self) -> None:
        # The proposer's per-step prompt now sources the
        # per-class block from render_patterns. End-to-end check
        # via the AnthropicProposer's exposed prompt builder.
        from modus.consistency import CorpusState
        from modus.proposer import AnthropicProposer, StepContext
        from modus.scope import ScopePolicy

        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
        )
        proposer = AnthropicProposer(scope=scope, api_key="sk-fake")
        ctx = StepContext(
            corpus_state=CorpusState(),
            scope=scope,
            objective="hunt",
            bug_classes=("sqli",),
            recent_history=("step 0: dummy",),
        )
        user_prompt = proposer._user_prompt(ctx)
        # The sqli recognition template made it into the prompt.
        assert "**sqli**" in user_prompt
        # The severity guidance for sqli (canonical = critical)
        # is in the prompt, so the model has a concrete cue to
        # pick the right severity_hint.
        assert "critical" in user_prompt

    def test_user_prompt_omits_per_class_block_when_no_bug_classes(self) -> None:
        # When the operator doesn't pass bug_classes (verified-
        # action surface, or a generic exploration run), the
        # closing rule shouldn't fire and the per-class block
        # shouldn't render — the prompt stays compact.
        from modus.consistency import CorpusState
        from modus.proposer import AnthropicProposer, StepContext
        from modus.scope import ScopePolicy

        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
        )
        proposer = AnthropicProposer(scope=scope, api_key="sk-fake")
        ctx = StepContext(
            corpus_state=CorpusState(),
            scope=scope,
            objective="hunt",
            recent_history=(),
            # bug_classes defaults to ()
        )
        user_prompt = proposer._user_prompt(ctx)
        assert "Closing rule" not in user_prompt
        assert "Recognition templates" not in user_prompt


class TestDetectEvidencePatterns:
    """Inverse-detection tests for the fallback proposer.

    These exercise the deterministic pattern matchers that fire
    when the LLM proposer keeps abdicating despite evidence-shaped
    observations being in the run pool. Each detector is exercised
    against a synthetic SessionObservation crafted to match (or
    deliberately not-match) one bug-class template.
    """

    @staticmethod
    def _obs(
        obs_id: str,
        url: str,
        status: int,
        body: str = "",
        request_headers: dict | None = None,
    ):
        from modus.session import SessionObservation

        return SessionObservation(
            id=obs_id,
            kind="request",
            payload={
                "url": url,
                "status": status,
                "response_body": body,
                "request_headers": request_headers or {},
            },
        )

    def test_info_disclosure_version_banner(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-1",
            "http://target/rest/admin/application-version",
            200,
            body='{"version":"19.2.1"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].bug_class == "info_disclosure"
        assert result[0].severity_hint == "low"
        assert result[0].evidence_refs == ("obs-1",)
        assert "version" in result[0].rationale.lower()

    def test_info_disclosure_secret_token(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-2",
            "http://target/api/leak",
            200,
            body='{"api_key":"sk-live-deadbeef-000"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "high"

    def test_info_disclosure_user_object_dump(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-3",
            "http://target/api/Feedbacks",
            200,
            body=(
                '{"status":"success","data":'
                '[{"UserId":1,"comment":"hi"},{"UserId":2,"comment":"hey"}]}'
            ),
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "medium"
        assert result[0].evidence_refs == ("obs-3",)

    def test_info_disclosure_skips_authenticated_request(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-4",
            "http://target/rest/admin/application-version",
            200,
            body='{"version":"19.2.1"}',
            request_headers={"Authorization": "Bearer token"},
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == []

    def test_auth_bypass_same_path_status_diff(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs_protected = self._obs("obs-5", "http://target/api/Users/1", 401)
        obs_open = self._obs("obs-6", "http://target/api/Users/1", 200, body='{"data":[]}')
        result = detect_evidence_patterns([obs_protected, obs_open], ("auth_bypass",))
        assert len(result) == 1
        assert result[0].bug_class == "auth_bypass"
        assert set(result[0].evidence_refs) == {"obs-5", "obs-6"}

    def test_auth_bypass_skips_when_only_one_status_class(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs_a = self._obs("obs-7", "http://target/api/Users/1", 401)
        obs_b = self._obs("obs-8", "http://target/api/Users/2", 401)
        result = detect_evidence_patterns([obs_a, obs_b], ("auth_bypass",))
        assert result == []

    def test_idor_enumerable_user_data(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs_1 = self._obs(
            "obs-9",
            "http://target/api/Users/1",
            200,
            body='{"UserId":1,"email":"a@x.com"}',
        )
        obs_2 = self._obs(
            "obs-10",
            "http://target/api/Users/2",
            200,
            body='{"UserId":2,"email":"b@x.com"}',
        )
        result = detect_evidence_patterns([obs_1, obs_2], ("idor",))
        assert len(result) == 1
        assert result[0].bug_class == "idor"
        assert result[0].severity_hint == "high"
        assert set(result[0].evidence_refs) == {"obs-9", "obs-10"}

    def test_auth_bypass_does_not_match_across_hosts(self) -> None:
        # Regression: the 2026-05-08 Anduril tool-validation run
        # promoted a false-positive auth_bypass HIGH because the
        # detector keyed only by path. ``foxglove.chaos.anduril.dev/``
        # (200, deliberate health endpoint) and
        # ``cyberchef.security.anduril.dev/`` (401, IP-allowlisted)
        # were two unrelated services that happened to share ``/``;
        # auth_bypass requires same-host same-path.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_open = self._obs("obs-fx", "https://foxglove.chaos.anduril.dev/", 200)
        obs_protected = self._obs("obs-cc", "https://cyberchef.security.anduril.dev/", 401)
        result = detect_evidence_patterns([obs_open, obs_protected], ("auth_bypass",))
        assert result == [], (
            "auth_bypass detector matched across two unrelated hosts that "
            "happen to share path '/'; same-host enforcement is broken"
        )

    def test_auth_bypass_matches_same_host_different_authstate(self) -> None:
        # The legitimate auth_bypass shape: same host, same path, one
        # request authenticated (or not) returns 200 while another
        # returns 401/403. Ensures the same-host fix didn't over-tighten.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_protected = self._obs("obs-p", "https://api.example.com/admin/users", 401)
        obs_open = self._obs(
            "obs-o", "https://api.example.com/admin/users", 200, body='{"data":[]}'
        )
        result = detect_evidence_patterns([obs_protected, obs_open], ("auth_bypass",))
        assert len(result) == 1
        assert set(result[0].evidence_refs) == {"obs-p", "obs-o"}

    def test_auth_bypass_does_not_match_same_path_different_subdomains(self) -> None:
        # Subdomains of the same parent are still different hosts —
        # ``foxglove.bunker.anduril.dev`` and
        # ``foxglove.chaos.anduril.dev`` are sibling deployments,
        # not the same handler with different auth.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_a = self._obs("obs-a", "https://foxglove.bunker.anduril.dev/", 200)
        obs_b = self._obs("obs-b", "https://foxglove.chaos.anduril.dev/", 401)
        result = detect_evidence_patterns([obs_a, obs_b], ("auth_bypass",))
        assert result == []

    def test_idor_does_not_match_across_hosts(self) -> None:
        # ``/users/1`` on host A and ``/users/2`` on host B aren't
        # enumerable IDs of the same handler — they're two unrelated
        # services that happen to share a URL shape.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_a = self._obs(
            "obs-iA",
            "https://api-a.example.com/users/1",
            200,
            body='{"UserId":1,"email":"a@x.com"}',
        )
        obs_b = self._obs(
            "obs-iB",
            "https://api-b.example.com/users/2",
            200,
            body='{"UserId":2,"email":"b@x.com"}',
        )
        result = detect_evidence_patterns([obs_a, obs_b], ("idor",))
        assert result == [], (
            "idor detector matched across two unrelated hosts with similar "
            "URL shapes; same-host enforcement is broken"
        )

    def test_idor_matches_same_host_enumerable_ids(self) -> None:
        # Sanity: same host, two different IDs of the same handler,
        # both 200 with user-shaped data — the canonical IDOR. The
        # same-host fix must not break this.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_1 = self._obs(
            "obs-h1",
            "https://api.example.com/users/1",
            200,
            body='{"UserId":1,"email":"a@x.com"}',
        )
        obs_2 = self._obs(
            "obs-h2",
            "https://api.example.com/users/2",
            200,
            body='{"UserId":2,"email":"b@x.com"}',
        )
        result = detect_evidence_patterns([obs_1, obs_2], ("idor",))
        assert len(result) == 1

    def test_sqli_db_error_in_response(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-11",
            "http://target/rest/products/search?q=apple%27%29%29",
            500,
            body='Error: SQLITE_ERROR: near "))": syntax error',
        )
        result = detect_evidence_patterns([obs], ("sqli",))
        assert len(result) == 1
        assert result[0].bug_class == "sqli"
        assert result[0].severity_hint == "high"

    def test_sqli_differential_empty_on_taint(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        baseline = self._obs(
            "obs-12",
            "http://target/rest/products/search?q=apple",
            200,
            body='{"status":"success","data":[{"id":1,"name":"Apple Juice"}]}',
        )
        tainted = self._obs(
            "obs-13",
            "http://target/rest/products/search?q=apple%27%29%29%20--",
            200,
            body='{"status":"success","data":[]}',
        )
        result = detect_evidence_patterns([baseline, tainted], ("sqli",))
        assert len(result) == 1
        assert result[0].bug_class == "sqli"
        assert result[0].evidence_refs == ("obs-13",)

    def test_bug_class_filter_applies(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-14",
            "http://target/rest/admin/application-version",
            200,
            body='{"version":"19.2.1"}',
        )
        result = detect_evidence_patterns([obs], ("idor",))
        assert result == []

    def test_empty_observation_pool_returns_empty(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        result = detect_evidence_patterns([], ("auth_bypass", "idor"))
        assert result == []

    def test_no_bug_classes_runs_all_detectors(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-15",
            "http://target/rest/admin/application-version",
            200,
            body='{"version":"19.2.1"}',
        )
        result = detect_evidence_patterns([obs], ())
        assert len(result) == 1
        assert result[0].bug_class == "info_disclosure"
