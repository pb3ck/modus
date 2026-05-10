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
        *,
        method: str = "GET",
        request_body: str = "",
        redirect_chain: list[str] | None = None,
    ):
        from modus.session import SessionObservation

        return SessionObservation(
            id=obs_id,
            kind="request",
            payload={
                "url": url,
                "method": method,
                "status": status,
                "response_body": body,
                "request_headers": request_headers or {},
                "request_body": request_body,
                "redirect_chain": redirect_chain or [],
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

    def test_info_disclosure_does_not_match_wp_json_namespace_root(self) -> None:
        # Regression: 2026-05-09 wp-lab calibration baseline promoted
        # info_disclosure MEDIUM on /wp-json/ on both profiles. The
        # response there is the WordPress REST API namespace listing —
        # a single object with "namespaces":[...] and "routes":{...}
        # whose route schemas mention "email":{"type":"string",...}
        # dozens of times. The old heuristic ('"[" in body' AND
        # email/UserId count >= 2) tripped on those route schemas.
        # The new ``_looks_like_user_array`` requires the body to start
        # with [{ AND have id+slug/avatar_urls fields in the head — a
        # route listing satisfies neither.
        from modus.evidence_patterns import detect_evidence_patterns

        wp_json_root = (
            '{"name":"Acme Industrial","description":"Precision components",'
            '"url":"http:\\/\\/host","home":"http:\\/\\/host","gmt_offset":"0",'
            '"namespaces":["oembed\\/1.0","wp\\/v2","contact-form-7\\/v1"],'
            '"routes":{"\\/wp\\/v2\\/users":{"args":{"context":{"type":"string"},'
            '"email":{"type":"string","format":"email","required":false}}},'
            '"\\/wp\\/v2\\/posts":{"args":{"author_email":{"type":"string"}}},'
            '"\\/wp\\/v2\\/comments":{"args":{"author_email":{"type":"string"}}}}}'
        )
        obs = self._obs("obs-wpjson", "http://corp/wp-json/", 200, body=wp_json_root)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        # No FallbackHypothesis from this body — body starts with `{`,
        # not `[{`, AND contains the namespaces marker.
        user_dump_matches = [r for r in result if r.detector == "info_disclosure:user_object_dump"]
        assert user_dump_matches == [], (
            f"user_object_dump fired on /wp-json/ namespace root: {user_dump_matches}"
        )

    def test_info_disclosure_user_object_dump_still_matches_real_user_array(
        self,
    ) -> None:
        # Counterpart to the wp-json regression test: ensure the tightened
        # detector still fires on an actual ``[{...}]`` of user records
        # (the canonical /wp-json/wp/v2/users response shape).
        from modus.evidence_patterns import detect_evidence_patterns

        wp_users = (
            '[{"id":1,"name":"admin","slug":"admin","url":"http:\\/\\/host\\/admin",'
            '"avatar_urls":{"24":"http:\\/\\/gravatar\\/abc"},"description":""},'
            '{"id":2,"name":"editor1","slug":"editor1","url":"http:\\/\\/host\\/e1",'
            '"avatar_urls":{"24":"http:\\/\\/gravatar\\/def"}}]'
        )
        obs = self._obs("obs-users", "http://corp/wp-json/wp/v2/users", 200, body=wp_users)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        user_dump_matches = [r for r in result if r.detector == "info_disclosure:user_object_dump"]
        assert len(user_dump_matches) == 1, (
            f"user_object_dump should fire on real user array, got {result}"
        )
        assert user_dump_matches[0].severity_hint == "medium"

    def test_info_disclosure_user_object_dump_rejects_array_of_primitives(
        self,
    ) -> None:
        # ``[1, 2, 3]`` or ``["a", "b"]`` aren't user arrays. Defensive
        # against the LLM's fallback flagging anything array-shaped that
        # happens to have "email" elsewhere.
        from modus.evidence_patterns import detect_evidence_patterns

        body = '["foo","bar","baz"]   <!-- email mentioned twice for noise: email email -->'
        obs = self._obs("obs-prim", "http://target/list", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        user_dump_matches = [r for r in result if r.detector == "info_disclosure:user_object_dump"]
        assert user_dump_matches == []

    def test_info_disclosure_does_not_match_html_form_password_field(self) -> None:
        # Regression: 2026-05-08 Anduril run promoted info_disclosure
        # HIGH on stock Okta SAML login HTML because the form contained
        # <input name="password">. Bare-keyword substring matching on
        # "password" / "secret" / "api_key" was the bug. The new
        # detector requires keyword + value-shape and rejects matches
        # inside HTML form attributes.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-okta",
            "https://dev-okta.example.com/login",
            200,
            body='<form><input type="password" name="password" id="password-field" /></form>',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == [], (
            "info_disclosure detector matched on HTML form attribute "
            "name='password' — keyword without value-shape should not fire"
        )

    def test_info_disclosure_does_not_match_okta_app_id_in_html(self) -> None:
        # The Okta SSO redirect path ``/app/<app-id>/<sso-key>/sso/saml``
        # is public by design. Ensure neither the path nor the
        # embedded Okta App ID (``exk*`` prefix) trips the detector.
        from modus.evidence_patterns import detect_evidence_patterns

        body = """<form action="/login">
            <input name="fromURI" value="/app/some_app_1/exkkn119uu80X7TDS4h7/sso/saml" />
        </form>"""
        obs = self._obs("obs-okta-sso", "https://okta.example.com/", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == []

    def test_info_disclosure_matches_aws_access_key(self) -> None:
        # AWS access keys have an unambiguous shape (AKIA + 16 chars)
        # so they fire critical without needing surrounding context.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-aws",
            "https://target.example.com/config",
            200,
            body='{"region": "us-east-1", "key": "AKIAIOSFODNN7EXAMPLE"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "critical"
        assert "aws_access_key" in result[0].rationale

    def test_info_disclosure_matches_pem_private_key(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-pem",
            "https://target.example.com/keys",
            200,
            body="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END",
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "critical"
        assert "pem_private_key" in result[0].rationale

    def test_info_disclosure_matches_github_token(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-gh",
            "https://target.example.com/config",
            200,
            body='{"repo_token": "ghp_' + "A" * 40 + '"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "critical"
        assert "github_token" in result[0].rationale

    def test_info_disclosure_matches_slack_token(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-slack",
            "https://target.example.com/integrations",
            200,
            body='{"slack": "xoxp-1234567890-AbCdEfGhIjKlMn"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "critical"

    def test_info_disclosure_skips_placeholder_value(self) -> None:
        # Documentation pages often have api_key=<your_key> or similar.
        # These are not credential leaks.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-placeholder",
            "https://docs.example.com/",
            200,
            body='{"api_key": "your-api-key-here"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == []

    def test_info_disclosure_skips_template_placeholder(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-tpl",
            "https://docs.example.com/",
            200,
            body='{"api_key": "<YOUR_API_KEY>"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == []

    def test_info_disclosure_skips_env_template_placeholder(self) -> None:
        # Shell / docker / k8s templates use ${VAR} placeholders.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-env",
            "https://docs.example.com/",
            200,
            body='{"api_key": "${API_KEY_FROM_ENV}"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == []

    # ---- static-artifact detectors (added 2026-05-09 from wp-lab v4) ----

    def test_info_disclosure_vcs_directory_exposure(self) -> None:
        # ``/.git/config`` returning 200 with characteristic git config
        # markup. The 2026-05-09 wp-lab v3 run probed this path and
        # got a 200 but no detector matched → the bug never promoted.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            '[remote "origin"]\n'
            "\turl = git@github.com:acme/marketing-site.git\n"
        )
        obs = self._obs("obs-git", "http://target/.git/config", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:vcs_directory_exposure"]
        assert len(matched) == 1
        assert matched[0].severity_hint == "medium"
        assert matched[0].evidence_refs == ("obs-git",)

    def test_info_disclosure_vcs_directory_skips_html_404_fallthrough(
        self,
    ) -> None:
        # Some webservers return 200 + an HTML error page for missing
        # files. The body-shape gate must reject those.
        from modus.evidence_patterns import detect_evidence_patterns

        body = "<!DOCTYPE html><html><head><title>Not found</title></head>"
        obs = self._obs("obs-404", "http://target/.git/config", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:vcs_directory_exposure"]
        assert matched == []

    def test_info_disclosure_vcs_head_ref(self) -> None:
        # ``/.git/HEAD`` content is a single ``ref: refs/heads/main`` line.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-head",
            "http://target/.git/HEAD",
            200,
            body="ref: refs/heads/main\n",
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:vcs_directory_exposure"]
        assert len(matched) == 1

    def test_info_disclosure_config_backup_exposure(self) -> None:
        # ``/wp-config.php.bak`` returning 200 with PHP source. The
        # secret-content detector might fire on real-looking secrets,
        # but plenty of backups don't contain shape-recognised secrets.
        # This detector fires on path-shape + body-shape regardless.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "<?php\n"
            "// Acme prod wp-config — accidentally backed up\n"
            "define( 'DB_NAME', 'wp_acme' );\n"
            "define( 'DB_USER', 'wp' );\n"
            "define( 'DB_PASSWORD', 'this_is_unique_to_target_redacted' );\n"
            "define( 'AUTH_KEY', 'unique-target-specific-string-here' );\n"
        )
        obs = self._obs(
            "obs-bak",
            "http://target/wp-config.php.bak",
            200,
            body=body,
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:config_backup_exposure"]
        assert len(matched) == 1
        assert matched[0].severity_hint == "high"

    def test_info_disclosure_config_backup_skips_404_fallthrough_html(
        self,
    ) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        body = "<!DOCTYPE html><html><body>Not found</body></html>"
        obs = self._obs(
            "obs-bak-404",
            "http://target/wp-config.php.bak",
            200,
            body=body,
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:config_backup_exposure"]
        assert matched == []

    def test_info_disclosure_dotenv_exposure_is_caught(self) -> None:
        # Env files with values that don't match the secret-content
        # detector (operator-specific values) should still fire as
        # config_backup_exposure on the path+shape gate.
        from modus.evidence_patterns import detect_evidence_patterns

        body = "DEBUG=true\nLOG_LEVEL=info\nPORT=3000\nNODE_ENV=production\n"
        obs = self._obs("obs-env", "http://target/.env", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:config_backup_exposure"]
        assert len(matched) == 1

    def test_info_disclosure_dotenv_with_secrets_fires_secret_detector(self) -> None:
        # When the .env content has shape-recognised secrets, the
        # higher-quality secret-content detector takes precedence
        # over the path-based config_backup_exposure detector. This
        # keeps the per-observation candidate count to one.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        obs = self._obs("obs-env-aws", "http://target/.env", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        # Exactly one candidate per observation; shape-recognised
        # secret takes priority over the path-based fallback.
        assert len(result) == 1
        assert result[0].detector.startswith("info_disclosure:")
        # Detector tag carries the specific secret pattern that fired.
        assert "config_backup_exposure" not in result[0].detector

    def test_info_disclosure_plugin_version_disclosure(self) -> None:
        # ``/wp-content/plugins/<slug>/readme.txt`` with ``Stable tag:``,
        # for a slug NOT in the curated CVE registry — emits the bare
        # version-disclosure candidate. (Slugs in the registry escalate
        # to ``plugin_cve_match`` instead — covered separately below.)
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "=== Some Custom Plugin ===\n"
            "Contributors: someone\n"
            "Tags: utility\n"
            "Stable tag: 2.4.0\n"
            "\n"
            "A utility plugin.\n"
        )
        obs = self._obs(
            "obs-custom",
            "http://target/wp-content/plugins/some-custom-plugin/readme.txt",
            200,
            body=body,
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:plugin_version_disclosure"]
        assert len(matched) == 1
        assert matched[0].severity_hint == "info"
        # Rationale carries the slug + version for the LLM hypothesizer
        # to pivot toward CVE selection.
        assert "some-custom-plugin" in matched[0].rationale
        assert "2.4.0" in matched[0].rationale

    def test_info_disclosure_plugin_version_only_fires_on_readme_txt(
        self,
    ) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        # Non-readme path with the same body shape — must not fire on
        # any plugin detector (neither the bare version nor the
        # CVE-match path).
        obs = self._obs(
            "obs-other",
            "http://target/wp-content/plugins/some-plugin/changelog.txt",
            200,
            body="Stable tag: 1.0.0\n",
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [
            r for r in result if "plugin_version" in r.detector or "plugin_cve" in r.detector
        ]
        assert matched == []

    def test_info_disclosure_plugin_cve_match_escalates_severity(self) -> None:
        # When the registry has a CVE entry covering the fingerprinted
        # ``(slug, version)``, the detector escalates the candidate's
        # bug_class + severity to the upstream CVE's values. This is
        # the issue #32 fix — ``elementor 3.6.2`` is an
        # ``auth_bypass / critical`` bug per CVE-2022-1329, not the
        # bare ``info_disclosure / info`` the version-only detector
        # would emit.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "=== Elementor ===\n"
            "Contributors: elemntor\n"
            "Tags: page builder, drag and drop\n"
            "Stable tag: 3.6.2\n"
            "\n"
            "Drag-and-drop page builder for WordPress.\n"
        )
        obs = self._obs(
            "obs-elementor",
            "http://target/wp-content/plugins/elementor/readme.txt",
            200,
            body=body,
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector.startswith("info_disclosure:plugin_cve_match")]
        assert len(matched) == 1
        # Escalated to the upstream exploit's class + severity.
        assert matched[0].bug_class == "auth_bypass"
        assert matched[0].severity_hint == "critical"
        # CVE ID is in the rationale so operators have the pivot.
        assert "CVE-2022-1329" in matched[0].rationale

    def test_info_disclosure_wp_version_disclosure_via_readme_html(
        self,
    ) -> None:
        # Issue #34: ``/readme.html`` is WordPress's canonical
        # version-disclosure endpoint. The body has
        # ``<title>WordPress &rsaquo; ReadMe</title>`` and the
        # version in the leading content. The bare
        # ``_VERSION_BANNER_RE`` is JSON-shaped and doesn't match;
        # ``_looks_like_user_array`` correctly rejects HTML. New
        # detector closes the gap.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            '<!DOCTYPE html><html lang="en"><head>'
            "<title>WordPress &rsaquo; ReadMe</title>"
            "</head><body>"
            "<h1>WordPress 6.4.2</h1>"
            "<p>Semantic Personal Publishing Platform</p>"
            "</body></html>"
        )
        obs = self._obs("obs-wp-readme", "http://target/readme.html", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:wp_version_disclosure"]
        assert len(matched) == 1
        assert matched[0].severity_hint == "info"
        # Version string was extracted into the rationale.
        assert "6.4.2" in matched[0].rationale

    def test_info_disclosure_xmlrpc_methods_disclosure(self) -> None:
        # Issue #33: ``POST /xmlrpc.php`` with ``system.listMethods``
        # returns a ``methodResponse`` envelope listing available
        # methods. That's the canonical "XML-RPC enabled" signal.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            '<?xml version="1.0"?>'
            "<methodResponse><params><param><value><array><data>"
            "<value><string>system.multicall</string></value>"
            "<value><string>system.listMethods</string></value>"
            "<value><string>demo.sayHello</string></value>"
            "<value><string>wp.getUsersBlogs</string></value>"
            "<value><string>pingback.ping</string></value>"
            "</data></array></value></param></params></methodResponse>"
        )
        obs = self._obs("obs-xmlrpc", "http://target/xmlrpc.php", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:xmlrpc_methods_disclosure"]
        assert len(matched) == 1
        assert matched[0].severity_hint == "low"
        # Method names appear in the rationale so operators can pivot
        # (e.g. seeing ``pingback.ping`` → amplification path).
        assert "pingback.ping" in matched[0].rationale

    def test_info_disclosure_xmlrpc_skips_405_get(self) -> None:
        # The 405 GET response is just text saying "POST only" — not
        # a methodResponse. Detector must not fire.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-xmlrpc-405",
            "http://target/xmlrpc.php",
            200,  # status 405 is filtered out earlier; 200 with non-XML body
            body="XML-RPC server accepts POST requests only.",
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:xmlrpc_methods_disclosure"]
        assert matched == []

    def test_info_disclosure_readme_html_without_wp_marker_skips(self) -> None:
        # ``/readme.html`` from a non-WordPress project must not fire
        # the WP-version detector.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "<!DOCTYPE html><html><head><title>Project ReadMe</title></head>"
            "<body><h1>Other Project 1.2.3</h1></body></html>"
        )
        obs = self._obs("obs-other-readme", "http://target/readme.html", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if r.detector == "info_disclosure:wp_version_disclosure"]
        assert matched == []

    def test_info_disclosure_plugin_no_cve_match_keeps_info_severity(
        self,
    ) -> None:
        # Slug IS in the registry (akismet has entries) but the
        # current version isn't in any affected range. Falls back to
        # the bare ``info_disclosure / info`` candidate.
        from modus.evidence_patterns import detect_evidence_patterns

        body = (
            "=== Akismet ===\nContributors: matt\nStable tag: 5.3.0\n\nComment spam protection.\n"
        )
        obs = self._obs(
            "obs-akismet",
            "http://target/wp-content/plugins/akismet/readme.txt",
            200,
            body=body,
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        matched = [r for r in result if "plugin" in r.detector]
        assert len(matched) == 1
        assert matched[0].detector == "info_disclosure:plugin_version_disclosure"
        assert matched[0].bug_class == "info_disclosure"
        assert matched[0].severity_hint == "info"

    def test_info_disclosure_skips_test_fixture_value(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-fix",
            "https://docs.example.com/",
            200,
            body='{"api_key": "test_example_dummy_value"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        # 'example' anywhere in the value matches the placeholder pattern.
        assert result == []

    def test_info_disclosure_matches_real_keyword_value(self) -> None:
        # Sanity: the existing positive case (concrete keyword=value)
        # still fires after the refactor.
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-real",
            "https://target.example.com/config",
            200,
            body='{"api_key": "concrete_real_value_AbCdEfGhIjKlMn"}',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "high"

    def test_info_disclosure_skips_bearer_placeholder(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-bearer-tpl",
            "https://docs.example.com/",
            200,
            body="Authorization: Bearer <your_token_here>",
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert result == []

    def test_info_disclosure_matches_real_bearer_token(self) -> None:
        from modus.evidence_patterns import detect_evidence_patterns

        obs = self._obs(
            "obs-bearer-real",
            "https://target.example.com/leaked",
            200,
            body="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.AbCdEfGh",
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        assert result[0].severity_hint == "high"

    def test_info_disclosure_excerpt_shows_match_not_body_prefix(self) -> None:
        # Companion to the false-positive bug: the prior rationale
        # showed body[:120] (HTML DOCTYPE / IE conditional comments
        # in the Anduril Okta case), which made the audit misleading.
        # The new detector shows the concrete matching text.
        from modus.evidence_patterns import detect_evidence_patterns

        body = "<!DOCTYPE html>" + (" " * 100) + "padding..." * 5
        body += '\n{"api_key": "concrete_real_value_AbCdEfGhIjKlMn"}'
        obs = self._obs("obs-excerpt", "https://target.example.com/", 200, body=body)
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        assert len(result) == 1
        rationale = result[0].rationale
        # The misleading body-prefix shouldn't appear in the audit.
        assert "<!DOCTYPE" not in rationale
        assert "padding" not in rationale
        # The actual matching keyword should be referenced.
        assert "api_key" in rationale.lower()

    def test_info_disclosure_skips_data_attribute_with_keyword_substring(self) -> None:
        # Edge case: HTML element with data-* attribute that contains
        # an embedded keyword (e.g. ``data-api-key="..."``). The
        # form-attribute exclusion catches the standard ``name=`` /
        # ``id=`` cases — this guards against the next class of FP.
        from modus.evidence_patterns import detect_evidence_patterns

        # Note: this currently DOES match (data-api-key="..." passes
        # the keyword+value regex because data-api-key has api-key as
        # a suffix and = follows). Documenting the limitation for
        # now; tightening to require non-dash boundary before the
        # keyword is a follow-up.
        obs = self._obs(
            "obs-data-attr",
            "https://target.example.com/",
            200,
            body='<div data-api-key="long-value-that-looks-secret-but-isnt-1234"></div>',
        )
        result = detect_evidence_patterns([obs], ("info_disclosure",))
        # Acknowledged false-positive class — see body excerpt for
        # which detector tag fires; review whether to tighten in the
        # next iteration.
        if result:
            assert "keyword_value" in result[0].rationale  # detector tag

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

    def test_auth_bypass_skips_admin_ajax_query_dispatch(self) -> None:
        # Regression: the 2026-05-10 user-registration audit (issue
        # #36 part 1) caught a second FP class. WordPress's
        # ``admin-ajax.php`` dispatches handlers via the ``?action=…``
        # query parameter. Two different actions look identical to the
        # ``(host, path, method)`` bucket because the path and method
        # are the same; only the query string distinguishes them.
        #
        # ``GET admin-ajax.php?action=foo → 200`` and
        # ``GET admin-ajax.php?action=bar → 403`` are NOT auth_bypass
        # — they're two different handlers with different auth
        # requirements. Including the sorted query string in the bucket
        # key separates them, suppressing the FP.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_open = self._obs(
            "obs-action-foo",
            "http://target/wp-admin/admin-ajax.php?action=user_registration_user_form_submit",
            200,
            method="GET",
            body='{"success":false,"data":{"message":"Nonce error, please reload."}}',
        )
        obs_blocked = self._obs(
            "obs-action-bar",
            "http://target/wp-admin/admin-ajax.php?action=user_registration_ajax_login_submit",
            403,
            method="GET",
        )
        result = detect_evidence_patterns([obs_open, obs_blocked], ("auth_bypass",))
        assert result == [], (
            f"different ?action= query params on admin-ajax.php are different "
            f"endpoints; detector fired anyway: {result}"
        )

    def test_auth_bypass_query_order_insensitive(self) -> None:
        # Two requests with the same query parameters in different
        # orders should bucket together — they're the same endpoint.
        # This protects against a regression where the sorting got
        # accidentally removed.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_a = self._obs(
            "obs-q1",
            "http://target/api/foo?a=1&b=2",
            401,
            method="GET",
        )
        obs_b = self._obs(
            "obs-q2",
            "http://target/api/foo?b=2&a=1",  # same params, different order
            200,
            method="GET",
            body='{"data":"sensitive"}',
        )
        result = detect_evidence_patterns([obs_a, obs_b], ("auth_bypass",))
        assert len(result) == 1, f"same params different order should bucket together; got {result}"

    def test_auth_bypass_skips_options_preflight_vs_get(self) -> None:
        # Regression: the 2026-05-10 WPForms Lite audit promoted three
        # false-positive auth_bypass candidates because the detector
        # bucketed by ``(host, path)`` regardless of method. A REST API
        # endpoint correctly returning ``OPTIONS /endpoint → 200`` (CORS
        # preflight, route schema) and ``GET /endpoint → 401`` (auth
        # required) tripped the differential. CORS preflight is
        # unauthenticated by spec — the 200 doesn't represent a bypass.
        # Now we bucket by ``(host, path, method)``: OPTIONS group has
        # only the 200, GET group has only the 401, neither group has
        # both 200 and 401, no candidate.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_options = self._obs(
            "obs-options",
            "http://target/wp-json/wpforms/v1/forms",
            200,
            method="OPTIONS",
            body='{"namespace":"wpforms/v1","methods":["GET"]}',
        )
        obs_get = self._obs(
            "obs-get",
            "http://target/wp-json/wpforms/v1/forms",
            401,
            method="GET",
        )
        result = detect_evidence_patterns([obs_options, obs_get], ("auth_bypass",))
        assert result == [], (
            f"OPTIONS preflight vs GET on same path is not auth_bypass; "
            f"detector fired anyway: {result}"
        )

    def test_auth_bypass_still_fires_on_same_method_differential(self) -> None:
        # Counterpart to the OPTIONS-vs-GET regression: two GETs to the
        # same path, one with bypass-shaped payload returning 200, one
        # without returning 401, IS still detected. This is the canonical
        # auth_bypass shape.
        from modus.evidence_patterns import detect_evidence_patterns

        obs_blocked = self._obs(
            "obs-blocked",
            "http://target/api/admin",
            401,
            method="GET",
        )
        obs_bypassed = self._obs(
            "obs-bypassed",
            "http://target/api/admin",
            200,
            method="GET",
            body='{"role":"admin","tokens":"..."}',
        )
        result = detect_evidence_patterns([obs_blocked, obs_bypassed], ("auth_bypass",))
        assert len(result) == 1
        assert result[0].bug_class == "auth_bypass"
        assert set(result[0].evidence_refs) == {"obs-blocked", "obs-bypassed"}

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
