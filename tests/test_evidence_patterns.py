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
