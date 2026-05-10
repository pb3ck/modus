"""Tests for the operating-mode toggle (``free`` vs ``strict``).

Modus shipped with a single design position: typed actions, 240-char
body excerpts, every invariant always on. The 2026-05-10 wp-bounty-lab
calibration showed that position caps what the LLM can find against
modern hardened plugins. The free / strict mode toggle (``modus.mode``)
gives operators a switch:

* ``free`` (default) — productive bug-hunting; LLM gets larger body
  context for token extraction / error parsing / URL discovery.
* ``strict`` — original audit-defensible mode; 240-char tail excerpts.

Both modes preserve scope enforcement, per-run isolation, typed
actions, Z3 preconditions, and detector dispatch — the toggle only
adjusts LLM visibility, not the safety perimeter.
"""

from __future__ import annotations

from modus.mode import (
    DEFAULT_MODE,
    FREE_BODY_EXCERPT_LIMIT,
    STRICT_BODY_EXCERPT_LIMIT,
    body_excerpt_limit,
    mode_from_env,
)


class TestModeFromEnv:
    def test_unset_env_returns_default(self) -> None:
        assert mode_from_env({}) == DEFAULT_MODE
        assert mode_from_env({}) == "free"

    def test_explicit_strict(self) -> None:
        assert mode_from_env({"MODUS_MODE": "strict"}) == "strict"

    def test_explicit_free(self) -> None:
        assert mode_from_env({"MODUS_MODE": "free"}) == "free"

    def test_case_insensitive(self) -> None:
        assert mode_from_env({"MODUS_MODE": "STRICT"}) == "strict"
        assert mode_from_env({"MODUS_MODE": "Free"}) == "free"
        assert mode_from_env({"MODUS_MODE": " strict "}) == "strict"

    def test_unknown_value_falls_back_to_default(self) -> None:
        # Defensive: a misconfigured env var shouldn't crash. Falls
        # back to the default rather than raising.
        assert mode_from_env({"MODUS_MODE": "paranoid"}) == DEFAULT_MODE
        assert mode_from_env({"MODUS_MODE": ""}) == DEFAULT_MODE


class TestBodyExcerptLimit:
    def test_strict_limit_is_240(self) -> None:
        assert body_excerpt_limit("strict") == 240
        assert body_excerpt_limit("strict") == STRICT_BODY_EXCERPT_LIMIT

    def test_free_limit_is_4096(self) -> None:
        assert body_excerpt_limit("free") == 4096
        assert body_excerpt_limit("free") == FREE_BODY_EXCERPT_LIMIT

    def test_free_is_strictly_larger_than_strict(self) -> None:
        # Free mode HAS to give more context than strict. If this
        # ever inverts something is wrong.
        assert FREE_BODY_EXCERPT_LIMIT > STRICT_BODY_EXCERPT_LIMIT


class TestSummariseStepRespectsMode:
    """The agent loop's ``_summarise_step`` is the seam where mode
    affects history. Strict mode caps body excerpts at 240 chars
    (the v0.1 design); free mode allows up to 4096 chars."""

    def test_strict_mode_truncates_at_240(self) -> None:
        from modus.actions import Request
        from modus.agent import _summarise_step

        action = Request(
            target="t.example.com",
            method="GET",
            path="/long-page",
            port=8080,
            tls=False,
        )
        long_body = "X" * 5000
        result = {
            "id": "obs-1",
            "status": 200,
            "response_body": long_body,
        }
        summary = _summarise_step(0, action, result, body_excerpt_chars=240)
        # Find the body_excerpt portion. It's a single-quoted Python
        # repr embedded in the summary; count just the X characters
        # to confirm truncation.
        excerpt_x_count = summary.count("X")
        assert excerpt_x_count <= 240, (
            f"strict-mode excerpt should cap at 240 X's, got {excerpt_x_count}"
        )

    def test_free_mode_allows_4096(self) -> None:
        from modus.actions import Request
        from modus.agent import _summarise_step

        action = Request(
            target="t.example.com",
            method="GET",
            path="/long-page",
            port=8080,
            tls=False,
        )
        # Body large enough to test the 4096 cap precisely.
        long_body = "X" * 5000
        result = {
            "id": "obs-1",
            "status": 200,
            "response_body": long_body,
        }
        summary = _summarise_step(0, action, result, body_excerpt_chars=4096)
        excerpt_x_count = summary.count("X")
        # Free mode gives us up to 4096; well over the strict 240.
        assert excerpt_x_count > 240, (
            f"free-mode excerpt should exceed 240 X's, got {excerpt_x_count}"
        )
        assert excerpt_x_count <= 4096, (
            f"free-mode excerpt should cap at 4096 X's, got {excerpt_x_count}"
        )

    def test_request_body_also_scales_with_mode(self) -> None:
        # The request body excerpt uses the same limit as the
        # response body excerpt. Test both directions.
        from modus.actions import Request
        from modus.agent import _summarise_step

        action = Request(
            target="t.example.com",
            method="POST",
            path="/echo",
            port=8080,
            tls=False,
            body="Y" * 5000,
        )
        result = {"id": "obs-2", "status": 200}
        strict = _summarise_step(0, action, result, body_excerpt_chars=240)
        free = _summarise_step(0, action, result, body_excerpt_chars=4096)
        # Strict: at most 240 Y's in the req_body excerpt.
        assert strict.count("Y") <= 240
        # Free: more than 240, up to 4096.
        free_y = free.count("Y")
        assert 240 < free_y <= 4096


class TestAgentLoopDefaultMode:
    """``AgentLoop.mode`` defaults to whatever ``mode_from_env()``
    returns — which in turn defaults to ``free``. Operators using the
    default config get the productive position."""

    def test_default_is_free(self) -> None:
        # Construct an AgentLoop with stub deps; mode should default
        # to free (assuming MODUS_MODE isn't set in the test env).
        # Set env explicitly to avoid leaking host config into the test.
        import os

        from modus.consistency import ConsistencyChecker
        from modus.proposer import FixedProposer
        from modus.scope import ScopePolicy
        from modus.session import ServerSession

        # Force unset to avoid host-env leakage.
        prior = os.environ.pop("MODUS_MODE", None)
        try:
            from modus.agent import AgentLoop

            scope = ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"t.example.com"}),
                allowed_methods=frozenset({"GET"}),
            )
            session = ServerSession(scope=scope, llm=None)

            async def _execute(action):
                return {}

            loop = AgentLoop(
                proposer=FixedProposer([]),
                checker=ConsistencyChecker(),
                session=session,
                execute_action=_execute,
            )
            assert loop.mode == "free"
        finally:
            if prior is not None:
                os.environ["MODUS_MODE"] = prior

    def test_strict_via_env(self) -> None:
        import os

        from modus.consistency import ConsistencyChecker
        from modus.proposer import FixedProposer
        from modus.scope import ScopePolicy
        from modus.session import ServerSession

        prior = os.environ.get("MODUS_MODE")
        os.environ["MODUS_MODE"] = "strict"
        try:
            from modus.agent import AgentLoop

            scope = ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"t.example.com"}),
                allowed_methods=frozenset({"GET"}),
            )
            session = ServerSession(scope=scope, llm=None)

            async def _execute(action):
                return {}

            loop = AgentLoop(
                proposer=FixedProposer([]),
                checker=ConsistencyChecker(),
                session=session,
                execute_action=_execute,
            )
            assert loop.mode == "strict"
        finally:
            if prior is None:
                os.environ.pop("MODUS_MODE", None)
            else:
                os.environ["MODUS_MODE"] = prior
