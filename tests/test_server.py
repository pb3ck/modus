"""Contract tests for the Modus MCP server.

These tests drive :class:`ModusServer` through its tool-dispatch
path without standing up an actual MCP transport. The server's
public surface — tool listing, tool dispatch, consistency gating,
session-state mutation — is exercised against a stubbed
``CorpusClient`` and a recording HTTP transport.

Integration tests against a real ``modus mcp`` subprocess are out
of scope here; the M3 smoke test (in CONTRIBUTING) covers the
stdio handshake side.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
    from pathlib import Path

from modus.consistency import ConsistencyChecker
from modus.corpus import (
    Candidate,
    CorpusStatus,
    SearchHit,
    StubCorpusClient,
    TargetSummary,
)
from modus.executor import HttpExecutor
from modus.scope import ScopePolicy
from modus.server import ModusServer, _build_tool_list
from modus.session import LlmProviderConfig, ServerSession

# ----------------------------------------------------------- helpers


class _FixedCorpusClient(StubCorpusClient):
    """StubCorpusClient with overridable per-method responses for tests."""

    def __init__(self, **overrides: Any) -> None:
        super().__init__(
            status_payload=CorpusStatus(
                schema_version=9,
                current_target="demo",
                targets=1,
                assets=2,
                runs=0,
                artifacts=0,
                evidence=0,
                findings=0,
                sessions=0,
                last_run_started_at=None,
            ),
            targets=[TargetSummary(id="t-1", name="demo", kind="lab", is_current=True)],
        )
        self._overrides = overrides

    async def search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 10,
        full: bool = False,
    ) -> list[SearchHit]:
        if "search" in self._overrides:
            return list(self._overrides["search"])
        return [
            SearchHit(
                kind="evidence",
                target_id="t-1",
                snippet=f"matched {query!r}",
                full_text_len=42,
                truncated=False,
            )
        ]

    async def list_assets(
        self,
        *,
        target: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        return list(
            self._overrides.get(
                "list_assets",
                [{"name": "target.example.com", "status": 200}],
            )
        )

    async def analyze_regression(self, *, target: str | None = None) -> list[Candidate]:
        return list(
            self._overrides.get(
                "analyze_regression",
                [
                    Candidate(
                        id="cand-1",
                        target_id="t-1",
                        module="regression",
                        key="https://target.example.com",
                        score=0.7,
                        rationale="status flip",
                        evidence_refs=("ev-1", "ev-2"),
                        was_new=True,
                    )
                ],
            )
        )


def _scope() -> ScopePolicy:
    return ScopePolicy(
        target_name="demo",
        allowed_assets=frozenset({"target.example.com", "admin.example.com"}),
        allowed_methods=frozenset({"GET", "HEAD"}),
    )


def _server_with(
    *,
    quarry: _FixedCorpusClient | None = None,
    transport: httpx.MockTransport | None = None,
    llm: LlmProviderConfig | None = None,
) -> tuple[ModusServer, ServerSession]:
    session = ServerSession(scope=_scope(), llm=llm)
    if quarry is not None:
        # Override the per-call context manager to yield the fake.
        from contextlib import asynccontextmanager

        injected = quarry

        @asynccontextmanager
        async def _yield_fake():  # type: ignore[no-untyped-def]
            yield injected

        session.with_quarry = _yield_fake  # type: ignore[method-assign]
    executor = HttpExecutor()
    if transport is not None:
        executor._client = httpx.AsyncClient(transport=transport)
    from modus.tool_executor import ToolExecutor

    server = ModusServer(
        session=session,
        executor=executor,
        checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
        tool_executor=ToolExecutor(session=session, scope=session.scope),
    )
    return server, session


# ----------------------------------------------------------- tool list


class TestToolList:
    def test_lists_every_action_tool(self) -> None:
        names = {tool.name for tool in _build_tool_list()}
        for required in (
            "probe",
            "request",
            "compare",
            "differential",
            "annotate",
            "hypothesize",
        ):
            assert required in names

    def test_lists_quarry_passthroughs(self) -> None:
        names = {tool.name for tool in _build_tool_list()}
        for required in (
            "corpus_status",
            "list_targets",
            "search",
            "list_assets",
            "diff",
            "coverage",
            "recall",
            "analyze_regression",
            "analyze_jsdelta",
            "analyze_interesting",
        ):
            assert required in names

    def test_lists_autonomous_tools_unconditionally(self) -> None:
        # ADR-0003: autonomous-session tools are always present in the tool
        # surface; missing LLM config surfaces as a per-call error.
        names = {tool.name for tool in _build_tool_list()}
        assert "run_autonomous_session" in names
        assert "propose_actions" in names

    def test_action_tool_input_schemas_are_objects(self) -> None:
        for tool in _build_tool_list():
            assert tool.inputSchema["type"] == "object"


# ----------------------------------------------------------- verified actions


class TestProbeTool:
    async def test_in_scope_target_returns_assets(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch("probe", {"target": "target.example.com"})
        assert result["verdict"]["accepted"] is True
        assert result["result"]["aspect"] == "httpx"

    async def test_out_of_scope_target_rejected_with_failed_precond(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch("probe", {"target": "evil.example.com"})
        assert result["verdict"]["accepted"] is False
        assert any(
            name.startswith("target_in_scope:")
            for name in result["verdict"]["failed_preconditions"]
        )


class TestRequestTool:
    async def test_in_scope_request_executes_and_persists(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"X-Y": "z"}, text='{"ok": true}')

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            transport=httpx.MockTransport(handler),
        )
        result = await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/health"},
        )
        assert result["verdict"]["accepted"] is True
        assert result["result"]["status"] == 200
        assert len(session.observations) == 1

    async def test_follows_same_origin_redirect_to_trailing_slash(self) -> None:
        # Common Next.js / FastAPI behaviour: GET /path → 308 → /path/.
        # The executor should follow the redirect within the same
        # origin and surface the chain on the observation.
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/Users":
                return httpx.Response(308, headers={"location": "/api/Users/"})
            if request.url.path == "/api/Users/":
                return httpx.Response(200, text='{"ok": true}')
            return httpx.Response(404)

        server, _session = _server_with(
            quarry=_FixedCorpusClient(), transport=httpx.MockTransport(handler)
        )
        result = await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/api/Users"},
        )
        assert result["verdict"]["accepted"] is True
        assert result["result"]["status"] == 200
        assert result["result"]["redirect_chain"] == ["https://target.example.com/api/Users/"]
        assert "/api/Users/" in result["result"]["url"]

    async def test_does_not_follow_cross_origin_redirect(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "target.example.com":
                return httpx.Response(302, headers={"location": "https://evil.example.com/"})
            # Should never reach here — but if we do, surface it as 200
            # so the test fails on assertion rather than timeout.
            return httpx.Response(200, text="WAS FOLLOWED — BAD")

        server, _session = _server_with(
            quarry=_FixedCorpusClient(), transport=httpx.MockTransport(handler)
        )
        result = await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/"},
        )
        assert result["result"]["status"] == 302
        assert result["result"]["redirect_chain"] == []
        # Cross-origin Location is preserved in the response headers
        # so the agent can decide what to do with it.
        assert result["result"]["response_headers"]["location"] == "https://evil.example.com/"

    async def test_plaintext_http_with_port_targets_correct_url(self) -> None:
        seen_urls: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(200, text="ok")

        server, _session = _server_with(
            quarry=_FixedCorpusClient(),
            transport=httpx.MockTransport(handler),
        )
        result = await server._dispatch(
            "request",
            {
                "target": "target.example.com",
                "method": "GET",
                "path": "/api",
                "port": 13000,
                "tls": False,
            },
        )
        assert result["verdict"]["accepted"] is True
        assert seen_urls == ["http://target.example.com:13000/api"]

    async def test_user_agent_comes_from_scope_policy(self) -> None:
        seen_user_agent: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_user_agent.append(request.headers.get("user-agent", ""))
            return httpx.Response(200, text="ok")

        # Use a custom scope with a non-default user_agent
        scope = ScopePolicy(
            target_name="acme-bbp",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            user_agent="ResearcherX/Modus (acme-bbp)",
        )
        session = ServerSession(scope=scope, llm=None)
        executor = HttpExecutor(user_agent=session.scope.user_agent)
        executor._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={"User-Agent": session.scope.user_agent},
        )
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=executor,
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/"},
        )
        assert seen_user_agent == ["ResearcherX/Modus (acme-bbp)"]

    async def test_action_headers_override_scope_user_agent(self) -> None:
        seen_user_agent: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_user_agent.append(request.headers.get("user-agent", ""))
            return httpx.Response(200, text="ok")

        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            user_agent="Default/Modus",
        )
        session = ServerSession(scope=scope, llm=None)
        executor = HttpExecutor(user_agent=session.scope.user_agent)
        executor._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={"User-Agent": session.scope.user_agent},
        )
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=executor,
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        await server._dispatch(
            "request",
            {
                "target": "target.example.com",
                "method": "GET",
                "path": "/",
                "headers": {"User-Agent": "OverrideUA/1.0"},
            },
        )
        assert seen_user_agent == ["OverrideUA/1.0"]

    async def test_disallowed_method_rejected(self) -> None:
        server, session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "DELETE", "path": "/admin"},
        )
        assert result["verdict"]["accepted"] is False
        assert "method_allowed:DELETE" in result["verdict"]["failed_preconditions"]
        assert session.observations == []

    async def test_default_headers_from_scope_appear_on_outbound_request(self) -> None:
        # The motivating case: HackerOne programs require
        # ``X-HackerOne-Research: <username>`` on every probe.
        # Pinning it in scope means the agent cannot omit it.
        seen_headers: list[dict[str, str]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_headers.append(dict(request.headers))
            return httpx.Response(200, text="ok")

        scope = ScopePolicy(
            target_name="anduril",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            default_headers={"X-HackerOne-Research": "pb3ck"},
        )
        session = ServerSession(scope=scope, llm=None)
        executor = HttpExecutor(
            user_agent=session.scope.user_agent,
            extra_default_headers=dict(session.scope.default_headers),
        )
        executor._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": session.scope.user_agent,
                **session.scope.default_headers,
            },
        )
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=executor,
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/"},
        )
        assert len(seen_headers) == 1
        # httpx normalises header names to lowercase on the request.
        assert seen_headers[0].get("x-hackerone-research") == "pb3ck"

    async def test_observation_request_headers_capture_merged_set(self) -> None:
        # Bug A regression (2026-05-08 Anduril tool-validation run):
        # the audit record's ``request_headers`` only captured the
        # per-request action.headers slice, not the merged set
        # actually sent on the wire. For bug-bounty programs that
        # require an identifying header on every probe, this means
        # the audit can't substantiate compliance even when the
        # header IS being sent. The fix uses ``build_request`` to
        # capture the merged headers; this test pins it.
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok")

        scope = ScopePolicy(
            target_name="anduril-like",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            user_agent="Modus/test (HackerOne:tester)",
            default_headers={"X-HackerOne-Research": "tester"},
        )
        session = ServerSession(scope=scope, llm=None)
        executor = HttpExecutor(
            user_agent=session.scope.user_agent,
            extra_default_headers=dict(session.scope.default_headers),
        )
        executor._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": session.scope.user_agent,
                **session.scope.default_headers,
            },
        )
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=executor,
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/"},
        )
        # The session pool now has one observation; its
        # request_headers should reflect the wire-level merged set,
        # not just the (empty) per-request action.headers.
        assert len(session.observations) == 1
        captured = session.observations[0].payload.get("request_headers", {})
        # Names are case-insensitive; httpx normalises to lowercase.
        lower = {k.lower(): v for k, v in captured.items()}
        assert lower.get("x-hackerone-research") == "tester", (
            f"H1 research header missing from audit; captured headers: {captured}"
        )
        assert lower.get("user-agent") == "Modus/test (HackerOne:tester)"

    async def test_action_header_overrides_scope_default_header(self) -> None:
        # Per-request headers from the action take precedence over
        # the scope default, matching the user_agent precedence
        # documented in :class:`ScopePolicy`.
        seen_headers: list[dict[str, str]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen_headers.append(dict(request.headers))
            return httpx.Response(200, text="ok")

        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET"}),
            default_headers={"X-Trace": "scope-default"},
        )
        session = ServerSession(scope=scope, llm=None)
        executor = HttpExecutor(
            user_agent=session.scope.user_agent,
            extra_default_headers=dict(session.scope.default_headers),
        )
        executor._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={
                "User-Agent": session.scope.user_agent,
                **session.scope.default_headers,
            },
        )
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=executor,
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        await server._dispatch(
            "request",
            {
                "target": "target.example.com",
                "method": "GET",
                "path": "/",
                "headers": {"X-Trace": "per-request-override"},
            },
        )
        assert len(seen_headers) == 1
        assert seen_headers[0].get("x-trace") == "per-request-override"


class TestHypothesizeTool:
    async def test_accepted_hypothesis_appended_to_session(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text='{"data": "leak"}')

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            transport=httpx.MockTransport(handler),
        )
        # Establish an observation the hypothesis can reference
        await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/me"},
        )
        observation_id = session.observations[0].id

        result = await server._dispatch(
            "hypothesize",
            {
                "bug_class": "idor",
                "evidence_refs": [observation_id],
                "rationale": "200 with another tenant's data",
                "severity_hint": "high",
            },
        )
        assert result["verdict"]["accepted"] is True
        assert len(session.candidates) == 1
        assert session.candidates[0].bug_class == "idor"
        # The action result now exposes candidate_id (from Quarry's
        # candidate_create) and severity_hint so the agent loop can
        # populate run_candidates and the proposer's auto-promotion
        # rule can reference them on the next step.
        action_result = result["result"]
        assert action_result["bug_class"] == "idor"
        assert action_result["severity_hint"] == "high"
        # The stub deterministically produces a candidate_id from
        # (module, key); key is the dedup hash from the action.
        assert action_result["candidate_id"] is not None
        assert action_result["candidate_id"].startswith("candidate-agent_hypothesize-idor:")
        # No persistence_error on the happy path.
        assert "persistence_error" not in action_result


class TestCompareTool:
    async def test_unknown_observation_rejected(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch(
            "compare",
            {
                "observation_a": "obs-missing-1",
                "observation_b": "obs-missing-2",
                "dimensions": ["status"],
            },
        )
        assert result["verdict"]["accepted"] is False

    async def test_dimensions_resolve_to_observation_payload_fields(self) -> None:
        # Compare uses dimension aliases — body/headers/status — and should
        # find the values inside the request observation's actual schema
        # (response_body, response_headers, status).
        async def handler(request: httpx.Request) -> httpx.Response:
            user = request.url.params.get("user_id", "?")
            return httpx.Response(
                200,
                headers={"x-user": user},
                text=f'{{"user_id": "{user}"}}',
            )

        server, session = _server_with(
            quarry=_FixedCorpusClient(), transport=httpx.MockTransport(handler)
        )
        # Seed two observations of the same path with different user ids.
        await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/get?user_id=1"},
        )
        await server._dispatch(
            "request",
            {"target": "target.example.com", "method": "GET", "path": "/get?user_id=2"},
        )
        obs_a, obs_b = session.observations[0].id, session.observations[1].id
        result = await server._dispatch(
            "compare",
            {
                "observation_a": obs_a,
                "observation_b": obs_b,
                "dimensions": ["body", "status", "headers"],
            },
        )
        assert result["verdict"]["accepted"] is True
        diffs = result["result"]["diffs"]
        # Body actually populated (was None before the fix)
        assert diffs["body"]["a"] == '{"user_id": "1"}'
        assert diffs["body"]["b"] == '{"user_id": "2"}'
        assert diffs["body"]["differs"] is True
        # Status is identical between the two requests
        assert diffs["status"]["differs"] is False
        # any_differs aggregate captures the body difference
        assert result["result"]["any_differs"] is True


# ----------------------------------------------------------- quarry passthroughs


class TestQuarryPassthroughs:
    async def test_corpus_status_returns_pinned_fields(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch("corpus_status", {})
        assert result["schema_version"] == 9
        assert result["current_target"] == "demo"

    async def test_list_targets_returns_dict_payload(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch("list_targets", {})
        assert result["targets"][0]["name"] == "demo"

    async def test_search_passes_through_args(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch("search", {"query": "admin"})
        assert "matched 'admin'" in result["hits"][0]["snippet"]

    async def test_analyze_regression_passes_through_candidates(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient())
        result = await server._dispatch("analyze_regression", {})
        assert result["count"] == 1
        assert result["candidates"][0]["module"] == "regression"


# ----------------------------------------------------------- autonomous tools


class TestAutonomousToolGate:
    async def test_run_autonomous_session_errors_when_no_llm(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient(), llm=None)
        result = await server._dispatch(
            "run_autonomous_session",
            {"target": "demo", "bug_classes": ["idor"]},
        )
        assert "error" in result
        assert "MODUS_LLM_PROVIDER" in result["missing"]

    async def test_run_autonomous_session_invokes_loop_when_llm_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, _session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        # Replace make_proposer in the server module with a stub that
        # returns a deterministic FixedProposer — avoids touching the
        # real anthropic client.
        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        result = await server._dispatch(
            "run_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["idor"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
            },
        )
        assert "session" in result
        assert result["session"]["target_name"] == "demo"
        assert result["session"]["step_count"] == 1
        assert result["session"]["executed_count"] == 1

    async def test_run_autonomous_session_fails_fast_when_corpus_unreachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Quarry is the corpus dependency — an autonomous session
        must refuse to start if the corpus isn't reachable, rather
        than silently degrading to per-callsite ``persistence_error``
        rows in the result JSON.
        """
        from contextlib import asynccontextmanager

        from modus.corpus import CorpusUnavailableError

        server, session = _server_with(
            quarry=None,  # no fake — we install a raising one below
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        @asynccontextmanager
        async def _raising_quarry():  # type: ignore[no-untyped-def]
            raise CorpusUnavailableError("no corpus at /tmp/missing — run `quarry init` first")
            yield  # pragma: no cover — unreachable

        session.with_quarry = _raising_quarry  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match=r"quarry init"):
            await server._dispatch(
                "run_autonomous_session",
                {
                    "target": "demo",
                    "bug_classes": ["idor"],
                    "budget": {"max_steps": 1, "max_wall_seconds": 5},
                },
            )

    async def test_start_autonomous_session_fails_fast_when_corpus_unreachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from contextlib import asynccontextmanager

        from modus.corpus import CorpusUnavailableError

        server, session = _server_with(
            quarry=None,
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        @asynccontextmanager
        async def _raising_quarry():  # type: ignore[no-untyped-def]
            raise CorpusUnavailableError("no corpus at /tmp/missing — run `quarry init` first")
            yield  # pragma: no cover — unreachable

        session.with_quarry = _raising_quarry  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match=r"quarry init"):
            await server._dispatch(
                "start_autonomous_session",
                {
                    "target": "demo",
                    "bug_classes": ["idor"],
                    "budget": {"max_steps": 1, "max_wall_seconds": 5},
                },
            )
        # No async session should have been registered on the
        # failed-fast path.
        assert session.async_sessions == {}

    async def test_propose_actions_returns_pruned_proposals(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, _session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer(
                [
                    Probe(target="target.example.com"),
                    Probe(target="evil.example.com"),
                ]
            )

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        result = await server._dispatch(
            "propose_actions", {"context": "find IDOR", "sample_count": 4}
        )
        assert "proposals" in result
        proposals = result["proposals"]
        assert len(proposals) == 2
        accepted = [p for p in proposals if p["accepted"]]
        rejected = [p for p in proposals if not p["accepted"]]
        assert len(accepted) == 1
        assert len(rejected) == 1

    async def test_propose_actions_errors_when_no_llm(self) -> None:
        server, _session = _server_with(quarry=_FixedCorpusClient(), llm=None)
        result = await server._dispatch("propose_actions", {"context": "anything"})
        assert "error" in result


class TestFindingsPromotedHelper:
    """``_extract_promoted_findings`` pulls auto-promoted Findings
    out of the SessionRecord's tool steps so the autonomous-session
    result payload can surface them without a Quarry round-trip."""

    def test_extracts_finding_from_corpus_promote_finding_step(self) -> None:
        from datetime import UTC
        from datetime import datetime as _dt

        from modus.actions import Tool
        from modus.agent import SessionRecord, StepRecord
        from modus.consistency import Verdict
        from modus.server import _extract_promoted_findings

        promote = Tool(
            name="corpus.promote_finding",
            args={"candidate_id": "cand-1", "severity": "high"},
        )
        record = SessionRecord(
            target_name="demo",
            bug_classes=("idor",),
            started_at=_dt.now(UTC),
            steps=[
                StepRecord(
                    step_index=0,
                    started_at=_dt.now(UTC),
                    proposals=(promote,),
                    verdicts=(Verdict(accepted=True, rationale="ok"),),
                    executed=(promote,),
                    execution_results=(
                        {
                            "observation_id": "tool-1",
                            "tool_name": "corpus.promote_finding",
                            "builtin_result": {
                                "finding_id": "fid-1",
                                "candidate_id": "cand-1",
                                "severity": "high",
                                "title": "/admin/users unauth",
                                "status": "hypothesis",
                            },
                        },
                    ),
                ),
            ],
        )
        out = _extract_promoted_findings(record)
        assert len(out) == 1
        assert out[0]["finding_id"] == "fid-1"
        assert out[0]["severity"] == "high"

    def test_returns_empty_list_when_no_promotions(self) -> None:
        from datetime import UTC
        from datetime import datetime as _dt

        from modus.actions import Probe
        from modus.agent import SessionRecord, StepRecord
        from modus.consistency import Verdict
        from modus.server import _extract_promoted_findings

        probe = Probe(target="target.example.com")
        record = SessionRecord(
            target_name="demo",
            bug_classes=(),
            started_at=_dt.now(UTC),
            steps=[
                StepRecord(
                    step_index=0,
                    started_at=_dt.now(UTC),
                    proposals=(probe,),
                    verdicts=(Verdict(accepted=True, rationale="ok"),),
                    executed=(probe,),
                    execution_results=({"aspect": "endpoints", "hits": []},),
                ),
            ],
        )
        assert _extract_promoted_findings(record) == []

    def test_skips_non_promote_tool_calls(self) -> None:
        from datetime import UTC
        from datetime import datetime as _dt

        from modus.actions import Tool
        from modus.agent import SessionRecord, StepRecord
        from modus.consistency import Verdict
        from modus.server import _extract_promoted_findings

        # A different Tool action — not corpus.promote_finding.
        amass = Tool(name="amass.enum", args={"domain": "target.example.com"})
        record = SessionRecord(
            target_name="demo",
            bug_classes=(),
            started_at=_dt.now(UTC),
            steps=[
                StepRecord(
                    step_index=0,
                    started_at=_dt.now(UTC),
                    proposals=(amass,),
                    verdicts=(Verdict(accepted=True, rationale="ok"),),
                    executed=(amass,),
                    execution_results=(
                        {
                            "observation_id": "tool-1",
                            "tool_name": "amass.enum",
                            "shell_result": {"stdout": "..."},
                        },
                    ),
                ),
            ],
        )
        # No corpus.promote_finding step, so no findings extracted.
        assert _extract_promoted_findings(record) == []


class TestReconJsonlSeeding:
    """The autonomous-session MCP tools accept a ``recon_jsonl_path``
    argument that materializes a `responses`-shape JSONL into the
    run's starting evidence pool. Lets MCP-host operators drive the
    seeded-corpus flow without a Python driver script.
    """

    async def test_run_autonomous_session_seeds_from_jsonl(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        # Write a 2-record JSONL the way the recon driver does.
        recon = tmp_path / "recon.jsonl"
        recon.write_text(
            json.dumps(
                {
                    "url": "http://target.example.com/api/Feedbacks",
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body": '{"data":[{"UserId":1,"comment":"hi"}]}',
                }
            )
            + "\n"
            + json.dumps(
                {
                    "url": "http://target.example.com/version",
                    "status": 200,
                    "headers": {},
                    "body": '{"version":"1.0.0"}',
                }
            )
            + "\n"
        )

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        result = await server._dispatch(
            "run_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["info_disclosure"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
                "recon_jsonl_path": str(recon),
            },
        )
        assert result["seeded_observation_count"] == 2
        assert "recon_warning" not in result
        # The seeded observations land in session.observations with
        # the synthetic id prefix and are usable as evidence_refs in
        # the same run (the precondition gate is satisfied because
        # they're in the run's pool).
        seeded = [o for o in session.observations if o.id.startswith("http-recon-seed-")]
        assert len(seeded) == 2
        assert seeded[0].payload["status"] == 200
        assert "Feedbacks" in seeded[0].payload["url"]

    async def test_run_autonomous_session_recon_path_missing_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        result = await server._dispatch(
            "run_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["info_disclosure"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
                "recon_jsonl_path": "/nonexistent/path/recon.jsonl",
            },
        )
        # Missing file is non-fatal: surfaces as recon_warning, the
        # run continues with an empty seeded pool.
        assert result["seeded_observation_count"] == 0
        assert "recon_warning" in result
        assert "not a readable file" in result["recon_warning"]
        # No seeded observations.
        assert not [o for o in session.observations if o.id.startswith("http-recon-seed-")]

    async def test_run_autonomous_session_recon_path_skips_malformed_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        recon = tmp_path / "mixed.jsonl"
        recon.write_text(
            json.dumps(
                {
                    "url": "http://target.example.com/version",
                    "status": 200,
                    "headers": {},
                    "body": '{"version":"1.0.0"}',
                }
            )
            + "\n"
            + "this is not json at all\n"
            + "\n"  # blank line
            + json.dumps([1, 2, 3])  # JSON but not an object
            + "\n"
            + json.dumps(
                {
                    "url": "http://target.example.com/api/Users",
                    "status": 401,
                    "headers": {},
                    "body": "unauthorized",
                }
            )
            + "\n"
        )

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        result = await server._dispatch(
            "run_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["info_disclosure"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
                "recon_jsonl_path": str(recon),
            },
        )
        # The two well-formed records are kept; malformed / non-object
        # lines are silently skipped (matching the responses adapter's
        # hygiene).
        assert result["seeded_observation_count"] == 2
        seeded = [o for o in session.observations if o.id.startswith("http-recon-seed-")]
        assert len(seeded) == 2

    async def test_run_autonomous_session_no_recon_path_is_no_op(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=LlmProviderConfig(
                provider="anthropic",
                model=None,
                api_key="sk-ant-fake",
                base_url=None,
            ),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        # No recon_jsonl_path argument — preserves prior behavior.
        result = await server._dispatch(
            "run_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["info_disclosure"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
            },
        )
        assert result["seeded_observation_count"] == 0
        assert "recon_warning" not in result
        assert not [o for o in session.observations if o.id.startswith("http-recon-seed-")]

    def test_input_schema_advertises_recon_jsonl_path(self) -> None:
        from modus.server import _autonomous_session_input_schema

        schema = _autonomous_session_input_schema()
        assert "recon_jsonl_path" in schema["properties"]
        assert schema["properties"]["recon_jsonl_path"]["type"] == "string"
        # Not in `required` — recon_jsonl_path is optional.
        assert "recon_jsonl_path" not in schema["required"]


# ----------------------------------------------------------- llm config


class TestLlmProviderConfig:
    def test_no_provider_returns_none(self) -> None:
        assert LlmProviderConfig.from_env({}) is None

    def test_anthropic_picks_up_anthropic_key(self) -> None:
        cfg = LlmProviderConfig.from_env(
            {"MODUS_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "x"}
        )
        assert cfg is not None
        assert cfg.provider == "anthropic"
        assert cfg.api_key == "x"

    def test_openai_compatible_picks_up_base_url(self) -> None:
        cfg = LlmProviderConfig.from_env(
            {
                "MODUS_LLM_PROVIDER": "openai-compatible",
                "MODUS_LLM_BASE_URL": "http://localhost:11434/v1",
                "MODUS_LLM_MODEL": "llama3",
            }
        )
        assert cfg is not None
        assert cfg.base_url == "http://localhost:11434/v1"
        assert cfg.model == "llama3"

    def test_unknown_provider_rejected(self) -> None:
        with pytest.raises(ValueError):
            LlmProviderConfig.from_env({"MODUS_LLM_PROVIDER": "made-up"})


class TestQuarryLaunchConfig:
    def test_default_is_quarry_mcp(self) -> None:
        from modus.session import QuarryLaunchConfig

        cfg = QuarryLaunchConfig.from_env({})
        assert cfg.command == "quarry"
        assert cfg.args == ("mcp",)

    def test_docker_exec_override(self) -> None:
        from modus.session import QuarryLaunchConfig

        cfg = QuarryLaunchConfig.from_env(
            {
                "MODUS_QUARRY_COMMAND": "docker",
                "MODUS_QUARRY_ARGS": (
                    "exec -i -e QUARRY_HOME=/workspace/.quarry "
                    "exegol-default /root/.cargo/bin/quarry mcp"
                ),
            }
        )
        assert cfg.command == "docker"
        assert cfg.args[0] == "exec"
        assert "/root/.cargo/bin/quarry" in cfg.args
        assert cfg.args[-1] == "mcp"

    def test_explicit_empty_args_when_command_overridden(self) -> None:
        from modus.session import QuarryLaunchConfig

        cfg = QuarryLaunchConfig.from_env({"MODUS_QUARRY_COMMAND": "/custom/quarry-launcher.sh"})
        assert cfg.command == "/custom/quarry-launcher.sh"
        assert cfg.args == ()

    def test_args_use_shlex_quoting(self) -> None:
        from modus.session import QuarryLaunchConfig

        cfg = QuarryLaunchConfig.from_env(
            {
                "MODUS_QUARRY_COMMAND": "wrapper",
                "MODUS_QUARRY_ARGS": '--flag "a value with spaces" mcp',
            }
        )
        assert cfg.args == ("--flag", "a value with spaces", "mcp")


class TestProposerWarmup:
    """Coverage for the startup pre-warm of the Modus-side LLM (#3)."""

    async def test_skips_silently_when_llm_unset(self) -> None:
        # No provider configured; warmup must do nothing and return.
        from modus.server import _warm_proposer_model

        session = ServerSession(scope=_scope(), llm=None)
        # Should not raise, should not block. No assertion needed
        # beyond "returns cleanly."
        await _warm_proposer_model(session)

    async def test_skips_for_host_provider(self) -> None:
        # Host-sampling proposers call back into the MCP host's LLM;
        # we can't pre-warm something we don't own. Must skip.
        from modus.server import _warm_proposer_model

        session = ServerSession(
            scope=_scope(),
            llm=LlmProviderConfig(
                provider="host",
                model=None,
                api_key=None,
                base_url=None,
            ),
        )
        await _warm_proposer_model(session)

    async def test_provider_failure_is_swallowed(self) -> None:
        # Point at an unreachable base_url. The openai-compatible
        # client will fail to connect; warmup must catch and log,
        # never propagate. Server startup cannot be brittle on
        # warmup failure.
        from modus.server import _warm_proposer_model

        session = ServerSession(
            scope=_scope(),
            llm=LlmProviderConfig(
                provider="openai-compatible",
                model="fake-model",
                api_key="fake",
                # Port 1 is reserved/unavailable on every reasonable
                # system — guaranteed connection refused.
                base_url="http://127.0.0.1:1/v1",
            ),
        )
        await _warm_proposer_model(session)  # must not raise


class TestToolDispatchThroughVerifiedSurface:
    """End-to-end: ``tool`` MCP tool dispatches via the registry,
    persists a ToolObservation into the session pool, and returns
    a payload the host's LLM can read.
    """

    async def test_shell_tool_via_dispatch(self, tmp_path: Path) -> None:
        # Register a deterministic shell tool that just echoes a
        # message, then dispatch it via the ``tool`` MCP surface.
        # /bin/echo is POSIX-portable.
        scope_data = {
            "target_name": "demo",
            "allowed_assets": ["target.example.com"],
            "tools": [
                {
                    "kind": "shell",
                    "name": "test.echo",
                    "description": "echo a message for tests",
                    "args_schema": {
                        "type": "object",
                        "properties": {"msg": {"type": "string"}},
                        "required": ["msg"],
                        "additionalProperties": False,
                    },
                    "side_effect": "read",
                    "argv_template": ["/bin/echo", "{msg}"],
                    "timeout_seconds": 5.0,
                },
            ],
        }
        scope_path = tmp_path / "scope.json"
        scope_path.write_text(json.dumps(scope_data))
        session = ServerSession.from_scope_file(scope_path)
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=HttpExecutor(),
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        result = await server._dispatch(
            "tool",
            {"name": "test.echo", "args": {"msg": "wire-up confirmed"}},
        )
        # Verdict accepted (registered, args valid, no preconditions).
        assert result.get("action") == "tool"
        assert result["verdict"]["accepted"], result["verdict"]
        # Observation persisted into the session pool.
        assert len(session.observations) == 1
        observation = session.observations[0]
        assert observation.kind == "tool"
        assert observation.payload["tool_name"] == "test.echo"
        assert "wire-up confirmed" in observation.payload["stdout"]
        assert observation.payload["exit_code"] == 0

    async def test_unregistered_tool_rejected_at_consistency(self, tmp_path: Path) -> None:
        scope_path = tmp_path / "scope.json"
        scope_path.write_text(
            json.dumps(
                {
                    "target_name": "demo",
                    "allowed_assets": ["target.example.com"],
                }
            )
        )
        session = ServerSession.from_scope_file(scope_path)
        from modus.tool_executor import ToolExecutor

        server = ModusServer(
            session=session,
            executor=HttpExecutor(),
            checker=ConsistencyChecker(scope=session.scope, registry=session.tool_registry),
            tool_executor=ToolExecutor(session=session, scope=session.scope),
        )
        result = await server._dispatch(
            "tool",
            {"name": "totally-fictional-tool", "args": {}},
        )
        assert result["verdict"]["accepted"] is False
        assert any(
            label.startswith("tool_registered:totally-fictional-tool")
            for label in result["verdict"]["failed_preconditions"]
        )


def _llm_for_async_tests() -> LlmProviderConfig:
    """Anthropic-shaped config so ``_handle_autonomous_tool`` doesn't
    bail on the LLM gate; the actual proposer is monkey-patched in
    the per-test setup so no API call is ever made."""
    return LlmProviderConfig(
        provider="anthropic",
        model=None,
        api_key="sk-ant-fake",
        base_url=None,
    )


class TestAsyncAutonomousSession:
    """Coverage for the start/poll/cancel async-session tools (#1)."""

    async def test_start_returns_session_id_and_registers_handle(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        result = await server._dispatch(
            "start_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["idor"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
            },
        )
        assert "session_id" in result
        assert result["status"] == "running"
        # Registered on the ServerSession.
        assert result["session_id"] in session.async_sessions
        # The session_id is UUID-shaped (lazy check).
        assert len(result["session_id"]) >= 32
        # Drain the background task so the test cleans up cleanly.
        async_session = session.async_sessions[result["session_id"]]
        await async_session.task

    async def test_poll_returns_step_records_and_advances_cursor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )

        # Two distinct probes so the loop's strict-dedup ranker has
        # a non-duplicate survivor each step → two steps execute.
        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer(
                [
                    Probe(target="target.example.com", aspect="httpx"),
                    Probe(target="target.example.com", aspect="endpoints"),
                ]
            )

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        started = await server._dispatch(
            "start_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["idor"],
                "budget": {"max_steps": 2, "max_wall_seconds": 5},
            },
        )
        session_id = started["session_id"]
        # Wait for the loop to finish so the poll snapshot is fully
        # populated. In production the host would poll while the
        # task is still running; both shapes are valid.
        await session.async_sessions[session_id].task

        # First poll: cursor 0, expect both step records.
        first = await server._dispatch(
            "poll_autonomous_session",
            {"session_id": session_id, "since_step": 0},
        )
        assert first["status"] == "completed"
        assert first["step_count"] == 2
        assert len(first["new_steps"]) == 2
        assert [s["step_index"] for s in first["new_steps"]] == [0, 1]
        assert first["next_cursor"] == 2
        assert first["termination_reason"] == "step_budget_exhausted"

        # Second poll with the cursor advanced — no new work.
        second = await server._dispatch(
            "poll_autonomous_session",
            {"session_id": session_id, "since_step": first["next_cursor"]},
        )
        assert second["status"] == "completed"
        assert second["new_steps"] == []

    async def test_poll_unknown_session_id_errors(self) -> None:
        server, _session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )
        result = await server._dispatch(
            "poll_autonomous_session",
            {"session_id": "00000000-not-a-real-session"},
        )
        assert "error" in result
        assert "00000000-not-a-real-session" in result["error"]

    async def test_cancel_terminates_inflight_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        # Proposer that hangs indefinitely so we can deterministically
        # cancel mid-run.
        class _HangingProposer:
            async def propose(self, context: object) -> list[Any]:
                await asyncio.Event().wait()
                return []

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return _HangingProposer()

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        started = await server._dispatch(
            "start_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["idor"],
                "budget": {"max_steps": 100, "max_wall_seconds": 60},
            },
        )
        session_id = started["session_id"]

        # Yield once so the task actually starts running before we
        # cancel; otherwise we'd cancel a not-yet-started task and
        # the status reporter wouldn't have anything to observe.
        await asyncio.sleep(0)
        assert session.async_sessions[session_id].status == "running"

        cancelled = await server._dispatch(
            "cancel_autonomous_session",
            {"session_id": session_id},
        )
        assert cancelled["status"] == "cancelled"
        assert cancelled["termination_reason"] == "cancelled"
        assert cancelled["finished_at"] is not None
        # The task is settled — calling cancel again is a no-op.
        again = await server._dispatch(
            "cancel_autonomous_session",
            {"session_id": session_id},
        )
        assert again["status"] == "cancelled"

    async def test_cancel_on_unknown_id_errors(self) -> None:
        server, _session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )
        result = await server._dispatch(
            "cancel_autonomous_session",
            {"session_id": "bogus"},
        )
        assert "error" in result

    async def test_cancel_on_completed_session_is_noop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modus.actions import Probe
        from modus.proposer import FixedProposer

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return FixedProposer([Probe(target="target.example.com")])

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        started = await server._dispatch(
            "start_autonomous_session",
            {
                "target": "demo",
                "bug_classes": ["idor"],
                "budget": {"max_steps": 1, "max_wall_seconds": 5},
            },
        )
        session_id = started["session_id"]
        # Drain naturally.
        await session.async_sessions[session_id].task
        # Cancelling a finished session should report completed,
        # not transition it to cancelled.
        result = await server._dispatch(
            "cancel_autonomous_session",
            {"session_id": session_id},
        )
        assert result["status"] == "completed"

    async def test_start_errors_when_no_llm_configured(self) -> None:
        # Same gate as run_autonomous_session — start hits the LLM
        # config check before constructing a proposer.
        server, _session = _server_with(quarry=_FixedCorpusClient(), llm=None)
        result = await server._dispatch(
            "start_autonomous_session",
            {"target": "demo", "bug_classes": ["idor"]},
        )
        assert "error" in result
        assert "MODUS_LLM_PROVIDER" in result["missing"]

    async def test_serversession_aexit_cancels_inflight_runs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # On server shutdown (ServerSession.__aexit__), any in-flight
        # async-session tasks must be cancelled and awaited so they
        # don't leak past the server's lifecycle.
        import asyncio

        class _HangingProposer:
            async def propose(self, context: object) -> list[Any]:
                await asyncio.Event().wait()
                return []

        server, session = _server_with(
            quarry=_FixedCorpusClient(),
            llm=_llm_for_async_tests(),
        )

        def _stub_make_proposer(
            *, llm: object, scope: object, mcp_session: object = None, **kwargs: object
        ) -> object:
            return _HangingProposer()

        from modus import server as server_module

        monkeypatch.setattr(server_module, "make_proposer", _stub_make_proposer)

        started = await server._dispatch(
            "start_autonomous_session",
            {"target": "demo", "bug_classes": ["idor"]},
        )
        session_id = started["session_id"]
        await asyncio.sleep(0)
        assert session.async_sessions[session_id].status == "running"

        # Exiting the ServerSession context should cancel the
        # in-flight task. We invoke the dunder directly here since
        # the test built the session without `async with`.
        await session.__aexit__(None, None, None)
        assert session.async_sessions[session_id].status == "cancelled"
