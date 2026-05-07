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

from typing import Any

import httpx
import pytest

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
    server = ModusServer(session=session, executor=executor, checker=ConsistencyChecker())
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
        server = ModusServer(session=session, executor=executor, checker=ConsistencyChecker())
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
        server = ModusServer(session=session, executor=executor, checker=ConsistencyChecker())
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
            },
        )
        assert result["verdict"]["accepted"] is True
        assert len(session.candidates) == 1
        assert session.candidates[0].bug_class == "idor"


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
        def _stub_make_proposer(*, llm: object, scope: object) -> object:
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

        def _stub_make_proposer(*, llm: object, scope: object) -> object:
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
