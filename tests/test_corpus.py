"""Contract tests for the Quarry MCP client.

These tests run a duck-typed fake session through the same code path
the real ``mcp.ClientSession`` flows through, so they exercise tool
verification, payload parsing, error mapping, and timeout behaviour
without requiring Quarry to be installed.

Integration tests against a real ``quarry mcp`` subprocess live in
``test_corpus_integration.py`` and are gated behind the
``integration`` pytest marker — see ``CONTRIBUTING.md``.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest
from mcp.types import CallToolResult, TextContent

if TYPE_CHECKING:
    from datetime import timedelta

from modus.corpus import (
    Candidate,
    CorpusSchemaError,
    CorpusStatus,
    CorpusTimeoutError,
    CorpusToolError,
    CorpusToolsMissingError,
    Finding,
    QuarryMcpClient,
    StubCorpusClient,
)

# ----------------------------------------------------------- fake session


@dataclass
class _FakeTool:
    name: str


@dataclass
class _FakeListToolsResult:
    tools: list[_FakeTool]


def _all_required_tools() -> list[_FakeTool]:
    return [_FakeTool(name=name) for name in QuarryMcpClient.REQUIRED_TOOLS]


def _text_result(payload: dict[str, Any], *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        isError=is_error,
    )


def _structured_result(payload: dict[str, Any]) -> CallToolResult:
    """Result with structuredContent set — exercises the SDK's modern path."""
    return CallToolResult(
        content=[TextContent(type="text", text="<unused>")],
        structuredContent=payload,
        isError=False,
    )


def _error_result(message: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=message)],
        isError=True,
    )


@dataclass
class _FakeSession:
    tools: list[_FakeTool] = field(default_factory=_all_required_tools)
    responses: dict[str, CallToolResult] = field(default_factory=dict)
    raise_on_initialize: BaseException | None = None
    raise_on_list_tools: BaseException | None = None
    call_delay_seconds: float = 0.0
    initialized: bool = field(default=False, init=False)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list, init=False)

    async def initialize(self) -> None:
        if self.raise_on_initialize is not None:
            raise self.raise_on_initialize
        self.initialized = True

    async def list_tools(self) -> _FakeListToolsResult:
        if self.raise_on_list_tools is not None:
            raise self.raise_on_list_tools
        return _FakeListToolsResult(tools=list(self.tools))

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> CallToolResult:
        self.calls.append((name, dict(arguments or {})))
        if self.call_delay_seconds:
            # Mimic the MCP SDK's per-call timeout: if our delay exceeds
            # the requested ``read_timeout_seconds``, raise TimeoutError
            # the way the SDK does.
            if (
                read_timeout_seconds is not None
                and self.call_delay_seconds > read_timeout_seconds.total_seconds()
            ):
                await asyncio.sleep(read_timeout_seconds.total_seconds())
                raise TimeoutError("fake call_tool exceeded read_timeout_seconds")
            await asyncio.sleep(self.call_delay_seconds)
        if name not in self.responses:
            raise KeyError(f"fake session has no response for {name!r}")
        return self.responses[name]


# ----------------------------------------------------------- fixtures


@pytest.fixture
def quarry_status_payload() -> dict[str, Any]:
    """A representative ``status`` response — matches Quarry's real shape."""
    return {
        "schema_version": 8,
        "current_target": "demo",
        "targets": 3,
        "assets": 42,
        "runs": 7,
        "artifacts": 17,
        "evidence": 119,
        "findings": 2,
        "sessions": 5,
        "last_run_started_at": "2026-05-01T12:00:00Z",
    }


# ----------------------------------------------------------- lifecycle


class TestLifecycle:
    async def test_from_session_does_not_require_aenter_for_calls(
        self, quarry_status_payload: dict[str, Any]
    ) -> None:
        session = _FakeSession(
            responses={"status": _text_result(quarry_status_payload)},
        )
        client = QuarryMcpClient.from_session(session)
        result = await client.status()
        assert result.schema_version == 8
        # initialize is the caller's job when injecting a session
        assert session.initialized is False

    async def test_from_session_aenter_is_a_no_op(
        self, quarry_status_payload: dict[str, Any]
    ) -> None:
        session = _FakeSession(
            responses={"status": _text_result(quarry_status_payload)},
        )
        async with QuarryMcpClient.from_session(session) as client:
            await client.status()
        assert session.initialized is False  # we did not own the session

    async def test_resolve_env_inherits_when_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from modus.corpus import _resolve_env

        monkeypatch.setenv("QUARRY_HOME", "/some/path")
        env = _resolve_env(None)
        assert env["QUARRY_HOME"] == "/some/path"

    async def test_resolve_env_empty_dict_is_explicit_no_inheritance(self) -> None:
        from modus.corpus import _resolve_env

        env = _resolve_env({})
        assert env == {}

    async def test_resolve_env_returns_copy_not_view(self) -> None:
        from modus.corpus import _resolve_env

        original = {"A": "1"}
        env = _resolve_env(original)
        env["A"] = "mutated"
        assert original["A"] == "1"

    async def test_aenter_verifies_required_tools(self) -> None:
        # Dropping a *required* tool fails verification.
        partial = [tool for tool in _all_required_tools() if tool.name != "search"]
        session = _FakeSession(tools=partial)
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusToolsMissingError) as info:
            await client._verify_tools()
        assert "search" in info.value.missing

    async def test_optional_tool_absence_does_not_fail_verification(self) -> None:
        # Dropping an *optional* tool (e.g. coverage) doesn't fail
        # verification — the connection stays up; per-call methods
        # surface the absence on demand.
        partial = [tool for tool in _all_required_tools() if tool.name != "coverage"]
        session = _FakeSession(tools=partial)
        client = QuarryMcpClient.from_session(session)
        # Force-set _available_tools the way real verification would.
        await client._verify_tools()
        assert "coverage" not in client._available_tools

    async def test_call_to_missing_optional_tool_raises_per_call(self) -> None:
        # Once we know the optional tool is absent, a per-call
        # invocation surfaces CorpusToolsMissingError.
        partial = [tool for tool in _all_required_tools() if tool.name != "coverage"]
        session = _FakeSession(tools=partial)
        client = QuarryMcpClient.from_session(session)
        await client._verify_tools()
        with pytest.raises(CorpusToolsMissingError):
            await client.coverage()


class TestStatus:
    async def test_parses_full_payload(self, quarry_status_payload: dict[str, Any]) -> None:
        session = _FakeSession(
            responses={"status": _text_result(quarry_status_payload)},
        )
        client = QuarryMcpClient.from_session(session)
        result = await client.status()
        assert result == CorpusStatus(
            schema_version=8,
            current_target="demo",
            targets=3,
            assets=42,
            runs=7,
            artifacts=17,
            evidence=119,
            findings=2,
            sessions=5,
            last_run_started_at="2026-05-01T12:00:00Z",
        )

    async def test_missing_field_raises_schema_error(self) -> None:
        broken = {"schema_version": 1}  # missing the rest
        session = _FakeSession(responses={"status": _text_result(broken)})
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusSchemaError):
            await client.status()

    async def test_prefers_structured_content_when_present(
        self, quarry_status_payload: dict[str, Any]
    ) -> None:
        session = _FakeSession(
            responses={"status": _structured_result(quarry_status_payload)},
        )
        client = QuarryMcpClient.from_session(session)
        result = await client.status()
        assert result.targets == 3


class TestListTargets:
    async def test_parses_targets_array(self) -> None:
        payload = {
            "targets": [
                {
                    "id": "uuid-a",
                    "name": "demo",
                    "kind": "lab",
                    "notes": "first target",
                    "current": True,
                },
                {
                    "id": "uuid-b",
                    "name": "prod",
                    "kind": "bug-bounty",
                    "notes": "",
                    "current": False,
                },
            ]
        }
        session = _FakeSession(responses={"list_targets": _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        result = await client.list_targets()
        assert [t.name for t in result] == ["demo", "prod"]
        assert result[0].is_current is True
        assert result[1].is_current is False
        assert result[0].kind == "lab"

    async def test_payload_not_a_list_raises(self) -> None:
        session = _FakeSession(
            responses={"list_targets": _text_result({"targets": "nope"})},
        )
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusSchemaError):
            await client.list_targets()


class TestSearch:
    async def test_parses_hits_and_passes_args(self) -> None:
        payload = {
            "hits": [
                {
                    "kind": "evidence",
                    "target_id": "uuid-a",
                    "snippet": "some text",
                    "full_text_len": 1234,
                    "truncated": True,
                    "extra_field": "preserved",
                }
            ],
            "target": "demo",
            "source": None,
            "note": None,
        }
        session = _FakeSession(responses={"search": _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        hits = await client.search("admin", target="demo", limit=5, full=False)
        assert len(hits) == 1
        assert hits[0].snippet == "some text"
        assert hits[0].truncated is True
        assert hits[0].raw["extra_field"] == "preserved"

        # Verify call shape
        name, args = session.calls[0]
        assert name == "search"
        assert args == {"query": "admin", "limit": 5, "full": False, "target": "demo"}

    async def test_no_target_omits_argument(self) -> None:
        session = _FakeSession(responses={"search": _text_result({"hits": []})})
        client = QuarryMcpClient.from_session(session)
        await client.search("admin")
        _, args = session.calls[0]
        assert "target" not in args


class TestAnalyze:
    @pytest.mark.parametrize(
        "tool_method",
        ["analyze_regression", "analyze_jsdelta", "analyze_interesting"],
    )
    async def test_parses_candidates(self, tool_method: str) -> None:
        payload = {
            "module": tool_method.removeprefix("analyze_"),
            "target": "demo",
            "candidates": [
                {
                    "id": "cand-1",
                    "target_id": "uuid-a",
                    "module": tool_method.removeprefix("analyze_"),
                    "key": "https://admin.example.com",
                    "score": 0.7,
                    "rationale": "status 401 → 200",
                    "evidence_refs": ["ev-1", "ev-2"],
                    "created_at": "2026-05-01T12:00:00Z",
                    "was_new": True,
                }
            ],
            "total": 1,
            "truncated": False,
            "new_count": 1,
            "refreshed_count": 0,
        }
        session = _FakeSession(responses={tool_method: _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        result = await getattr(client, tool_method)(target="demo")
        assert len(result) == 1
        cand = result[0]
        assert isinstance(cand, Candidate)
        assert cand.score == pytest.approx(0.7)
        assert cand.evidence_refs == ("ev-1", "ev-2")
        assert cand.was_new is True

    async def test_malformed_candidate_raises(self) -> None:
        payload = {"candidates": [{"id": "x"}]}  # missing required fields
        session = _FakeSession(
            responses={"analyze_regression": _text_result(payload)},
        )
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusSchemaError):
            await client.analyze_regression()


class TestCreateCandidate:
    @staticmethod
    def _payload(
        *,
        candidate_id: str = "cand-1",
        target_id: str = "tgt-1",
        module: str = "agent_hypothesize",
        key: str = "auth_bypass:obs-1,obs-2",
        score: float = 0.85,
        rationale: str = "200 → 200 across identity dimension",
        evidence_refs: list[str] | None = None,
        was_new: bool = True,
        created_at: str = "2026-05-07T22:30:00Z",
    ) -> dict[str, Any]:
        return {
            "candidate_id": candidate_id,
            "target_id": target_id,
            "module": module,
            "key": key,
            "score": score,
            "rationale": rationale,
            "evidence_refs": evidence_refs or [],
            "was_new": was_new,
            "created_at": created_at,
        }

    async def test_returns_candidate_dataclass(self) -> None:
        session = _FakeSession(responses={"candidate_create": _text_result(self._payload())})
        client = QuarryMcpClient.from_session(session)
        result = await client.create_candidate(
            target="alpha",
            module="agent_hypothesize",
            key="auth_bypass:obs-1,obs-2",
            rationale="200 → 200 across identity dimension",
            score=0.85,
        )
        assert isinstance(result, Candidate)
        assert result.id == "cand-1"
        assert result.module == "agent_hypothesize"
        assert result.score == pytest.approx(0.85)
        assert result.was_new is True

    async def test_passes_args_through(self) -> None:
        session = _FakeSession(responses={"candidate_create": _text_result(self._payload())})
        client = QuarryMcpClient.from_session(session)
        await client.create_candidate(
            target="alpha",
            module="agent_hypothesize",
            key="k",
            rationale="r",
            score=0.7,
            evidence_refs=("ev-1", "ev-2"),
        )
        assert session.calls == [
            (
                "candidate_create",
                {
                    "target": "alpha",
                    "module": "agent_hypothesize",
                    "key": "k",
                    "rationale": "r",
                    "score": 0.7,
                    "evidence_refs": ["ev-1", "ev-2"],
                },
            ),
        ]

    async def test_omits_optional_fields_when_unset(self) -> None:
        session = _FakeSession(responses={"candidate_create": _text_result(self._payload())})
        client = QuarryMcpClient.from_session(session)
        await client.create_candidate(
            target="alpha", module="agent_hypothesize", key="k", rationale="r"
        )
        # Score and evidence_refs must NOT appear when omitted —
        # Quarry defaults score to 0.5 and evidence_refs to [] server-side.
        args = session.calls[0][1]
        assert "score" not in args
        assert "evidence_refs" not in args

    async def test_malformed_payload_raises_schema_error(self) -> None:
        broken = self._payload()
        del broken["candidate_id"]
        session = _FakeSession(responses={"candidate_create": _text_result(broken)})
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusSchemaError):
            await client.create_candidate(
                target="alpha", module="agent_hypothesize", key="k", rationale="r"
            )


class TestPromoteFinding:
    @staticmethod
    def _payload(
        *,
        finding_id: str = "find-1",
        candidate_id: str = "cand-1",
        target_id: str = "tgt-1",
        severity: str = "high",
        title: str = "200 → 401 status flip",
        status: str = "hypothesis",
        created_at: str = "2026-05-07T22:30:00Z",
    ) -> dict[str, Any]:
        return {
            "finding_id": finding_id,
            "candidate_id": candidate_id,
            "target_id": target_id,
            "severity": severity,
            "title": title,
            "status": status,
            "created_at": created_at,
        }

    async def test_returns_finding_dataclass(self) -> None:
        session = _FakeSession(responses={"finding_promote": _text_result(self._payload())})
        client = QuarryMcpClient.from_session(session)
        result = await client.promote_finding(candidate_id="cand-1", severity="high")
        assert isinstance(result, Finding)
        assert result.id == "find-1"
        assert result.candidate_id == "cand-1"
        assert result.target_id == "tgt-1"
        assert result.severity == "high"
        assert result.status == "hypothesis"
        assert result.title == "200 → 401 status flip"
        assert result.created_at == "2026-05-07T22:30:00Z"

    async def test_passes_args_through_to_quarry(self) -> None:
        session = _FakeSession(responses={"finding_promote": _text_result(self._payload())})
        client = QuarryMcpClient.from_session(session)
        await client.promote_finding(
            candidate_id="cand-1",
            severity="medium",
            title="explicit title",
        )
        assert session.calls == [
            (
                "finding_promote",
                {
                    "candidate_id": "cand-1",
                    "severity": "medium",
                    "title": "explicit title",
                },
            ),
        ]

    async def test_omits_title_when_not_supplied(self) -> None:
        session = _FakeSession(responses={"finding_promote": _text_result(self._payload())})
        client = QuarryMcpClient.from_session(session)
        await client.promote_finding(candidate_id="cand-1", severity="high")
        # ``title`` must NOT appear in the args — Quarry derives one
        # from the Candidate's rationale when omitted.
        assert "title" not in session.calls[0][1]

    async def test_missing_required_field_raises_schema_error(self) -> None:
        broken = self._payload()
        del broken["finding_id"]
        session = _FakeSession(responses={"finding_promote": _text_result(broken)})
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusSchemaError):
            await client.promote_finding(candidate_id="cand-1", severity="high")

    async def test_quarry_error_surfaces_as_corpus_tool_error(self) -> None:
        session = _FakeSession(
            responses={"finding_promote": _error_result("candidate already promoted")}
        )
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusToolError) as info:
            await client.promote_finding(candidate_id="cand-1", severity="high")
        assert "already promoted" in str(info.value)

    async def test_missing_optional_tool_raises_per_call(self) -> None:
        # Server doesn't expose ``finding_promote`` (older Quarry).
        # Modus connects fine; promotion call surfaces the absence.
        partial = [_FakeTool(name=name) for name in QuarryMcpClient.REQUIRED_TOOLS]
        session = _FakeSession(tools=partial)
        client = QuarryMcpClient.from_session(session)
        # _verify_tools wasn't called via from_session, so populate
        # the available set manually to mimic post-handshake state.
        client._available_tools = frozenset(t.name for t in partial)
        with pytest.raises(CorpusToolsMissingError):
            await client.promote_finding(candidate_id="cand-1", severity="high")


class TestPassthroughTools:
    async def test_diff_returns_payload_verbatim(self) -> None:
        payload = {"target": "demo", "added_assets": [], "note": None}
        session = _FakeSession(responses={"diff": _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        result = await client.diff(target="demo")
        assert result == payload

    async def test_coverage_returns_payload_verbatim(self) -> None:
        payload = {
            "target": "demo",
            "discovered": 100,
            "probed": 80,
            "unprobed_count": 20,
            "unprobed": ["a.example.com"],
            "truncated": False,
        }
        session = _FakeSession(responses={"coverage": _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        result = await client.coverage(target="demo")
        assert result["discovered"] == 100

    async def test_list_assets_returns_assets_list(self) -> None:
        payload = {
            "assets": [{"name": "a.example.com", "status": 200}],
            "target": "demo",
        }
        session = _FakeSession(responses={"list_assets": _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        result = await client.list_assets(target="demo")
        assert result == [{"name": "a.example.com", "status": 200}]

    async def test_recall_returns_rows(self) -> None:
        payload = {"rows": [{"target": "demo", "asset": "a.example.com"}], "filter": "tech"}
        session = _FakeSession(responses={"recall": _text_result(payload)})
        client = QuarryMcpClient.from_session(session)
        result = await client.recall(tech="nginx")
        assert len(result) == 1
        _, args = session.calls[0]
        assert args == {"tech": "nginx"}


class TestErrorMapping:
    async def test_tool_error_maps_to_corpus_tool_error(self) -> None:
        session = _FakeSession(
            responses={"status": _error_result("schema lock contention")},
        )
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusToolError) as info:
            await client.status()
        assert info.value.tool == "status"
        assert "schema lock contention" in str(info.value)

    async def test_timeout_maps_to_corpus_timeout_error(self) -> None:
        session = _FakeSession(
            responses={"status": _text_result({"schema_version": 1})},
            call_delay_seconds=0.5,
        )
        client = QuarryMcpClient.from_session(session, call_timeout_seconds=0.05)
        with pytest.raises(CorpusTimeoutError) as info:
            await client.status()
        assert info.value.tool == "status"

    async def test_non_json_text_maps_to_schema_error(self) -> None:
        bad = CallToolResult(
            content=[TextContent(type="text", text="not json at all")],
            isError=False,
        )
        session = _FakeSession(responses={"status": bad})
        client = QuarryMcpClient.from_session(session)
        with pytest.raises(CorpusSchemaError):
            await client.status()

    async def test_call_before_aenter_raises(self) -> None:
        client = QuarryMcpClient(command="quarry")
        # No `async with` and no from_session — the client has no session
        with pytest.raises(RuntimeError):
            await client.status()


# ----------------------------------------------------------- stub


class TestStubCorpusClient:
    async def test_default_status_is_zeroed(self) -> None:
        stub = StubCorpusClient()
        result = await stub.status()
        assert result.schema_version == 0
        assert result.targets == 0
        assert result.current_target is None

    async def test_targets_round_trip(self) -> None:
        from modus.corpus import TargetSummary

        stub = StubCorpusClient(
            targets=[
                TargetSummary(id="u", name="demo", kind="lab", is_current=True),
            ]
        )
        result = await stub.list_targets()
        assert [t.name for t in result] == ["demo"]

    async def test_promote_finding_returns_deterministic_finding(self) -> None:
        stub = StubCorpusClient()
        result = await stub.promote_finding(candidate_id="cand-9", severity="high")
        assert isinstance(result, Finding)
        assert result.candidate_id == "cand-9"
        assert result.severity == "high"
        assert result.status == "hypothesis"
        assert result.id == "finding-of-cand-9"
        assert "stub finding for cand-9" in result.title

    async def test_promote_finding_honours_explicit_title(self) -> None:
        stub = StubCorpusClient()
        result = await stub.promote_finding(
            candidate_id="cand-9", severity="medium", title="manual title"
        )
        assert result.title == "manual title"

    async def test_create_candidate_returns_deterministic_candidate(self) -> None:
        stub = StubCorpusClient()
        result = await stub.create_candidate(
            target="alpha",
            module="agent_hypothesize",
            key="auth_bypass:obs-1",
            rationale="reasoning here",
            score=0.85,
        )
        assert isinstance(result, Candidate)
        assert result.id == "candidate-agent_hypothesize-auth_bypass:obs-1"
        assert result.module == "agent_hypothesize"
        assert result.score == pytest.approx(0.85)
        assert result.was_new is True
