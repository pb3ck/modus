"""Unit tests for the ``modus.builtins.corpus`` builtin tool callables.

These exercise the builtin's contract: input args → Quarry MCP
call → returned dict shape. The Quarry side is exercised via a
fake MCP session injected into a :class:`QuarryMcpClient`; the
``ServerSession.with_quarry`` context manager is monkeypatched
so the test doesn't spawn a real ``quarry mcp`` subprocess.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest
from mcp.types import CallToolResult, TextContent

from modus.builtins.corpus import promote_finding
from modus.corpus import QuarryMcpClient
from modus.scope import ScopePolicy
from modus.session import ServerSession

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from datetime import timedelta


@dataclass
class _FakeSession:
    """A minimal stand-in for ``mcp.ClientSession`` for the builtin tests."""

    responses: dict[str, CallToolResult] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list, init=False)

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return type("Tools", (), {"tools": []})()

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> CallToolResult:
        self.calls.append((name, dict(arguments or {})))
        if name not in self.responses:
            raise KeyError(f"fake session has no response for {name!r}")
        return self.responses[name]


def _text_result(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        isError=False,
    )


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


def _session_with_fake_quarry(fake: _FakeSession) -> ServerSession:
    scope = ScopePolicy(target_name="demo", allowed_assets=frozenset())
    session = ServerSession(scope=scope, llm=None)

    @asynccontextmanager
    async def fake_with_quarry() -> AsyncIterator[QuarryMcpClient]:
        yield QuarryMcpClient.from_session(fake)

    session.with_quarry = fake_with_quarry  # type: ignore[method-assign]
    return session


class TestPromoteFindingBuiltin:
    async def test_returns_finding_dict(self) -> None:
        fake = _FakeSession(responses={"finding_promote": _text_result(_payload())})
        session = _session_with_fake_quarry(fake)
        scope = session.scope

        result = await promote_finding(
            {"candidate_id": "cand-1", "severity": "high"},
            session,
            scope,
        )
        assert result == {
            "finding_id": "find-1",
            "candidate_id": "cand-1",
            "target_id": "tgt-1",
            "severity": "high",
            "title": "200 → 401 status flip",
            "status": "hypothesis",
            "created_at": "2026-05-07T22:30:00Z",
        }
        assert fake.calls == [("finding_promote", {"candidate_id": "cand-1", "severity": "high"})]

    async def test_passes_explicit_title_through(self) -> None:
        fake = _FakeSession(responses={"finding_promote": _text_result(_payload(title="explicit"))})
        session = _session_with_fake_quarry(fake)

        result = await promote_finding(
            {
                "candidate_id": "cand-1",
                "severity": "medium",
                "title": "explicit",
            },
            session,
            session.scope,
        )
        assert result["title"] == "explicit"
        assert fake.calls[0][1]["title"] == "explicit"

    async def test_omits_title_when_not_supplied(self) -> None:
        fake = _FakeSession(responses={"finding_promote": _text_result(_payload())})
        session = _session_with_fake_quarry(fake)

        await promote_finding(
            {"candidate_id": "cand-1", "severity": "high"},
            session,
            session.scope,
        )
        assert "title" not in fake.calls[0][1]

    async def test_propagates_quarry_error(self) -> None:
        from modus.corpus import CorpusToolError

        fake = _FakeSession(
            responses={
                "finding_promote": CallToolResult(
                    content=[TextContent(type="text", text="candidate already promoted")],
                    isError=True,
                ),
            }
        )
        session = _session_with_fake_quarry(fake)

        with pytest.raises(CorpusToolError):
            await promote_finding(
                {"candidate_id": "cand-1", "severity": "high"},
                session,
                session.scope,
            )
