"""Corpus client — the Modus side of the Quarry contract.

Modus does not own a corpus. Quarry does. This module is the thin
client that drives Quarry's MCP server (``quarry mcp``) over JSON-RPC
on stdio, plus the Pydantic types the rest of Modus uses to receive
results.

The contract this client depends on is documented in
``docs/corpus-interface.md`` and is the load-bearing reason the
client surface stays small. We expose exactly the seven read tools
plus the three analytical tools listed there; we do not wrap CLI
operations (``quarry init``, ``quarry target add``,
``quarry finding promote``) on purpose, because those are operator
actions and Modus is not the operator.

The client itself is a stub at Milestone 0. Milestone 2 in the
roadmap is "Quarry corpus client"; that's where the JSON-RPC
plumbing actually lands. The interface is pinned here now so the
agent loop and the consistency layer can be written against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class CorpusStatus:
    """Result shape for ``status``.

    Mirrors the fields Quarry's ``status`` MCP tool returns. We do
    not duplicate every field; we surface the ones the consistency
    layer and the proposer's cached prefix actually need.
    """

    schema_version: str
    current_target: str | None
    counts: dict[str, int]


@dataclass(frozen=True)
class TargetSummary:
    """One row from ``list_targets``."""

    name: str
    kind: str
    is_current: bool


@dataclass(frozen=True)
class SearchHit:
    """One row from ``search``.

    Quarry returns rich snippet data; we represent it shallowly
    here and let the proposer reach for the full chunk via
    ``full=True`` when it needs to.
    """

    chunk_id: str
    asset: str | None
    snippet: str
    score: float
    truncated: bool


class CorpusClient(Protocol):
    """The protocol the agent loop depends on.

    Implementations:
      * :class:`QuarryMcpClient` — the production client (M2).
      * :class:`StubCorpusClient` — a deterministic in-memory stand-in
        used by tests and the ``modus action validate`` CLI flow.

    Every method is async because the underlying transport (MCP over
    stdio) is async. Synchronous wrappers are deliberately omitted to
    avoid encouraging blocking calls from inside the agent loop.
    """

    async def status(self) -> CorpusStatus: ...

    async def list_targets(self) -> list[TargetSummary]: ...

    async def search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 10,
        full: bool = False,
    ) -> list[SearchHit]: ...

    async def list_assets(
        self,
        *,
        target: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]: ...

    async def diff(self, *, target: str | None = None) -> list[dict[str, Any]]: ...

    async def coverage(self, *, target: str | None = None) -> list[dict[str, Any]]: ...

    async def recall(self, query: str, *, dimension: str) -> list[dict[str, Any]]: ...

    async def analyze_regression(self, *, target: str | None = None) -> list[dict[str, Any]]: ...

    async def analyze_jsdelta(self, *, target: str | None = None) -> list[dict[str, Any]]: ...

    async def analyze_interesting(self, *, target: str | None = None) -> list[dict[str, Any]]: ...


class QuarryMcpClient:
    """Production Quarry MCP client. Stub at Milestone 0.

    Wires ``quarry mcp`` as a subprocess and drives it via JSON-RPC
    over stdio per ``docs/corpus-interface.md``. The actual transport
    code lands at Milestone 2; this class is here so the rest of
    Modus has a name to import.
    """

    def __init__(self, *, command: str = "quarry", args: tuple[str, ...] = ("mcp",)) -> None:
        self._command = command
        self._args = args

    async def status(self) -> CorpusStatus:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def list_targets(self) -> list[TargetSummary]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 10,
        full: bool = False,
    ) -> list[SearchHit]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def list_assets(
        self,
        *,
        target: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def diff(
        self, *, target: str | None = None
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def coverage(
        self, *, target: str | None = None
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def recall(
        self, query: str, *, dimension: str
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def analyze_regression(
        self, *, target: str | None = None
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def analyze_jsdelta(
        self, *, target: str | None = None
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")

    async def analyze_interesting(
        self, *, target: str | None = None
    ) -> list[dict[str, Any]]:  # pragma: no cover - M2
        raise NotImplementedError("QuarryMcpClient lands at Milestone 2")


class StubCorpusClient:
    """Deterministic in-memory client for tests and offline flows.

    The ``modus action validate`` CLI subcommand uses this when no
    Quarry server is reachable: the operator hands Modus a JSON
    state file describing the corpus slice the action runs against,
    and Modus reasons over it.
    """

    def __init__(
        self,
        *,
        targets: list[TargetSummary] | None = None,
        status_payload: CorpusStatus | None = None,
    ) -> None:
        self._targets = targets or []
        self._status = status_payload or CorpusStatus(
            schema_version="stub", current_target=None, counts={}
        )

    async def status(self) -> CorpusStatus:
        return self._status

    async def list_targets(self) -> list[TargetSummary]:
        return list(self._targets)

    async def search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 10,
        full: bool = False,
    ) -> list[SearchHit]:
        return []

    async def list_assets(
        self,
        *,
        target: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        return []

    async def diff(self, *, target: str | None = None) -> list[dict[str, Any]]:
        return []

    async def coverage(self, *, target: str | None = None) -> list[dict[str, Any]]:
        return []

    async def recall(self, query: str, *, dimension: str) -> list[dict[str, Any]]:
        return []

    async def analyze_regression(self, *, target: str | None = None) -> list[dict[str, Any]]:
        return []

    async def analyze_jsdelta(self, *, target: str | None = None) -> list[dict[str, Any]]:
        return []

    async def analyze_interesting(self, *, target: str | None = None) -> list[dict[str, Any]]:
        return []


__all__ = [
    "CorpusClient",
    "CorpusStatus",
    "QuarryMcpClient",
    "SearchHit",
    "StubCorpusClient",
    "TargetSummary",
]
