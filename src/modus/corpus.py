"""Corpus client — the Modus side of the Quarry contract.

Modus does not own a corpus. Quarry does. This module is the thin
client that drives Quarry's MCP server (``quarry mcp``) over JSON-RPC
on stdio, plus the Pydantic types the rest of Modus uses to receive
results.

The contract this client depends on is documented in
``docs/corpus-interface.md``: the seven read tools (``status``,
``list_targets``, ``search``, ``list_assets``, ``diff``, ``coverage``,
``recall``) plus the three analytical tools
(``analyze_regression``, ``analyze_jsdelta``, ``analyze_interesting``).
We deliberately do not wrap CLI operations (``quarry init``,
``quarry target add``, ``quarry finding promote``) because those are
operator actions and Modus is not the operator.

Result types are pinned where Quarry's schema is stable
(``CorpusStatus``, ``TargetSummary``, ``SearchHit``, ``Candidate``)
and left as raw ``dict[str, Any]`` where the schema is in flux per
Quarry's own README (the analytical tools, ``list_assets``,
``recall``, ``coverage``, ``diff``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import TracebackType

    from mcp.types import CallToolResult


_LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------- errors


class CorpusError(Exception):
    """Base class for everything corpus-side that can go wrong.

    Callers that just want "did the corpus work?" can catch
    :class:`CorpusError`. Callers that want to react differently to
    different failure modes catch the specific subclass.
    """


class CorpusUnavailableError(CorpusError):
    """The Quarry MCP server could not be started or contacted."""


class CorpusToolsMissingError(CorpusError):
    """The Quarry server is reachable but is missing required tools.

    This is the schema-mismatch failure mode from
    ``docs/corpus-interface.md``: Modus refuses to run rather than
    silently degrade against a Quarry that doesn't expose what we need.
    """

    def __init__(self, *, missing: Iterable[str], available: Iterable[str]) -> None:
        self.missing = frozenset(missing)
        self.available = frozenset(available)
        super().__init__(
            f"Quarry MCP server is missing required tool(s): "
            f"{sorted(self.missing)}. Available: {sorted(self.available)}."
        )


class CorpusToolError(CorpusError):
    """A tool call returned ``isError = true``."""

    def __init__(self, *, tool: str, message: str) -> None:
        self.tool = tool
        self.message = message
        super().__init__(f"Quarry tool {tool!r} returned an error: {message}")


class CorpusTimeoutError(CorpusError):
    """A tool call exceeded the per-call timeout.

    Per the corpus-interface contract, a timed-out call is treated as
    a non-entailment in the consistency layer rather than retried.
    The agent simply doesn't get to use whatever the timed-out call
    would have provided.
    """

    def __init__(self, *, tool: str, timeout_seconds: float) -> None:
        self.tool = tool
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Quarry tool {tool!r} did not respond within {timeout_seconds}s")


class CorpusSchemaError(CorpusError):
    """A tool call returned a payload Modus can't interpret.

    Raised when ``content`` is empty, when the text isn't JSON, or
    when the JSON is missing a structurally required key.
    """


# --------------------------------------------------------------------- types


@dataclass(frozen=True)
class CorpusStatus:
    """Result shape for ``status``.

    Mirrors Quarry's ``StatusOut``: per-entity row counts at the top
    level (not in a nested ``counts`` dict), plus the schema version
    and the current-target name. The proposer caches this verbatim
    in its prompt prefix, so the field set is intentionally narrow.
    """

    schema_version: int
    current_target: str | None
    targets: int
    assets: int
    runs: int
    artifacts: int
    evidence: int
    findings: int
    sessions: int
    last_run_started_at: str | None


@dataclass(frozen=True)
class TargetSummary:
    """One row from ``list_targets``."""

    id: str
    name: str
    kind: str
    is_current: bool
    notes: str = ""


@dataclass(frozen=True)
class SearchHit:
    """One row from ``search``.

    Quarry returns rich snippet data; we surface the fields the
    proposer reads at decision time. The full chunk is available
    by re-querying with ``full=True``.
    """

    kind: str  # "evidence" | "note"
    target_id: str
    snippet: str
    full_text_len: int
    truncated: bool
    raw: dict[str, Any] = field(default_factory=dict)
    """The full original payload, for fields not pinned above."""


@dataclass(frozen=True)
class Candidate:
    """One row from ``analyze_*``.

    The Candidate row a successful agent action terminates in; per
    the submission-line invariant, Modus writes Candidates and stops.
    Promotion to Finding is Quarry's ``quarry finding promote``,
    run by the operator outside Modus.
    """

    id: str
    target_id: str
    module: str
    key: str
    score: float
    rationale: str
    evidence_refs: tuple[str, ...]
    was_new: bool


# --------------------------------------------------------------------- client


class CorpusClient(Protocol):
    """The protocol the agent loop depends on.

    Every method is async because the underlying MCP transport is
    async. Synchronous wrappers are deliberately omitted to avoid
    encouraging blocking calls from inside the agent loop.

    Implementations:
      * :class:`QuarryMcpClient` — the production client.
      * :class:`StubCorpusClient` — deterministic in-memory stand-in
        used by tests and the ``modus action validate`` CLI flow.
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

    async def diff(self, *, target: str | None = None) -> dict[str, Any]: ...

    async def coverage(self, *, target: str | None = None) -> dict[str, Any]: ...

    async def recall(
        self,
        *,
        value: str | None = None,
        tech: str | None = None,
        webserver: str | None = None,
    ) -> list[dict[str, Any]]: ...

    async def analyze_regression(self, *, target: str | None = None) -> list[Candidate]: ...

    async def analyze_jsdelta(self, *, target: str | None = None) -> list[Candidate]: ...

    async def analyze_interesting(self, *, target: str | None = None) -> list[Candidate]: ...


class _SessionProtocol(Protocol):
    """The slice of :class:`mcp.ClientSession` this module uses.

    Pinned as a Protocol so contract tests can pass a duck-typed
    fake without standing up a real ``ClientSession``.
    """

    async def initialize(self) -> Any: ...

    async def list_tools(self) -> Any: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> CallToolResult: ...


class QuarryMcpClient:
    """Production Quarry MCP client.

    Lifecycle: use as an async context manager. ``__aenter__`` spawns
    ``quarry mcp`` as a subprocess (or attaches to an injected
    session), runs the MCP initialize handshake, and verifies that
    every required tool is exposed. ``__aexit__`` shuts the
    subprocess down cleanly.

    Tests inject a session via :meth:`from_session` to bypass
    subprocess management.
    """

    REQUIRED_TOOLS: ClassVar[frozenset[str]] = frozenset(
        {
            "status",
            "list_targets",
            "search",
            "list_assets",
            "diff",
            "coverage",
            "recall",
            "analyze_regression",
            "analyze_jsdelta",
            "analyze_interesting",
        }
    )

    DEFAULT_CALL_TIMEOUT_SECONDS: ClassVar[float] = 30.0

    def __init__(
        self,
        *,
        command: str = "quarry",
        args: tuple[str, ...] = ("mcp",),
        env: dict[str, str] | None = None,
        call_timeout_seconds: float = DEFAULT_CALL_TIMEOUT_SECONDS,
    ) -> None:
        """Construct a client. ``env=None`` means inherit ``os.environ`` —
        the common case, since Quarry needs ``QUARRY_HOME`` (or ``HOME``,
        if it's falling back to the default ``~/.quarry`` path) to find
        the corpus. Pass an explicit dict to run with a restricted env.
        """
        self._command = command
        self._args = args
        self._env = env
        self._call_timeout = call_timeout_seconds
        self._session: _SessionProtocol | None = None
        self._stack: AsyncExitStack | None = None
        self._owns_session = True

    @classmethod
    def from_session(
        cls,
        session: _SessionProtocol,
        *,
        call_timeout_seconds: float = DEFAULT_CALL_TIMEOUT_SECONDS,
    ) -> QuarryMcpClient:
        """Construct a client against an externally-managed session.

        The caller is responsible for the session's lifecycle —
        ``__aenter__`` will not initialize it and ``__aexit__`` will
        not close it. Used by contract tests that pass a fake.
        """
        instance = cls.__new__(cls)
        instance._command = "<external>"
        instance._args = ()
        instance._env = None
        instance._call_timeout = call_timeout_seconds
        instance._session = session
        instance._stack = None
        instance._owns_session = False
        return instance

    async def __aenter__(self) -> QuarryMcpClient:
        if not self._owns_session:
            return self
        stack = AsyncExitStack()
        try:
            params = StdioServerParameters(
                command=self._command,
                args=list(self._args),
                env=_resolve_env(self._env),
            )
            try:
                read, write = await stack.enter_async_context(stdio_client(params))
            except FileNotFoundError as exc:
                raise CorpusUnavailableError(
                    f"Quarry binary {self._command!r} was not found. "
                    f"Install Quarry or pass --quarry <path>."
                ) from exc
            except OSError as exc:
                raise CorpusUnavailableError(
                    f"Failed to start Quarry MCP server ({self._command!r}): {exc}"
                ) from exc
            try:
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
            except CorpusError:
                raise
            except Exception as exc:
                # Most likely cause: the Quarry subprocess wrote an error to
                # stderr and exited before the MCP handshake completed, e.g.
                # `quarry init` was never run for this corpus directory. The
                # SDK surfaces that as a generic McpError; map it to the
                # corpus-unavailable category so the operator gets a useful
                # message and a meaningful exit code.
                raise CorpusUnavailableError(
                    f"Quarry MCP server {self._command!r} did not complete the "
                    f"initialize handshake: {exc}. Check that the corpus "
                    f"directory is initialised (`quarry init`) and that "
                    f"$QUARRY_HOME points at it."
                ) from exc
            self._session = session
            self._stack = stack
            await self._verify_tools()
        except Exception:
            await stack.aclose()
            self._session = None
            self._stack = None
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        stack = self._stack
        self._stack = None
        if not self._owns_session:
            self._session = None
            return
        self._session = None
        if stack is not None:
            await stack.aclose()

    async def _verify_tools(self) -> None:
        assert self._session is not None
        try:
            response = await self._session.list_tools()
        except Exception as exc:  # broad: SDK may raise its own subtypes
            raise CorpusUnavailableError(
                f"Quarry MCP server did not respond to list_tools: {exc}"
            ) from exc
        available = {tool.name for tool in response.tools}
        missing = self.REQUIRED_TOOLS - available
        if missing:
            raise CorpusToolsMissingError(missing=missing, available=available)

    async def _call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError(
                "QuarryMcpClient must be used inside `async with` (or constructed "
                "via from_session) before calling tools."
            )
        try:
            result = await asyncio.wait_for(
                self._session.call_tool(
                    tool,
                    arguments or {},
                    read_timeout_seconds=timedelta(seconds=self._call_timeout),
                ),
                timeout=self._call_timeout,
            )
        except TimeoutError as exc:
            raise CorpusTimeoutError(tool=tool, timeout_seconds=self._call_timeout) from exc
        if result.isError:
            raise CorpusToolError(tool=tool, message=_first_text_block(result) or "<no message>")
        return _decode_payload(tool, result)

    # --- read tools ---------------------------------------------------

    async def status(self) -> CorpusStatus:
        payload = await self._call("status")
        try:
            return CorpusStatus(
                schema_version=int(payload["schema_version"]),
                current_target=payload.get("current_target"),
                targets=int(payload["targets"]),
                assets=int(payload["assets"]),
                runs=int(payload["runs"]),
                artifacts=int(payload["artifacts"]),
                evidence=int(payload["evidence"]),
                findings=int(payload["findings"]),
                sessions=int(payload["sessions"]),
                last_run_started_at=payload.get("last_run_started_at"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CorpusSchemaError(f"status payload missing required field: {exc}") from exc

    async def list_targets(self) -> list[TargetSummary]:
        payload = await self._call("list_targets")
        targets = payload.get("targets", [])
        if not isinstance(targets, list):
            raise CorpusSchemaError("list_targets payload is not a list")
        out: list[TargetSummary] = []
        for row in targets:
            try:
                out.append(
                    TargetSummary(
                        id=str(row["id"]),
                        name=str(row["name"]),
                        kind=str(row["kind"]),
                        is_current=bool(row.get("current", False)),
                        notes=str(row.get("notes", "")),
                    )
                )
            except KeyError as exc:
                raise CorpusSchemaError(f"list_targets row missing field: {exc}") from exc
        return out

    async def search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 10,
        full: bool = False,
    ) -> list[SearchHit]:
        args: dict[str, Any] = {"query": query, "limit": limit, "full": full}
        if target is not None:
            args["target"] = target
        payload = await self._call("search", args)
        hits = payload.get("hits", [])
        if not isinstance(hits, list):
            raise CorpusSchemaError("search payload missing 'hits' list")
        out: list[SearchHit] = []
        for hit in hits:
            try:
                out.append(
                    SearchHit(
                        kind=str(hit["kind"]),
                        target_id=str(hit["target_id"]),
                        snippet=str(hit["snippet"]),
                        full_text_len=int(hit["full_text_len"]),
                        truncated=bool(hit["truncated"]),
                        raw=dict(hit),
                    )
                )
            except KeyError as exc:
                raise CorpusSchemaError(f"search hit missing field: {exc}") from exc
        return out

    async def list_assets(
        self,
        *,
        target: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        args: dict[str, Any] = dict(filters or {})
        if target is not None:
            args["target"] = target
        payload = await self._call("list_assets", args)
        assets = payload.get("assets", [])
        if not isinstance(assets, list):
            raise CorpusSchemaError("list_assets payload missing 'assets' list")
        return [dict(asset) for asset in assets]

    async def diff(self, *, target: str | None = None) -> dict[str, Any]:
        args: dict[str, Any] = {}
        if target is not None:
            args["target"] = target
        return await self._call("diff", args)

    async def coverage(self, *, target: str | None = None) -> dict[str, Any]:
        args: dict[str, Any] = {}
        if target is not None:
            args["target"] = target
        return await self._call("coverage", args)

    async def recall(
        self,
        *,
        value: str | None = None,
        tech: str | None = None,
        webserver: str | None = None,
    ) -> list[dict[str, Any]]:
        args: dict[str, Any] = {}
        if value is not None:
            args["value"] = value
        if tech is not None:
            args["tech"] = tech
        if webserver is not None:
            args["webserver"] = webserver
        payload = await self._call("recall", args)
        rows = payload.get("rows", [])
        if not isinstance(rows, list):
            raise CorpusSchemaError("recall payload missing 'rows' list")
        return [dict(row) for row in rows]

    # --- analytical tools (write Candidates) --------------------------

    async def analyze_regression(self, *, target: str | None = None) -> list[Candidate]:
        return await self._analyze("analyze_regression", target=target)

    async def analyze_jsdelta(self, *, target: str | None = None) -> list[Candidate]:
        return await self._analyze("analyze_jsdelta", target=target)

    async def analyze_interesting(self, *, target: str | None = None) -> list[Candidate]:
        return await self._analyze("analyze_interesting", target=target)

    async def _analyze(self, tool: str, *, target: str | None) -> list[Candidate]:
        args: dict[str, Any] = {}
        if target is not None:
            args["target"] = target
        payload = await self._call(tool, args)
        candidates = payload.get("candidates", [])
        if not isinstance(candidates, list):
            raise CorpusSchemaError(f"{tool} payload missing 'candidates' list")
        out: list[Candidate] = []
        for row in candidates:
            try:
                out.append(
                    Candidate(
                        id=str(row["id"]),
                        target_id=str(row["target_id"]),
                        module=str(row["module"]),
                        key=str(row["key"]),
                        score=float(row["score"]),
                        rationale=str(row["rationale"]),
                        evidence_refs=tuple(row.get("evidence_refs", [])),
                        was_new=bool(row.get("was_new", False)),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise CorpusSchemaError(f"{tool} candidate row malformed: {exc}") from exc
        return out


# ---------------------------------------------------------- payload helpers


def _first_text_block(result: CallToolResult) -> str | None:
    """Return the first text block's text, or None if none present."""
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            return str(text)
    return None


def _decode_payload(tool: str, result: CallToolResult) -> dict[str, Any]:
    """Pull the JSON payload out of an MCP tool result.

    Quarry emits all tool results as a single text-content block
    containing the serialised JSON; we prefer ``structuredContent``
    when present (newer MCP servers may set it), falling back to the
    text block. Either way the result must decode to a dict.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict) and structured:
        return structured
    text = _first_text_block(result)
    if text is None:
        raise CorpusSchemaError(f"{tool} returned no text content and no structuredContent")
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorpusSchemaError(f"{tool} returned non-JSON text content: {exc}") from exc
    if not isinstance(decoded, dict):
        raise CorpusSchemaError(
            f"{tool} returned JSON of type {type(decoded).__name__}, expected object"
        )
    return decoded


def _resolve_env(env: dict[str, str] | None) -> dict[str, str]:
    """Resolve the env dict the subprocess will see.

    The semantic distinction:

    * ``env=None`` (the default) means *inherit* the parent's environment.
      This is what most callers want — Quarry typically needs ``HOME``,
      ``QUARRY_HOME``, and ``PATH`` to find the corpus and resolve
      transitive binaries. Pinned with explicit ``os.environ.copy()`` so
      the subprocess starts with the parent's view, not the MCP SDK's
      minimal ``get_default_environment()`` set.
    * ``env={}`` (explicit empty dict) means run with no inherited env.
      Sometimes useful to pin reproducibility in tests.
    * ``env={'KEY': 'value', ...}`` (explicit dict with entries) is the
      *exact* env the subprocess sees — no inheritance.
    """
    if env is None:
        return os.environ.copy()
    return dict(env)


# --------------------------------------------------------------------- stub


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
            schema_version=0,
            current_target=None,
            targets=0,
            assets=0,
            runs=0,
            artifacts=0,
            evidence=0,
            findings=0,
            sessions=0,
            last_run_started_at=None,
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

    async def diff(self, *, target: str | None = None) -> dict[str, Any]:
        return {"target": target or "", "added_assets": []}

    async def coverage(self, *, target: str | None = None) -> dict[str, Any]:
        return {
            "target": target or "",
            "discovered": 0,
            "probed": 0,
            "unprobed_count": 0,
            "unprobed": [],
            "truncated": False,
        }

    async def recall(
        self,
        *,
        value: str | None = None,
        tech: str | None = None,
        webserver: str | None = None,
    ) -> list[dict[str, Any]]:
        return []

    async def analyze_regression(self, *, target: str | None = None) -> list[Candidate]:
        return []

    async def analyze_jsdelta(self, *, target: str | None = None) -> list[Candidate]:
        return []

    async def analyze_interesting(self, *, target: str | None = None) -> list[Candidate]:
        return []


__all__ = [
    "Candidate",
    "CorpusClient",
    "CorpusError",
    "CorpusSchemaError",
    "CorpusStatus",
    "CorpusTimeoutError",
    "CorpusToolError",
    "CorpusToolsMissingError",
    "CorpusUnavailableError",
    "QuarryMcpClient",
    "SearchHit",
    "StubCorpusClient",
    "TargetSummary",
]
