"""Per-MCP-server session state.

A :class:`ServerSession` holds everything the MCP server needs across
tool calls: the scope policy (loaded once at startup, immutable for
the server's lifetime), the Quarry MCP client (lazily entered),
session-local observations the agent has produced but Quarry hasn't
ingested yet, and the LLM-provider configuration for the
autonomous-session tools.

Session state is process-scoped — one ``modus mcp`` subprocess holds
one :class:`ServerSession`. Restarting the server with a different
scope is the operator's path to working on a different target.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from modus.consistency import CorpusState
from modus.corpus import QuarryMcpClient
from modus.tools import ToolRegistry, build_default_registry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path
    from types import TracebackType
    from typing import Any

    from modus.agent import SessionRecord
    from modus.scope import ScopePolicy


@dataclass(frozen=True)
class QuarryLaunchConfig:
    """How to spawn the Quarry MCP server subprocess.

    Defaults to running ``quarry mcp`` on the host. Operators whose
    Quarry runs inside a container (Exegol, Docker) override via
    ``MODUS_QUARRY_COMMAND`` and ``MODUS_QUARRY_ARGS`` to spawn it
    through ``docker exec`` or any other shim — Modus stays
    transport-agnostic.
    """

    command: str
    args: tuple[str, ...]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> QuarryLaunchConfig:
        env = env if env is not None else dict(os.environ)
        command = env.get("MODUS_QUARRY_COMMAND") or "quarry"
        raw_args = env.get("MODUS_QUARRY_ARGS")
        if raw_args is None:
            args: tuple[str, ...] = ("mcp",) if command == "quarry" else ()
        else:
            args = tuple(shlex.split(raw_args))
        return cls(command=command, args=args)


@dataclass(frozen=True)
class LlmProviderConfig:
    """Resolved configuration for Modus's internal LLM provider.

    Read from the process environment at server start. The autonomous
    -session tools refuse to run without one of these resolved.
    """

    provider: str  # "host" | "anthropic" | "openai" | "openai-compatible"
    model: str | None
    api_key: str | None
    base_url: str | None  # only meaningful for openai-compatible

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LlmProviderConfig | None:
        """Return a resolved config, or None if no provider is set.

        The autonomous-session tools fail the call rather than the
        server start when this returns None — operators who only want
        the verified-action surface shouldn't need to set up an LLM
        provider just to start Modus.

        Provider values:

        * ``host`` — delegate every proposer call to the MCP host's
          LLM via ``sampling/createMessage``. No API key needed.
          Recommended for Claude Desktop / Claude Code operators
          since they're already paying for the host's model and
          sampling routes the agent's traffic through the same
          conversation surface.
        * ``anthropic``, ``openai``, ``openai-compatible`` — direct
          API calls from Modus's process. Requires the matching
          API key in env. Useful when the host doesn't support
          sampling, or when the operator wants Modus's internal
          LLM to be different from the host's.
        """
        env = env if env is not None else dict(os.environ)
        provider = env.get("MODUS_LLM_PROVIDER", "").strip().lower()
        if not provider:
            return None
        valid = {"host", "anthropic", "openai", "openai-compatible"}
        if provider not in valid:
            raise ValueError(f"MODUS_LLM_PROVIDER={provider!r} is not one of {sorted(valid)}")
        return cls(
            provider=provider,
            model=env.get("MODUS_LLM_MODEL") or None,
            api_key=(
                None
                if provider == "host"
                else env.get("ANTHROPIC_API_KEY")
                if provider == "anthropic"
                else env.get("OPENAI_API_KEY")
            ),
            base_url=env.get("MODUS_LLM_BASE_URL") or None,
        )


@dataclass
class SessionObservation:
    """An observation produced during the current session.

    Quarry's MCP surface is read-only at v0.1, so observations Modus
    produces (the request/response pairs from ``Request`` actions,
    the comparison results from ``Compare``, ...) live in this
    in-memory pool until the operator ingests them out of band. The
    consistency layer's :class:`CorpusState` merges this pool with
    Quarry's known-observations set so the agent's `Compare` and
    `Hypothesize` actions can reference what it just produced.
    """

    id: str
    kind: str  # "request" | "compare" | "differential" | "probe"
    payload: dict[str, Any]


@dataclass
class SessionCandidate:
    """A Candidate the agent has authored in this session.

    Per the submission line, Modus does not promote Candidates to
    Findings — there is no ``submit``/``publish``/``post`` action in
    the grammar. The autonomous-session tool returns its accumulated
    Candidates as part of its MCP result; the operator decides what
    to do with them via Quarry's own ``quarry finding promote`` flow.
    A Candidate's ``rationale`` may legitimately recommend the
    operator promote or submit; the act remains the operator's.
    """

    bug_class: str
    evidence_refs: tuple[str, ...]
    rationale: str
    severity_hint: str = "info"


@dataclass
class AsyncSession:
    """An autonomous-session run executing as a background task.

    Created by ``start_autonomous_session``, polled by
    ``poll_autonomous_session``, optionally terminated early by
    ``cancel_autonomous_session``. The agent loop runs as a detached
    asyncio task that mutates :attr:`record` in place; the poll
    handler snapshots the current state and returns the new step
    records and Candidates since the operator's cursor.

    Lives in :attr:`ServerSession.async_sessions` until the server
    shuts down (no GC at v0.1).

    See :issue:`1` for the design context: this exists to escape the
    MCP host's per-tool-call timeout (~60s on Claude Desktop and
    Claude Code), which would otherwise cap the autonomous loop's
    wall budget at one host-handshake worth of work.
    """

    session_id: str
    target_name: str
    bug_classes: tuple[str, ...]
    started_at: datetime
    record: SessionRecord  # mutated in place by AgentLoop.run
    task: asyncio.Task[SessionRecord]
    candidate_start_index: int
    """Cursor into ``ServerSession.candidates`` taken at this run's
    start. Per-run candidates are
    ``session.candidates[candidate_start_index:]`` once the loop
    has had a chance to author them."""
    cancelled: bool = False
    """Set to ``True`` by :meth:`cancel` before
    ``asyncio.Task.cancel`` so the status reporter can distinguish
    operator-initiated cancellation from a CancelledError that came
    from elsewhere."""

    @property
    def status(self) -> str:
        """One of ``running``, ``completed``, ``cancelled``, ``failed``."""
        if not self.task.done():
            return "running"
        if self.cancelled or self.task.cancelled():
            return "cancelled"
        try:
            exc = self.task.exception()
        except asyncio.CancelledError:
            return "cancelled"
        if exc is not None:
            return "failed"
        return "completed"

    def error_message(self) -> str | None:
        """Short human-readable error string if the task failed.

        ``None`` if the task is still running, completed cleanly,
        or was cancelled. Surfaced to the host via the poll tool's
        result so the operator can see what blew up.
        """
        if not self.task.done() or self.task.cancelled() or self.cancelled:
            return None
        try:
            exc = self.task.exception()
        except asyncio.CancelledError:
            return None
        if exc is None:
            return None
        return f"{type(exc).__name__}: {exc}"

    async def cancel(self) -> None:
        """Cancel the running task and wait for it to settle.

        Safe to call on a session that already completed (no-op).
        After this returns, :attr:`status` is ``cancelled``,
        ``completed``, or ``failed`` depending on whether the
        cancellation arrived in time.

        When the cancellation aborts ``AgentLoop.run`` mid-step,
        the loop's normal exit code (which writes
        ``termination_reason`` and ``finished_at`` on the record)
        does not run. We patch those fields here so the polled
        record reflects a clean cancelled state instead of dangling
        ``None``s.
        """
        if self.task.done():
            return
        self.cancelled = True
        self.task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await self.task
        if self.record.termination_reason is None:
            self.record.termination_reason = "cancelled"
        if self.record.finished_at is None:
            self.record.finished_at = datetime.now(UTC)


@dataclass
class ServerSession:
    """Holds the running MCP server's per-process state.

    Use as an async context manager: ``__aenter__`` connects the
    Quarry MCP client lazily on first use; ``__aexit__`` shuts it
    down. The lifecycle is tied to the MCP server process, not to
    individual tool calls.
    """

    scope: ScopePolicy
    llm: LlmProviderConfig | None
    quarry_launch: QuarryLaunchConfig = field(default_factory=QuarryLaunchConfig.from_env)
    observations: list[SessionObservation] = field(default_factory=list)
    candidates: list[SessionCandidate] = field(default_factory=list)
    async_sessions: dict[str, AsyncSession] = field(default_factory=dict)
    tool_registry: ToolRegistry = field(default_factory=lambda: build_default_registry())
    """Registry of tools the agent may invoke. Populated at session
    construction with the six typed-action builtins; operators can
    add shell or MCP-passthrough tools via the scope file's
    ``tools`` block (loaded by :meth:`from_scope_file`)."""
    """Registry of in-flight (or completed-but-not-collected)
    autonomous-session runs started by ``start_autonomous_session``.
    The poll and cancel tools look sessions up by ID. Lives until
    the server shuts down; not GC'd at v0.1."""

    async def __aenter__(self) -> ServerSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Cancel any in-flight async sessions so background tasks
        # don't outlive the server. Best-effort: we await each
        # cancellation but suppress exceptions — shutdown should
        # never block on a stuck task.
        for s in list(self.async_sessions.values()):
            await s.cancel()

    @asynccontextmanager
    async def with_quarry(self) -> AsyncIterator[QuarryMcpClient]:
        """Open a Quarry MCP client for the duration of one tool call.

        Each Modus tool handler that needs Quarry opens its own
        connection: ``async with session.with_quarry() as quarry:``.
        The MCP SDK's ``stdio_client`` and ``ClientSession`` use anyio
        task groups that must be entered and exited in the same async
        scope; sharing one client across multiple request handlers in
        the outer MCP server runs into anyio's "task group is
        reentrant only within its own scope" constraint and surfaces
        as a ``Connection closed`` error on the first cross-scope
        call. Opening per-call sidesteps that — we pay the
        subprocess-start cost on each invocation in exchange for
        correctness.
        """
        client = QuarryMcpClient(
            command=self.quarry_launch.command,
            args=self.quarry_launch.args,
        )
        async with client as opened:
            yield opened

    def corpus_state(self) -> CorpusState:
        """Build the :class:`CorpusState` slice for the consistency check.

        Combines the (immutable) scope-derived sets with the
        session-local observation/Candidate pool so that actions can
        reference observations the agent itself just produced. The
        scope's ``allowed_assets`` entries are parsed into structured
        endpoint patterns and into a flat set of hostnames; both flow
        into the corpus state so that hostname-level actions and
        endpoint-level Request actions each get the right check.
        """
        observation_ids = frozenset(obs.id for obs in self.observations)
        endpoints = self.scope.endpoints()
        hosts = self.scope.hosts()
        return CorpusState(
            in_scope_assets=hosts,
            allowed_endpoints=endpoints,
            allowed_methods=self.scope.allowed_methods,
            known_observations=observation_ids,
            known_evidence=frozenset(),
            known_referents=hosts | observation_ids,
        )

    @classmethod
    def from_scope_file(
        cls, scope_path: Path, *, env: dict[str, str] | None = None
    ) -> ServerSession:
        """Load a scope policy from disk and resolve LLM + Quarry config from env.

        Tool registry is initialised with Modus's builtin
        typed-action specs and then extended with any
        operator-declared tools in the scope file's ``tools``
        block. Duplicate names (collision with a builtin or with
        another scope-file entry) raise at load time so config
        errors surface here, not at dispatch.
        """
        from modus.scope import ScopePolicy

        scope = ScopePolicy.from_json(scope_path)
        registry = build_default_registry()
        for declaration in scope.tools:
            registry.register(declaration.to_spec())
        return cls(
            scope=scope,
            llm=LlmProviderConfig.from_env(env),
            quarry_launch=QuarryLaunchConfig.from_env(env),
            tool_registry=registry,
        )


__all__ = [
    "LlmProviderConfig",
    "QuarryLaunchConfig",
    "ServerSession",
    "SessionCandidate",
    "SessionObservation",
]
