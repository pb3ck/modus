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

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from modus.consistency import CorpusState
from modus.corpus import QuarryMcpClient

if TYPE_CHECKING:
    from contextlib import AsyncExitStack
    from pathlib import Path
    from types import TracebackType
    from typing import Any

    from modus.scope import ScopePolicy


@dataclass(frozen=True)
class LlmProviderConfig:
    """Resolved configuration for Modus's internal LLM provider.

    Read from the process environment at server start. The autonomous
    -session tools refuse to run without one of these resolved.
    """

    provider: str  # "anthropic" | "openai" | "openai-compatible"
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
        """
        env = env if env is not None else dict(os.environ)
        provider = env.get("MODUS_LLM_PROVIDER", "").strip().lower()
        if not provider:
            return None
        valid = {"anthropic", "openai", "openai-compatible"}
        if provider not in valid:
            raise ValueError(f"MODUS_LLM_PROVIDER={provider!r} is not one of {sorted(valid)}")
        return cls(
            provider=provider,
            model=env.get("MODUS_LLM_MODEL") or None,
            api_key=(
                env.get("ANTHROPIC_API_KEY")
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
    Findings. The autonomous-session tool returns its accumulated
    Candidates as part of its MCP result; the operator decides what
    to do with them via Quarry's own ``quarry finding promote`` flow.
    """

    bug_class: str
    evidence_refs: tuple[str, ...]
    rationale: str
    severity_hint: str = "info"


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
    _quarry: QuarryMcpClient | None = field(default=None, init=False, repr=False)
    _quarry_stack: AsyncExitStack | None = field(default=None, init=False, repr=False)
    observations: list[SessionObservation] = field(default_factory=list)
    candidates: list[SessionCandidate] = field(default_factory=list)

    async def __aenter__(self) -> ServerSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._quarry_stack is not None:
            await self._quarry_stack.aclose()
            self._quarry_stack = None
            self._quarry = None

    async def quarry(self) -> QuarryMcpClient:
        """Lazily open and cache the Quarry MCP client.

        Tool calls that need Quarry call this. The first call pays
        the subprocess-start cost; subsequent calls reuse the same
        connection.
        """
        if self._quarry is not None:
            return self._quarry
        from contextlib import AsyncExitStack

        stack = AsyncExitStack()
        client = QuarryMcpClient()
        try:
            await stack.enter_async_context(client)
        except Exception:
            await stack.aclose()
            raise
        self._quarry_stack = stack
        self._quarry = client
        return client

    def corpus_state(self) -> CorpusState:
        """Build the :class:`CorpusState` slice for the consistency check.

        Combines the (immutable) scope-derived sets with the
        session-local observation/Candidate pool so that actions can
        reference observations the agent itself just produced.
        """
        observation_ids = frozenset(obs.id for obs in self.observations)
        return CorpusState(
            in_scope_assets=self.scope.allowed_assets,
            allowed_methods=self.scope.allowed_methods,
            known_observations=observation_ids,
            known_evidence=frozenset(),
            known_referents=self.scope.allowed_assets | observation_ids,
        )

    @classmethod
    def from_scope_file(
        cls, scope_path: Path, *, env: dict[str, str] | None = None
    ) -> ServerSession:
        """Load a scope policy from disk and resolve LLM config from env."""
        from modus.scope import ScopePolicy

        return cls(scope=ScopePolicy.from_json(scope_path), llm=LlmProviderConfig.from_env(env))


__all__ = [
    "LlmProviderConfig",
    "ServerSession",
    "SessionCandidate",
    "SessionObservation",
]
