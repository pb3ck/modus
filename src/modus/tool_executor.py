"""Generic Tool dispatcher.

Takes a validated :class:`~modus.actions.Tool` action plus its
:class:`~modus.tools.ToolSpec` from the registry and dispatches to
the right backend, returning a normalised :class:`ToolObservation`
the caller can persist into the session pool the same way
:class:`~modus.executor.HttpObservation` is persisted today.

Three backends:

* **shell** (:class:`~modus.tools.ShellInvocation`) — subprocess via
  ``asyncio.create_subprocess_exec``. Argv tokens may contain
  ``{arg_name}`` placeholders that are substituted from the action's
  ``args``; unsubstituted placeholders are an error (refuses to run a
  partially-templated command). No ``shell=True``: shell metacharacters
  in args are inert. Per-call timeout; on timeout the subprocess is
  killed and the observation carries ``error="timeout"``.
* **builtin** (:class:`~modus.tools.BuiltinInvocation`) — resolves
  the ``callable_dotted_path`` to an awaitable callable, invokes it
  with ``(args, session, scope)``, wraps the returned dict into a
  :class:`ToolObservation`. Used for the typed-action builtins (#10).
* **mcp** (:class:`~modus.tools.McpInvocation`) — stub for now:
  returns an error observation. Real MCP-passthrough (Modus acting
  as MCP client to a foreign server the host has configured) is
  deferred — operators may declare MCP tools, but dispatch surfaces
  ``error="mcp-passthrough not yet implemented"`` until the backend
  lands.

Output capping: stdout/stderr are truncated at 64 KB each (same
budget as the HTTP executor's response body). Beyond that, the
observation carries a ``stdout_truncated`` / ``stderr_truncated``
flag and the proposer's ``_summarise_step`` history line uses
the truncated-tail excerpt the same way it does for HTTP responses.
"""

from __future__ import annotations

import asyncio
import importlib
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from modus.tools import (
    BuiltinInvocation,
    McpInvocation,
    ShellInvocation,
)

if TYPE_CHECKING:
    from modus.actions import Tool
    from modus.scope import ScopePolicy
    from modus.session import ServerSession
    from modus.tools import ToolSpec


_OUTPUT_BUDGET_BYTES = 64 * 1024
"""Per-stream truncation budget. Matches the HTTP executor's
response-body cap so tool observations and request observations
have the same prompt-cost characteristics for the proposer's
``body_excerpt`` / ``stdout_excerpt`` history lines."""


@dataclass(frozen=True)
class ToolObservation:
    """Result of executing a :class:`~modus.actions.Tool` action.

    One observation type for all three backends — the
    backend-specific fields are nullable so the consumer can
    introspect ``invocation_kind`` and read whichever fields apply.

    Persisted into ``ServerSession.observations`` so subsequent
    :class:`~modus.actions.Compare` / :class:`~modus.actions.Hypothesize`
    actions can reference the observation by ``id`` in the same
    way they reference :class:`~modus.executor.HttpObservation`
    rows today.
    """

    id: str
    """Stable identifier (``tool-<uuid4>``) the agent's
    history line and ``Hypothesize.evidence_refs`` cite."""
    tool_name: str
    args: dict[str, Any]
    invocation_kind: str  # "shell" | "mcp" | "builtin"
    side_effect: str  # "read" | "write" | "active"
    started_at: float  # monotonic timestamp at dispatch
    elapsed_ms: float
    error: str | None = None
    """Surface for backend-level failures: missing binary, timeout,
    template error, callable resolution failure, anything else
    that prevented a clean run. Backend-specific result fields are
    populated when ``error`` is ``None``."""
    # Shell-specific
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    argv: tuple[str, ...] = ()
    """The fully-substituted argv that was actually exec'd —
    audit-grade record of what hit the kernel."""
    # MCP-specific
    mcp_result: dict[str, Any] | None = None
    # Builtin-specific
    builtin_result: dict[str, Any] | None = None

    def as_payload(self) -> dict[str, Any]:
        """Serialise to a dict the session pool can stash."""
        payload: dict[str, Any] = {
            "id": self.id,
            "tool_name": self.tool_name,
            "args": dict(self.args),
            "invocation_kind": self.invocation_kind,
            "side_effect": self.side_effect,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }
        if self.stdout is not None:
            payload["stdout"] = self.stdout
            payload["stdout_truncated"] = self.stdout_truncated
        if self.stderr is not None:
            payload["stderr"] = self.stderr
            payload["stderr_truncated"] = self.stderr_truncated
        if self.exit_code is not None:
            payload["exit_code"] = self.exit_code
        if self.argv:
            payload["argv"] = list(self.argv)
        if self.mcp_result is not None:
            payload["mcp_result"] = self.mcp_result
        if self.builtin_result is not None:
            payload["builtin_result"] = self.builtin_result
        return payload


@dataclass
class ToolExecutor:
    """Dispatcher for :class:`~modus.actions.Tool` actions.

    Stateless across calls; the only state is the per-call
    subprocess management for shell tools. Holds a reference to
    the :class:`~modus.session.ServerSession` so builtin
    invocations can read corpus state, append observations, etc.

    The executor does NOT re-check tool registration or per-tool
    preconditions — those are the consistency layer's job (#9).
    By the time ``execute`` is called, the spec has been verified
    and the args have passed the spec's ``args_schema``.
    """

    session: ServerSession
    scope: ScopePolicy

    async def execute(self, action: Tool, spec: ToolSpec) -> ToolObservation:
        """Dispatch ``action`` via the right backend for ``spec``."""
        observation_id = f"tool-{uuid.uuid4()}"
        started_monotonic = time.monotonic()
        common_kwargs: dict[str, Any] = {
            "id": observation_id,
            "tool_name": spec.name,
            "args": dict(action.args),
            "invocation_kind": spec.kind,
            "side_effect": spec.side_effect,
            "started_at": started_monotonic,
        }

        try:
            if isinstance(spec.invocation, ShellInvocation):
                return await self._execute_shell(action, spec, common_kwargs, started_monotonic)
            if isinstance(spec.invocation, BuiltinInvocation):
                return await self._execute_builtin(action, spec, common_kwargs, started_monotonic)
            if isinstance(spec.invocation, McpInvocation):
                return self._execute_mcp_stub(spec, common_kwargs, started_monotonic)
        except Exception as exc:  # broad: don't kill the loop on a backend bug
            return ToolObservation(
                **common_kwargs,
                elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
                error=f"{type(exc).__name__}: {exc}",
            )
        # Unreachable: spec.invocation is the discriminated union of
        # the three above. mypy proves this.
        raise AssertionError(f"unhandled invocation: {type(spec.invocation).__name__}")

    async def _execute_shell(
        self,
        action: Tool,
        spec: ToolSpec,
        common_kwargs: dict[str, Any],
        started_monotonic: float,
    ) -> ToolObservation:
        assert isinstance(spec.invocation, ShellInvocation)
        invocation = spec.invocation
        argv = _render_argv(invocation.argv_template, action.args)
        env = _scoped_env(invocation.env_passthrough)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=invocation.cwd,
                env=env,
            )
        except FileNotFoundError as exc:
            return ToolObservation(
                **common_kwargs,
                elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
                argv=tuple(argv),
                error=f"binary not found: {exc.filename or argv[0]}",
            )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=invocation.timeout_seconds,
            )
        except TimeoutError:
            proc.kill()
            # Drain so the process actually reaps.
            with suppress(Exception):
                await proc.communicate()
            return ToolObservation(
                **common_kwargs,
                elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
                argv=tuple(argv),
                error=f"timeout after {invocation.timeout_seconds}s",
            )

        stdout, stdout_truncated = _decode_and_truncate(stdout_bytes)
        stderr, stderr_truncated = _decode_and_truncate(stderr_bytes)
        return ToolObservation(
            **common_kwargs,
            elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
            argv=tuple(argv),
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            exit_code=proc.returncode,
        )

    async def _execute_builtin(
        self,
        action: Tool,
        spec: ToolSpec,
        common_kwargs: dict[str, Any],
        started_monotonic: float,
    ) -> ToolObservation:
        assert isinstance(spec.invocation, BuiltinInvocation)
        callable_path = spec.invocation.callable_dotted_path
        try:
            module_path, _, name = callable_path.rpartition(".")
            if not module_path:
                raise ImportError(f"not a dotted path: {callable_path!r}")
            module = importlib.import_module(module_path)
            fn = getattr(module, name)
        except (ImportError, AttributeError) as exc:
            return ToolObservation(
                **common_kwargs,
                elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
                error=f"builtin resolution failed: {exc}",
            )
        try:
            result = await fn(action.args, self.session, self.scope)
        except Exception as exc:
            return ToolObservation(
                **common_kwargs,
                elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
                error=f"{type(exc).__name__}: {exc}",
            )
        return ToolObservation(
            **common_kwargs,
            elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
            builtin_result=dict(result) if isinstance(result, dict) else {"value": result},
        )

    def _execute_mcp_stub(
        self,
        spec: ToolSpec,
        common_kwargs: dict[str, Any],
        started_monotonic: float,
    ) -> ToolObservation:
        # MCP-passthrough: real implementation requires Modus to act
        # as MCP client to a foreign server the host has configured.
        # That's deferred to a follow-up — for v0.3.0 the backend
        # surfaces a clear error so operators can declare MCP tools
        # but get told they don't dispatch yet.
        return ToolObservation(
            **common_kwargs,
            elapsed_ms=(time.monotonic() - started_monotonic) * 1000.0,
            error="mcp-passthrough not yet implemented (deferred follow-up to #8)",
        )


def _render_argv(template: tuple[str, ...], args: dict[str, Any]) -> list[str]:
    """Substitute ``{arg_name}`` placeholders in argv tokens.

    Only top-level ``{name}`` placeholders are recognised — nothing
    fancier (no Python ``str.format`` field specs, no nested
    attribute access). If a placeholder names a missing arg, raises
    :class:`KeyError` so the executor surfaces it as
    ``error="...KeyError..."``. After substitution, no token may
    still contain ``{name}`` — a leftover placeholder means the
    template referenced an arg that wasn't passed, and the dispatch
    refuses to run.
    """
    rendered: list[str] = []
    for token in template:
        # Walk the token, expanding any {name} occurrence.
        out_parts: list[str] = []
        i = 0
        while i < len(token):
            if token[i] == "{" and "}" in token[i + 1 :]:
                close = token.index("}", i + 1)
                name = token[i + 1 : close]
                if not name or "{" in name:
                    # Malformed; leave the literal in place and let
                    # the post-render check catch it.
                    out_parts.append(token[i])
                    i += 1
                    continue
                if name not in args:
                    raise KeyError(
                        f"argv template references {{{name}}} but args do not contain {name!r}"
                    )
                out_parts.append(str(args[name]))
                i = close + 1
            else:
                out_parts.append(token[i])
                i += 1
        rendered_token = "".join(out_parts)
        if "{" in rendered_token and "}" in rendered_token:
            # Lingering placeholder — refuse to dispatch.
            raise ValueError(
                f"argv token {token!r} has unsubstituted placeholder "
                f"after rendering: {rendered_token!r}"
            )
        rendered.append(rendered_token)
    return rendered


def _scoped_env(passthrough: tuple[str, ...]) -> dict[str, str]:
    """Build a clean env with only operator-allowed passthroughs.

    Always includes ``PATH`` (otherwise binaries can't be found)
    and any names the spec opted in via ``env_passthrough``.
    Anything else from Modus's own environment is dropped so the
    subprocess can't accidentally inherit secrets, API keys, or
    operator credentials.
    """
    import os

    base: dict[str, str] = {}
    for name in {"PATH", *passthrough}:
        value = os.environ.get(name)
        if value is not None:
            base[name] = value
    return base


def _decode_and_truncate(data: bytes) -> tuple[str, bool]:
    """Decode UTF-8 (with replacement) and truncate at the byte budget.

    Returns ``(text, truncated_flag)``. Truncation happens at the
    byte level *before* decoding so a multi-byte sequence at the
    cut point doesn't synthesise garbage; the ``replace`` decode
    handles whatever incomplete tail survives.
    """
    if len(data) > _OUTPUT_BUDGET_BYTES:
        return data[:_OUTPUT_BUDGET_BYTES].decode("utf-8", errors="replace"), True
    return data.decode("utf-8", errors="replace"), False


__all__ = ["ToolExecutor", "ToolObservation"]
