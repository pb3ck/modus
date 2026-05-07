"""Tests for the generic Tool executor (#8).

Three backends — shell, builtin, mcp-stub — exercised via the
public ``ToolExecutor.execute`` surface. Shell tests use POSIX
binaries (``/bin/echo``, the test interpreter via ``sys.executable``)
so they run on macOS and Linux without external setup. Builtin
tests register a callable in this module and resolve via dotted
path. MCP tests pin the stub's "not yet implemented" error.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from modus.actions import Tool
from modus.scope import ScopePolicy
from modus.session import ServerSession
from modus.tool_executor import ToolExecutor, _render_argv
from modus.tools import (
    BuiltinInvocation,
    McpInvocation,
    ShellInvocation,
    ToolSpec,
)


def _scope() -> ScopePolicy:
    return ScopePolicy(
        target_name="demo",
        allowed_assets=frozenset({"target.example.com"}),
    )


def _executor() -> ToolExecutor:
    return ToolExecutor(session=ServerSession(scope=_scope(), llm=None), scope=_scope())


# ============================================================
# argv template rendering
# ============================================================


class TestRenderArgv:
    def test_no_placeholders(self) -> None:
        assert _render_argv(("echo", "hi"), {"x": 1}) == ["echo", "hi"]

    def test_simple_substitution(self) -> None:
        assert _render_argv(("echo", "{msg}"), {"msg": "hello"}) == ["echo", "hello"]

    def test_int_args_str_coerced(self) -> None:
        assert _render_argv(("echo", "{n}"), {"n": 42}) == ["echo", "42"]

    def test_multiple_placeholders_in_one_token(self) -> None:
        assert _render_argv(("--{flag}={value}",), {"flag": "x", "value": "y"}) == ["--x=y"]

    def test_missing_arg_raises(self) -> None:
        with pytest.raises(KeyError):
            _render_argv(("echo", "{missing}"), {"present": 1})

    def test_unsubstituted_after_render_raises(self) -> None:
        # If the template contains a malformed brace, the renderer
        # may leave it intact — we catch that case post-render and
        # refuse to dispatch.
        with pytest.raises(ValueError, match="unsubstituted"):
            _render_argv(("echo", "{x{nested}}"), {"x": "literal{", "nested": "y"})


# ============================================================
# Shell backend
# ============================================================


def _shell_spec(
    name: str,
    argv_template: tuple[str, ...],
    timeout_seconds: float = 5.0,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        kind="shell",
        description="test shell tool",
        args_schema={"type": "object"},
        side_effect="read",
        invocation=ShellInvocation(
            argv_template=argv_template,
            timeout_seconds=timeout_seconds,
        ),
    )


class TestShellBackend:
    async def test_echo_captures_stdout_and_exit(self) -> None:
        spec = _shell_spec("echo.test", ("/bin/echo", "{msg}"))
        action = Tool(name="echo.test", args={"msg": "hello world"})
        obs = await _executor().execute(action, spec)
        assert obs.error is None
        assert obs.exit_code == 0
        assert obs.stdout is not None
        assert "hello world" in obs.stdout
        assert obs.stdout_truncated is False
        assert obs.stderr_truncated is False
        assert obs.argv == ("/bin/echo", "hello world")
        assert obs.invocation_kind == "shell"
        assert obs.tool_name == "echo.test"
        assert obs.id.startswith("tool-")
        assert obs.elapsed_ms > 0.0

    async def test_python_nonzero_exit(self) -> None:
        # Using sys.executable is more portable than hard-coding a
        # python3 path; works on the dev's venv and CI.
        spec = _shell_spec(
            "exit.test",
            (sys.executable, "-c", "import sys; sys.exit(42)"),
        )
        obs = await _executor().execute(Tool(name="exit.test"), spec)
        assert obs.error is None
        assert obs.exit_code == 42

    async def test_stderr_captured(self) -> None:
        spec = _shell_spec(
            "stderr.test",
            (sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(0)"),
        )
        obs = await _executor().execute(Tool(name="stderr.test"), spec)
        assert obs.error is None
        assert obs.stderr is not None
        assert "boom" in obs.stderr
        assert obs.exit_code == 0

    async def test_timeout_kills_subprocess(self) -> None:
        # Sleep 5 seconds, but timeout at 0.3 — the executor should
        # kill the process and surface error="timeout".
        spec = _shell_spec(
            "sleep.test",
            (sys.executable, "-c", "import time; time.sleep(5)"),
            timeout_seconds=0.3,
        )
        obs = await _executor().execute(Tool(name="sleep.test"), spec)
        assert obs.error is not None
        assert "timeout" in obs.error.lower()
        # Real elapsed time should be near the timeout, not the
        # full sleep — proves the subprocess was killed.
        assert obs.elapsed_ms < 2000.0

    async def test_missing_binary_surfaces_error(self) -> None:
        spec = _shell_spec(
            "missing.test",
            ("/this/path/does/not/exist/nonsense-binary",),
        )
        obs = await _executor().execute(Tool(name="missing.test"), spec)
        assert obs.error is not None
        assert "binary not found" in obs.error.lower()
        assert obs.exit_code is None

    async def test_unsubstituted_placeholder_surfaces_error(self) -> None:
        spec = _shell_spec("templ.test", ("/bin/echo", "{missing}"))
        # The action provides no `missing` arg → the renderer
        # raises KeyError → executor wraps into observation.error.
        obs = await _executor().execute(Tool(name="templ.test"), spec)
        assert obs.error is not None
        assert "missing" in obs.error.lower() or "keyerror" in obs.error.lower()

    async def test_stdout_truncation_at_budget(self) -> None:
        # Emit 200 KB of output; budget is 64 KB.
        bytes_to_emit = 200 * 1024
        spec = _shell_spec(
            "big.test",
            (
                sys.executable,
                "-c",
                f"import sys; sys.stdout.write('x' * {bytes_to_emit})",
            ),
            timeout_seconds=10.0,
        )
        obs = await _executor().execute(Tool(name="big.test"), spec)
        assert obs.error is None
        assert obs.stdout_truncated is True
        assert obs.stdout is not None
        # Truncated text should be at or below the budget.
        assert len(obs.stdout.encode("utf-8")) <= 64 * 1024


# ============================================================
# Builtin backend
# ============================================================


# Module-level callable so the dotted-path resolution can find it.
async def _module_level_builtin(
    args: dict[str, Any], session: ServerSession, scope: ScopePolicy
) -> dict[str, Any]:
    return {"echoed": args, "scope_target": scope.target_name}


def _builtin_spec(name: str, callable_path: str) -> ToolSpec:
    return ToolSpec(
        name=name,
        kind="builtin",
        description="test builtin",
        args_schema={"type": "object"},
        side_effect="read",
        invocation=BuiltinInvocation(callable_dotted_path=callable_path),
    )


class TestBuiltinBackend:
    async def test_resolves_and_invokes(self) -> None:
        spec = _builtin_spec(
            "test.echo",
            "tests.test_tool_executor._module_level_builtin",
        )
        obs = await _executor().execute(Tool(name="test.echo", args={"x": 1, "y": "hi"}), spec)
        assert obs.error is None
        assert obs.builtin_result == {
            "echoed": {"x": 1, "y": "hi"},
            "scope_target": "demo",
        }
        assert obs.invocation_kind == "builtin"

    async def test_missing_module_surfaces_error(self) -> None:
        spec = _builtin_spec(
            "missing.test",
            "modus.this_module_does_not_exist.thing",
        )
        obs = await _executor().execute(Tool(name="missing.test"), spec)
        assert obs.error is not None
        assert "builtin resolution failed" in obs.error.lower()

    async def test_missing_attr_surfaces_error(self) -> None:
        spec = _builtin_spec(
            "missing-attr.test",
            "modus.tool_executor.this_attr_does_not_exist",
        )
        obs = await _executor().execute(Tool(name="missing-attr.test"), spec)
        assert obs.error is not None
        assert "builtin resolution failed" in obs.error.lower()

    async def test_callable_exception_caught(self) -> None:
        spec = _builtin_spec(
            "raises.test",
            "tests.test_tool_executor._raises_builtin",
        )
        obs = await _executor().execute(Tool(name="raises.test"), spec)
        assert obs.error is not None
        assert "RuntimeError" in obs.error
        assert "deliberate" in obs.error

    async def test_non_dict_result_wrapped(self) -> None:
        spec = _builtin_spec(
            "scalar.test",
            "tests.test_tool_executor._returns_scalar",
        )
        obs = await _executor().execute(Tool(name="scalar.test"), spec)
        assert obs.error is None
        # Non-dict returns get wrapped under "value" so the
        # observation shape stays uniform.
        assert obs.builtin_result == {"value": 42}


async def _raises_builtin(
    args: dict[str, Any], session: ServerSession, scope: ScopePolicy
) -> dict[str, Any]:
    raise RuntimeError("deliberate failure")


async def _returns_scalar(args: dict[str, Any], session: ServerSession, scope: ScopePolicy) -> int:
    return 42  # type: ignore[return-value]


# ============================================================
# MCP backend (stub)
# ============================================================


class TestMcpBackendStub:
    async def test_returns_not_implemented_error(self) -> None:
        spec = ToolSpec(
            name="mcp.stub",
            kind="mcp",
            description="passthrough stub",
            args_schema={"type": "object"},
            side_effect="read",
            invocation=McpInvocation(server_name="files", tool_name="read"),
        )
        obs = await _executor().execute(Tool(name="mcp.stub"), spec)
        assert obs.error is not None
        assert "mcp-passthrough not yet implemented" in obs.error.lower()
        assert obs.invocation_kind == "mcp"


# ============================================================
# Output payload
# ============================================================


class TestPayloadSerialisation:
    async def test_as_payload_round_trip(self) -> None:
        spec = _shell_spec("echo.test", ("/bin/echo", "hi"))
        obs = await _executor().execute(Tool(name="echo.test"), spec)
        payload = obs.as_payload()
        assert payload["id"] == obs.id
        assert payload["tool_name"] == "echo.test"
        assert payload["invocation_kind"] == "shell"
        assert payload["side_effect"] == "read"
        assert payload["error"] is None
        # Shell-specific fields populated.
        assert "stdout" in payload
        assert "exit_code" in payload
        assert payload["argv"] == ["/bin/echo", "hi"]

    async def test_as_payload_omits_unused_backend_fields(self) -> None:
        # Builtin observations don't set stdout/stderr/exit_code/argv.
        spec = _builtin_spec(
            "test.echo",
            "tests.test_tool_executor._module_level_builtin",
        )
        obs = await _executor().execute(Tool(name="test.echo"), spec)
        payload = obs.as_payload()
        assert "stdout" not in payload
        assert "stderr" not in payload
        assert "exit_code" not in payload
        assert "argv" not in payload
        assert payload["builtin_result"] is not None
