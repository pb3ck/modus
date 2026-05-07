"""Tests for the tool registry, tool specs, and the three
invocation backends (#7).

These tests cover the registry's contract — what shapes the
operator can declare, how the registry rejects bad config, what
the default registry contains. The actual dispatch tests (executor
behaviour) belong with #8; the per-tool preconditions tests belong
with #9.
"""

from __future__ import annotations

import dataclasses
import json
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from pathlib import Path

from modus.scope import (
    McpToolDeclaration,
    ScopePolicy,
    ShellToolDeclaration,
)
from modus.session import ServerSession
from modus.tools import (
    BuiltinInvocation,
    McpInvocation,
    ShellInvocation,
    ToolRegistry,
    ToolSpec,
    build_default_registry,
    builtin_typed_action_specs,
)


class TestToolRegistry:
    def test_register_and_lookup(self) -> None:
        registry = ToolRegistry()
        spec = ToolSpec(
            name="amass.enum",
            kind="shell",
            description="recon",
            args_schema={"type": "object"},
            side_effect="active",
            invocation=ShellInvocation(argv_template=("amass", "enum", "-d", "{domain}")),
        )
        registry.register(spec)
        assert registry.get("amass.enum") is spec
        assert "amass.enum" in registry

    def test_get_returns_none_for_unknown(self) -> None:
        registry = ToolRegistry()
        assert registry.get("nope") is None
        assert "nope" not in registry

    def test_register_rejects_duplicate_name(self) -> None:
        registry = ToolRegistry()
        spec = ToolSpec(
            name="x",
            kind="shell",
            description="d",
            args_schema={"type": "object"},
            side_effect="read",
            invocation=ShellInvocation(argv_template=("echo",)),
        )
        registry.register(spec)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(spec)

    def test_names_are_sorted(self) -> None:
        registry = ToolRegistry()
        for name in ("zeta", "alpha", "mu"):
            registry.register(
                ToolSpec(
                    name=name,
                    kind="shell",
                    description="d",
                    args_schema={"type": "object"},
                    side_effect="read",
                    invocation=ShellInvocation(argv_template=("echo",)),
                )
            )
        # Sorted output is what the proposer's prompt-rendering
        # path will rely on for deterministic tool listing.
        assert registry.names() == ("alpha", "mu", "zeta")

    def test_len_tracks_registrations(self) -> None:
        registry = ToolRegistry()
        assert len(registry) == 0
        registry.register(
            ToolSpec(
                name="x",
                kind="shell",
                description="d",
                args_schema={"type": "object"},
                side_effect="read",
                invocation=ShellInvocation(argv_template=("echo",)),
            )
        )
        assert len(registry) == 1


class TestBuiltinSpecs:
    def test_six_builtins_present(self) -> None:
        names = {spec.name for spec in builtin_typed_action_specs()}
        assert names == {
            "probe",
            "request",
            "compare",
            "differential",
            "annotate",
            "hypothesize",
        }

    def test_every_builtin_uses_builtin_invocation(self) -> None:
        for spec in builtin_typed_action_specs():
            assert spec.kind == "builtin"
            assert isinstance(spec.invocation, BuiltinInvocation)
            # Each callable_dotted_path points at modus.builtins.<name>
            assert spec.invocation.callable_dotted_path == f"modus.builtins.{spec.name}"

    def test_side_effect_tiers_are_sensible(self) -> None:
        # Spot-check a couple — probe is read-only, request is
        # active (touches the target), hypothesize is write
        # (mutates session pool).
        by_name = {s.name: s for s in builtin_typed_action_specs()}
        assert by_name["probe"].side_effect == "read"
        assert by_name["request"].side_effect == "active"
        assert by_name["hypothesize"].side_effect == "write"


class TestDefaultRegistry:
    def test_default_registry_has_six_builtins(self) -> None:
        registry = build_default_registry()
        assert len(registry) == 6
        for name in ("probe", "request", "compare", "differential", "annotate", "hypothesize"):
            assert name in registry

    def test_default_registry_specs_are_frozen(self) -> None:
        # ToolSpec is a frozen dataclass — attempting to mutate
        # raises FrozenInstanceError. Important so the registry
        # stays read-mostly and downstream code can hold references
        # safely.
        registry = build_default_registry()
        spec = registry.get("request")
        assert spec is not None
        with pytest.raises(dataclasses.FrozenInstanceError):
            spec.name = "other"  # type: ignore[misc]


class TestShellToolDeclaration:
    def test_minimal_valid(self) -> None:
        decl = ShellToolDeclaration(
            name="amass.enum",
            description="subdomain enumeration",
            args_schema={"type": "object", "properties": {"domain": {"type": "string"}}},
            side_effect="active",
            argv_template=("amass", "enum", "-d", "{domain}"),
        )
        assert decl.kind == "shell"
        assert decl.timeout_seconds == 60.0  # default

    def test_to_spec_round_trips(self) -> None:
        decl = ShellToolDeclaration(
            name="amass.enum",
            description="subdomain enumeration",
            args_schema={"type": "object"},
            side_effect="active",
            argv_template=("amass", "enum", "-d", "{domain}"),
            timeout_seconds=300.0,
            env_passthrough=("PATH",),
        )
        spec = decl.to_spec()
        assert spec.name == "amass.enum"
        assert spec.kind == "shell"
        assert isinstance(spec.invocation, ShellInvocation)
        assert spec.invocation.argv_template == ("amass", "enum", "-d", "{domain}")
        assert spec.invocation.timeout_seconds == 300.0
        assert spec.invocation.env_passthrough == ("PATH",)

    def test_argv_template_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            ShellToolDeclaration(
                name="x",
                description="d",
                args_schema={"type": "object"},
                side_effect="read",
                argv_template=(),
            )

    def test_timeout_bounds_enforced(self) -> None:
        with pytest.raises(ValidationError):
            ShellToolDeclaration(
                name="x",
                description="d",
                args_schema={"type": "object"},
                side_effect="read",
                argv_template=("echo",),
                timeout_seconds=0.0,  # gt=0 required
            )
        with pytest.raises(ValidationError):
            ShellToolDeclaration(
                name="x",
                description="d",
                args_schema={"type": "object"},
                side_effect="read",
                argv_template=("echo",),
                timeout_seconds=99999.0,  # le=3600 required
            )


class TestMcpToolDeclaration:
    def test_minimal_valid(self) -> None:
        decl = McpToolDeclaration(
            name="files.read",
            description="read a file",
            args_schema={"type": "object"},
            side_effect="read",
            server_name="filesystem",
            tool_name="read_file",
        )
        assert decl.kind == "mcp"

    def test_to_spec_round_trips(self) -> None:
        decl = McpToolDeclaration(
            name="files.read",
            description="read a file",
            args_schema={"type": "object"},
            side_effect="read",
            server_name="filesystem",
            tool_name="read_file",
        )
        spec = decl.to_spec()
        assert spec.kind == "mcp"
        assert isinstance(spec.invocation, McpInvocation)
        assert spec.invocation.server_name == "filesystem"
        assert spec.invocation.tool_name == "read_file"


class TestScopeFileToolsBlock:
    def test_scope_file_with_tools_block_loads(self, tmp_path: Path) -> None:
        scope_data = {
            "target_name": "demo",
            "allowed_assets": ["target.example.com"],
            "tools": [
                {
                    "kind": "shell",
                    "name": "amass.enum",
                    "description": "subdomain enum",
                    "args_schema": {"type": "object"},
                    "side_effect": "active",
                    "argv_template": ["amass", "enum", "-d", "{domain}"],
                },
                {
                    "kind": "mcp",
                    "name": "files.read",
                    "description": "filesystem read",
                    "args_schema": {"type": "object"},
                    "side_effect": "read",
                    "server_name": "filesystem",
                    "tool_name": "read_file",
                },
            ],
        }
        scope_path = tmp_path / "scope.json"
        scope_path.write_text(json.dumps(scope_data))
        session = ServerSession.from_scope_file(scope_path)
        # Six builtins + two operator-declared = eight.
        assert len(session.tool_registry) == 8
        assert "amass.enum" in session.tool_registry
        assert "files.read" in session.tool_registry
        # The operator-declared ones got the right invocation kind.
        amass = session.tool_registry.get("amass.enum")
        assert amass is not None and amass.kind == "shell"
        files = session.tool_registry.get("files.read")
        assert files is not None and files.kind == "mcp"

    def test_scope_file_without_tools_block_uses_defaults_only(self, tmp_path: Path) -> None:
        scope_data = {
            "target_name": "demo",
            "allowed_assets": ["target.example.com"],
        }
        scope_path = tmp_path / "scope.json"
        scope_path.write_text(json.dumps(scope_data))
        session = ServerSession.from_scope_file(scope_path)
        assert len(session.tool_registry) == 6  # only builtins

    def test_scope_file_duplicate_tool_name_rejected(self, tmp_path: Path) -> None:
        # Same name twice in the scope file's tools block —
        # surfaced at session construction, not silently shadowed.
        scope_data = {
            "target_name": "demo",
            "allowed_assets": ["target.example.com"],
            "tools": [
                {
                    "kind": "shell",
                    "name": "amass.enum",
                    "description": "first",
                    "args_schema": {"type": "object"},
                    "side_effect": "active",
                    "argv_template": ["amass"],
                },
                {
                    "kind": "shell",
                    "name": "amass.enum",  # collision
                    "description": "second",
                    "args_schema": {"type": "object"},
                    "side_effect": "active",
                    "argv_template": ["amass", "enum"],
                },
            ],
        }
        scope_path = tmp_path / "scope.json"
        scope_path.write_text(json.dumps(scope_data))
        with pytest.raises(ValueError, match="already registered"):
            ServerSession.from_scope_file(scope_path)

    def test_scope_file_tool_colliding_with_builtin_rejected(self, tmp_path: Path) -> None:
        # Operator-declared "request" — collides with the builtin.
        # Reject so a stray scope file can't shadow Modus's
        # built-in surface.
        scope_data = {
            "target_name": "demo",
            "allowed_assets": ["target.example.com"],
            "tools": [
                {
                    "kind": "shell",
                    "name": "request",  # collides with builtin
                    "description": "shadowing the builtin",
                    "args_schema": {"type": "object"},
                    "side_effect": "active",
                    "argv_template": ["echo", "hi"],
                },
            ],
        }
        scope_path = tmp_path / "scope.json"
        scope_path.write_text(json.dumps(scope_data))
        with pytest.raises(ValueError, match="already registered"):
            ServerSession.from_scope_file(scope_path)


class TestServerSessionDefault:
    def test_default_session_has_default_registry(self) -> None:
        # ServerSession() without going through from_scope_file
        # still gets the six-builtin default registry — important
        # so unit tests of other systems don't have to construct a
        # registry explicitly.
        scope = ScopePolicy(
            target_name="demo",
            allowed_assets=frozenset({"target.example.com"}),
        )
        session = ServerSession(scope=scope, llm=None)
        assert len(session.tool_registry) == 6
        assert "request" in session.tool_registry
