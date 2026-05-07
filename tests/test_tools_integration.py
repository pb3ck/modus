"""Integration tests for the recon shell tools (#10).

Gated behind the ``integration`` pytest marker; run with::

    pytest -m integration tests/test_tools_integration.py

These tests spawn the real ``amass`` and ``nuclei`` binaries
against controlled test inputs. They're skipped by default —
contract tests in ``test_tools.py`` and ``test_tool_executor.py``
carry the load on the no-binaries-required path. Use these
locally when changing tool registrations or argv templates so
the wire-up gets exercised end-to-end.
"""

from __future__ import annotations

import shutil

import pytest

from modus.actions import Tool
from modus.scope import ScopePolicy
from modus.session import ServerSession
from modus.tool_executor import ToolExecutor
from modus.tools import build_default_registry

pytestmark = pytest.mark.integration


def _executor_with_scope(allowed_assets: frozenset[str]) -> ToolExecutor:
    scope = ScopePolicy(target_name="t", allowed_assets=allowed_assets)
    session = ServerSession(scope=scope, llm=None)
    return ToolExecutor(session=session, scope=scope)


class TestAmassEnum:
    async def test_amass_enum_runs_against_in_scope_domain(self) -> None:
        if shutil.which("amass") is None:
            pytest.skip("amass not on PATH")
        scope_domain = "owasp.org"  # public, harmless to enumerate
        executor = _executor_with_scope(frozenset({scope_domain}))
        registry = build_default_registry()
        spec = registry.get("amass.enum")
        assert spec is not None
        action = Tool(name="amass.enum", args={"domain": scope_domain})
        observation = await executor.execute(action, spec)
        # Either the binary ran and produced output, or it
        # surfaced a binary-level error in ``error``. We don't
        # assert subdomains because amass results vary; we only
        # pin the wire-up.
        assert observation.invocation_kind == "shell"
        assert observation.tool_name == "amass.enum"
        if observation.error is None:
            assert observation.exit_code is not None


class TestNucleiScan:
    async def test_nuclei_scan_runs_against_in_scope_url(self) -> None:
        if shutil.which("nuclei") is None:
            pytest.skip("nuclei not on PATH")
        # Use httpbin.org as a stable, public, low-risk target.
        # The scope policy only authorises this exact host; the
        # nuclei.scan precondition rejects URLs outside it.
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"https://httpbin.org"}),
        )
        session = ServerSession(scope=scope, llm=None)
        executor = ToolExecutor(session=session, scope=scope)
        registry = build_default_registry()
        spec = registry.get("nuclei.scan")
        assert spec is not None
        action = Tool(name="nuclei.scan", args={"url": "https://httpbin.org/"})
        observation = await executor.execute(action, spec)
        assert observation.invocation_kind == "shell"
        assert observation.tool_name == "nuclei.scan"
        if observation.error is None:
            assert observation.exit_code is not None
