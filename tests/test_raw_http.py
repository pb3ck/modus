"""Tests for the ``raw.http`` builtin and its registration gates.

The 2026-05-10 calibration arc identified that ``claude-bug-bounty``-style
agents win on raw flexibility. The ``raw.http`` builtin is Modus's
operator-opt-in escape hatch from the typed-action grammar — letting
the LLM dispatch arbitrary HTTP requests (any method, any headers,
any body) when the operator has explicitly enabled it.

Tests cover:

* Registration gating: ``MODUS_ALLOW_RAW_HTTP`` must be set AND
  mode must be ``free``. Either condition missing → tool not in
  registry → typed-grammar bypass impossible.
* Scope perimeter: even when registered, ``raw.http`` enforces
  ``scope.request_in_scope`` and ``method in allowed_methods``.
  Out-of-scope or wrong-method calls return error structures
  *without* issuing traffic.
* Successful invocation flow: in-scope URL with allowed method
  hits the configured target.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any

import pytest

from modus.builtins.raw_http import is_enabled, raw_http
from modus.scope import ScopePolicy
from modus.session import ServerSession
from modus.tools import build_default_registry, builtin_free_mode_tool_specs


@contextmanager
def env(**vars):
    """Temporarily set / unset env vars; restore on exit."""
    prior: dict[str, str | None] = {}
    for k, v in vars.items():
        prior[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in prior.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _scope(asset: str = "http://target.example.com:8080") -> ScopePolicy:
    return ScopePolicy(
        target_name="t",
        allowed_assets=frozenset({asset}),
        allowed_methods=frozenset({"GET", "HEAD", "POST"}),
    )


class TestIsEnabled:
    def test_default_unset_disables(self) -> None:
        with env(MODUS_ALLOW_RAW_HTTP=None, MODUS_MODE=None):
            assert is_enabled() is False

    def test_explicit_opt_in_enables_in_free_mode(self) -> None:
        with env(MODUS_ALLOW_RAW_HTTP="1", MODUS_MODE=None):
            assert is_enabled() is True
        with env(MODUS_ALLOW_RAW_HTTP="1", MODUS_MODE="free"):
            assert is_enabled() is True

    def test_truthy_variants_accepted(self) -> None:
        for val in ("1", "true", "TRUE", "yes", "YES"):
            with env(MODUS_ALLOW_RAW_HTTP=val, MODUS_MODE=None):
                assert is_enabled() is True, f"expected truthy on {val!r}"

    def test_falsy_variants_rejected(self) -> None:
        for val in ("0", "false", "no", "off", ""):
            with env(MODUS_ALLOW_RAW_HTTP=val, MODUS_MODE=None):
                assert is_enabled() is False, f"expected falsy on {val!r}"

    def test_strict_mode_disables_even_with_opt_in(self) -> None:
        # Audit-defensibility property of strict mode is preserved
        # without operator forethought — strict mode wins.
        with env(MODUS_ALLOW_RAW_HTTP="1", MODUS_MODE="strict"):
            assert is_enabled() is False


class TestRegistryGating:
    def test_default_registry_does_not_register_raw_http(self) -> None:
        with env(MODUS_ALLOW_RAW_HTTP=None, MODUS_MODE=None):
            registry = build_default_registry()
        assert registry.get("raw.http") is None

    def test_opt_in_registers_raw_http(self) -> None:
        with env(MODUS_ALLOW_RAW_HTTP="1", MODUS_MODE=None):
            registry = build_default_registry()
        assert registry.get("raw.http") is not None
        spec = registry.get("raw.http")
        assert spec.kind == "builtin"
        assert spec.side_effect == "active"

    def test_strict_mode_does_not_register_even_with_opt_in(self) -> None:
        with env(MODUS_ALLOW_RAW_HTTP="1", MODUS_MODE="strict"):
            registry = build_default_registry()
        assert registry.get("raw.http") is None

    def test_free_mode_specs_function_returns_nothing_when_off(self) -> None:
        with env(MODUS_ALLOW_RAW_HTTP=None):
            assert builtin_free_mode_tool_specs() == ()


@pytest.mark.asyncio
class TestRawHttpScopeEnforcement:
    """Even when registered, ``raw.http`` must not breach scope. The
    perimeter is the load-bearing safety property; everything else is
    convenience for the LLM."""

    async def _session(self, scope: ScopePolicy) -> ServerSession:
        return ServerSession(scope=scope, llm=None)

    async def test_in_scope_request_fires(self) -> None:
        # The actual HTTP send should attempt — we only care that
        # the scope check doesn't reject. Use httpx's MockTransport
        # to avoid real network.
        import httpx

        scope = _scope("http://target.example.com:8080")
        session = await self._session(scope)

        # Patch httpx.AsyncClient to use a mock transport. The
        # builtin constructs its own client internally, so we patch
        # at the class level for this test.
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, text="ok")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(self, *args, **kwargs)

        httpx.AsyncClient.__init__ = patched_init  # type: ignore[method-assign]
        try:
            result = await raw_http(
                {
                    "method": "GET",
                    "url": "http://target.example.com:8080/api/foo",
                },
                session,
                scope,
            )
        finally:
            httpx.AsyncClient.__init__ = original_init  # type: ignore[method-assign]

        assert "error" not in result, result
        assert result["status"] == 200
        assert captured["method"] == "GET"
        assert "target.example.com" in captured["url"]

    async def test_out_of_scope_host_rejected_without_traffic(self) -> None:
        scope = _scope("http://target.example.com:8080")
        session = await self._session(scope)
        result = await raw_http(
            {
                "method": "GET",
                "url": "http://attacker.example.com:8080/x",
            },
            session,
            scope,
        )
        assert "error" in result
        assert "out of scope" in result["error"]
        # No status returned — no traffic was sent.
        assert "status" not in result

    async def test_out_of_scope_port_rejected(self) -> None:
        scope = _scope("http://target.example.com:8080")
        session = await self._session(scope)
        result = await raw_http(
            {
                "method": "GET",
                "url": "http://target.example.com:9999/x",
            },
            session,
            scope,
        )
        assert "error" in result
        assert "out of scope" in result["error"]

    async def test_disallowed_method_rejected(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://target.example.com:8080"}),
            allowed_methods=frozenset({"GET"}),  # POST not allowed
        )
        session = await self._session(scope)
        result = await raw_http(
            {
                "method": "POST",
                "url": "http://target.example.com:8080/x",
                "body": "test",
            },
            session,
            scope,
        )
        assert "error" in result
        assert "not in scope.allowed_methods" in result["error"]

    async def test_unsupported_scheme_rejected(self) -> None:
        scope = _scope("http://target.example.com:8080")
        session = await self._session(scope)
        result = await raw_http(
            {
                "method": "GET",
                "url": "file:///etc/passwd",
            },
            session,
            scope,
        )
        assert "error" in result
        assert "scheme" in result["error"]
