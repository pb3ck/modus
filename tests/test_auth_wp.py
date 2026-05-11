"""Tests for the ``auth.wp_login`` builtin.

Uses ``httpx.MockTransport`` to simulate the WordPress login flow
shape — GET /wp-login.php sets a test cookie, POST credentials
returns ``wordpress_logged_in_*`` on success or an error body on
failure. Verifies the cookie jar is captured, the scope perimeter
is enforced, and credentials never leak into the result rationale.
"""

from __future__ import annotations

import httpx
import pytest

from modus.builtins.auth_wp import wp_login
from modus.scope import ScopePolicy


def _scope(*, allowed_methods: frozenset[str] | None = None) -> ScopePolicy:
    return ScopePolicy(
        target_name="demo",
        allowed_assets=frozenset({"target.example.com"}),
        allowed_methods=allowed_methods or frozenset({"GET", "POST", "HEAD"}),
    )


class _FakeWP:
    """Minimal in-process WordPress login simulator.

    Routes:
      - GET /wp-login.php → 200, sets ``wordpress_test_cookie``.
      - POST /wp-login.php → either 302 with ``wordpress_logged_in_<hash>``
        (when credentials match) or 200 with a login_error body.
    """

    def __init__(
        self,
        *,
        valid_user: str = "subscriber1",
        valid_pass: str = "Sub!Audit-2026-x",
    ) -> None:
        self.valid_user = valid_user
        self.valid_pass = valid_pass

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/wp-login.php":
            return httpx.Response(404, text="not wp-login")
        if request.method == "GET":
            return httpx.Response(
                200,
                headers={"Set-Cookie": "wordpress_test_cookie=WP+Cookie+check; Path=/"},
                text="<form>login</form>",
            )
        # POST — parse form body.
        body = request.content.decode("utf-8") if request.content else ""
        fields = dict(part.split("=", 1) for part in body.split("&") if "=" in part)
        from urllib.parse import unquote_plus

        user = unquote_plus(fields.get("log", ""))
        pwd = unquote_plus(fields.get("pwd", ""))
        if user == self.valid_user and pwd == self.valid_pass:
            return httpx.Response(
                302,
                headers={
                    "Location": "/wp-admin/",
                    "Set-Cookie": (
                        "wordpress_logged_in_abc123=user%7C1234567890%7C"
                        "session_token; Path=/; HttpOnly"
                    ),
                },
            )
        return httpx.Response(
            200,
            text=("<div id='login_error'><strong>Error:</strong> Invalid credentials.</div>"),
        )


@pytest.fixture
def patch_async_client(monkeypatch: pytest.MonkeyPatch):
    """Patch ``httpx.AsyncClient`` so the wp_login builtin uses the
    MockTransport instead of real network calls."""

    def _factory(fake: _FakeWP):
        original = httpx.AsyncClient

        def _wrap(*args, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["transport"] = httpx.MockTransport(fake.handler)
            return original(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _wrap)

    return _factory


async def test_successful_login_returns_session_cookie(patch_async_client) -> None:
    patch_async_client(_FakeWP())
    result = await wp_login(
        {
            "target": "http://target.example.com",
            "username": "subscriber1",
            "password": "Sub!Audit-2026-x",
        },
        session=None,  # type: ignore[arg-type]
        scope=_scope(),
    )
    assert result.get("success") is True
    assert "wordpress_logged_in_abc123" in result["cookies"]
    # cookie_header concatenates name=value pairs for direct paste into
    # a raw.http call's headers arg.
    assert "wordpress_logged_in_abc123=" in result["cookie_header"]
    # The username is echoed for audit clarity; the password is NOT.
    assert result.get("username") == "subscriber1"
    assert "password" not in result
    assert "Sub!Audit-2026-x" not in str(result)


async def test_bad_credentials_returns_error(patch_async_client) -> None:
    patch_async_client(_FakeWP())
    result = await wp_login(
        {
            "target": "http://target.example.com",
            "username": "subscriber1",
            "password": "wrong-password",
        },
        session=None,  # type: ignore[arg-type]
        scope=_scope(),
    )
    assert result.get("success") is False
    assert "error" in result
    # No wordpress_logged_in cookie on failure.
    assert not any(c.startswith("wordpress_logged_in_") for c in result.get("cookies", {}))


async def test_out_of_scope_target_rejected() -> None:
    result = await wp_login(
        {
            "target": "http://evil.example.com",
            "username": "subscriber1",
            "password": "anything",
        },
        session=None,  # type: ignore[arg-type]
        scope=_scope(),
    )
    assert "out of scope" in (result.get("error") or "")


async def test_post_method_required() -> None:
    # Scope without POST in allowed_methods rejects.
    result = await wp_login(
        {
            "target": "http://target.example.com",
            "username": "subscriber1",
            "password": "anything",
        },
        session=None,  # type: ignore[arg-type]
        scope=_scope(allowed_methods=frozenset({"GET", "HEAD"})),
    )
    assert "POST" in (result.get("error") or "")


async def test_missing_args_returns_error() -> None:
    result = await wp_login(
        {"target": "http://target.example.com"},
        session=None,  # type: ignore[arg-type]
        scope=_scope(),
    )
    assert "username" in (result.get("error") or "")


async def test_redirect_to_param_captured_in_chain(
    patch_async_client,
) -> None:
    patch_async_client(_FakeWP())
    result = await wp_login(
        {
            "target": "http://target.example.com",
            "username": "subscriber1",
            "password": "Sub!Audit-2026-x",
            "redirect_to": "http://target.example.com/wp-admin/profile.php",
        },
        session=None,  # type: ignore[arg-type]
        scope=_scope(),
    )
    # The login flow's redirect chain is captured for the audit trail.
    assert result.get("redirect_chain")
    assert isinstance(result["redirect_chain"], list)


class TestRegistryIntegration:
    def test_auth_wp_login_registered_in_default_registry(self) -> None:
        from modus.tools import build_default_registry

        registry = build_default_registry()
        spec = registry.get("auth.wp_login")
        assert spec is not None
        assert spec.side_effect == "active"

    def test_wp_login_preconditions_check_scope(self) -> None:
        from modus.consistency import CorpusState
        from modus.tools import _wp_login_preconditions

        scope = _scope()
        preconds = _wp_login_preconditions(
            {
                "target": "http://target.example.com",
                "username": "x",
                "password": "y",
            },
            scope,
            CorpusState(),
        )
        names = {n for n, _ in preconds}
        passed = {n for n, ok in preconds if ok}
        assert "auth_wp_login:post_allowed" in names
        assert "auth_wp_login:post_allowed" in passed
        assert any("auth_wp_login:in_scope:" in n for n in passed)

    def test_wp_login_preconditions_reject_out_of_scope(self) -> None:
        from modus.consistency import CorpusState
        from modus.tools import _wp_login_preconditions

        scope = _scope()
        preconds = _wp_login_preconditions(
            {
                "target": "http://evil.example.com",
                "username": "x",
                "password": "y",
            },
            scope,
            CorpusState(),
        )
        passed = {n for n, ok in preconds if ok}
        # in_scope precondition for evil host must NOT pass.
        assert not any("evil.example.com" in n for n in passed)
