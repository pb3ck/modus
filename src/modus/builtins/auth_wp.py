"""Builtin: ``auth.wp_login`` — WordPress login flow that returns the
authenticated cookie jar so subsequent ``raw.http`` calls can attach
the session.

Every wp-bounty triage in the 2026-05-10/11 arc identified that the
high-EV attack surface (subscriber-tier broken-access-control,
admin-only AJAX gated by capability check rather than nonce, member-
data IDOR) is **unreachable** from unauthenticated probing alone. The
LLM needs an authenticated session to test "any-authenticated-user
can do an admin-only thing" — historically the most common
Wordfence-payable bug shape.

This builtin performs the standard WP login dance — GET
``/wp-login.php`` to seed cookies, POST credentials, capture the
resulting ``wordpress_logged_in_*`` cookie — and returns the cookie
jar as a dict the LLM can attach to subsequent ``raw.http`` requests
via a ``Cookie`` header.

The credentials come directly from the action args. The operator
spells them out in the audit objective ("lab accounts: subscriber1
/ Sub!Audit-2026-x"), the LLM passes them into ``auth.wp_login``,
the audit trail captures the login attempt and the resulting
cookies. No hidden credential storage.

Scope perimeter is enforced same as ``raw.http``: the target's
``(host, port, tls)`` triple must be in scope and ``POST`` must be
in ``allowed_methods``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from modus.scope import ScopePolicy
    from modus.session import ServerSession


# Standard WP login form field names.
_LOGIN_USERNAME_FIELD = "log"
_LOGIN_PASSWORD_FIELD = "pwd"
_LOGIN_REMEMBER_FIELD = "rememberme"
_LOGIN_SUBMIT_FIELD = "wp-submit"
_LOGIN_TESTCOOKIE_FIELD = "testcookie"


async def wp_login(
    args: dict[str, Any],
    session: ServerSession,
    scope: ScopePolicy,
) -> dict[str, Any]:
    """Perform a WordPress login flow against the target.

    Args (validated against the registry schema before arrival):

    * ``target`` (str, required) — base URL of the WordPress site
      (e.g. ``http://localhost:8090``). The login endpoint is
      derived as ``target + "/wp-login.php"``.
    * ``username`` (str, required) — login name. WordPress accepts
      either the user_login or the user_email field; both go in
      the ``log`` form field.
    * ``password`` (str, required) — plaintext password.
    * ``redirect_to`` (str, optional) — the ``redirect_to`` POST
      field. Defaults to ``target/wp-admin/``. Probe value when
      hunting for open-redirect on the login flow.

    Returns a dict with:

    * ``success`` (bool) — True when the response chain ends on a
      ``wp-admin``-shaped URL OR the response sets a
      ``wordpress_logged_in_*`` cookie. False otherwise.
    * ``status`` (int) — final status code in the redirect chain.
    * ``cookies`` (dict[str, str]) — every cookie set by the server
      during the login flow. The session-bearing names are
      ``wordpress_logged_in_<site_hash>`` and
      ``wordpress_sec_<site_hash>``; the LLM should attach them to
      subsequent requests via a ``Cookie`` header. Also includes
      ``wordpress_test_cookie`` (always set by the login page).
    * ``cookie_header`` (str) — pre-formatted ``Cookie: name=value;
      name2=value2`` string the LLM can drop straight into a
      ``raw.http`` ``headers`` arg.
    * ``redirect_chain`` (list[str]) — the URLs the response chain
      passed through. Useful for detecting login-flow anomalies
      (e.g. a redirect to an external host = open redirect on the
      ``redirect_to`` param).
    * ``error`` (str, optional) — set when the login failed; the
      caller should not attempt to use the cookies.
    """
    target_raw = str(args.get("target", ""))
    username = str(args.get("username", ""))
    password = str(args.get("password", ""))
    redirect_to = args.get("redirect_to")

    if not target_raw:
        return {"error": "target is required"}
    if not username or not password:
        return {"error": "username and password are required"}

    target = target_raw.rstrip("/")
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return {"error": f"unsupported scheme: {parsed.scheme!r}"}
    host = parsed.hostname
    if not host:
        return {"error": f"could not parse host from {target!r}"}
    tls = parsed.scheme == "https"
    port = parsed.port if parsed.port is not None else (443 if tls else 80)

    # Scope perimeter: same enforcement as ``raw.http``.
    if not scope.request_in_scope(host, port, tls):
        return {
            "error": (
                f"out of scope: {host}:{port} (tls={tls}) is not in {sorted(scope.allowed_assets)}"
            )
        }
    if "POST" not in scope.allowed_methods:
        return {
            "error": (
                "POST not in scope.allowed_methods — required for the "
                "login POST. Add POST to the scope's allowed_methods."
            )
        }

    login_url = f"{target}/wp-login.php"
    redirect_to_value = (
        str(redirect_to) if isinstance(redirect_to, str) and redirect_to else f"{target}/wp-admin/"
    )

    # Merge default headers + user agent under operator control,
    # same shape as raw.http.
    base_headers: dict[str, str] = {}
    if scope.user_agent:
        base_headers["User-Agent"] = scope.user_agent
    for k, v in (scope.default_headers or {}).items():
        base_headers[k] = v

    form_body = {
        _LOGIN_USERNAME_FIELD: username,
        _LOGIN_PASSWORD_FIELD: password,
        _LOGIN_REMEMBER_FIELD: "forever",
        _LOGIN_SUBMIT_FIELD: "Log In",
        _LOGIN_TESTCOOKIE_FIELD: "1",
        "redirect_to": redirect_to_value,
    }

    cookies: dict[str, str] = {}
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # The WP login flow requires the testcookie to be set on
            # the FIRST attempt. We do a quick GET to populate
            # ``wordpress_test_cookie``, then POST with that cookie
            # attached.
            await client.get(login_url, headers=base_headers)
            post_headers = dict(base_headers)
            post_headers["Content-Type"] = "application/x-www-form-urlencoded"
            response = await client.post(login_url, headers=post_headers, data=form_body)
            # Harvest the FULL client cookie jar. The
            # ``wordpress_logged_in_*`` cookie is set on the 302
            # response from /wp-login.php; httpx follows the
            # redirect, so the final response's per-response
            # cookies are empty. The client's jar accumulates
            # cookies across the entire chain.
            for cookie in client.cookies.jar:
                if cookie.name and cookie.value:
                    cookies[cookie.name] = cookie.value
    except httpx.HTTPError as exc:
        return {
            "error": f"http error: {type(exc).__name__}: {exc}",
            "url": login_url,
        }

    success = any(c.startswith("wordpress_logged_in_") for c in cookies)
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    redirect_chain = [str(r.url) for r in response.history] + [str(response.url)]

    result: dict[str, Any] = {
        "success": success,
        "status": response.status_code,
        "cookies": cookies,
        "cookie_header": cookie_header,
        "redirect_chain": redirect_chain,
        "login_url": login_url,
        "username": username,  # echo for audit trail; password is NOT echoed
    }
    if not success:
        result["error"] = (
            "login did not produce a wordpress_logged_in_* cookie. "
            "Check credentials. The response body may contain the "
            "WP error message — fetch it via raw.http if needed."
        )
    return result


__all__ = ["wp_login"]
