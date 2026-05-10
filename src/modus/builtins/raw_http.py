"""Free-mode builtin: ``raw.http`` — typed-grammar bypass under operator opt-in.

The 2026-05-10 wp-bounty-lab calibration arc identified that
``claude-bug-bounty``-style agents win on raw flexibility — they
hand the LLM full shell access (curl, sed, jq) so multi-step flows,
unusual content types, and creative payload shaping all work
naturally. Modus's typed ``Request`` action covers most of the same
ground (any method, arbitrary headers, arbitrary body) but in a
shape the LLM has to learn to assemble correctly. This builtin
gives operators an explicit escape hatch when they want the LLM
to have direct curl-equivalence.

The escape hatch is **doubly gated**:

1. Operator must opt in by setting ``MODUS_ALLOW_RAW_HTTP=1``.
   Default (unset) → tool is not registered → tool dispatch
   precondition rejects the action.
2. The current operating mode must be ``free``. Strict mode never
   registers this tool, regardless of the env var. The strict-mode
   audit-defensibility property is preserved without operator
   forethought.

Even when both gates pass, **the scope perimeter still holds**:

* The URL's ``(host, port, tls)`` triple must be in scope per
  :meth:`ScopePolicy.request_in_scope`.
* The HTTP method must be in :attr:`ScopePolicy.allowed_methods`.

The builtin enforces these checks before issuing any traffic. An
in-bounds ``raw.http`` call has no more reach than an ordinary
``Request`` action; the difference is only in ergonomics for the
LLM and operator visibility into the call shape.

Tracked in the ADR roadmap; this is the third pillar of "Path B"
identified during the 2026-05-10 wp-bounty-lab triage (alongside
the head-excerpt body window — already shipped — and wrapped
scanner tools — in flight).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from modus.scope import ScopePolicy
    from modus.session import ServerSession


def is_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True when ``raw.http`` should appear in the registry.

    Two-condition gate per the module docstring:

    * ``MODUS_ALLOW_RAW_HTTP`` set to a truthy value (``1`` /
      ``true`` / ``yes``, case-insensitive).
    * Mode is ``free`` (``MODUS_MODE`` unset or set to ``free``).
    """
    src = env if env is not None else os.environ
    raw = src.get("MODUS_ALLOW_RAW_HTTP", "").strip().lower()
    if raw not in ("1", "true", "yes"):
        return False
    # Mode check: strict mode never registers raw.http even with
    # the opt-in env var. Avoid circular import — read MODUS_MODE
    # directly rather than calling ``mode_from_env``.
    mode = src.get("MODUS_MODE", "").strip().lower()
    return mode != "strict"


_ALLOWED_METHODS: frozenset[str] = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)


async def raw_http(
    args: dict[str, Any],
    session: ServerSession,
    scope: ScopePolicy,
) -> dict[str, Any]:
    """Execute an arbitrary HTTP request against an in-scope target.

    Args (validated against the registry's ``args_schema`` before
    arrival here, but defensively re-checked):

    * ``method`` (str, required) — uppercase HTTP method.
    * ``url`` (str, required) — full URL including scheme, host,
      port, path, query.
    * ``headers`` (dict[str, str], optional) — request headers
      merged on top of the scope's ``default_headers`` and
      ``user_agent``. Operator-supplied values win.
    * ``body`` (str, optional) — request body as a string.
      Operators wanting binary bodies must base64-encode and
      include a header to signal that — this entry point is
      string-only by design (audit clarity).
    * ``follow_redirects`` (bool, optional, default True) — same
      semantics as :class:`httpx.AsyncClient` redirect handling.
    """
    method = str(args.get("method", "")).upper()
    url = str(args.get("url", ""))
    headers = dict(args.get("headers", {}))
    body = args.get("body")
    follow_redirects = bool(args.get("follow_redirects", True))

    if method not in _ALLOWED_METHODS:
        return {"error": f"unsupported method: {method!r}"}

    if not url:
        return {"error": "url is required"}

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"error": f"unsupported scheme: {parsed.scheme!r}"}
    host = parsed.hostname
    if not host:
        return {"error": f"could not parse host from {url!r}"}
    tls = parsed.scheme == "https"
    port = parsed.port if parsed.port is not None else (443 if tls else 80)

    # Scope perimeter — load-bearing. Same check the typed Request
    # action uses; raw.http is no looser.
    if not scope.request_in_scope(host, port, tls):
        return {
            "error": (
                f"out of scope: {host}:{port} (tls={tls}) is not in {sorted(scope.allowed_assets)}"
            )
        }
    if method not in scope.allowed_methods:
        return {
            "error": (
                f"method {method!r} not in scope.allowed_methods ({sorted(scope.allowed_methods)})"
            )
        }

    # Merge scope's default headers and user agent under operator
    # control. Operator-supplied headers in args win.
    merged_headers: dict[str, str] = {}
    if scope.user_agent:
        merged_headers["User-Agent"] = scope.user_agent
    for k, v in (scope.default_headers or {}).items():
        merged_headers[k] = v
    for k, v in headers.items():
        merged_headers[k] = v

    request_kwargs: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": merged_headers,
    }
    if body is not None:
        # ``content`` accepts str/bytes; we restrict to str so the
        # audit trail captures the exact wire bytes.
        request_kwargs["content"] = str(body)

    try:
        async with httpx.AsyncClient(follow_redirects=follow_redirects) as client:
            response = await client.request(**request_kwargs)
    except httpx.HTTPError as exc:
        return {
            "error": f"http error: {type(exc).__name__}: {exc}",
            "url": url,
            "method": method,
        }

    body_text = response.text
    return {
        "url": str(response.url),
        "method": method,
        "status": response.status_code,
        "request_headers": dict(merged_headers),
        "request_body": str(body) if body is not None else "",
        "response_headers": {k.lower(): v for k, v in response.headers.items()},
        "response_body": body_text,
        "redirect_chain": [str(r.url) for r in response.history],
    }


__all__ = ["is_enabled", "raw_http"]
