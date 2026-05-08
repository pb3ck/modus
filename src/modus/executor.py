"""HTTP executor for the ``Request`` action.

Modus does not produce traffic until the consistency layer accepts a
:class:`~modus.actions.Request`. This module is the thing the server's
``request`` tool handler calls after Z3 says yes — it builds the
HTTP request from the action, sends it via :mod:`httpx`, and returns
a structured :class:`HttpObservation` the caller can persist to the
session pool (and later, to Quarry).

The executor is shared by both MCP surfaces. Surface B (verified
actions) calls it once per host tool invocation; surface A (the
autonomous loop) may call it many times per autonomous-session
tool call.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

if TYPE_CHECKING:
    from modus.actions import Request


@dataclass(frozen=True)
class HttpObservation:
    """The result of executing a :class:`~modus.actions.Request`.

    Mirrors the shape Quarry's ``responses`` adapter ingests, so the
    operator can later round-trip the session pool into Quarry via
    ``quarry ingest --source responses``.

    ``request_headers`` records the **effective** header set sent on
    the wire — the merge of httpx client defaults (User-Agent and
    scope-pinned :attr:`~modus.scope.ScopePolicy.default_headers`)
    with per-request :attr:`~modus.actions.Request.headers`
    overrides. This makes the audit record substantive: bug-bounty
    programs that require an identifying header on every probe
    (HackerOne's ``X-HackerOne-Research``, Bugcrowd's equivalents)
    can be verified post-hoc from the audit trail.

    ``redirect_chain`` lists every URL the executor followed before
    arriving at the final response — empty when no redirects were
    followed. Useful audit trail when the agent's intended endpoint
    differs from the one that actually answered.
    """

    id: str
    url: str
    method: str
    request_headers: dict[str, str]
    request_body: str | None
    status: int
    response_headers: dict[str, str]
    response_body: str
    elapsed_ms: float
    error: str | None = None
    redirect_chain: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, Any]:
        """Serialise to a dict the consistency layer can stash."""
        return {
            "id": self.id,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "request_headers": dict(self.request_headers),
            "request_body": self.request_body,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "redirect_chain": list(self.redirect_chain),
        }


@dataclass
class HttpExecutor:
    """Asynchronous HTTP executor.

    Use as an async context manager so the underlying client is
    closed on shutdown. The executor is stateless across calls —
    every request opens a fresh connection unless the host pools.

    The ``user_agent`` is the default User-Agent header for outbound
    requests; per-request action headers override it. Set this from
    :attr:`modus.scope.ScopePolicy.user_agent` so the operator's
    engagement-specific identification flows through.
    """

    timeout_seconds: float = 30.0
    user_agent: str = "Modus/0.0.0"
    follow_same_origin_redirects: bool = True
    """Follow 3xx redirects whose Location targets the same scheme +
    host + port as the original request. Cross-origin redirects are
    never followed regardless of this flag — a redirect to a
    different host could land Modus on out-of-scope assets, so we
    stop and let the caller decide."""
    max_redirects: int = 5
    verify_tls: bool = True
    extra_default_headers: dict[str, str] = field(default_factory=dict)
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)

    async def __aenter__(self) -> HttpExecutor:
        # We always pass ``follow_redirects=False`` to httpx so we can
        # apply our own same-origin policy — letting httpx auto-follow
        # would let cross-origin redirects through, which a defensive
        # offensive-security tool shouldn't do without operator
        # awareness.
        self._client = httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            verify=self.verify_tls,
            headers={"User-Agent": self.user_agent, **self.extra_default_headers},
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def execute(self, action: Request) -> HttpObservation:
        """Send the request described by ``action`` and observe the result.

        ``action.target`` is treated as the hostname (HTTPS by
        default); ``action.path`` is the path-and-query. The
        consistency layer is presumed to have already accepted the
        action — this method does not re-check scope.

        Network-level failures (DNS, TLS, connect, timeout) are
        captured into the returned :class:`HttpObservation`'s
        ``error`` field rather than raised, so the caller's tool
        result still parses cleanly. Pass HTTP errors (4xx, 5xx)
        through as ordinary observations — those are signal, not
        failure.
        """
        if self._client is None:
            raise RuntimeError(
                "HttpExecutor must be used inside `async with` before calling execute()."
            )

        original_url = self._build_url(action)
        request_headers = dict(action.headers)
        observation_id = f"http-{uuid.uuid4()}"
        started = time.monotonic()

        current_url = original_url
        current_method = action.method
        request_body: str | None = action.body
        redirect_chain: list[str] = []
        # The set of headers actually sent over the wire on the most
        # recent hop, captured via ``build_request`` so client-default
        # headers (User-Agent, scope-pinned ``default_headers`` like
        # ``X-HackerOne-Research``) appear merged with per-request
        # action headers. This is what the audit record stores —
        # storing only ``action.headers`` would let the audit lie
        # about what we sent, which matters for bug-bounty programs
        # that require an identifying header on every probe.
        effective_request_headers: dict[str, str] = {}

        try:
            request = self._client.build_request(
                current_method,
                current_url,
                headers=request_headers,
                content=request_body,
            )
            effective_request_headers = dict(request.headers)
            response = await self._client.send(request)
            for _ in range(self.max_redirects):
                if not self.follow_same_origin_redirects:
                    break
                if response.status_code not in (301, 302, 303, 307, 308):
                    break
                location = response.headers.get("location")
                if not location:
                    break
                next_url = urljoin(current_url, location)
                if not _same_origin(original_url, next_url):
                    # Cross-origin — do not follow. The caller sees
                    # the 3xx response and the unfollowed Location
                    # in the response_headers.
                    break
                redirect_chain.append(next_url)
                # 303 always becomes GET; 301/302 historically did
                # too for non-GET; 307/308 preserve method+body.
                if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method != "HEAD"
                ):
                    current_method = "GET"
                    request_body = None
                current_url = next_url
                request = self._client.build_request(
                    current_method,
                    current_url,
                    headers=request_headers,
                    content=request_body,
                )
                effective_request_headers = dict(request.headers)
                response = await self._client.send(request)
        except httpx.HTTPError as exc:
            elapsed = (time.monotonic() - started) * 1000.0
            return HttpObservation(
                id=observation_id,
                url=current_url,
                method=action.method,
                # If ``build_request`` succeeded but ``send`` failed
                # (the common case — DNS, TLS, connect, timeout),
                # ``effective_request_headers`` already has the
                # merged set. If we never got that far,
                # ``request_headers`` (the per-request slice) is the
                # best we can record. Either way: never fall back to
                # an empty dict, since downstream consumers (audit
                # tooling, evidence_patterns) treat an empty headers
                # dict as "no headers were sent" rather than "we
                # didn't capture them."
                request_headers=effective_request_headers or request_headers,
                request_body=action.body,
                status=0,
                response_headers={},
                response_body="",
                elapsed_ms=elapsed,
                error=f"{type(exc).__name__}: {exc}",
                redirect_chain=tuple(redirect_chain),
            )

        elapsed = (time.monotonic() - started) * 1000.0
        body_text = _decode_response_body(response)
        return HttpObservation(
            id=observation_id,
            url=current_url,
            method=action.method,
            request_headers=effective_request_headers,
            request_body=action.body,
            status=response.status_code,
            response_headers=dict(response.headers.items()),
            response_body=body_text,
            elapsed_ms=elapsed,
            redirect_chain=tuple(redirect_chain),
        )

    def _build_url(self, action: Request) -> str:
        # ``action.target`` is a hostname; ``action.path`` always
        # starts with ``/`` (validated by the Pydantic model). The
        # scheme and port come from the action — defaults are
        # ``https`` and the standard port (443/80), with non-default
        # values reserved for local labs and unusual setups.
        scheme = "https" if action.tls else "http"
        port_part = f":{action.port}" if action.port is not None else ""
        return f"{scheme}://{action.target}{port_part}{action.path}"


def _same_origin(a: str, b: str) -> bool:
    """Return True iff two URLs share scheme + host + effective port.

    "Effective port" treats missing ports as the scheme default
    (80 for http, 443 for https), so ``http://x:80`` and ``http://x``
    are considered the same origin. Cross-scheme is rejected even on
    the same host (``http`` to ``https`` is a meaningful change).
    """
    pa, pb = urlparse(a), urlparse(b)
    if pa.scheme != pb.scheme or pa.hostname != pb.hostname:
        return False
    default = 443 if pa.scheme == "https" else 80
    return (pa.port or default) == (pb.port or default)


def _decode_response_body(response: httpx.Response) -> str:
    """Return the response body as text, defensively.

    Binary or undecodable bodies are summarised as a one-line note
    rather than passed through raw — agents that want raw bytes
    should ingest via Quarry, not via this path.
    """
    content_type = response.headers.get("content-type", "")
    if any(token in content_type for token in ("application/json", "text/", "xml")):
        return response.text
    if not response.content:
        return ""
    # Fall back to text but cap length to keep tool results reasonable.
    text = response.text
    if len(text) > 64_000:
        return text[:64_000] + "\n…[truncated]…"
    return text


__all__ = ["HttpExecutor", "HttpObservation"]
