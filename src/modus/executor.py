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

import httpx

if TYPE_CHECKING:
    from modus.actions import Request


@dataclass(frozen=True)
class HttpObservation:
    """The result of executing a :class:`~modus.actions.Request`.

    Mirrors the shape Quarry's ``responses`` adapter ingests, so the
    operator can later round-trip the session pool into Quarry via
    ``quarry ingest --source responses``.
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
        }


@dataclass
class HttpExecutor:
    """Asynchronous HTTP executor.

    Use as an async context manager so the underlying client is
    closed on shutdown. The executor is stateless across calls —
    every request opens a fresh connection unless the host pools.
    """

    timeout_seconds: float = 30.0
    user_agent: str = "modus/0.0.0 (autonomous offensive agent; +https://github.com/pb3ck/modus)"
    follow_redirects: bool = False
    verify_tls: bool = True
    extra_default_headers: dict[str, str] = field(default_factory=dict)
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)

    async def __aenter__(self) -> HttpExecutor:
        self._client = httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=self.follow_redirects,
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

        url = self._build_url(action)
        request_headers = dict(action.headers)
        observation_id = f"http-{uuid.uuid4()}"
        started = time.monotonic()
        try:
            response = await self._client.request(
                action.method,
                url,
                headers=request_headers,
                content=action.body,
            )
        except httpx.HTTPError as exc:
            elapsed = (time.monotonic() - started) * 1000.0
            return HttpObservation(
                id=observation_id,
                url=url,
                method=action.method,
                request_headers=request_headers,
                request_body=action.body,
                status=0,
                response_headers={},
                response_body="",
                elapsed_ms=elapsed,
                error=f"{type(exc).__name__}: {exc}",
            )

        elapsed = (time.monotonic() - started) * 1000.0
        body_text = _decode_response_body(response)
        return HttpObservation(
            id=observation_id,
            url=url,
            method=action.method,
            request_headers=request_headers,
            request_body=action.body,
            status=response.status_code,
            response_headers=dict(response.headers.items()),
            response_body=body_text,
            elapsed_ms=elapsed,
        )

    def _build_url(self, action: Request) -> str:
        # ``action.target`` is a hostname; ``action.path`` always
        # starts with ``/`` (validated by the Pydantic model). We
        # default to HTTPS — operators who genuinely need plaintext
        # HTTP can include the protocol in the target via a future
        # action-grammar extension; v0.1 is HTTPS-only.
        return f"https://{action.target}{action.path}"


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
