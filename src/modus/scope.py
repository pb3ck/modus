"""Operator-defined scope policy.

Scope is what makes an autonomous agent ethically defensible in
offensive security work. The agent runs without per-step approval;
scope is the structural guarantee it cannot exceed.

Modus encodes scope as preconditions in the consistency layer
(:mod:`modus.consistency`) rather than as prompt language. The LLM
proposer never decides whether something is in scope; the
consistency check rejects every proposed action whose target isn't
in :attr:`ScopePolicy.allowed_assets`.

Scope entries can be either bare hostnames (`"example.com"`,
allowing any port + any TLS) or URL patterns (`"http://localhost:13000"`,
constraining the scheme and port). The full URL form is the
operator's tool for tightening scope down to specific endpoints —
useful when a host happens to run multiple services on different
ports and only one of them is in scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator

from modus import __version__

if TYPE_CHECKING:
    from pathlib import Path


#: Default User-Agent sent on outbound HTTP requests when the scope
#: policy doesn't override it. Conservative on purpose — identifies
#: the tool generically without leaking the project URL or any
#: operator-identifying information. Bug-bounty programs commonly
#: require a hunter-identifying header; operators set
#: :attr:`ScopePolicy.user_agent` per engagement to comply.
DEFAULT_USER_AGENT = f"Modus/{__version__}"


@dataclass(frozen=True)
class AllowedEndpoint:
    """One parsed entry from :attr:`ScopePolicy.allowed_assets`.

    Each entry is a (host, port, tls) triple where ``port`` and
    ``tls`` may be ``None`` to mean "any value matches." Bare
    hostnames in the scope file parse to ``(host, None, None)`` —
    matching any scheme and any port. URL forms parse to specific
    constraints: ``"http://x:8080"`` becomes ``("x", 8080, False)``,
    ``"https://x"`` becomes ``("x", None, True)``, etc.
    """

    host: str
    port: int | None
    tls: bool | None

    def matches(self, host: str, port: int | None, tls: bool) -> bool:
        if self.host != host:
            return False
        if self.port is not None and self.port != port:
            return False
        return not (self.tls is not None and self.tls != tls)

    def render(self) -> str:
        """Compact display form, useful in error messages and logs."""
        scheme = "https" if self.tls else ("http" if self.tls is False else "*")
        port = f":{self.port}" if self.port is not None else ""
        return f"{scheme}://{self.host}{port}"


def _parse_allowed_asset(spec: str) -> AllowedEndpoint:
    """Parse an allowed-asset string into an :class:`AllowedEndpoint`.

    Accepted forms:

    * ``"hostname"`` — any scheme, any port on that host.
    * ``"http://hostname"`` / ``"https://hostname"`` — scheme
      constrained, port unconstrained (so https:443, https:8443,
      etc. all match for an https entry).
    * ``"http://hostname:port"`` / ``"https://hostname:port"`` —
      scheme + port both constrained.
    * ``"hostname:port"`` — port constrained, scheme unconstrained.
      Rare, but supported for symmetry.

    Wildcards in the hostname (``*``, ``?``) are rejected; operators
    must expand wildcard patterns out-of-band so the consistency
    check stays finite.
    """
    if not spec or not spec.strip():
        raise ValueError("empty allowed-asset spec")
    if "*" in spec or "?" in spec:
        raise ValueError(
            f"ScopePolicy.allowed_assets must contain expanded hostnames; "
            f"got wildcard pattern: {spec!r}"
        )

    remaining = spec
    tls: bool | None = None
    if remaining.startswith("http://"):
        tls = False
        remaining = remaining[len("http://") :]
    elif remaining.startswith("https://"):
        tls = True
        remaining = remaining[len("https://") :]

    # Strip any trailing path/query/fragment — scope is at the
    # endpoint level, not the URL level.
    for sep in ("/", "?", "#"):
        if sep in remaining:
            remaining = remaining.split(sep, 1)[0]

    if ":" in remaining:
        host, port_str = remaining.rsplit(":", 1)
        try:
            port_val: int | None = int(port_str)
        except ValueError as exc:
            raise ValueError(f"port in allowed-asset spec is not an integer: {spec!r}") from exc
        if port_val is not None and not (1 <= port_val <= 65535):
            raise ValueError(f"port in allowed-asset spec is out of range (1-65535): {spec!r}")
    else:
        host = remaining
        port_val = None

    if not host:
        raise ValueError(f"empty hostname in allowed-asset spec: {spec!r}")

    return AllowedEndpoint(host=host, port=port_val, tls=tls)


class ScopePolicy(BaseModel):
    """Operator-authored scope envelope for a single Modus session.

    Three axes:

    * **Asset scope** — which hostnames the agent may touch. Each
      entry is either a bare hostname (any scheme/port) or a URL
      pattern (scheme/port constrained). See
      :func:`_parse_allowed_asset` for the supported forms.
      Wildcards are expanded by the operator before the policy is
      loaded; Modus does not expand ``*.example.com`` itself,
      because doing so silently is the class of mistake that loses
      an authorization.
    * **Method scope** — which HTTP methods the session permits.
      Defaults to read-only (``GET``, ``HEAD``, ``OPTIONS``); the
      operator must opt into write methods explicitly.
    * **HTTP identification** — the User-Agent sent on outbound
      requests. The default is conservative; operators override per
      engagement (e.g. some bug-bounty programs require a
      researcher-identifying header, some forbid bug-bounty UA
      strings). Per-request overrides via the action's ``headers``
      take precedence over this default.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_name: str = Field(min_length=1, max_length=255)
    allowed_assets: frozenset[str] = Field(default_factory=frozenset)
    allowed_methods: frozenset[str] = Field(
        default_factory=lambda: frozenset({"GET", "HEAD", "OPTIONS"})
    )
    user_agent: str = Field(default=DEFAULT_USER_AGENT, min_length=1, max_length=512)

    @field_validator("allowed_assets")
    @classmethod
    def _validate_assets(cls, value: frozenset[str]) -> frozenset[str]:
        # Validate each entry parses cleanly; raises on wildcards
        # and on malformed URL/port specs.
        for asset in value:
            _parse_allowed_asset(asset)
        return value

    @field_validator("allowed_methods")
    @classmethod
    def _known_methods(cls, value: frozenset[str]) -> frozenset[str]:
        known = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
        unknown = value - known
        if unknown:
            raise ValueError(f"unknown HTTP method(s) in scope: {sorted(unknown)}")
        return value

    def endpoints(self) -> tuple[AllowedEndpoint, ...]:
        """Parse ``allowed_assets`` into structured endpoint patterns."""
        return tuple(
            sorted(
                (_parse_allowed_asset(spec) for spec in self.allowed_assets),
                key=lambda ep: (ep.host, ep.port or 0, ep.tls is True),
            )
        )

    def hosts(self) -> frozenset[str]:
        """The set of hostnames any endpoint pattern matches.

        Used by Probe / Compare / Annotate / Hypothesize / Differential
        — actions that work at the host level rather than the
        endpoint level.
        """
        return frozenset(ep.host for ep in self.endpoints())

    def request_in_scope(self, host: str, port: int | None, tls: bool) -> bool:
        """Is this (host, port, tls) tuple allowed by any endpoint pattern?"""
        return any(ep.matches(host, port, tls) for ep in self.endpoints())

    @classmethod
    def from_json(cls, path: Path) -> ScopePolicy:
        """Load a policy from a JSON file the operator authored."""
        return cls.model_validate_json(path.read_text())


__all__ = ["DEFAULT_USER_AGENT", "AllowedEndpoint", "ScopePolicy"]
