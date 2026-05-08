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

ADR 0005 introduces three additional scope axes for agent-driven
recon: :attr:`scope_wildcards` (the program's published wildcard
authorization, used as the substrate for recon-mode enumeration),
:attr:`recon_mode` (a flag that gates ``Request`` actions off and
restricts ``Tool`` actions to the ``read`` side-effect tier), and
:attr:`denied_patterns` (a deny-by-pattern set that re-checks every
probed host as defence-in-depth even when the host is in
``allowed_assets``). All three default to empty / False — operators
who don't need recon-mode get the v0.4 behaviour unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from modus import __version__

if TYPE_CHECKING:
    from pathlib import Path

    from modus.tools import ToolSpec


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


class ShellToolDeclaration(BaseModel):
    """Operator-declared shell tool entry from the scope file.

    Lossily converts to a :class:`~modus.tools.ToolSpec` at session
    construction. The ``argv_template`` is the shell command broken
    into discrete tokens; ``{arg_name}`` placeholders get
    substituted from the action's ``args`` at dispatch time. No
    shell parsing happens — tokens go straight to the kernel.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["shell"] = "shell"
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=2048)
    args_schema: dict[str, Any]
    side_effect: Literal["read", "write", "active"]
    argv_template: tuple[str, ...] = Field(min_length=1)
    cwd: str | None = None
    env_passthrough: tuple[str, ...] = ()
    timeout_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)

    def to_spec(self) -> ToolSpec:
        from modus.tools import ShellInvocation, ToolSpec, _accept_all_preconditions

        return ToolSpec(
            name=self.name,
            kind="shell",
            description=self.description,
            args_schema=self.args_schema,
            side_effect=self.side_effect,
            invocation=ShellInvocation(
                argv_template=self.argv_template,
                cwd=self.cwd,
                env_passthrough=self.env_passthrough,
                timeout_seconds=self.timeout_seconds,
            ),
            # Operator-declared shell tools default to "accept after
            # args_schema validation passed." The operator is
            # responsible for scoping the tool's reach via the
            # ``argv_template`` — if the template can be coerced to
            # escape scope, that's on them. Built-in shell tools
            # (amass, nuclei) override with their own scope-gating
            # preconditions in :mod:`modus.tools`.
            preconditions=_accept_all_preconditions,
        )


class McpToolDeclaration(BaseModel):
    """Operator-declared MCP-passthrough tool from the scope file.

    Routes through the host's MCP infrastructure to a foreign
    server. Useful for filesystem reads, web fetches, and any
    other host-side MCP server's surface.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["mcp"] = "mcp"
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=2048)
    args_schema: dict[str, Any]
    side_effect: Literal["read", "write", "active"]
    server_name: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)

    def to_spec(self) -> ToolSpec:
        from modus.tools import McpInvocation, ToolSpec, _accept_all_preconditions

        return ToolSpec(
            name=self.name,
            kind="mcp",
            description=self.description,
            args_schema=self.args_schema,
            side_effect=self.side_effect,
            invocation=McpInvocation(
                server_name=self.server_name,
                tool_name=self.tool_name,
            ),
            preconditions=_accept_all_preconditions,
        )


ToolDeclaration = Annotated[
    ShellToolDeclaration | McpToolDeclaration,
    Field(discriminator="kind"),
]


class DeniedPattern(BaseModel):
    """One pattern that denies a hostname when matched (ADR 0005).

    Same matching modes as the partition tool's internal markers; see
    :mod:`modus.partition` for the canonical token list. Operators
    typically populate :attr:`ScopePolicy.denied_patterns` from
    :func:`modus.partition.default_tier_c_denied_patterns` for the
    maintained DO-NOT-TOUCH set, plus engagement-specific additions.

    Modes:

    * ``substring`` — appears anywhere in the lowercased hostname.
      Suitable for tokens long enough that incidental matches are
      vanishingly rare (combatant commands, ITAR).
    * ``segment`` — must be bounded by a label separator
      (``.``, ``-``, ``_``) or string start/end. Suitable for short
      tokens (``usaf``, ``usmc``) that would otherwise match
      incidentally inside longer words.
    * ``prefix`` — matches when the hostname starts with the token.
      Suitable for credential-gated deployment prefixes (``piv.``).
    * ``infix`` — literal substring; semantically identical to
      ``substring`` but documents intent (``.gov.``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str = Field(min_length=1, max_length=128)
    mode: Literal["substring", "segment", "prefix", "infix"] = "substring"


def _validate_wildcard_pattern(spec: str) -> str:
    """Parse a ``*.example.com``-shape wildcard, returning the parent zone.

    Exactly one leading ``*.`` label is allowed; embedded wildcards
    (e.g. ``*.foo.*.com``) are rejected. Each subsequent label is
    LDH-validated (letters, digits, hyphens; no leading/trailing
    hyphen). The wildcard form is for ``ScopePolicy.scope_wildcards``
    in recon mode (per ADR 0005), not for ``allowed_assets`` — that
    field stays exact-match per the structural firewall property.
    """
    if not spec or not spec.strip():
        raise ValueError("empty wildcard pattern")
    if not spec.startswith("*."):
        raise ValueError(f"wildcard must start with '*.': {spec!r}")
    parent = spec[2:]
    if not parent:
        raise ValueError(f"empty parent zone in wildcard: {spec!r}")
    if "*" in parent or "?" in parent:
        raise ValueError(
            f"only one leading wildcard label allowed; embedded wildcards rejected: {spec!r}"
        )
    for label in parent.split("."):
        if not label:
            raise ValueError(f"empty label in wildcard parent zone: {spec!r}")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"label may not start or end with '-': {label!r} in {spec!r}")
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                raise ValueError(f"invalid character {ch!r} in wildcard label {label!r} ({spec!r})")
    return parent


def host_matches_denied_pattern(host: str, patterns: tuple[DeniedPattern, ...]) -> tuple[str, ...]:
    """Return the tokens of patterns that match ``host`` (empty if none).

    Used by the consistency layer's Request precondition (per ADR
    0005) to deny probes against hosts matching any
    :attr:`ScopePolicy.denied_patterns` entry. Returning the matched
    tokens (rather than just a boolean) lets the rejection rationale
    name what triggered the denial — useful when an operator is
    debugging "why isn't this host in scope?".
    """
    h = host.lower()
    matched: list[str] = []
    for p in patterns:
        t = p.token.lower()
        if (
            (p.mode in ("substring", "infix") and t in h)
            or (p.mode == "prefix" and h.startswith(t))
            or (p.mode == "segment" and re.search(rf"(?:^|[.\-_]){re.escape(t)}(?:[.\-_]|$)", h))
        ):
            matched.append(p.token)
    return tuple(matched)


class ScopePolicy(BaseModel):
    """Operator-authored scope envelope for a single Modus session.

    Four axes:

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
    * **Default headers** — additional headers pinned on every
      outbound request. Bug-bounty programs commonly require a
      researcher-identifying header on every probe (e.g.
      HackerOne's ``X-HackerOne-Research: <h1-username>``); pinning
      it here means the agent cannot accidentally omit it. The
      action's per-request ``headers`` take precedence over these
      defaults when the same header name is set both places.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_name: str = Field(min_length=1, max_length=255)
    allowed_assets: frozenset[str] = Field(default_factory=frozenset)
    allowed_methods: frozenset[str] = Field(
        default_factory=lambda: frozenset({"GET", "HEAD", "OPTIONS"})
    )
    user_agent: str = Field(default=DEFAULT_USER_AGENT, min_length=1, max_length=512)
    default_headers: dict[str, str] = Field(default_factory=dict)
    """Headers pinned on every outbound request the executor sends.
    Use for bug-bounty researcher-identifying headers (HackerOne,
    Bugcrowd, intigriti) the program requires on every probe.
    Per-request action headers override these by name. The
    User-Agent is set separately via :attr:`user_agent` and should
    not be duplicated here."""
    scope_wildcards: frozenset[str] = Field(default_factory=frozenset)
    """ADR 0005: program-published wildcard scope (e.g.
    ``*.anduril.com``). Used by recon-mode autonomous sessions as
    the substrate for passive enumeration and as the candidate set
    for ``corpus.propose_scope_expansion``. NOT a probe-mode
    allow-list — ``Request`` actions still require an exact-match
    ``allowed_assets`` entry. Multiple entries supported (programs
    that publish several wildcards).
    """
    recon_mode: bool = False
    """ADR 0005: when True, the consistency layer rejects ``Request``
    actions unconditionally and gates ``Tool`` actions to the
    ``read`` side-effect tier. Recon-mode autonomous sessions can do
    passive OSINT (subfinder, crt.sh, dnsdumpster) but cannot
    generate live HTTP traffic to wildcard-matched hosts. The
    intended workflow: phase 1 recon-mode session enumerates and
    proposes a Tier A/B/C expansion; operator commits;
    ``recon_mode`` flips to False for the probe-mode session."""
    denied_patterns: tuple[DeniedPattern, ...] = ()
    """ADR 0005: deny-by-pattern set, applied as defence-in-depth
    even when a host is in :attr:`allowed_assets`. Operators
    typically populate from
    :func:`modus.partition.default_tier_c_denied_patterns` for the
    maintained DO-NOT-TOUCH set (``.gov.``, combatant commands,
    USAF/USMC/USCG/USSF, PIV/CAC prefixes), plus engagement-specific
    additions. Two filters (allow-list + deny-pattern) — both must
    pass for a probe to fire."""
    tools: tuple[ToolDeclaration, ...] = ()
    """Operator-declared tools to register on top of Modus's
    builtin set. Each entry is a shell or MCP-passthrough
    declaration; see :class:`ShellToolDeclaration` and
    :class:`McpToolDeclaration`. The session's
    :attr:`~modus.session.ServerSession.tool_registry` is built
    by registering these on top of the default registry of
    builtins."""

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

    @field_validator("scope_wildcards")
    @classmethod
    def _validate_scope_wildcards(cls, value: frozenset[str]) -> frozenset[str]:
        for spec in value:
            _validate_wildcard_pattern(spec)
        return value

    @field_validator("default_headers")
    @classmethod
    def _validate_default_headers(cls, value: dict[str, str]) -> dict[str, str]:
        # RFC 7230 token chars for header names: alphanum plus the
        # punctuation set below. Reject anything outside that — it'd
        # just blow up at the httpx layer with a less-clear error.
        token_punct = set("!#$%&'*+-.^_`|~")
        for name, header_value in value.items():
            if not name:
                raise ValueError("header name must be non-empty")
            for ch in name:
                if not (ch.isalnum() or ch in token_punct):
                    raise ValueError(
                        f"invalid character {ch!r} in header name {name!r}; "
                        f"RFC 7230 token chars only"
                    )
            if name.lower() == "user-agent":
                # Operators set the UA via :attr:`user_agent`. Allowing
                # both surfaces would let the two disagree silently;
                # force the canonical path.
                raise ValueError("set User-Agent via ScopePolicy.user_agent, not default_headers")
            if not header_value:
                raise ValueError(f"header value must be non-empty for {name!r}")
            if "\r" in header_value or "\n" in header_value:
                raise ValueError(
                    f"header value for {name!r} must not contain CR/LF "
                    f"(would enable header injection)"
                )
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


__all__ = [
    "DEFAULT_USER_AGENT",
    "AllowedEndpoint",
    "DeniedPattern",
    "McpToolDeclaration",
    "ScopePolicy",
    "ShellToolDeclaration",
    "ToolDeclaration",
    "host_matches_denied_pattern",
]
