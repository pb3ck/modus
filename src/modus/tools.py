"""Tool registry — what the agent is allowed to invoke.

The trust boundary for the open-vocabulary agent. Each
:class:`ToolSpec` declares one tool's dispatch backend, argument
schema, side-effect tier, and per-tool preconditions. The
consistency layer dispatches :class:`~modus.actions.Tool` actions
via the registry's per-tool preconditions (#9); the executor
dispatches to the backend (#8).

Three dispatch backends:

* :class:`ShellInvocation` — ``subprocess`` with placeholder-
  substituted argv. For external binaries (amass, nuclei, ffuf,
  custom shell scripts).
* :class:`McpInvocation` — routes through the host's MCP client to
  a tool exposed by a different MCP server (filesystem read,
  fetch, search, etc.).
* :class:`BuiltinInvocation` — Modus-internal callable. The six
  typed actions (Probe, Request, ...) become first-party builtins
  in #10 so the entire executor goes through one path.

ADR-0004 (filed in #11) documents the agent-first / tools-first
framing this module is the structural backbone of.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from modus.consistency import CorpusState
    from modus.scope import ScopePolicy


PreconditionFn = Callable[
    [dict[str, Any], "ScopePolicy", "CorpusState"],
    list[tuple[str, bool]],
]
"""Per-tool preconditions evaluator. Same shape the consistency
layer's :func:`modus.consistency._preconditions` uses internally
for typed actions, lifted out so each tool spec can declare its
own. Returns a list of ``(label, value)`` tuples; the Z3 layer
encodes each as a tracked atom and the unsat-core surfaces the
failing labels for the verdict's ``failed_preconditions``.

The default ``_no_preconditions`` (used by stub registrations) is
``always-False`` on a single placeholder label so a tool that
hasn't had its preconditions written yet can't be silently
dispatched."""


def _no_preconditions(
    args: dict[str, Any], scope: ScopePolicy, state: CorpusState
) -> list[tuple[str, bool]]:
    """Default preconditions for a stub registration.

    Always rejects with the ``tool_preconditions_not_yet_implemented``
    label. Used so tool entries registered before their
    preconditions function exists (e.g. during the #7 → #9
    transition) can't accidentally execute.
    """
    return [("tool_preconditions_not_yet_implemented", False)]


def _accept_all_preconditions(
    args: dict[str, Any], scope: ScopePolicy, state: CorpusState
) -> list[tuple[str, bool]]:
    """Builtin tools that don't have a meaningful precondition
    beyond JSON Schema args validation accept unconditionally.

    Used by the typed-action builtin specs whose real gating
    happens in the legacy ``_preconditions`` switch (the
    typed-action MCP surface still routes through it). Once #10's
    full migration lands and typed actions dispatch via the
    registry, these stubs get replaced with the per-action
    preconditions lifted from the legacy switch.
    """
    return []


def _amass_preconditions(
    args: dict[str, Any], scope: ScopePolicy, state: CorpusState
) -> list[tuple[str, bool]]:
    """Gate ``amass.enum`` invocations on the domain being in
    ``scope.allowed_assets``.

    Recon tools are still subject to the operator's scope envelope
    even though they don't directly hit the target's HTTP surface
    — DNS enumeration of ``*.target.com`` is "active" against the
    target's authoritative servers and counts as in-scope traffic.
    """
    domain = str(args.get("domain", ""))
    return [(f"amass_domain_in_scope:{domain}", domain in scope.hosts())]


def _nuclei_preconditions(
    args: dict[str, Any], scope: ScopePolicy, state: CorpusState
) -> list[tuple[str, bool]]:
    """Gate ``nuclei.scan`` invocations on the URL's
    ``(host, port, tls)`` matching ``scope.allowed_endpoints`` —
    the same precision the ``Request`` action's gating uses.
    """
    from urllib.parse import urlparse

    url = str(args.get("url", ""))
    parsed = urlparse(url)
    if not parsed.hostname or parsed.scheme not in {"http", "https"}:
        return [(f"nuclei_url_parseable:{url}", False)]
    host = parsed.hostname
    tls = parsed.scheme == "https"
    port = parsed.port  # may be None for default ports
    in_scope = scope.request_in_scope(host, port, tls)
    return [(f"nuclei_endpoint_in_scope:{parsed.scheme}://{host}", in_scope)]


@dataclass(frozen=True)
class ShellInvocation:
    """Dispatch via ``asyncio.create_subprocess_exec``.

    ``argv_template`` is the shell command broken into discrete
    tokens (no shell parsing). Each token may be a literal or
    contain ``{arg_name}`` placeholders that get substituted from
    the action's ``args`` dict at dispatch time. Unsubstituted
    placeholders are an error — the executor (#8) refuses to run
    a partially-templated command.

    No ``shell=True`` ever. The token list is passed directly to
    the kernel; shell metacharacters in args are inert.
    """

    argv_template: tuple[str, ...]
    """The argv template. Tokens with ``{arg_name}`` are
    substituted from the Tool action's ``args``."""
    cwd: str | None = None
    """Optional working directory for the subprocess."""
    env_passthrough: tuple[str, ...] = ()
    """Names of env vars to forward from Modus's own environment.
    Anything else gets a clean (mostly-empty) env."""
    timeout_seconds: float = 60.0
    """Per-call timeout. The executor kills the subprocess if it
    exceeds this and surfaces a timeout error in the observation."""


@dataclass(frozen=True)
class McpInvocation:
    """Dispatch via the host's MCP client to a foreign MCP server.

    The host (Claude Desktop, Claude Code, etc.) typically has
    several MCP servers configured; Modus can reach any of them
    through ``sampling``-like passthrough. This is how filesystem
    reads, web fetches, and other host-provided tools become
    first-class registry entries.
    """

    server_name: str
    """Name of the MCP server the host has configured."""
    tool_name: str
    """The tool's name within that server's surface."""


@dataclass(frozen=True)
class BuiltinInvocation:
    """Dispatch to a Modus-internal callable.

    Used for the six typed-action builtins (Probe, Request, ...),
    and for any future tool where the implementation lives in
    Modus's own codebase rather than as a subprocess or
    cross-server passthrough.
    """

    callable_dotted_path: str
    """Dotted path resolvable to an awaitable callable. Signature:
    ``async def fn(args: dict, session: ServerSession,
    scope: ScopePolicy) -> dict``. Returns an observation dict
    that the executor wraps into a ``ToolObservation``."""


Invocation = ShellInvocation | McpInvocation | BuiltinInvocation


@dataclass(frozen=True)
class ToolSpec:
    """One tool's full registration.

    Carries everything the executor (#8) and consistency checker
    (#9) need: how to dispatch, what arguments are allowed, what
    scope/corpus preconditions must hold before invocation, and
    the side-effect tier (informational for the rest of the
    system; not enforced here).
    """

    name: str
    """Registry key. Lowercase, optionally ``.``-namespaced. Must
    match :class:`~modus.actions.Tool`'s name validation pattern."""
    kind: Literal["shell", "mcp", "builtin"]
    """Dispatch backend selector. The executor switches on this."""
    description: str
    """Operator-facing description. Surfaced into the proposer's
    prompt so the model knows what the tool does."""
    args_schema: dict[str, Any]
    """JSON Schema describing the tool's argument shape. The
    consistency layer validates ``Tool.args`` against this before
    the tool's :attr:`preconditions` function is invoked."""
    side_effect: Literal["read", "write", "active"]
    """``read`` — passive query, no outbound traffic to the target.
    ``write`` — modifies local state (corpus, observation pool).
    ``active`` — generates outbound traffic to the target. Used
    for prompt-side guidance to the proposer; rate-limit / DoS
    avoidance work happens in the executor (#8 followups)."""
    invocation: Invocation
    """How to actually dispatch the tool — ``ShellInvocation``,
    ``McpInvocation``, or ``BuiltinInvocation``."""
    preconditions: PreconditionFn = field(default=_no_preconditions)
    """Function that returns the tool's per-call preconditions
    given (args, scope, corpus_state). Default is the stub
    ``_no_preconditions`` which always rejects, so a registration
    without explicit preconditions can't accidentally execute."""


class ToolRegistry:
    """Registry of available tools, keyed by name.

    Built at server start from (a) Modus's first-party builtin
    registrations (the six typed actions, exposed as builtin tools
    so the seam between "typed" and "tool" is visible from day one)
    and (b) the operator's scope-file ``tools`` block
    (operator-declared shell or MCP entries). Names are unique;
    re-registering an existing name is an error so a typo in the
    scope file can't silently shadow a builtin.

    The registry is *read-mostly* — populated once at session
    construction, queried on every Tool dispatch. No locking
    needed for Python's GIL semantics on dict reads.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        """Add a tool to the registry.

        Raises :class:`ValueError` if the name is already
        registered. Operator config errors should surface here at
        session construction, not silently at dispatch time.
        """
        if spec.name in self._tools:
            raise ValueError(
                f"tool name {spec.name!r} is already registered "
                "(check for duplicate entries in scope.tools or a "
                "collision with a Modus builtin)"
            )
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        """Look up a tool by name, returning ``None`` if absent.

        The consistency layer uses this on every Tool action; an
        absent tool surfaces as the ``tool_registered:<name>``
        precondition failing in the verdict.
        """
        return self._tools.get(name)

    def names(self) -> tuple[str, ...]:
        """All registered tool names, sorted for deterministic
        prompt rendering and audit output."""
        return tuple(sorted(self._tools.keys()))

    def specs(self) -> tuple[ToolSpec, ...]:
        """All registered tool specs, ordered like :meth:`names`."""
        return tuple(self._tools[n] for n in self.names())

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._tools


def builtin_typed_action_specs() -> tuple[ToolSpec, ...]:
    """First-party tool entries for the six typed actions.

    Registered at session construction so the registry has them
    from day one. The :attr:`invocation` here points at builtin
    callables that #10 will land — until then, the
    :attr:`preconditions` default (``_no_preconditions``) rejects
    every Tool emission targeting these names. Typed actions
    continue to dispatch through the legacy
    :func:`modus.consistency._preconditions` switch.

    Once #10 migrates the typed actions to dispatch via the
    registry, these stub registrations become live.
    """
    return (
        ToolSpec(
            name="probe",
            kind="builtin",
            description=(
                "Read what the corpus already knows about a target asset — "
                "the latest httpx record, the jsbundle catalogue, the "
                "endpoint list, or the tech stack. Passive: no network "
                "traffic generated."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "aspect": {
                        "type": "string",
                        "enum": ["httpx", "jsbundle", "endpoints", "tech"],
                    },
                },
                "required": ["target"],
            },
            side_effect="read",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.probe",
            ),
            preconditions=_accept_all_preconditions,
        ),
        ToolSpec(
            name="request",
            kind="builtin",
            description=(
                "Send one HTTP request to a target asset and persist the "
                "request/response pair as a session observation. "
                "active — generates outbound traffic to the target."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    },
                    "path": {"type": "string"},
                    "headers": {"type": "object"},
                    "body": {"type": ["string", "null"]},
                    "port": {"type": ["integer", "null"]},
                    "tls": {"type": "boolean"},
                },
                "required": ["target", "method", "path"],
            },
            side_effect="active",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.request",
            ),
            preconditions=_accept_all_preconditions,
        ),
        ToolSpec(
            name="compare",
            kind="builtin",
            description=(
                "Compare two existing observations along the named "
                "dimensions. Produces a comparison row in the corpus."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "observation_a": {"type": "string"},
                    "observation_b": {"type": "string"},
                    "dimensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                    },
                },
                "required": ["observation_a", "observation_b", "dimensions"],
            },
            side_effect="write",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.compare",
            ),
            preconditions=_accept_all_preconditions,
        ),
        ToolSpec(
            name="differential",
            kind="builtin",
            description=(
                "Differential test across observations along a single "
                "dimension (identity / auth / role / tenant) for a given "
                "bug class (idor / auth_bypass / tenant_isolation)."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "observations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 2,
                    },
                    "dimension": {
                        "type": "string",
                        "enum": ["identity", "auth", "role", "tenant"],
                    },
                    "bug_class": {
                        "type": "string",
                        "enum": ["idor", "auth_bypass", "tenant_isolation"],
                    },
                },
                "required": ["observations", "dimension", "bug_class"],
            },
            side_effect="write",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.differential",
            ),
            preconditions=_accept_all_preconditions,
        ),
        ToolSpec(
            name="annotate",
            kind="builtin",
            description=(
                "Attach an FTS-indexed note to a corpus referent (target, "
                "asset, observation, or evidence)."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "referent": {"type": "string"},
                    "note": {"type": "string"},
                },
                "required": ["referent", "note"],
            },
            side_effect="write",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.annotate",
            ),
            preconditions=_accept_all_preconditions,
        ),
        ToolSpec(
            name="hypothesize",
            kind="builtin",
            description=(
                "Author a Candidate of a given bug class with evidence "
                "references and a four-section rationale "
                "(Vulnerability / Exploit / Evidence / Impact). Terminal "
                "action — every successful Modus session ends with one "
                "or more hypothesize calls. Modus never auto-promotes."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "bug_class": {"type": "string"},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                    },
                    "rationale": {"type": "string"},
                    "severity_hint": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                },
                "required": ["bug_class", "evidence_refs", "rationale"],
            },
            side_effect="write",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.hypothesize",
            ),
            preconditions=_accept_all_preconditions,
        ),
    )


def _promote_finding_preconditions(
    args: dict[str, Any], scope: ScopePolicy, state: CorpusState
) -> list[tuple[str, bool]]:
    """Gate ``corpus.promote_finding`` on the candidate id being
    referenced by something in this run's observation pool.

    Cross-run bleed is structurally undesirable: an autonomous run
    should only promote Candidates that *this* run observed enough
    to vouch for. The check is "candidate_id matches one of the
    Candidates this run authored via :class:`Hypothesize` or that
    came back from a same-run :class:`Tool` invocation of an
    ``analyze_*`` tool". We approximate that with
    ``state.known_evidence`` membership — Hypothesize calls always
    add the new Candidate's id to ``known_evidence`` (per #4), and
    a same-run analyze_*-produced Candidate id flows through the
    same pool when its observation lands.

    If the registered Candidate id wasn't seen this run, the
    promotion is structurally rejected. Operators who explicitly
    want cross-run promotion run ``quarry finding promote`` from
    the CLI, which Modus does not gate.
    """
    candidate_id = str(args.get("candidate_id", ""))
    return [
        (
            f"promote_candidate_in_run_pool:{candidate_id}",
            candidate_id in state.known_evidence,
        ),
    ]


def builtin_corpus_tool_specs() -> tuple[ToolSpec, ...]:
    """First-party tool entries that mutate corpus state via Quarry.

    Currently a single entry: ``corpus.promote_finding``, the
    Candidate→Finding promotion verb. Wired through to Quarry's
    MCP ``finding_promote`` write tool via
    :func:`modus.builtins.corpus.promote_finding`.

    Promotion's structural firewall around external bug-bounty
    submission is *registry membership*, not a per-tool
    precondition: no submission-shaped tool ships in the default
    registry, and adding one is off-limits for scope files. What
    this builtin does is internal: closes the Candidate→Finding
    lifecycle within Quarry. Submission to bounty platforms remains
    a hard non-goal.
    """
    return (
        ToolSpec(
            name="corpus.promote_finding",
            kind="builtin",
            description=(
                "Promote a Candidate to a Finding in the Quarry "
                "corpus. Args: {candidate_id: str, severity: str, "
                "title?: str}. severity is one of info/low/medium/"
                "high/critical. The autonomous loop's policy "
                "promotes severity medium-or-higher Candidates "
                "automatically; severity-low and severity-info "
                "Candidates stay un-promoted for operator review. "
                "Returns the new Finding row. Status is always "
                "'hypothesis' on first promotion. NOT a submission "
                "verb — Modus never submits to bounty platforms."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "title": {"type": "string"},
                },
                "required": ["candidate_id", "severity"],
                "additionalProperties": False,
            },
            side_effect="write",
            invocation=BuiltinInvocation(
                callable_dotted_path="modus.builtins.corpus.promote_finding",
            ),
            preconditions=_promote_finding_preconditions,
        ),
    )


def builtin_recon_tool_specs() -> tuple[ToolSpec, ...]:
    """First-party shell-tool registrations for recon binaries.

    These ship in the default registry so operators get them out
    of the box (assuming the binaries are on ``$PATH``). The
    executor surfaces ``binary not found`` if they aren't —
    operators who don't have ``amass`` or ``nuclei`` installed
    just see those tools error at dispatch, which is the right
    fallback behaviour: the registry entry exists, the proposer
    can emit it, but invocation fails cleanly.

    Each entry's preconditions function is the structural scope
    gate — amass.enum requires the domain to be in
    ``scope.hosts()``; nuclei.scan requires the URL's
    ``(host, port, tls)`` to match ``scope.allowed_endpoints``.
    Without these, the agent could DNS-enumerate or vuln-scan an
    out-of-scope target as easily as an in-scope one.
    """
    return (
        ToolSpec(
            name="amass.enum",
            kind="shell",
            description=(
                "Subdomain enumeration via amass. Args: "
                "{domain: str}. The domain must be in scope. Side "
                "effect is `active` — generates DNS queries to the "
                "target's authoritative servers."
            ),
            args_schema={
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
                "additionalProperties": False,
            },
            side_effect="active",
            invocation=ShellInvocation(
                argv_template=("amass", "enum", "-d", "{domain}", "-timeout", "5"),
                env_passthrough=("PATH", "HOME"),
                timeout_seconds=600.0,
            ),
            preconditions=_amass_preconditions,
        ),
        ToolSpec(
            name="nuclei.scan",
            kind="shell",
            description=(
                "Vulnerability scan with nuclei. Args: "
                "{url: str, templates: list[str]}. The URL's "
                "host:port:tls must be in scope. Side effect is "
                "`active` — sends HTTP requests to the target."
            ),
            args_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "templates": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            side_effect="active",
            invocation=ShellInvocation(
                # ``nuclei -t {templates}`` accepts a comma-joined
                # template list. The placeholder substitutes a
                # str() of the list — operators may want to invoke
                # this directly via stdin or a config file in a
                # follow-up; for v0.3.0 the simple shape ships.
                argv_template=("nuclei", "-u", "{url}", "-jsonl", "-silent"),
                env_passthrough=("PATH", "HOME"),
                timeout_seconds=900.0,
            ),
            preconditions=_nuclei_preconditions,
        ),
    )


def build_default_registry() -> ToolRegistry:
    """Construct a registry pre-populated with Modus's first-party
    tool specs: the six typed-action builtins plus the recon
    shell tools (amass, nuclei).

    Operator-declared tools are added on top by callers that have
    a scope file in hand (see :meth:`modus.session.ServerSession.\
from_scope_file`). The default registry is what every
    :class:`~modus.session.ServerSession` starts with before scope-
    file loading.
    """
    registry = ToolRegistry()
    for spec in builtin_typed_action_specs():
        registry.register(spec)
    for spec in builtin_corpus_tool_specs():
        registry.register(spec)
    for spec in builtin_recon_tool_specs():
        registry.register(spec)
    return registry


__all__ = [
    "BuiltinInvocation",
    "Invocation",
    "McpInvocation",
    "PreconditionFn",
    "ShellInvocation",
    "ToolRegistry",
    "ToolSpec",
    "build_default_registry",
    "builtin_corpus_tool_specs",
    "builtin_recon_tool_specs",
    "builtin_typed_action_specs",
]
