"""LLM proposer.

The proposer samples ``N`` candidate actions per autonomous step.
The consistency layer prunes the inconsistent ones; the agent loop
ranks survivors and executes the top ``K``. ADR 0002 is the
load-bearing document for this shape; ADR 0003 plants it inside
an MCP tool handler rather than a CLI loop.

The proposer is provider-portable per the project's portability
rule. Concrete implementations:

* :class:`AnthropicProposer` — uses the Anthropic Messages API.
  Structured around prompt caching: the action grammar, the scope,
  and the stable target context all sit in the cached prefix
  (``cache_control={"type": "ephemeral"}``); only per-step
  retrieval and history flow uncached.
* :class:`OpenAICompatibleProposer` — uses the OpenAI Chat
  Completions API with optional ``base_url`` to cover OpenAI,
  OpenAI-compatible local servers (Ollama, vLLM), and proxies
  (OpenRouter). No cache directives — degrades to structural
  prompt discipline only.
* :class:`HostSamplingProposer` — delegates to the MCP host's
  LLM via ``sampling/createMessage`` (ADR 0003 §3). Subscription-
  billed in principle; in practice neither Claude Desktop nor
  Claude Code v2.1.136 currently advertise this capability, so
  this provider returns "Method not found" against Anthropic's
  products as of 2026-05-08.
* :class:`ClaudeCliProposer` — workaround for the host-sampling
  gap above. Shells out to ``claude --print`` per proposer call,
  using the user's Claude Code authentication (subscription
  billing) without depending on the MCP sampling protocol.
  Trade-off: ~3 seconds of Node startup overhead per call.

All implementations share :class:`_LlmProposerBase` for the
prompt construction, response parsing, and validation logic that
isn't provider-specific. Adding a fifth provider is roughly
"implement ``_complete``."
"""

from __future__ import annotations

import json
import logging
import re
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
from pydantic import TypeAdapter, ValidationError

from modus.actions import Action
from modus.recon import (
    build_misconfig_proposals,
    build_weak_credential_proposals,
    build_wp_plugin_proposals,
    build_xmlrpc_followup_proposals,
)

if TYPE_CHECKING:
    from modus.consistency import CorpusState
    from modus.scope import ScopePolicy
    from modus.session import LlmProviderConfig
    from modus.token_extractor import ExtractedToken
    from modus.tools import ToolRegistry


_LOG = logging.getLogger(__name__)
_ACTION_LIST_ADAPTER: TypeAdapter[list[Action]] = TypeAdapter(list[Action])


@dataclass(frozen=True)
class StepContext:
    """Inputs to a single proposer step.

    The agent loop builds one of these at the start of each step
    from the Quarry MCP retrieval surface and its own session
    state. The proposer is pure with respect to this object —
    given the same context it must produce the same proposal
    distribution (modulo LLM sampling temperature).
    """

    corpus_state: CorpusState
    scope: ScopePolicy
    objective: str = ""
    bug_classes: tuple[str, ...] = field(default_factory=tuple)
    retrieval: tuple[str, ...] = field(default_factory=tuple)
    recent_history: tuple[str, ...] = field(default_factory=tuple)
    sample_count: int = 8
    extracted_tokens: dict[str, ExtractedToken] = field(default_factory=dict)
    """Tokens harvested from prior observations by
    :func:`modus.token_extractor.extract_tokens`. Indexed by canonical
    name (e.g. ``"_wpnonce"``). The proposer's prompt renders an
    "available tokens" block so the LLM can embed token values
    literally in its proposed Request actions. ADR 0007."""
    mining_signals: tuple[Any, ...] = field(default_factory=tuple)
    """Mined :class:`modus.mining.MiningSignal` entries the
    autonomous loop's :class:`Miner` produced since the last propose
    call. Surfaced to the LLM via a system-prompt block so it can
    pivot to re-probe flagged assets. Issue #38 — actively pumping
    Quarry's analytical surface during autonomous runs. Typed as
    ``tuple[Any, ...]`` here to keep the modus.proposer module free
    of a hard dependency on :mod:`modus.mining`; the agent loop
    populates this with ``MiningSignal`` instances."""


class Proposer(Protocol):
    """The protocol the agent loop calls each step."""

    async def propose(self, context: StepContext) -> list[Action]:
        """Sample up to ``context.sample_count`` candidate actions.

        The returned list may contain fewer actions than requested
        if the model declined to fill the budget. It must not
        contain *more* than requested. Every element is a fully
        validated :class:`~modus.actions.Action`; the caller hands
        the list straight to :meth:`ConsistencyChecker.prune`.

        Implementations should *not* raise on a malformed model
        response — log the issue and return ``[]`` so the agent
        loop can record an empty step rather than crashing the
        whole session.
        """
        ...


# ----------------------------------------------------------- prompt parts


_VOCABULARY_DESCRIPTION = """\
Available actions, drawn from a typed grammar enforced by an SMT \
consistency check. Each action is a JSON object with a ``kind`` \
discriminator:

- ``probe(target, aspect=httpx|jsbundle|endpoints|tech)`` — read what \
  the corpus already knows about an asset. Passive; no network.
- ``request(target, method, path, headers?, body?, port?, tls=true)`` \
  — send one HTTP request to an in-scope asset. ``target`` MUST be a \
  bare hostname like ``"localhost"`` or ``"api.example.com"`` — NEVER \
  a full URL. The scheme/port are set by the SEPARATE ``port`` and \
  ``tls`` fields, not encoded into ``target``. Method must be in the \
  session's allowed-methods set. ``path`` must start with ``/``. \
  Defaults: ``tls=true`` (HTTPS) on the scheme's standard port. For \
  the (host, port, tls) triples in scope below, copy the values \
  EXACTLY into your action — including ``tls=false`` for plain HTTP. \
  Worked example for ``host="localhost" port=13000 tls=false``: \
  ``{"kind":"request","target":"localhost","port":13000,"tls":false,\
  "method":"GET","path":"/robots.txt"}`` produces \
  ``http://localhost:13000/robots.txt``. \
  COMMON MISTAKE: emitting ``target="http://localhost:13000"`` with \
  ``path="/robots.txt"`` and omitting ``port``/``tls`` — Pydantic \
  accepts the shape, but the SMT layer rejects because ``tls`` \
  defaulted to ``true`` and the (host, port, tls) triple no longer \
  matches scope. Persists request/response pair as a session \
  observation.
- ``compare(observation_a, observation_b, dimensions)`` — diff two \
  existing observations along the named dimensions.
- ``differential(observations, dimension=identity|auth|role|tenant|payload, \
  bug_class=idor|auth_bypass|tenant_isolation|sqli)`` — bug-class \
  oracle across observations. Identity-class dimensions \
  (identity/auth/role/tenant) drive idor/auth_bypass/tenant_isolation \
  candidates from same-path-different-caller comparisons. The \
  ``payload`` dimension drives ``sqli`` candidates from \
  same-caller-different-payload comparisons — measurable timing \
  delta (``SLEEP(5)`` payload vs baseline) is a time-based oracle; \
  structural response delta (``UNION SELECT`` payload vs baseline) \
  is a content-based oracle.
- ``annotate(referent, note)`` — attach an FTS-indexed note to a \
  corpus row.
- ``tool(name, args)`` — invoke a registered tool by name with \
  structured arguments. Open-ended dispatch primitive: the \
  operator-configured registry declares what tools are available \
  (recon scanners, content discovery, MCP-passthroughs, custom shell \
  scripts). Use this to reach anything outside the typed-action set \
  above. The consistency layer dispatches preconditions via the \
  registry; emitting a ``tool`` action with an unregistered name \
  fails the precondition check and is silently dropped before \
  execution. **The registry's current contents are listed in the \
  "Registered tools" block below the scope** — invoke any of those \
  by name. Names not in that block fail the precondition check.
- ``hypothesize(bug_class, evidence_refs, rationale, severity_hint?)`` \
  — author a Candidate. Terminal; this is where the agent commits \
  what it found. The ``rationale`` is read by the operator to triage \
  the Candidate; it MUST describe the vulnerability, the exploit, \
  the evidence, and the impact — not a structural verdict like \
  "200 vs 401". Cover four labelled sections: \
  **Vulnerability** — name the bug class and pinpoint where it \
  lives (endpoint, HTTP method, vulnerable parameter or field). \
  **Exploit** — the concrete request that triggers it: method, full \
  path, headers (e.g. ``Content-Type``), and the exact body or query \
  string. A copy-pasteable reproducer (``curl`` one-liner or \
  equivalent) belongs here. \
  **Evidence** — what was in the response that proves exploitation. \
  Cite key fields verbatim ("the body contained \
  ``authentication.token`` decoding to ``id=1, role=admin``"); \
  contrast with the baseline observation referenced in \
  ``evidence_refs``. \
  **Impact** — what the attacker gains. Admin access? PII exposure? \
  Account takeover? Be specific about consequences. \
  ``severity_hint`` MUST be picked deliberately: ``critical`` = \
  unauthenticated admin access, RCE, or mass data exfiltration; \
  ``high`` = auth bypass on privileged accounts or significant data \
  exposure; ``medium`` = single-user IDOR, predictable authorization \
  tokens, meaningful info leaks; ``low`` = minor disclosure (version \
  strings, internal paths); ``info`` = nothing actionable. \
  Defaulting to ``info`` on a clear bypass or exfil is wrong. \
  ``severity_hint`` also gates auto-promotion: medium/high/critical \
  Candidates are auto-promoted to Findings on the next step via \
  ``tool(name="corpus.promote_finding", args=...)``; low/info \
  Candidates are not. See the promotion policy in the system prompt.
"""


_OUTPUT_INSTRUCTIONS = """\
Respond with a single JSON object of the form:

{"actions": [
  {"kind": "...", ...},
  ...
]}

Output JSON only — no surrounding prose, no markdown fence. Each \
action must be valid per the grammar above. Aim for ``sample_count`` \
proposals; fewer is acceptable if the corpus state genuinely \
constrains your options. Don't pad with no-op actions.
"""


def _render_corpus_state(state: CorpusState) -> str:
    return (
        f"in_scope_assets={sorted(state.in_scope_assets)}\n"
        f"allowed_methods={sorted(state.allowed_methods)}\n"
        f"known_observations={sorted(state.known_observations)}\n"
        f"known_evidence={sorted(state.known_evidence)}\n"
    )


def _render_tool_registry(registry: ToolRegistry | None) -> str:
    """Render the registered-tool catalog for the system prompt.

    The 2026-05-10 wp-bounty-lab iteration 2 caught the gap: ``raw.http``
    was correctly registered when the operator opted in, the
    ``tool(name="raw.http", ...)`` action would have passed Z3, but the
    LLM never invoked it because the prompt's action-grammar block
    only enumerated the typed actions. The registry's contents weren't
    visible to the LLM by name.

    This renders the registry's ``specs()`` into a markdown table the
    LLM can scan: tool name, description, args schema, side-effect
    tier. Empty / None registry → empty string (no prompt block), so
    the typed-actions-only invocation paths stay compact.

    Filters out the six typed-action specs (probe/request/compare/etc.)
    since they're already covered by ``_VOCABULARY_DESCRIPTION`` —
    listing them again under "registered tools" would double the prompt
    weight without adding new information.
    """
    if registry is None:
        return ""
    typed_action_names = {
        "probe",
        "request",
        "compare",
        "differential",
        "annotate",
        "hypothesize",
    }
    extra_specs = tuple(s for s in registry.specs() if s.name not in typed_action_names)
    if not extra_specs:
        return ""
    lines = [
        "# Registered tools (invoke via `tool(name=..., args=...)`)",
        "",
        (
            "These are the non-typed-action tools the operator has "
            "registered for this session. Invoke them via the `tool` "
            "action grammar (see Action grammar above). Each entry "
            "lists the canonical name, description, side-effect tier, "
            "and JSON-schema for its `args`. Names not in this list "
            "fail the consistency layer's `tool_registered:<name>` "
            "precondition and are silently dropped."
        ),
        "",
    ]
    for spec in extra_specs:
        lines.append(f"## `{spec.name}` ({spec.side_effect})")
        lines.append("")
        lines.append(spec.description)
        lines.append("")
        # Compact args representation — the full JSON schema can be
        # large; the shape is what the LLM needs.
        if spec.args_schema:
            import json as _json

            args_summary = _json.dumps(spec.args_schema, separators=(",", ":"))
            # Truncate ridiculously-long schemas; keep the head.
            if len(args_summary) > 600:
                args_summary = args_summary[:600] + "…"
            lines.append(f"args: `{args_summary}`")
            lines.append("")
    return "\n".join(lines) + "\n"


def _render_scope(scope: ScopePolicy) -> str:
    """Render scope for the system prompt.

    Exposes the parsed ``(host, port, tls)`` endpoint triples directly
    so the model copies them into ``request`` actions verbatim. Showing
    the URL-form ``allowed_assets`` list is misleading: the model treats
    ``"http://host:port"`` as a candidate ``target`` value and drops
    ``port``/``tls``, which then defaults to ``tls=true`` and fails the
    Z3 endpoint check. The triples below are the ground truth.
    """
    endpoints = scope.endpoints()
    if endpoints:
        endpoint_block = (
            "allowed_endpoints (use these EXACT values in `request` actions):\n"
            + "\n".join(
                f"  - host={e.host!r} port={e.port} tls={str(e.tls).lower()}" for e in endpoints
            )
        )
    else:
        endpoint_block = (
            "allowed_endpoints: (none parseable; fall back to bare hostnames "
            f"from allowed_hosts={sorted(scope.hosts())})"
        )
    return (
        f"target_name={scope.target_name!r}\n"
        f"{endpoint_block}\n"
        f"allowed_methods={sorted(scope.allowed_methods)}\n"
        f"user_agent={scope.user_agent!r}\n"
    )


# ----------------------------------------------------------- response parsing


_JSON_OBJECT_RE = re.compile(r"\{[\s\S]*\}")


def _parse_actions(text: str, sample_count: int) -> list[Action]:
    """Extract validated Action instances from a model response.

    Tolerant of the common LLM-output shapes: JSON object directly,
    JSON wrapped in ```json fences, or JSON embedded in narration.
    Returns at most ``sample_count`` actions. Invalid items are
    dropped with a warning rather than failing the whole batch.
    """
    cleaned = text.strip()
    # Strip code fences if present.
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].lstrip()
    match = _JSON_OBJECT_RE.search(cleaned)
    if match is None:
        _LOG.warning("proposer response had no JSON object; treating as empty batch")
        return []
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        _LOG.warning("proposer response JSON failed to parse: %s", exc)
        return []
    if not isinstance(payload, dict):
        _LOG.warning("proposer response wasn't a JSON object; got %s", type(payload).__name__)
        return []
    raw_actions = payload.get("actions")
    if not isinstance(raw_actions, list):
        _LOG.warning("proposer response missing 'actions' list")
        return []

    out: list[Action] = []
    for entry in raw_actions[:sample_count]:
        try:
            validated = _ACTION_LIST_ADAPTER.validate_python([entry])
        except ValidationError as exc:
            _LOG.info("dropping invalid action proposal: %s", exc.errors()[:1])
            continue
        out.extend(validated)
    return out


# ----------------------------------------------------------- base


class _LlmProposerBase:
    """Shared logic across LLM-backed proposers.

    Subclasses implement :meth:`_complete` — call out to the
    provider, return the raw text response. The rest (prompt
    construction, response parsing, error handling) is shared.
    """

    def __init__(
        self,
        *,
        scope: ScopePolicy,
        model: str,
        max_tokens: int = 4096,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        self._scope = scope
        self._model = model
        self._max_tokens = max_tokens
        self._tool_registry = tool_registry

    def _system_prompt(self) -> str:
        """The cache-friendly prefix: vocabulary + scope + tool registry.

        Stable across all steps in a session — same scope, same action
        grammar, same registry. Anthropic's prompt cache attaches to
        this block. Other providers see it as ordinary system text.

        The registry block lists the non-typed-action tools the
        operator has registered (corpus.promote_finding, recon shells,
        ``raw.http`` when opted-in, operator-declared scope-file
        tools). Without this, the LLM only knows about the six typed
        actions and never reaches for tools it doesn't see by name.
        """
        registry_block = _render_tool_registry(self._tool_registry)
        registry_section = "\n" + registry_block + "\n" if registry_block else ""
        return (
            "You are Modus, an autonomous offensive security agent operating "
            "under formal scope constraints. You propose actions from a typed "
            "vocabulary; an SMT consistency check rejects proposals that "
            "violate scope or precondition rules.\n\n"
            "Promotion & submission policy: Modus closes the Candidate→Finding "
            "lifecycle inside the corpus. After a `hypothesize` lands a "
            "Candidate whose `severity_hint` is `medium`, `high`, or "
            "`critical`, your NEXT proposal on the following step MUST be a "
            "`tool` action invoking `corpus.promote_finding` against that "
            "Candidate's id (with the same severity). Severity-low and "
            "severity-info Candidates stay un-promoted for operator review — "
            "do NOT promote them. Submission to bug-bounty platforms is a "
            "separate, hard non-goal: there is no `submit`, `publish`, "
            "`post`, or equivalent tool in the registry, none will be added, "
            "and you must not propose one. The operator submits Findings to "
            "bounty programmes themselves; Modus's job ends at the Finding "
            "row in Quarry.\n\n"
            "# Action grammar\n\n"
            f"{_VOCABULARY_DESCRIPTION}\n"
            "# Scope (immutable for this session)\n\n"
            f"{_render_scope(self._scope)}"
            f"{registry_section}"
        )

    def _user_prompt(self, context: StepContext) -> str:
        """The per-step zone: corpus state + retrieval + history + ask."""
        objective_block = f"# Objective\n\n{context.objective}\n\n" if context.objective else ""
        retrieval_block = (
            "# Retrieved corpus context\n\n"
            + "\n".join(f"- {item}" for item in context.retrieval)
            + "\n\n"
            if context.retrieval
            else ""
        )
        history_block = (
            "# Recent action history\n\n"
            + "\n".join(f"- {item}" for item in context.recent_history)
            + "\n\n"
            if context.recent_history
            else ""
        )
        # ADR 0007 — extracted-token block. Surfaces curated-pattern-
        # matched values from prior observations so the LLM can embed
        # them literally in nonce-bearing follow-up requests.
        token_block = ""
        if context.extracted_tokens:
            from modus.token_extractor import render_token_block

            token_block = render_token_block(context.extracted_tokens) + "\n"
        # Issue #38 — mined-signal block. Surfaces Candidates from
        # Quarry's analytical layer (analyze_regression, _interesting,
        # _jsdelta) and cross-engagement recall hits, so the LLM can
        # pivot to re-probe flagged assets rather than waiting to
        # discover them via blind exploration.
        mining_block = ""
        if context.mining_signals:
            from modus.mining import render_mining_block

            mining_block = render_mining_block(context.mining_signals) + "\n"
        closing_block = ""
        if context.bug_classes:
            from modus.evidence_patterns import render_patterns

            classes = ", ".join(context.bug_classes)
            patterns_block = render_patterns(context.bug_classes)
            closing_block = (
                "# Closing rule (read this every step)\n\n"
                f"You are testing for: {classes}. If the recent action history "
                "contains observations that EVIDENCE one of these bug classes, "
                "your NEXT action MUST be a `hypothesize` action — do NOT propose "
                "more `request` or `probe` actions. Reference the relevant "
                "observation IDs (the `obs=...` values shown in history) in the "
                "`evidence_refs` list.\n\n"
                f"{patterns_block}\n"
                "When evidence is present, close the loop. Compose the "
                "`rationale` per the four-section format (Vulnerability / "
                "Exploit / Evidence / Impact) spelled out in the action "
                "grammar above; pick `severity_hint` deliberately per the "
                "canonical-instance default in the recognition template "
                "above (and shift up or down per the severity notes). A "
                "one-sentence rationale ('200 vs 401, hence auth bypass') "
                "is insufficient — the operator reads this field to "
                "decide whether to confirm the Finding. "
                "The `rationale` field MUST be a non-empty string with all "
                "four sections inline; emitting `null`, an empty string, or "
                "omitting the field fails Pydantic validation and the "
                "action is silently dropped — your hypothesize won't make "
                "it into the corpus. If you don't have enough context to "
                "write a substantive rationale, propose another `request` "
                "or `probe` instead and gather more evidence first.\n\n"
                "# Auto-promotion rule\n\n"
                "If a `hypothesize` action from a previous step is reflected "
                "in `# Current corpus state` (its Candidate id appears in "
                "the known_observations / Candidate pool) AND its "
                "`severity_hint` was `medium`, `high`, or `critical`, your "
                "NEXT action MUST be:\n\n"
                '    {"kind": "tool", "name": "corpus.promote_finding", '
                '"args": {"candidate_id": "<the candidate id>", '
                '"severity": "<the same severity_hint>"}}\n\n'
                "Severity-low and severity-info Candidates are NOT promoted "
                "— they stay in the corpus as Candidates only, for the "
                "operator to review. Promoting a low/info Candidate is a "
                "policy violation. Do NOT propose a `corpus.promote_finding` "
                "for a Candidate not visible in this run's pool — the "
                "consistency layer rejects cross-run promotion.\n\n"
            )
        return (
            f"{objective_block}"
            "# Current corpus state\n\n"
            f"{_render_corpus_state(context.corpus_state)}\n"
            f"{retrieval_block}"
            f"{history_block}"
            f"{token_block}"
            f"{mining_block}"
            f"{closing_block}"
            f"# Your task\n\n"
            f"Propose up to {context.sample_count} candidate actions. "
            f"{_OUTPUT_INSTRUCTIONS}"
        )

    @abstractmethod
    async def _complete(self, system: str, user: str) -> str:
        """Provider-specific completion call. Return the raw response text."""

    async def propose(self, context: StepContext) -> list[Action]:
        system = self._system_prompt()
        user = self._user_prompt(context)
        try:
            text = await self._complete(system, user)
        except Exception as exc:
            _LOG.warning("proposer LLM call failed: %s", exc)
            return []
        return _parse_actions(text, context.sample_count)


# ----------------------------------------------------------- anthropic


class AnthropicProposer(_LlmProposerBase):
    """Anthropic Messages API proposer with prompt caching.

    The system prompt and the cached prefix sit in a single
    ``system`` block with ``cache_control={"type": "ephemeral"}``,
    so a 5-minute TTL warms across consecutive steps in a session.
    """

    DEFAULT_MODEL = "claude-opus-4-7"

    def __init__(
        self,
        *,
        scope: ScopePolicy,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = 4096,
        client: Any | None = None,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            model=model or self.DEFAULT_MODEL,
            max_tokens=max_tokens,
            tool_registry=tool_registry,
        )
        if client is not None:
            self._client = client
        else:
            self._client = AsyncAnthropic(api_key=api_key)

    async def _complete(self, system: str, user: str) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user}],
        )
        # Concatenate text blocks. Anthropic returns content as a list of
        # blocks; for our use we expect text only, but handle gracefully.
        parts: list[str] = []
        for block in response.content:
            text = getattr(block, "text", None)
            if text is not None:
                parts.append(str(text))
        return "".join(parts)


# ----------------------------------------------------------- openai-compatible


class OpenAICompatibleProposer(_LlmProposerBase):
    """OpenAI Chat Completions proposer.

    Covers OpenAI itself plus any OpenAI-compatible endpoint
    (Ollama, vLLM, OpenRouter, LM Studio, etc.) when ``base_url``
    is set. Uses ``response_format={"type": "json_object"}`` when
    the upstream supports it; falls back to plain text parsing
    otherwise (some local servers reject the parameter).
    """

    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(
        self,
        *,
        scope: ScopePolicy,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        max_tokens: int = 4096,
        client: Any | None = None,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            model=model or self.DEFAULT_MODEL,
            max_tokens=max_tokens,
            tool_registry=tool_registry,
        )
        if client is not None:
            self._client = client
        else:
            self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def _complete(self, system: str, user: str) -> str:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        # Try JSON mode if supported; fall back to text on TypeError or
        # provider-specific BadRequestError. Local servers like older
        # Ollama versions don't recognise the parameter.
        try:
            response = await self._client.chat.completions.create(
                response_format={"type": "json_object"}, **kwargs
            )
        except (TypeError, Exception):
            try:
                response = await self._client.chat.completions.create(**kwargs)
            except Exception:  # pragma: no cover - propagate to caller via return ""
                raise
        choice = response.choices[0]
        content = getattr(choice.message, "content", None) or ""
        return str(content)


# ----------------------------------------------------------- host sampling


class HostSamplingProposer(_LlmProposerBase):
    """Proposer that delegates completion to the MCP host's LLM.

    No direct API connection. Modus's MCP server sends a
    ``sampling/createMessage`` request back to the host on each
    proposer step; the host's LLM (Claude in Claude Desktop / Claude
    Code, whatever the operator is already paying for) generates the
    proposal. Saves the operator from configuring a second provider,
    avoids double-billing the same conversation through two endpoints,
    and keeps the model-selection question in one place — the host's.

    Per the MCP spec, hosts typically prompt the user to approve each
    sampling call. That's a feature, not a bug, when the loop runs
    inside an explicitly-invoked autonomous-session tool: the host's
    user already approved that one tool call, so most hosts auto-allow
    sampling requests originated from inside it. Hosts that prompt per
    call surface the proposer's traffic to the operator transparently.

    Requires the host to support sampling. Claude Desktop and Claude
    Code do; some other MCP hosts don't yet. Operators whose host
    doesn't support sampling should set ``MODUS_LLM_PROVIDER`` to
    ``anthropic`` or ``openai-compatible`` and configure a direct API
    key instead.
    """

    DEFAULT_MODEL = "<host-sampled>"

    def __init__(
        self,
        *,
        scope: ScopePolicy,
        mcp_session: Any,
        max_tokens: int = 4096,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            model=self.DEFAULT_MODEL,
            max_tokens=max_tokens,
            tool_registry=tool_registry,
        )
        self._session = mcp_session

    async def _complete(self, system: str, user: str) -> str:
        from mcp.types import SamplingMessage, TextContent

        result = await self._session.create_message(
            messages=[SamplingMessage(role="user", content=TextContent(type="text", text=user))],
            max_tokens=self._max_tokens,
            system_prompt=system,
        )
        # ``CreateMessageResult.content`` is a single content block.
        text = getattr(result.content, "text", None)
        if text is None:
            return ""
        return str(text)


# ----------------------------------------------------------- claude-cli


class ClaudeCliProposer(_LlmProposerBase):
    """Proposer that shells out to ``claude --print`` for each call.

    Workaround for the host-sampling gap (#33): Anthropic's MCP
    client implementations don't yet expose ``sampling/createMessage``,
    so :class:`HostSamplingProposer` cannot route proposer calls
    through Claude Desktop or Claude Code's MCP transport. This
    proposer instead invokes the ``claude`` CLI binary as a
    subprocess per call, using its non-interactive ``--print`` mode.

    The CLI reads OAuth/keychain credentials when run without
    ``--bare``, so authenticated sessions bill against the
    operator's Claude Pro/Max subscription rather than an API
    token. The ``cost_usd`` field in the JSON response is
    informational — actual billing flows through the subscription.

    Trade-offs vs. :class:`AnthropicProposer`:

    * **Cost model**: subscription-flat vs. per-token. Long
      engagements eat into the Pro/Max weekly/5-hour quotas,
      after which the CLI falls back to a "rate limit reached"
      error that this proposer surfaces as an empty action list.
    * **Latency**: ~3-5 seconds of Node startup overhead per
      call on top of the LLM round-trip. A 30-step session adds
      ~90-150 seconds of wall-clock vs. direct API.
    * **Default model**: whatever Claude Code defaults to (Opus
      4.7 with 1M context as of 2026-05-08), unless overridden
      via ``MODUS_LLM_MODEL``. Top-tier reasoning by default.
    * **TOS**: Anthropic's terms for programmatic CLI use are
      implicit-OK at best. If they introduce restrictions, this
      provider is the first thing to break. The user is on the
      hook for accepting that risk.

    Configure via ``MODUS_LLM_PROVIDER=claude-cli`` and
    optionally ``MODUS_CLAUDE_BIN`` (defaults to ``claude``;
    operators with nvm-installed binaries set the absolute path).
    """

    DEFAULT_MODEL = "<claude-cli-default>"

    def __init__(
        self,
        *,
        scope: ScopePolicy,
        claude_bin: str = "claude",
        model: str | None = None,
        max_tokens: int = 4096,
        timeout_seconds: float = 120.0,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            model=model or self.DEFAULT_MODEL,
            max_tokens=max_tokens,
            tool_registry=tool_registry,
        )
        self._claude_bin = claude_bin
        self._timeout_seconds = timeout_seconds

    async def _complete(self, system: str, user: str) -> str:
        import asyncio

        # Build argv. ``--print`` (non-interactive), ``--output-format json``
        # (structured response with the model output in ``result``),
        # ``--append-system-prompt`` (Modus's action-grammar prompt sits
        # alongside Claude Code's default system prompt rather than
        # replacing it; ``--system-prompt`` would replace, but the
        # default Claude Code prompt's tool-use rules don't conflict
        # with proposer instructions in practice).
        #
        # NOT using ``--bare``: that mode strips OAuth/keychain reads
        # and forces ANTHROPIC_API_KEY usage, which would defeat the
        # subscription-billing premise.
        argv = [
            self._claude_bin,
            "--print",
            "--output-format",
            "json",
            "--no-session-persistence",  # proposer calls are stateless
            "--append-system-prompt",
            system,
        ]
        if self._model and self._model != self.DEFAULT_MODEL:
            argv.extend(["--model", self._model])

        # Pipe the user prompt via stdin to keep argv bounded — the
        # action-grammar system prompt alone is ~5KB and some shells
        # cap argv length at 256KB.
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            _LOG.error("claude CLI not found at %r: %s", self._claude_bin, exc)
            return ""
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=user.encode("utf-8")),
                timeout=self._timeout_seconds,
            )
        except TimeoutError:
            _LOG.error(
                "claude --print timed out after %.1fs; killing subprocess",
                self._timeout_seconds,
            )
            proc.kill()
            await proc.wait()
            return ""

        if proc.returncode != 0:
            _LOG.error(
                "claude --print exited %d: %s",
                proc.returncode,
                stderr.decode("utf-8", errors="replace")[:500],
            )
            return ""

        try:
            payload = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            _LOG.error("claude --print returned non-JSON: %s", exc)
            return ""

        if payload.get("is_error"):
            _LOG.error(
                "claude --print reported error: %s",
                payload.get("api_error_status") or payload.get("result"),
            )
            return ""

        result = payload.get("result")
        if not isinstance(result, str):
            return ""
        return result


# ----------------------------------------------------------- factory


class ReconAugmentedProposer:
    """Wraps another :class:`Proposer` with a deterministic recon floor.

    Two scout buckets prepended to the inner proposer's batch each
    step (capped — LLM creativity stays in the mix):

    * **Misconfig probes** — ``/.git/config``, ``/wp-config.php.bak``,
      ``/wp-content/debug.log`` and ~25 other high-signal paths on each
      in-scope endpoint, drained in curated priority order across steps.
    * **WordPress plugin fingerprints** — once a WordPress marker
      appears in history, ``/wp-content/plugins/<slug>/readme.txt`` for
      ~30 popular slugs gets prepended too.

    Why prepend (not append): the agent loop's "first novel survivor"
    ranker means appended proposals only execute when the LLM's batch
    is fully duplicated. The 2026-05-09 wp-lab calibration baseline
    showed this gap empirically — appended scout proposals never landed
    a single ``/wp-content/plugins/<slug>/readme.txt`` despite firing
    every step. Prepending puts the curated list ahead of LLM creative
    paths, so each step the highest-priority unprobed scout path wins.

    Why a cap (``misconfig_per_step`` / ``plugin_per_step``): with no
    cap, scout would emit hundreds of proposals per step and crowd out
    the LLM batch entirely. With a small cap (4 each), only the top-N
    unprobed scout paths land in the proposal batch — the rest of the
    curated list waits for next step. The LLM's full ``sample_count``
    follows after, keeping creative slots available when scout's
    proposals all duplicate (or when scout has nothing to say).

    Disable per-session via ``recon_floor=False`` in :func:`make_proposer`
    if the operator wants pure LLM-driven recon (e.g. ablation tests).
    """

    # Per-step caps. 1 each → at most 2 prepended scout proposals on
    # scout-led steps. The 2026-05-09 wp-lab v4 baseline showed why
    # higher caps are bad: with cap=4+4 and unconditional prepend,
    # scout dominated 22 of 25 steps, the LLM never emitted a
    # candidate, recall fell to 6.7%. 1+1 + interleaved scheduling
    # (see ``propose``) keeps scout to ~50% of the budget.
    DEFAULT_MISCONFIG_PER_STEP: int = 1
    DEFAULT_PLUGIN_PER_STEP: int = 1

    def __init__(
        self,
        inner: Proposer,
        *,
        scope: ScopePolicy,
        misconfig_per_step: int | None = None,
        plugin_per_step: int | None = None,
    ) -> None:
        self._inner = inner
        self._scope = scope
        self._misconfig_per_step = (
            misconfig_per_step
            if misconfig_per_step is not None
            else self.DEFAULT_MISCONFIG_PER_STEP
        )
        self._plugin_per_step = (
            plugin_per_step if plugin_per_step is not None else self.DEFAULT_PLUGIN_PER_STEP
        )

    async def propose(self, context: StepContext) -> list[Action]:
        proposals = await self._inner.propose(context)

        # Always-on follow-ups that key off specific history signals
        # (rather than parity-based scheduling). These are tightly
        # gated so they don't crowd the LLM batch — only fire when a
        # specific recon result calls for them.
        followups: list[Action] = []
        followups.extend(build_xmlrpc_followup_proposals(self._scope, context.recent_history))
        followups.extend(build_weak_credential_proposals(self._scope, context.recent_history))

        # Two-level interleave:
        #
        # 1. **LLM vs scout** by history-length parity. Even-parity
        #    (length 0, 2, 4, ...) is LLM-led — no scout prepended,
        #    the inner batch flows through unchanged. The 2026-05-09
        #    v4 baseline showed why this matters: with scout prepending
        #    every step, scout's curated list always has an unprobed
        #    path to lead with, the LLM never wins the "first novel
        #    survivor" race, recall fell to 6.7%. Half the steps go
        #    to the LLM so it keeps emitting novel paths.
        #
        # 2. **Misconfig vs plugin** within scout-led steps. Without
        #    bucket alternation, plugin proposals always sit *after*
        #    misconfig in the scout batch — and scout's misconfig list
        #    almost always has something unprobed (~30 paths x N
        #    hosts). The 2026-05-09 v5 baseline showed plugin probes
        #    never won a slot. Now scout-led steps alternate: scout
        #    step #0 → misconfig only, scout step #1 → plugin only,
        #    scout step #2 → misconfig, etc. Plugin gets dedicated
        #    slots so plugin-CVE coverage starts to land.
        #
        # Net pattern over 40 steps: 20 LLM-led, 10 misconfig-led,
        # 10 plugin-led. Plugin sweep drains 10 of its priority list
        # within budget — enough for the highest-installed-base slugs.
        history_len = len(context.recent_history)
        if history_len % 2 == 0:
            return [*followups, *proposals]

        # Scout step index counts only the scout-led iterations, so
        # bucket alternation tracks scout-budget rather than total
        # session steps.
        scout_step_index = history_len // 2
        if scout_step_index % 2 == 0:
            scout = build_misconfig_proposals(
                self._scope,
                context.recent_history,
                limit=self._misconfig_per_step,
            )
        else:
            scout = build_wp_plugin_proposals(
                self._scope,
                context.recent_history,
                limit=self._plugin_per_step,
            )
        return [*followups, *scout, *proposals]


def make_proposer(
    *,
    llm: LlmProviderConfig,
    scope: ScopePolicy,
    mcp_session: Any | None = None,
    recon_floor: bool = True,
    tool_registry: ToolRegistry | None = None,
) -> Proposer:
    """Construct the right proposer for the operator's configured provider.

    Called by the autonomous-session tool handler in ``server.py``
    once it's confirmed the LLM provider is configured. Provider
    portability lives here — adding a fourth provider is "add a
    branch."

    When ``llm.provider == "host"``, the caller must pass the
    in-flight MCP session so the proposer can route sampling requests
    back to the host. Other providers ignore ``mcp_session``.

    The result is wrapped with :class:`ReconAugmentedProposer` unless
    ``recon_floor=False`` — that adds a deterministic floor of common
    misconfig and WordPress plugin probes to every proposal batch.
    Operators measuring pure-LLM recon can opt out.
    """
    inner: Proposer
    if llm.provider == "host":
        if mcp_session is None:
            raise ValueError(
                "MODUS_LLM_PROVIDER=host requires an active MCP session. The "
                "autonomous-session tool handler should pass the host's "
                "ServerSession; this proposer cannot work outside an "
                "MCP request context."
            )
        inner = HostSamplingProposer(
            scope=scope, mcp_session=mcp_session, tool_registry=tool_registry
        )
    elif llm.provider == "claude-cli":
        inner = ClaudeCliProposer(
            scope=scope,
            claude_bin=llm.base_url or "claude",
            model=llm.model,
            tool_registry=tool_registry,
        )
    elif llm.provider == "anthropic":
        inner = AnthropicProposer(
            scope=scope,
            api_key=llm.api_key,
            model=llm.model,
            tool_registry=tool_registry,
        )
    elif llm.provider in ("openai", "openai-compatible"):
        inner = OpenAICompatibleProposer(
            scope=scope,
            api_key=llm.api_key,
            base_url=llm.base_url,
            model=llm.model,
            tool_registry=tool_registry,
        )
    else:
        raise ValueError(f"unsupported LLM provider: {llm.provider!r}")

    if recon_floor:
        return ReconAugmentedProposer(inner, scope=scope)
    return inner


# ----------------------------------------------------------- test helpers


class FixedProposer:
    """Deterministic test proposer.

    Returns a pre-loaded list of actions regardless of context.
    Used by tests of the agent loop.
    """

    def __init__(self, actions: list[Action]) -> None:
        self._actions = list(actions)

    async def propose(self, context: StepContext) -> list[Action]:
        return list(self._actions[: context.sample_count])


__all__ = [
    "AnthropicProposer",
    "ClaudeCliProposer",
    "FixedProposer",
    "HostSamplingProposer",
    "OpenAICompatibleProposer",
    "Proposer",
    "ReconAugmentedProposer",
    "StepContext",
    "make_proposer",
]
