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
from modus.recon import build_misconfig_proposals, build_wp_plugin_proposals

if TYPE_CHECKING:
    from modus.consistency import CorpusState
    from modus.scope import ScopePolicy
    from modus.session import LlmProviderConfig


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
- ``differential(observations, dimension=identity|auth|role|tenant, \
  bug_class=idor|auth_bypass|tenant_isolation)`` — bug-class oracle \
  across observations.
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
  execution. **Today the registry is empty** — at v0.3.0a-WIP this \
  action validates structurally but every emission is rejected by \
  the consistency layer. Use one of the typed actions above for now.
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

    def __init__(self, *, scope: ScopePolicy, model: str, max_tokens: int = 4096) -> None:
        self._scope = scope
        self._model = model
        self._max_tokens = max_tokens

    def _system_prompt(self) -> str:
        """The cache-friendly prefix: vocabulary + scope.

        Stable across all steps in a session — same scope and same
        action grammar. Anthropic's prompt cache attaches to this
        block. Other providers see it as ordinary system text.
        """
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
    ) -> None:
        super().__init__(scope=scope, model=model or self.DEFAULT_MODEL, max_tokens=max_tokens)
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
    ) -> None:
        super().__init__(scope=scope, model=model or self.DEFAULT_MODEL, max_tokens=max_tokens)
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
    ) -> None:
        super().__init__(scope=scope, model=self.DEFAULT_MODEL, max_tokens=max_tokens)
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
    ) -> None:
        super().__init__(
            scope=scope,
            model=model or self.DEFAULT_MODEL,
            max_tokens=max_tokens,
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

        # Alternate scout-led and LLM-led steps. The 2026-05-09 wp-lab
        # v4 baseline showed unconditional scout prepend crushes LLM
        # creativity: scout's curated list always has an unprobed path
        # to lead with, so it wins the "first novel survivor" race
        # every single step. Even-parity (history_len even) is LLM-led
        # — no scout prepended, the LLM batch flows through unchanged.
        # Odd-parity is scout-led — 1 misconfig + 1 plugin prepended in
        # priority order. Net over a 40-step budget: ~20 LLM-led +
        # ~20 scout-led actions; scout drains its top-20 priority
        # paths and LLM owns the long-tail novelty exploration.
        history_len = len(context.recent_history)
        if history_len % 2 == 0:
            return list(proposals)

        misconfig = build_misconfig_proposals(
            self._scope, context.recent_history, limit=self._misconfig_per_step
        )
        plugin = build_wp_plugin_proposals(
            self._scope, context.recent_history, limit=self._plugin_per_step
        )
        return [*misconfig, *plugin, *proposals]


def make_proposer(
    *,
    llm: LlmProviderConfig,
    scope: ScopePolicy,
    mcp_session: Any | None = None,
    recon_floor: bool = True,
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
        inner = HostSamplingProposer(scope=scope, mcp_session=mcp_session)
    elif llm.provider == "claude-cli":
        inner = ClaudeCliProposer(
            scope=scope,
            claude_bin=llm.base_url or "claude",
            model=llm.model,
        )
    elif llm.provider == "anthropic":
        inner = AnthropicProposer(scope=scope, api_key=llm.api_key, model=llm.model)
    elif llm.provider in ("openai", "openai-compatible"):
        inner = OpenAICompatibleProposer(
            scope=scope,
            api_key=llm.api_key,
            base_url=llm.base_url,
            model=llm.model,
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
