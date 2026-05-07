"""LLM proposer.

The proposer samples ``N`` candidate actions per autonomous step.
The consistency layer prunes the inconsistent ones; the agent loop
ranks survivors and executes the top ``K``. ADR 0002 is the
load-bearing document for this shape; ADR 0003 plants it inside
an MCP tool handler rather than a CLI loop.

The proposer is provider-portable per the project's portability
rule. Two concrete implementations ship at v0.1:

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

Both implementations share :class:`_LlmProposerBase` for the
prompt construction, response parsing, and validation logic that
isn't provider-specific. Adding a third provider is roughly
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
  — send one HTTP request to an in-scope asset. Method must be in the \
  session's allowed-methods set. Defaults: ``tls=true`` (HTTPS) on the \
  scheme's standard port. For local labs / non-standard ports set both: \
  e.g. ``port=8080, tls=false`` produces ``http://target:8080/path``. \
  Persists request/response pair as a session observation.
- ``compare(observation_a, observation_b, dimensions)`` — diff two \
  existing observations along the named dimensions.
- ``differential(observations, dimension=identity|auth|role|tenant, \
  bug_class=idor|auth_bypass|tenant_isolation)`` — bug-class oracle \
  across observations.
- ``annotate(referent, note)`` — attach an FTS-indexed note to a \
  corpus row.
- ``hypothesize(bug_class, evidence_refs, rationale, severity_hint?)`` \
  — author a Candidate. Terminal; this is where the agent commits \
  what it found. Modus never promotes Candidates to Findings — \
  that's the operator's job.
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
    return (
        f"target_name={scope.target_name!r}\n"
        f"allowed_assets={sorted(scope.allowed_assets)}\n"
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
            "Submission policy: you never submit findings. You never tell the "
            "operator to submit. The terminal action of every successful run "
            "is one or more `hypothesize` calls, which write Candidates the "
            "operator later promotes to Findings via Quarry.\n\n"
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
        return (
            f"{objective_block}"
            "# Current corpus state\n\n"
            f"{_render_corpus_state(context.corpus_state)}\n"
            f"{retrieval_block}"
            f"{history_block}"
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


# ----------------------------------------------------------- factory


def make_proposer(*, llm: LlmProviderConfig, scope: ScopePolicy) -> Proposer:
    """Construct the right proposer for the operator's configured provider.

    Called by the autonomous-session tool handler in ``server.py``
    once it's confirmed the LLM provider is configured. Provider
    portability lives here — adding a fourth provider is "add a
    branch."
    """
    if llm.provider == "anthropic":
        return AnthropicProposer(scope=scope, api_key=llm.api_key, model=llm.model)
    if llm.provider in ("openai", "openai-compatible"):
        return OpenAICompatibleProposer(
            scope=scope,
            api_key=llm.api_key,
            base_url=llm.base_url,
            model=llm.model,
        )
    raise ValueError(f"unsupported LLM provider: {llm.provider!r}")


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
    "FixedProposer",
    "OpenAICompatibleProposer",
    "Proposer",
    "StepContext",
    "make_proposer",
]
