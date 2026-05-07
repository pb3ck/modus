"""LLM proposer.

The proposer samples ``N`` candidate actions per agent step. The
consistency layer prunes the inconsistent ones; the value heuristic
ranks the survivors; the executor runs the top ``K``. ADR 0002 is
the load-bearing document for this shape.

The Anthropic-backed proposer is structured around prompt caching:

* **Cached prefix** (one-time per session): the system prompt, the
  rendered action grammar, the scope policy, and the stable target
  context. Marked for caching with the API's cache control flag so
  it stays warm across steps within the 5-minute TTL.
* **Per-step zone** (rebuilt every step): the Quarry MCP retrieval
  results, the agent's recent action/result history (compressed),
  and the "propose ``N`` actions" instruction.

The proposer emits :class:`~modus.actions.Action` instances via
provider-native tool use, so what comes out is grammatical against
:mod:`modus.actions` by construction. Failed JSON parses do not
silently degrade into free-form text — the proposer raises.

The Anthropic implementation is stubbed at Milestone 0; Milestone 3
in the roadmap is "Verifier-driven proposer" and is where the
sampling and cache plumbing lands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from modus.actions import Action
    from modus.consistency import CorpusState
    from modus.scope import ScopePolicy


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
    retrieval: tuple[str, ...] = field(default_factory=tuple)
    recent_history: tuple[str, ...] = field(default_factory=tuple)
    sample_count: int = 8


class Proposer(Protocol):
    """The protocol the agent loop calls each step."""

    async def propose(self, context: StepContext) -> list[Action]:
        """Sample ``context.sample_count`` candidate actions.

        The returned list may contain fewer actions than requested
        if the model declined to fill the budget. It must not
        contain *more* than requested. Every element is a fully
        validated :class:`~modus.actions.Action`; the caller hands
        the list straight to :meth:`ConsistencyChecker.prune`.
        """
        ...


class AnthropicProposer:
    """Anthropic-backed proposer with prompt-cache-aware structure.

    Stub at Milestone 0. The structure is:

    1. ``_cached_prefix`` is built once per session from the action
       grammar, the scope policy, and the stable target context.
       It is sent with ``cache_control={"type": "ephemeral"}``.
    2. ``_step_zone`` is rebuilt every step from
       :class:`StepContext` and is sent uncached.
    3. The model emits actions via tool-use blocks whose schemas
       are derived from :data:`modus.actions.Action`'s discriminated
       union; each tool block becomes one sampled action.
    """

    def __init__(
        self,
        *,
        model: str = "claude-opus-4-7",
        scope: ScopePolicy,
        max_tokens: int = 4096,
    ) -> None:
        self._model = model
        self._scope = scope
        self._max_tokens = max_tokens
        self._cached_prefix: str | None = None

    def _build_cached_prefix(self) -> str:  # pragma: no cover - M3
        """Assemble the prompt zone that stays constant across steps.

        Lands at Milestone 3 with the rest of the proposer. Listed
        here so tests of zone-stability can pin it, and so the cache
        contract is visible in the type signature.
        """
        raise NotImplementedError("AnthropicProposer lands at Milestone 3")

    async def propose(self, context: StepContext) -> list[Action]:  # pragma: no cover - M3
        raise NotImplementedError("AnthropicProposer lands at Milestone 3")


class FixedProposer:
    """Deterministic test proposer.

    Returns a pre-loaded list of actions regardless of context.
    Used by tests of the agent loop and by the
    ``modus action validate`` CLI flow when an operator wants to
    feed in actions from a JSON file rather than from a model.
    """

    def __init__(self, actions: list[Action]) -> None:
        self._actions = list(actions)

    async def propose(self, context: StepContext) -> list[Action]:
        return list(self._actions[: context.sample_count])


__all__ = ["AnthropicProposer", "FixedProposer", "Proposer", "StepContext"]
