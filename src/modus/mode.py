"""Operating-mode toggle: ``free`` vs ``strict``.

The 2026-05-10 wp-bounty-lab calibration showed that Modus's
single-mode design — typed actions, 240-char body excerpts, all
stated invariants always on — caps what the LLM can find against
modern hardened plugins. ``claude-bug-bounty``-style agents trade
audit-trail and methodology defensibility for raw LLM flexibility:
full body context, shell-tool wrappers, free-form curl. They find
more bugs at the cost of provenance.

This module is the toggle between those design positions.

Modes:

* **``free`` (default)** — Productive bug-hunting mode. The LLM gets
  larger response-body context (4 KB excerpts vs 240-char tail),
  and (in future commits) wrapped scanner tools. Z3 scope
  enforcement + per-run isolation invariants STAY ON: the looser
  position only relaxes the LLM's *visibility*, never the safety
  perimeter. ``MODUS_MODE`` unset → free.

* **``strict``** — Audit-defensible mode. The original Modus
  invariants exactly: 240-char body excerpts, no scanner-tool
  wrapping, every action passes through the typed-grammar +
  Z3 + detector pipeline. Use for engagements where the operator
  needs to defend the methodology in a triage call, an attack-of-
  the-week post-mortem, or a regulatory review. ``MODUS_MODE=strict``.

Both modes preserve:

* Scope policy (allow-list enforcement; ``ScopePolicy`` is
  load-bearing in either mode)
* Per-run observation isolation (no cross-run evidence leakage)
* Typed action grammar (``Request``, ``Probe``, ``Hypothesize``, etc.)
* Z3 consistency precondition checks
* All deterministic detectors (``evidence_patterns``)

The mode does NOT relax those guarantees — it only adjusts what the
LLM sees and how many tools it has access to.
"""

from __future__ import annotations

import os
from typing import Literal

Mode = Literal["free", "strict"]
"""Operating mode for an autonomous session.

* ``"free"`` — default. Larger LLM context, more tool surface
  available. Optimised for finding bugs.

* ``"strict"`` — opt-in. Original Modus invariants only. Optimised
  for auditable / defensible methodology.
"""

DEFAULT_MODE: Mode = "free"


def mode_from_env(env: dict[str, str] | None = None) -> Mode:
    """Read the operating mode from the environment.

    Honours ``MODUS_MODE`` (case-insensitive). Unset / unrecognised
    values fall back to :data:`DEFAULT_MODE`. Returns the canonical
    lowercased string.
    """
    src = env if env is not None else os.environ
    raw = src.get("MODUS_MODE", "").strip().lower()
    if raw == "strict":
        return "strict"
    if raw == "free":
        return "free"
    return DEFAULT_MODE


# Per-mode constants for body / request-body excerpts in the agent
# loop's history summaries. Strict caps at 240 chars (the original
# value chosen in v0.1 to keep the proposer's prompt bounded under
# small-context-window models). Free expands to 4096 chars so the
# LLM can see enough of each response to extract tokens, parse error
# messages, and identify response-embedded URLs without needing
# additional probe actions.
STRICT_BODY_EXCERPT_LIMIT = 240
FREE_BODY_EXCERPT_LIMIT = 4096


def body_excerpt_limit(mode: Mode) -> int:
    """Return the body-excerpt char limit for ``mode``."""
    if mode == "strict":
        return STRICT_BODY_EXCERPT_LIMIT
    return FREE_BODY_EXCERPT_LIMIT


__all__ = [
    "DEFAULT_MODE",
    "FREE_BODY_EXCERPT_LIMIT",
    "STRICT_BODY_EXCERPT_LIMIT",
    "Mode",
    "body_excerpt_limit",
    "mode_from_env",
]
