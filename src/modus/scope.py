"""Operator-defined scope policy.

Scope is what makes an autonomous agent ethically defensible in
offensive security work. The agent runs without per-step approval;
scope is the structural guarantee it cannot exceed.

Modus encodes scope as preconditions in the consistency layer
(:mod:`modus.consistency`) rather than as prompt language. The LLM
proposer never decides whether something is in scope; the
consistency check rejects every proposed action whose target isn't
in :attr:`ScopePolicy.allowed_assets`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from pathlib import Path


class ScopePolicy(BaseModel):
    """Operator-authored scope envelope for a single Modus session.

    Two axes:

    * **Asset scope** — which hostnames the agent may touch.
      Hostnames are matched exactly. Wildcards are expanded by the
      operator before the policy is loaded; Modus does not expand
      ``*.example.com`` itself, because doing so silently is the
      class of mistake that loses an authorization.
    * **Method scope** — which HTTP methods the session permits.
      Defaults to read-only (``GET``, ``HEAD``, ``OPTIONS``); the
      operator must opt into write methods explicitly.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_name: str = Field(min_length=1, max_length=255)
    allowed_assets: frozenset[str] = Field(default_factory=frozenset)
    allowed_methods: frozenset[str] = Field(
        default_factory=lambda: frozenset({"GET", "HEAD", "OPTIONS"})
    )

    @field_validator("allowed_assets")
    @classmethod
    def _no_wildcards(cls, value: frozenset[str]) -> frozenset[str]:
        for asset in value:
            if "*" in asset or "?" in asset:
                raise ValueError(
                    "ScopePolicy.allowed_assets must contain expanded hostnames; "
                    f"got wildcard pattern: {asset!r}"
                )
        return value

    @field_validator("allowed_methods")
    @classmethod
    def _known_methods(cls, value: frozenset[str]) -> frozenset[str]:
        known = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
        unknown = value - known
        if unknown:
            raise ValueError(f"unknown HTTP method(s) in scope: {sorted(unknown)}")
        return value

    @classmethod
    def from_json(cls, path: Path) -> ScopePolicy:
        """Load a policy from a JSON file the operator authored."""
        return cls.model_validate_json(path.read_text())


__all__ = ["ScopePolicy"]
