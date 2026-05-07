"""Quarry-backed builtin tools.

These are first-party tool callables that mutate corpus state via
Quarry's MCP surface. Each takes the standard builtin signature
``async def(args, session, scope)`` and returns a JSON-serialisable
``dict`` that the :class:`ToolExecutor` records on the resulting
:class:`ToolObservation`.

Currently exposed:

* :func:`promote_finding` — Candidate→Finding promotion. Backs
  the ``corpus.promote_finding`` registry entry.

The tool's structural firewall around external bug-bounty
submission is *not* in this module — that lives at the registry
boundary (no submission-shaped tool ships in
:func:`modus.tools.build_default_registry`, and adding one is
off-limits in scope files). What lives here is the Candidate→
Finding lifecycle close, which is corpus-internal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from modus.scope import ScopePolicy
    from modus.session import ServerSession


async def promote_finding(
    args: dict[str, Any],
    session: ServerSession,
    scope: ScopePolicy,
) -> dict[str, Any]:
    """Promote a Candidate to a Finding via Quarry's MCP write tool.

    Args (validated against the registry's ``args_schema``):

    * ``candidate_id`` (str, required) — full UUID (with or without
      dashes) or a 4+ char hex prefix.
    * ``severity`` (str, required) — one of ``info`` / ``low`` /
      ``medium`` / ``high`` / ``critical``.
    * ``title`` (str, optional) — override for the auto-derived
      title. When omitted, Quarry derives one from the Candidate's
      rationale (first line, truncated to 80 chars).

    Returns the new Finding's fields verbatim from Quarry — see
    :class:`modus.corpus.Finding`. Status is always ``"hypothesis"``
    on first promotion; the operator confirms or escalates via
    ``quarry finding update`` after reproduction.

    Re-promoting the same Candidate raises
    :class:`modus.corpus.CorpusToolError` from Quarry's side
    ("candidate already promoted"). Calling against an older
    Quarry that doesn't expose ``finding_promote`` raises
    :class:`modus.corpus.CorpusToolsMissingError` with a clear
    upgrade message.

    The ``scope`` arg is unused — promotion has no scope
    dimension; the source Candidate's scope was already
    enforced when it was authored.
    """
    candidate_id = str(args["candidate_id"])
    severity = str(args["severity"])
    raw_title = args.get("title")
    title: str | None = None if raw_title is None else str(raw_title)
    async with session.with_quarry() as quarry:
        finding = await quarry.promote_finding(
            candidate_id=candidate_id,
            severity=severity,
            title=title,
        )
    return {
        "finding_id": finding.id,
        "candidate_id": finding.candidate_id,
        "target_id": finding.target_id,
        "severity": finding.severity,
        "title": finding.title,
        "status": finding.status,
        "created_at": finding.created_at,
    }


__all__ = ["promote_finding"]
