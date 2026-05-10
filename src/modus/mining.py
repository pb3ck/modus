"""Mining sub-agent — actively pumps Quarry's analytical surface.

Closes the gap identified in issue #38. Without this module, Quarry's
analytical commands (``analyze_regression``, ``analyze_jsdelta``,
``analyze_interesting``) and retrieval surface (``recall``) are exposed
as MCP tools the LLM proposer *could* call but empirically never does.
The autonomous loop runs propose → prune → execute on the typed
grammar with the corpus's signal-extraction layer dark — Quarry
becomes a write-only logbook instead of the bidirectional reasoning
surface its README promises.

This module:

1. Defines :class:`MiningSignal` — one mined-Candidate render of
   Quarry's analytical output, with the source tool (regression /
   interesting / jsdelta / recall) and a one-line summary.

2. Defines :class:`Miner` — the sub-agent that, on demand, runs the
   three ``analyze_*`` commands and ``recall`` for any new hosts the
   autonomous loop has observed since the last mining pass. Returns a
   deduplicated list of signals.

3. Tolerates per-tool failures gracefully — older Quarry servers
   (pre-M2.5 without ``analyze_*``) and transient MCP hiccups don't
   kill the run. Each tool's failure is logged at INFO and the
   remaining tools continue.

The :class:`AgentLoop` schedules :meth:`Miner.mine` every
``mining_cadence`` steps (default 5). Results land in
:attr:`StepContext.mining_signals` for the next propose call. The
proposer's system prompt renders the signals as a visible block so the
LLM can pivot to re-probe the flagged assets and emit fresh
``Hypothesize`` actions citing this-run evidence_refs.

Why not emit Hypothesize directly from mining? Quarry's
analytical-tool Candidates carry evidence_refs that point into Quarry's
artifact pool — observations the autonomous loop hasn't ingested into
its per-run pool. The :class:`modus.consistency.ConsistencyChecker`
gates ``hypothesize.evidence_refs`` to this-run observations only to
prevent cross-run bleed. Surfacing mining results to the LLM (which
then probes the flagged asset and earns a this-run evidence_ref) keeps
the firewall intact while still feeding the agent the signal it
needs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from modus.corpus import CorpusError, CorpusToolsMissingError

if TYPE_CHECKING:
    from modus.corpus import Candidate
    from modus.session import ServerSession


_LOG = logging.getLogger(__name__)


# Public so test stubs and consumers can build signals directly.
MINING_SOURCES = ("regression", "interesting", "jsdelta", "recall")


@dataclass(frozen=True)
class MiningSignal:
    """One mined-Candidate render of Quarry's analytical output.

    ``source`` is one of :data:`MINING_SOURCES`. ``summary`` is a
    short, prompt-friendly one-liner the proposer renders into the
    system prompt; the full ``rationale`` from the underlying
    Candidate is kept separately for the operator's audit trail but
    not surfaced verbatim to the LLM (keeps the prompt bounded).

    ``evidence_refs`` carries the Quarry-side artifact ids the
    analytical tool cited. The LLM cannot use these directly as
    ``hypothesize.evidence_refs`` (per-run isolation) but they
    appear in the surfaced block as breadcrumbs the LLM can re-probe.
    """

    source: str
    key: str
    summary: str
    rationale: str
    score: float
    evidence_refs: tuple[str, ...]

    @classmethod
    def from_candidate(cls, source: str, candidate: Candidate) -> MiningSignal:
        # Trim the rationale to a single sentence-ish chunk for the
        # one-liner summary. The full rationale lives in
        # ``rationale``; ``summary`` is what the LLM sees inline.
        summary = candidate.rationale.split("\n", 1)[0]
        if len(summary) > 160:
            summary = summary[:157] + "..."
        return cls(
            source=source,
            key=candidate.key,
            summary=summary,
            rationale=candidate.rationale,
            score=candidate.score,
            evidence_refs=tuple(candidate.evidence_refs),
        )


@dataclass
class Miner:
    """Pump Quarry's analytical surface during an autonomous run.

    The autonomous loop holds one :class:`Miner` per session and calls
    :meth:`mine` every ``mining_cadence`` steps. Per call, we run the
    three analyze_* commands plus ``recall`` for any new hosts the
    loop has observed since the previous mining pass, then return a
    deduplicated list of :class:`MiningSignal`. Dedup is keyed on
    ``(source, key)`` so a stable Candidate doesn't re-surface every
    mining pass — only new analytical output reaches the prompt.

    The miner is stateful on purpose: ``_seen_keys`` carries the
    dedup set across calls within one session. A fresh
    :class:`Miner` per session keeps cross-session bleed impossible
    while still letting the same Quarry corpus serve many runs.
    """

    session: ServerSession
    target_name: str
    _seen_keys: set[tuple[str, str]] = field(default_factory=set)
    _recall_seen_hosts: set[str] = field(default_factory=set)

    async def mine(self, *, observed_hosts: frozenset[str] = frozenset()) -> list[MiningSignal]:
        """Run one mining pass and return new signals.

        Tolerates per-tool failures: any ``CorpusError`` (including
        :class:`CorpusToolsMissingError` from older Quarry servers
        that don't expose all analyze_* tools) is logged at INFO and
        we move on to the next tool. The autonomous run survives a
        partially-missing analytical surface.

        ``observed_hosts`` is the set of hostnames the loop has
        observed since the *last* mining pass — used to drive
        ``recall`` lookups. Cross-engagement memory only fires for
        hosts we haven't already recalled this session, keeping the
        prompt growth bounded.
        """
        signals: list[MiningSignal] = []

        for source, fn_name in (
            ("regression", "analyze_regression"),
            ("interesting", "analyze_interesting"),
            ("jsdelta", "analyze_jsdelta"),
        ):
            try:
                async with self.session.with_quarry() as quarry:
                    method = getattr(quarry, fn_name)
                    candidates: list[Candidate] = await method(target=self.target_name)
            except CorpusToolsMissingError as exc:
                _LOG.info(
                    "mining: %s unavailable on this Quarry server (%s) — skipping",
                    fn_name,
                    exc,
                )
                continue
            except CorpusError as exc:
                _LOG.info(
                    "mining: %s failed (%s) — skipping this pass",
                    fn_name,
                    exc,
                )
                continue
            except Exception as exc:  # broad: an analytical tool bug shouldn't kill the run
                _LOG.warning(
                    "mining: %s raised unexpectedly (%s) — skipping this pass",
                    fn_name,
                    exc,
                )
                continue

            for c in candidates:
                k = (source, c.key)
                if k in self._seen_keys:
                    continue
                self._seen_keys.add(k)
                signals.append(MiningSignal.from_candidate(source, c))

        # Recall pass for every host the loop has observed but we
        # haven't recalled before this session. Bounded by the size
        # of observed_hosts \ _recall_seen_hosts; typical wp-bounty
        # run observes 1 host, so this fires once.
        new_hosts = observed_hosts - self._recall_seen_hosts
        for host in sorted(new_hosts):
            self._recall_seen_hosts.add(host)
            try:
                async with self.session.with_quarry() as quarry:
                    hits = await quarry.recall(value=host)
            except CorpusToolsMissingError as exc:
                _LOG.info("mining: recall unavailable (%s) — skipping host=%r", exc, host)
                continue
            except CorpusError as exc:
                _LOG.info("mining: recall failed (%s) — skipping host=%r", exc, host)
                continue
            except Exception as exc:  # broad
                _LOG.warning("mining: recall raised (%s) — skipping host=%r", exc, host)
                continue
            for hit in hits:
                # ``recall`` returns dicts (one per engagement-match);
                # synthesize a Candidate-shaped signal so the
                # downstream renderer treats it uniformly.
                target = str(hit.get("target") or hit.get("target_name") or "")
                kind = str(hit.get("kind") or hit.get("source") or "match")
                key = f"{host}@{target}"
                if ("recall", key) in self._seen_keys:
                    continue
                self._seen_keys.add(("recall", key))
                summary = f"{host} seen in target={target!r} (source={kind})"
                signals.append(
                    MiningSignal(
                        source="recall",
                        key=key,
                        summary=summary,
                        rationale=summary,
                        score=0.5,
                        evidence_refs=(),
                    )
                )

        if signals:
            _LOG.info(
                "mining surfaced %d new signal(s): %s",
                len(signals),
                ", ".join(f"{s.source}:{s.key}" for s in signals[:5])
                + ("..." if len(signals) > 5 else ""),
            )
        return signals


def render_mining_block(signals: tuple[MiningSignal, ...]) -> str:
    """Render mined signals as a markdown block for the system prompt.

    Returns the empty string when ``signals`` is empty so the prompt
    builder can unconditionally call this and skip the section
    without a guard. Kept short — the LLM treats this as breadcrumbs,
    not as a complete picture; the underlying ``rationale`` stays
    inside the session record for the operator.
    """
    if not signals:
        return ""
    lines = [
        "# Quarry analytical layer — mined signals",
        "",
        (
            "Each entry below was produced by Quarry's deterministic "
            "analytical tools running over the corpus. They are NOT "
            "this-run observations — you cannot cite their evidence_refs "
            "directly in a ``hypothesize`` action (per-run isolation). "
            "If a signal looks worth investigating, re-probe the cited "
            "asset and emit a fresh ``hypothesize`` whose evidence_refs "
            "point at the observations from your re-probe."
        ),
        "",
    ]
    for s in signals:
        ref_hint = (
            f" (Quarry evidence_refs: {', '.join(s.evidence_refs[:3])}"
            f"{'...' if len(s.evidence_refs) > 3 else ''})"
            if s.evidence_refs
            else ""
        )
        lines.append(f"- **[{s.source}]** {s.key} (score={s.score:.2f}): {s.summary}{ref_hint}")
    lines.append("")
    return "\n".join(lines)
