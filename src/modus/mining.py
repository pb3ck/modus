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
from typing import TYPE_CHECKING, Any

from modus.corpus import CorpusError, CorpusToolsMissingError

if TYPE_CHECKING:
    from modus.corpus import Candidate
    from modus.session import ServerSession


_LOG = logging.getLogger(__name__)


# Public so test stubs and consumers can build signals directly.
MINING_SOURCES = (
    "regression",
    "interesting",
    "jsdelta",
    "recall",
    "coverage",
    "search",
    "diff",
)


# Bug-class-driven FTS5 queries for the ``search`` mining pass.
# Each bug class fires a curated set of queries against the corpus,
# surfacing operator notes or prior-engagement evidence chunks that
# match. Keys must match values accepted in ``bug_classes`` arrays at
# session start. The queries lean on Quarry's auto-quoting of
# hostname/URL-shaped tokens so we can pass code-shaped strings bare.
#
# Empirical bias: prefer terms that show up in *operator notes* and
# WordPress/web-app code review writeups, since those are what
# cross-engagement search most often retrieves. Terms that only
# match adapter-produced evidence (HTTP response bodies) tend to
# pattern-match across so many engagements they aren't useful.
_SEARCH_QUERIES_BY_CLASS: dict[str, tuple[str, ...]] = {
    "auth_bypass": (
        "permission_callback",
        "is_user_logged_in",
        "current_user_can",
        "rest_no_route",
    ),
    "idor": (
        "user_id",
        "owner",
        "ownership",
        "post_id",
    ),
    "sqli": (
        "wpdb prepare",
        "WHERE clause",
        "SQL error",
        "syntax error",
    ),
    "info_disclosure": (
        "api_key",
        "private",
        "secret",
        "leaked",
    ),
    "rce": (
        "eval(",
        "exec(",
        "system(",
        "remote code",
    ),
}


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
    _search_done: bool = False
    _diff_done: bool = False
    # How many unprobed assets to surface per coverage pass. Bounded
    # so a large discovery-side / empty-probe-side corpus doesn't
    # produce a 500-bullet prompt block. The remainder still lives
    # in the corpus; the operator can drive ``quarry coverage`` from
    # the CLI for the full picture.
    coverage_max_assets_per_pass: int = 10
    # How many search hits to surface per (class, query) pair.
    # Quarry's ``search`` returns up to 10 by default and we have at
    # least one query per bug class — capping to top-3 keeps the
    # bullet count bounded.
    search_max_hits_per_query: int = 3
    # How many added-asset rows from ``diff`` to surface in one
    # session. Same bounding reason as coverage; the remainder lives
    # in the corpus.
    diff_max_assets: int = 10

    async def mine(
        self,
        *,
        observed_hosts: frozenset[str] = frozenset(),
        bug_classes: tuple[str, ...] = (),
    ) -> list[MiningSignal]:
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

        ``bug_classes`` is the set of bug classes declared at session
        start. Drives the ``search`` pass — for each class in
        :data:`_SEARCH_QUERIES_BY_CLASS`, a curated set of FTS5
        queries hits the corpus once per session. Surfaced hits are
        cross-engagement evidence chunks or operator notes whose text
        matches the class's canonical keywords.
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

        # Coverage pass. Quarry's ``coverage`` returns the in-corpus
        # gap between discovery-side artifacts (subfinder, etc.) and
        # probe-side artifacts (httpx, katana, responses). For Modus
        # the actionable signal is: "asset X is in the corpus's
        # discovery side but has no probe artifact — go probe it."
        # Most useful when the operator pre-ingested recon before
        # launching the autonomous run; on a cold-start corpus this
        # typically returns an empty unprobed list, which is fine.
        try:
            async with self.session.with_quarry() as quarry:
                report = await quarry.coverage(target=self.target_name)
        except CorpusToolsMissingError as exc:
            _LOG.info("mining: coverage unavailable (%s) — skipping", exc)
            report = None
        except CorpusError as exc:
            _LOG.info("mining: coverage failed (%s) — skipping this pass", exc)
            report = None
        except Exception as exc:  # broad
            _LOG.warning("mining: coverage raised (%s) — skipping this pass", exc)
            report = None

        if isinstance(report, dict):
            unprobed = report.get("unprobed") or []
            if isinstance(unprobed, list):
                surfaced = 0
                for asset in unprobed:
                    if not isinstance(asset, str) or not asset:
                        continue
                    seen_key: tuple[str, str] = ("coverage", asset)
                    if seen_key in self._seen_keys:
                        continue
                    if surfaced >= self.coverage_max_assets_per_pass:
                        break
                    self._seen_keys.add(seen_key)
                    surfaced += 1
                    note = report.get("note") or ""
                    summary = (
                        "discovered in corpus but no probe artifact yet — probe to close the gap"
                    )
                    if isinstance(note, str) and note:
                        # Trim to keep the bullet bounded.
                        summary = f"{summary}. note: {note[:120]}"
                    signals.append(
                        MiningSignal(
                            source="coverage",
                            key=asset,
                            summary=summary,
                            rationale=(
                                f"Quarry coverage reports {asset} as an "
                                f"unprobed asset for target "
                                f"{self.target_name!r}. The autonomous "
                                f"loop should issue a Request or Probe "
                                f"against this asset before the budget "
                                f"runs out."
                            ),
                            score=0.6,
                            evidence_refs=(),
                        )
                    )

        # Search pass — once per session. For each bug class declared
        # at session start, fire the curated FTS5 queries against the
        # corpus. Cross-engagement evidence and operator notes that
        # match the class's canonical keywords surface as breadcrumbs
        # the proposer can pivot on. Empty corpora / fresh engagements
        # return nothing, which is fine.
        if not self._search_done and bug_classes:
            self._search_done = True
            for bug_class in bug_classes:
                queries = _SEARCH_QUERIES_BY_CLASS.get(bug_class, ())
                for query in queries:
                    search_seen: tuple[str, str] = ("search", f"{bug_class}:{query}")
                    if search_seen in self._seen_keys:
                        continue
                    self._seen_keys.add(search_seen)
                    raw_hits: Any
                    try:
                        async with self.session.with_quarry() as quarry:
                            raw_hits = await quarry.search(query, limit=10)
                    except CorpusToolsMissingError as exc:
                        _LOG.info(
                            "mining: search unavailable (%s) — skipping query=%r",
                            exc,
                            query,
                        )
                        continue
                    except CorpusError as exc:
                        _LOG.info(
                            "mining: search failed (%s) — skipping query=%r",
                            exc,
                            query,
                        )
                        continue
                    except Exception as exc:  # broad
                        _LOG.warning(
                            "mining: search raised (%s) — skipping query=%r",
                            exc,
                            query,
                        )
                        continue
                    hits_iter: list[Any] = list(raw_hits or [])[: self.search_max_hits_per_query]
                    for idx, hit in enumerate(hits_iter):
                        # hit may be a SearchHit dataclass or a dict
                        # depending on Quarry version; pull fields
                        # defensively.
                        snippet_raw: Any = getattr(hit, "snippet", None)
                        if snippet_raw is None and isinstance(hit, dict):
                            snippet_raw = hit.get("snippet")
                        kind_raw: Any = getattr(hit, "kind", None)
                        if kind_raw is None and isinstance(hit, dict):
                            kind_raw = hit.get("kind")
                        target_id_raw: Any = getattr(hit, "target_id", None)
                        if target_id_raw is None and isinstance(hit, dict):
                            target_id_raw = hit.get("target_id")
                        if not isinstance(snippet_raw, str):
                            continue
                        snippet_clip = snippet_raw.replace("\n", " ").strip()
                        if len(snippet_clip) > 200:
                            snippet_clip = snippet_clip[:197] + "..."
                        kind_str = str(kind_raw) if kind_raw else "evidence"
                        target_str = str(target_id_raw) if target_id_raw else ""
                        key = f"{bug_class}:{query}#{idx}"
                        summary = (
                            f"corpus match for {query!r} in {kind_str} "
                            f"(target {target_str!r}): {snippet_clip}"
                        )
                        signals.append(
                            MiningSignal(
                                source="search",
                                key=key,
                                summary=summary,
                                rationale=(
                                    f"Quarry FTS5 search for query={query!r} "
                                    f"(driven by bug_class={bug_class!r}) "
                                    f"surfaced a {kind_str} match. Snippet: "
                                    f"{snippet_clip}"
                                ),
                                score=0.4,
                                evidence_refs=(),
                            )
                        )

        # Diff pass — once per session. Quarry's ``diff`` returns
        # the latest ingest run summary plus the assets first-seen
        # during that run. Useful when the operator runs
        # ``quarry ingest httpx.jsonl`` immediately before launching
        # the audit: the new assets become first-class probe
        # targets for the autonomous loop.
        if not self._diff_done:
            self._diff_done = True
            try:
                async with self.session.with_quarry() as quarry:
                    diff_report = await quarry.diff(target=self.target_name)
            except CorpusToolsMissingError as exc:
                _LOG.info("mining: diff unavailable (%s) — skipping", exc)
                diff_report = None
            except CorpusError as exc:
                _LOG.info("mining: diff failed (%s) — skipping this pass", exc)
                diff_report = None
            except Exception as exc:  # broad
                _LOG.warning("mining: diff raised (%s) — skipping this pass", exc)
                diff_report = None

            if isinstance(diff_report, dict):
                added = diff_report.get("added_assets") or []
                if isinstance(added, list):
                    surfaced = 0
                    for asset in added:
                        if not isinstance(asset, dict):
                            continue
                        value_raw = asset.get("value")
                        if not isinstance(value_raw, str) or not value_raw:
                            continue
                        diff_key: tuple[str, str] = ("diff", value_raw)
                        if diff_key in self._seen_keys:
                            continue
                        if surfaced >= self.diff_max_assets:
                            break
                        self._seen_keys.add(diff_key)
                        surfaced += 1
                        kind_label = str(asset.get("kind") or "asset")
                        first_seen_raw = asset.get("first_seen")
                        first_seen = (
                            str(first_seen_raw)[:19] if isinstance(first_seen_raw, str) else ""
                        )
                        summary = (
                            f"new {kind_label} {value_raw!r} first-seen in the "
                            f"latest ingest run ({first_seen})"
                        )
                        signals.append(
                            MiningSignal(
                                source="diff",
                                key=value_raw,
                                summary=summary,
                                rationale=(
                                    f"Quarry diff against target "
                                    f"{self.target_name!r} reports "
                                    f"{value_raw!r} as a {kind_label} first "
                                    f"seen in the latest ingest run. The "
                                    f"operator just added this; the "
                                    f"autonomous loop should probe it "
                                    f"before older corpus-known assets."
                                ),
                                score=0.55,
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
