"""Tier A/B/C partition for recon hostnames.

The partition step is the bridge between agent-driven recon (subfinder
output, CT-log enumeration, etc.) and the operator-curated allow-list
that goes into ``ScopePolicy.allowed_assets``. Done freehand, it's a
recurring source of slips — the 2026-05-02 Anduril engagement caught
``testsocom.anduril.com`` slipping into Tier A because the ad-hoc
tokenizer split on hyphens only, not substrings; the 2026-05-08 follow-
up caught ``piv.usmc.anduril.com`` slipping for the symmetric reason
that ``usmc`` wasn't on the operator's mental token list.

This module makes the partition deterministic, versioned, and tested.
The maintained token list under :data:`_MARKERS` is the central place
where engagement learnings accrete — adding a missed marker here
prevents that class of slip in every future engagement.

The submission line stays absolute: this module never decides what to
*probe*. The output is a recommendation; the operator authors
``allowed_assets`` from ``tier-a.txt`` (with optional manual
adjustments) and the structural firewall in :mod:`modus.consistency`
remains the load-bearing safety property.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

#: Tier produced by the partition. ``A`` is probe-eligible, ``B`` is
#: skip-this-engagement-but-not-permanently-banned (corporate /
#: internal / dev markers), ``C`` is DO-NOT-TOUCH (military /
#: government / customer-deployment markers), and ``ambiguous`` flags
#: cases that need explicit operator review rather than auto-tiering.
Tier = Literal["A", "B", "C", "ambiguous"]


@dataclass(frozen=True)
class _TierMarker:
    """One token that classifies hostnames into a tier when matched.

    ``mode`` controls the matching strategy:

    * ``substring``: appears anywhere in the lowercased hostname.
      Suitable for tokens long enough that incidental matches are
      vanishingly rare (``africom``, ``cybercom``, ``pentagon``).
    * ``segment``: must be bounded by a label separator (``.``, ``-``,
      ``_``) or string start/end. Suitable for short tokens that
      could otherwise match incidentally (``ad`` would match
      ``addons``; ``usaf`` would match ``usafrica`` — the segment
      mode prevents both).
    * ``prefix``: matches when the hostname starts with the token.
      Suitable for credential-gated deployment prefixes (``piv.``,
      ``cac.``).
    * ``infix``: literal substring with no boundary check. Distinct
      from ``substring`` only as documentation; the matching
      semantics are identical. Used for tokens whose intent is to
      match across labels (``.gov.``).
    """

    token: str
    mode: Literal["substring", "segment", "prefix", "infix"]
    tier: Tier
    rationale: str


# Maintained token list. Each entry's ``rationale`` is what shows up
# in the partition review report; keep it concrete enough that an
# operator scanning the output can verify the tier was chosen for the
# right reason.
#
# Adding a marker: pick the narrowest ``mode`` that catches the cases
# you've seen without false-positive matching on benign hostnames.
# When in doubt, use ``segment`` — over-tightening produces false
# negatives (slips), but those get caught at engagement-time and fed
# back here; over-eager matching produces false positives that
# silently exclude legitimate probe targets.
_MARKERS: tuple[_TierMarker, ...] = (
    # ---- Tier C — DO NOT TOUCH ----
    # Government/military zone infix
    _TierMarker(".gov.", "infix", "C", "government/military zone"),
    # ITAR — defense export control
    _TierMarker("itar", "substring", "C", "ITAR (defense export control)"),
    # Combatant commands — long enough for substring matching
    _TierMarker("africom", "substring", "C", "AFRICOM (US Africa Command)"),
    _TierMarker("centcom", "substring", "C", "CENTCOM (US Central Command)"),
    _TierMarker("cybercom", "substring", "C", "CYBERCOM (US Cyber Command)"),
    _TierMarker("eucom", "substring", "C", "EUCOM (US European Command)"),
    _TierMarker("indopacom", "substring", "C", "INDOPACOM (Indo-Pacific Command)"),
    _TierMarker("northcom", "substring", "C", "NORTHCOM (Northern Command)"),
    _TierMarker("pacom", "substring", "C", "PACOM (Pacific Command, legacy)"),
    _TierMarker("socom", "substring", "C", "SOCOM (Special Operations Command)"),
    _TierMarker("southcom", "substring", "C", "SOUTHCOM (Southern Command)"),
    _TierMarker("spacecom", "substring", "C", "SPACECOM (Space Command)"),
    _TierMarker("stratcom", "substring", "C", "STRATCOM (Strategic Command)"),
    _TierMarker("transcom", "substring", "C", "TRANSCOM (Transportation Command)"),
    # Service-branch acronyms — short, segment-bounded to avoid false matches
    _TierMarker("usff", "segment", "C", "USFF (US Fleet Forces)"),
    _TierMarker("usaf", "segment", "C", "USAF (US Air Force)"),
    _TierMarker("usmc", "segment", "C", "USMC (US Marine Corps)"),
    _TierMarker("uscg", "segment", "C", "USCG (US Coast Guard)"),
    _TierMarker("ussf", "segment", "C", "USSF (US Space Force)"),
    # Defense agencies / installations
    _TierMarker("pentagon", "substring", "C", "Pentagon"),
    _TierMarker("darpa", "substring", "C", "DARPA"),
    # Credential-gated deployment prefixes
    _TierMarker("piv.", "prefix", "C", "PIV (Personal Identity Verification, smart-card auth)"),
    _TierMarker("cac.", "prefix", "C", "CAC (Common Access Card, DoD smart-card auth)"),
    # ---- Ambiguous — flag for operator review ----
    # These markers COULD be defense-related or could be product
    # codenames; classifying them either way without engagement
    # context is the wrong move.
    _TierMarker(
        "lonestar",
        "substring",
        "ambiguous",
        "'lonestar' — could be Texas state customer or product codename",
    ),
    _TierMarker(
        "bogey",
        "substring",
        "ambiguous",
        "'bogey' — military slang for unknown aircraft, could be product codename",
    ),
    _TierMarker(
        "afn",
        "segment",
        "ambiguous",
        "AFN — could be Armed Forces Network or product abbreviation",
    ),
    # ---- Tier B — careful, skip this run ----
    # Internal / dev / corporate infrastructure markers
    _TierMarker("infosec", "substring", "B", "InfoSec internal infrastructure"),
    _TierMarker("internal", "substring", "B", "internal-only deployment marker"),
    _TierMarker("azuregov", "substring", "B", "Azure Government cloud (federal/military hosting)"),
    _TierMarker("govcloud", "substring", "B", "AWS GovCloud"),
    _TierMarker("gov-cloud", "substring", "B", "GovCloud variant spelling"),
    _TierMarker("corp", "segment", "B", "corporate-internal deployment"),
    _TierMarker("ad", "segment", "B", "Active Directory infrastructure"),
)


def _segment_match(host: str, token: str) -> bool:
    """True if ``token`` appears as a label or hyphen-separated component of ``host``.

    Bounded by ``.``, ``-``, ``_``, or string start/end. Avoids
    incidental matches like ``addons`` for token ``ad``, or
    ``usafrica`` for token ``usaf``.
    """
    pattern = re.compile(rf"(?:^|[.\-_]){re.escape(token)}(?:[.\-_]|$)")
    return bool(pattern.search(host))


def _matches(host: str, marker: _TierMarker) -> bool:
    """Return True iff ``marker.token`` matches ``host`` per ``marker.mode``."""
    h = host.lower()
    t = marker.token.lower()
    if marker.mode == "substring" or marker.mode == "infix":
        return t in h
    if marker.mode == "segment":
        return _segment_match(h, t)
    if marker.mode == "prefix":
        return h.startswith(t)
    raise ValueError(f"unknown match mode: {marker.mode!r}")


@dataclass(frozen=True)
class HostClassification:
    """The partition decision for one hostname.

    ``matched_tokens`` lists every token that fired at the chosen
    tier — typically one, occasionally several when a host hits
    multiple Tier C markers (e.g. ``piv.usmc.anduril.com`` matches
    both ``piv.`` prefix and ``usmc`` segment).
    """

    hostname: str
    tier: Tier
    matched_tokens: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class PartitionResult:
    """Result of partitioning a list of hostnames into tiers."""

    tier_a: tuple[HostClassification, ...]
    tier_b: tuple[HostClassification, ...]
    tier_c: tuple[HostClassification, ...]
    ambiguous: tuple[HostClassification, ...]

    @property
    def total(self) -> int:
        return len(self.tier_a) + len(self.tier_b) + len(self.tier_c) + len(self.ambiguous)


# Tier precedence — higher number wins when a host matches markers at
# multiple tiers. Tier C trumps everything (a ``.gov.`` zone doesn't
# become probe-eligible just because it also matches ``ad``);
# ambiguous trumps Tier B (defaults to "ask" rather than "skip");
# Tier B trumps Tier A.
_TIER_PRECEDENCE: dict[Tier, int] = {"A": 0, "B": 1, "ambiguous": 2, "C": 3}


def classify_host(hostname: str) -> HostClassification:
    """Classify a single hostname into a tier.

    Iterates every marker, collects all matches, picks the highest-
    precedence tier among them. Ties within a tier surface all
    matched tokens in ``matched_tokens`` so the operator can verify
    the partition decision.
    """
    h = hostname.strip()
    if not h:
        raise ValueError("empty hostname")
    matched_markers = [m for m in _MARKERS if _matches(h, m)]
    if not matched_markers:
        return HostClassification(
            hostname=h,
            tier="A",
            matched_tokens=(),
            rationale="no defense/internal markers matched",
        )
    chosen_tier: Tier = max((m.tier for m in matched_markers), key=lambda t: _TIER_PRECEDENCE[t])
    tier_matches = [m for m in matched_markers if m.tier == chosen_tier]
    return HostClassification(
        hostname=h,
        tier=chosen_tier,
        matched_tokens=tuple(m.token for m in tier_matches),
        rationale=" / ".join(m.rationale for m in tier_matches),
    )


def partition_hosts(hostnames: list[str]) -> PartitionResult:
    """Partition a list of hostnames into A/B/C/ambiguous tiers.

    Blank lines and ``#``-prefixed comments in the input are
    skipped. Whitespace around hostnames is stripped. Duplicate
    hostnames are deduplicated (case-insensitively) — a hostname
    appearing twice in the input appears once in the output.
    """
    seen: set[str] = set()
    by_tier: dict[Tier, list[HostClassification]] = {
        "A": [],
        "B": [],
        "C": [],
        "ambiguous": [],
    }
    for raw in hostnames:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        normalised = stripped.lower()
        if normalised in seen:
            continue
        seen.add(normalised)
        classified = classify_host(stripped)
        by_tier[classified.tier].append(classified)
    return PartitionResult(
        tier_a=tuple(sorted(by_tier["A"], key=lambda c: c.hostname)),
        tier_b=tuple(sorted(by_tier["B"], key=lambda c: c.hostname)),
        tier_c=tuple(sorted(by_tier["C"], key=lambda c: c.hostname)),
        ambiguous=tuple(sorted(by_tier["ambiguous"], key=lambda c: c.hostname)),
    )


def render_review(result: PartitionResult, source: str | None = None) -> str:
    """Render a Markdown review report for operator inspection.

    Tier C / B / ambiguous each get a table showing the matched
    tokens and rationale per hostname so the operator can verify the
    decision. Tier A is summarised with a count and a pointer to the
    sibling ``tier-a.txt`` file rather than dumped inline.
    """
    lines: list[str] = ["# Partition Review", ""]
    if source:
        lines.append(f"Source: `{source}`")
    lines.append(f"Total hosts: {result.total}")
    lines.append("")

    def _section(title: str, classifications: tuple[HostClassification, ...]) -> None:
        lines.append(f"## {title} ({len(classifications)} hosts)")
        lines.append("")
        if not classifications:
            lines.append("_None._")
            lines.append("")
            return
        lines.append("| Host | Matched | Reason |")
        lines.append("|------|---------|--------|")
        for c in classifications:
            tokens = ", ".join(f"`{t}`" for t in c.matched_tokens)
            lines.append(f"| `{c.hostname}` | {tokens} | {c.rationale} |")
        lines.append("")

    _section("Tier C — DO NOT TOUCH", result.tier_c)
    _section("Tier B — careful, skip", result.tier_b)
    _section("Ambiguous — operator review required", result.ambiguous)

    lines.append(f"## Tier A — probe ({len(result.tier_a)} hosts)")
    lines.append("")
    lines.append("_See `tier-a.txt` for the full list._")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "HostClassification",
    "PartitionResult",
    "Tier",
    "classify_host",
    "partition_hosts",
    "render_review",
]
