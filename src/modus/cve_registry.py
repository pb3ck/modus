"""WordPress plugin CVE registry — version-fingerprint to bug-class map.

The 2026-05-09 wp-lab calibration baseline showed the gap directly:
``plugin_version_disclosure`` correctly fingerprints
``(slug, version)`` from ``/wp-content/plugins/<slug>/readme.txt``,
but emits ``info_disclosure / info`` because the detector only sees
the version string — it doesn't know which versions of which plugins
are exploitable. The eventual exploit class (``auth_bypass``,
``rce``, ``sqli``) needs a CVE database lookup.

This module is the lookup. It loads a curated JSON registry shipped
with Modus (``data/wp_plugin_cves.json``), parses each entry's
affected version range, and exposes :func:`lookup_cves` for the
evidence-pattern detector to call. When the detector fingerprints a
plugin the registry knows about, the candidate gets escalated:
``bug_class`` switched to the registry's class, ``severity`` bumped
to the registry's, CVE ID + summary appended to the rationale.

Architectural notes:

* The registry is a **curated subset** — not the full Wordfence
  Intelligence feed (~13K entries). Curation keeps the data file
  small enough to ship in the wheel, reviewable in PR, and focused
  on the CVE-version pairs an offensive operator would pivot on.
  Issue #32 tracks the eventual full integration (M9+); the curated
  registry is the calibration shortcut.

* Version comparison uses tuple-of-int parsing — no ``packaging``
  dependency. WordPress plugin versions are dot-separated integers
  (sometimes with trailing ``-beta`` markers we strip). Tuple compare
  handles ``5.3.1 ≤ 5.3.2 ≤ 5.4.0`` correctly.

* The lookup is **read-only** and **side-effect-free**: it cannot
  alter scope, can't write to the corpus, can't call out. Same trust
  posture as the rest of ``evidence_patterns``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files


@dataclass(frozen=True)
class PluginCve:
    """One curated CVE row from ``wp_plugin_cves.json``."""

    slug: str
    cve: str
    fixed_in: str
    bug_class: str
    severity: str
    summary: str
    # Sorted tuple of (min_inclusive, max_inclusive) version-tuple pairs.
    # ``(0, 0, 0)`` is the implicit floor when ``min`` is empty.
    affected_ranges: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]


_VERSION_TOKEN_RE = re.compile(r"\d+")


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers.

    Handles dotted versions (``5.3.1`` → ``(5, 3, 1)``), trailing
    qualifiers (``5.3.1-beta`` → ``(5, 3, 1)``, beta dropped), and
    multi-segment WordPress versions (``4.1.5.2`` → ``(4, 1, 5, 2)``).
    Empty / unparseable input returns ``(0,)`` so range comparisons
    don't crash on malformed registry entries.
    """
    parts: list[int] = []
    for segment in v.split("."):
        match = _VERSION_TOKEN_RE.match(segment)
        if match is None:
            break
        parts.append(int(match.group()))
    return tuple(parts) if parts else (0,)


def _version_in_range(
    v: tuple[int, ...],
    lo: tuple[int, ...],
    hi: tuple[int, ...],
) -> bool:
    """Inclusive range check on parsed version tuples."""
    return lo <= v <= hi


@lru_cache(maxsize=1)
def _load_registry() -> tuple[PluginCve, ...]:
    """Load and parse the curated CVE registry.

    Cached after first call. The registry file is expected to live at
    ``modus.data/wp_plugin_cves.json`` per the package layout.
    """
    raw = files("modus.data").joinpath("wp_plugin_cves.json").read_text(encoding="utf-8")
    parsed = json.loads(raw)
    out: list[PluginCve] = []
    for entry in parsed.get("entries", []):
        ranges_raw = entry.get("affected_versions", [])
        ranges: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
        for lo_raw, hi_raw in ranges_raw:
            lo = _parse_version(str(lo_raw))
            hi = _parse_version(str(hi_raw))
            ranges.append((lo, hi))
        out.append(
            PluginCve(
                slug=entry["slug"].lower(),
                cve=entry["cve"],
                fixed_in=entry.get("fixed_in", ""),
                bug_class=entry["bug_class"],
                severity=entry["severity"],
                summary=entry["summary"],
                affected_ranges=tuple(ranges),
            )
        )
    return tuple(out)


def lookup_cves(slug: str, version: str) -> tuple[PluginCve, ...]:
    """Return all registry entries matching ``(slug, version)``.

    Slug matching is case-insensitive. Version matching uses inclusive
    range bounds against the registry's ``affected_versions`` ranges
    (a single CVE may cover multiple non-contiguous ranges, hence
    "all matching" rather than "first matching").

    Returns an empty tuple when nothing matches — the calling detector
    keeps its baseline ``info_disclosure / info`` candidate without
    escalation.
    """
    if not slug or not version:
        return ()
    parsed_version = _parse_version(version)
    slug_lc = slug.lower()
    matches = []
    for entry in _load_registry():
        if entry.slug != slug_lc:
            continue
        for lo, hi in entry.affected_ranges:
            if _version_in_range(parsed_version, lo, hi):
                matches.append(entry)
                break
    return tuple(matches)


def all_known_slugs() -> frozenset[str]:
    """The set of plugin slugs the registry has any CVE entry for.

    Useful for diagnostic / coverage reporting; not load-bearing for
    the evidence-pattern detector itself.
    """
    return frozenset(entry.slug for entry in _load_registry())


__all__ = [
    "PluginCve",
    "all_known_slugs",
    "lookup_cves",
]
