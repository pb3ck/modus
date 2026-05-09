"""Tests for the WordPress plugin CVE registry.

The registry is the lookup that turns ``plugin_version_disclosure``
fingerprints (slug + version) into bug-class-correct candidates with
the upstream CVE's severity. Curated subset, not the full Wordfence
feed — see issue #32 for the architectural constraints.
"""

from __future__ import annotations

from modus.cve_registry import (
    PluginCve,
    _parse_version,
    _version_in_range,
    all_known_slugs,
    lookup_cves,
)


class TestParseVersion:
    def test_dotted_version(self) -> None:
        assert _parse_version("5.3.1") == (5, 3, 1)

    def test_multi_segment_wp_version(self) -> None:
        # WordPress plugin versions sometimes have 4 segments.
        assert _parse_version("4.1.5.2") == (4, 1, 5, 2)

    def test_strips_trailing_qualifier(self) -> None:
        assert _parse_version("5.3.1-beta") == (5, 3, 1)
        assert _parse_version("5.3.1-RC1") == (5, 3, 1)

    def test_empty_returns_zero(self) -> None:
        # Pathological input: don't crash; return a comparable tuple
        # that's lower than any real version.
        assert _parse_version("") == (0,)
        assert _parse_version("not-a-version") == (0,)


class TestVersionInRange:
    def test_inclusive_lower(self) -> None:
        assert _version_in_range((5, 3, 0), (5, 3, 0), (5, 3, 5))

    def test_inclusive_upper(self) -> None:
        assert _version_in_range((5, 3, 5), (5, 3, 0), (5, 3, 5))

    def test_below_range(self) -> None:
        assert not _version_in_range((5, 2, 9), (5, 3, 0), (5, 3, 5))

    def test_above_range(self) -> None:
        assert not _version_in_range((5, 3, 6), (5, 3, 0), (5, 3, 5))

    def test_different_segment_counts(self) -> None:
        # Tuple compare handles ``(5, 3) < (5, 3, 1)`` — Python's
        # default lexicographic semantics. The registry stores the
        # bound tuples explicitly so this is fine.
        assert _version_in_range((5, 3, 1), (5, 3), (5, 4))


class TestLookupCves:
    """The 2026-05-09 wp-lab pinned plugin versions are the canonical
    test fixtures here — the registry exists to make them resolve
    correctly. If these break, the lab calibration baseline gets
    under-credited for plugin-CVE recall."""

    def test_contact_form_7_5_3_1_matches_cve_2020_35489(self) -> None:
        matches = lookup_cves("contact-form-7", "5.3.1")
        assert any(c.cve == "CVE-2020-35489" for c in matches)
        primary = next(c for c in matches if c.cve == "CVE-2020-35489")
        assert primary.bug_class == "rce"
        assert primary.severity == "high"

    def test_elementor_3_6_2_matches_cve_2022_1329(self) -> None:
        matches = lookup_cves("elementor", "3.6.2")
        assert any(c.cve == "CVE-2022-1329" for c in matches)

    def test_elementor_3_6_5_no_match(self) -> None:
        # 3.6.3+ is the fix; 3.6.5 should NOT match CVE-2022-1329.
        matches = lookup_cves("elementor", "3.6.5")
        assert not any(c.cve == "CVE-2022-1329" for c in matches)

    def test_wp_statistics_13_0_7_matches(self) -> None:
        matches = lookup_cves("wp-statistics", "13.0.7")
        assert any(c.cve == "CVE-2022-25148" for c in matches)

    def test_woocommerce_payments_5_6_1_matches(self) -> None:
        matches = lookup_cves("woocommerce-payments", "5.6.1")
        assert any(c.cve == "CVE-2023-28121" for c in matches)
        primary = next(c for c in matches if c.cve == "CVE-2023-28121")
        assert primary.bug_class == "auth_bypass"
        assert primary.severity == "critical"

    def test_aioseo_4_1_5_2_matches(self) -> None:
        # The wp-lab woo-shop profile pins 4.1.5.2 because 4.1.5.0 was
        # yanked from wp.org's archive. 4.1.5.2 is in the same
        # vulnerable window (fix landed in 4.1.5.3).
        matches = lookup_cves("all-in-one-seo-pack", "4.1.5.2")
        assert any(c.cve == "CVE-2021-25036" for c in matches)

    def test_aioseo_4_1_5_3_no_match(self) -> None:
        # Fixed-in version must NOT match.
        matches = lookup_cves("all-in-one-seo-pack", "4.1.5.3")
        assert not any(c.cve == "CVE-2021-25036" for c in matches)

    def test_unknown_slug_returns_empty(self) -> None:
        assert lookup_cves("not-a-real-plugin", "1.0.0") == ()

    def test_known_slug_unaffected_version_returns_empty(self) -> None:
        # Latest akismet should not match anything in the curated set.
        assert lookup_cves("akismet", "5.3.0") == ()

    def test_slug_match_is_case_insensitive(self) -> None:
        upper = lookup_cves("CONTACT-FORM-7", "5.3.1")
        lower = lookup_cves("contact-form-7", "5.3.1")
        assert {c.cve for c in upper} == {c.cve for c in lower}

    def test_empty_inputs_return_empty(self) -> None:
        assert lookup_cves("", "5.3.1") == ()
        assert lookup_cves("contact-form-7", "") == ()


class TestRegistryShape:
    def test_known_slugs_includes_lab_plugins(self) -> None:
        # All 5 wp-lab pinned plugins must be in the registry — the
        # registry's job is to credit those exact (slug, version) pairs.
        slugs = all_known_slugs()
        for required in (
            "contact-form-7",
            "elementor",
            "wp-statistics",
            "woocommerce-payments",
            "all-in-one-seo-pack",
        ):
            assert required in slugs, f"registry missing {required!r}"

    def test_each_entry_has_required_fields(self) -> None:
        # Sanity check: every entry must populate the fields the
        # detector reads. Without these the candidate emission code
        # would crash on ``primary.bug_class`` / ``primary.severity``.
        from modus.cve_registry import _load_registry

        for entry in _load_registry():
            assert isinstance(entry, PluginCve)
            assert entry.slug
            assert entry.cve
            assert entry.bug_class in {
                "info_disclosure",
                "auth_bypass",
                "idor",
                "rce",
                "sqli",
                "csrf",
                "ssrf",
                "weak_credential",
            }, f"{entry.cve}: invalid bug_class {entry.bug_class!r}"
            assert entry.severity in {"info", "low", "medium", "high", "critical"}
            assert entry.affected_ranges  # non-empty
            assert entry.summary.strip()
