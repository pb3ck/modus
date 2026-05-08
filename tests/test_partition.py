"""Tests for :mod:`modus.partition`.

The partition step is load-bearing for the recon-to-scope-file
workflow; slips here translate directly to operator slips like the
2026-05-02 ``testsocom.anduril.com`` and 2026-05-08
``piv.usmc.anduril.com`` incidents. Every test here documents either
a real-engagement regression or a class of partition mistake the
maintained token list is meant to prevent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from click.testing import CliRunner

from modus.cli import main
from modus.partition import (
    HostClassification,
    classify_host,
    partition_hosts,
    render_review,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestRegressionSlips:
    """Pin every partition slip we've actually hit in an engagement.

    Each test case is a real hostname from a real engagement that
    went the wrong tier. Adding a new entry here when a slip is
    caught at engagement-time is how the partition knowledge accretes.
    """

    def test_testsocom_substring_match_catches_may02_slip(self) -> None:
        # 2026-05-02 Anduril engagement: ``testsocom.anduril.com``
        # slipped Tier A because the ad-hoc tokenizer split on ``-``
        # only, not substring. ``socom`` is the marker; the
        # ``test`` prefix shouldn't matter.
        c = classify_host("testsocom.anduril.com")
        assert c.tier == "C"
        assert "socom" in c.matched_tokens

    def test_piv_usmc_double_match_catches_may08_slip(self) -> None:
        # 2026-05-08 Anduril engagement: ``piv.usmc.anduril.com``
        # slipped Tier A because ``usmc`` wasn't on the operator's
        # mental list. Today this matches BOTH the ``piv.`` prefix
        # AND the ``usmc`` segment — both should be recorded.
        c = classify_host("piv.usmc.anduril.com")
        assert c.tier == "C"
        # Both markers fire and both go into matched_tokens.
        assert "piv." in c.matched_tokens
        assert "usmc" in c.matched_tokens

    def test_piv_lonestar_classifies_as_tier_c_not_ambiguous(self) -> None:
        # ``lonestar`` alone is ambiguous (could be Texas customer or
        # product codename). But ``piv.<deployment>`` is a
        # credential-gated military/government deployment marker and
        # should win — Tier C is higher precedence than ambiguous.
        c = classify_host("piv.lonestar.anduril.com")
        assert c.tier == "C"
        assert "piv." in c.matched_tokens


class TestTierC:
    """Tier C — DO NOT TOUCH cases."""

    def test_gov_infix(self) -> None:
        c = classify_host("access-metrics.gov.africom.anduril.dev")
        assert c.tier == "C"
        # Both .gov. and africom match.
        assert ".gov." in c.matched_tokens
        assert "africom" in c.matched_tokens

    def test_itar_substring(self) -> None:
        c = classify_host("desert-guardian-itar.anduril.com")
        assert c.tier == "C"
        assert "itar" in c.matched_tokens

    def test_combatant_command_top_level(self) -> None:
        c = classify_host("africom.anduril.com")
        assert c.tier == "C"
        assert "africom" in c.matched_tokens

    def test_combatant_command_substring_in_label(self) -> None:
        # Catches the testsocom-class slip even when the marker is
        # inside a longer label.
        c = classify_host("foo-northcom-bar.anduril.com")
        assert c.tier == "C"
        assert "northcom" in c.matched_tokens

    def test_usaf_segment_match(self) -> None:
        c = classify_host("access-metrics.ais-usaf.anduril.com")
        assert c.tier == "C"
        assert "usaf" in c.matched_tokens

    def test_usaf_does_not_match_inside_unrelated_label(self) -> None:
        # ``usaf`` is segment-matched: it should NOT fire on a
        # hostname like ``usafrica.example.com`` where it's part of
        # a longer word.
        c = classify_host("usafrica.example.com")
        # ``usafrica`` has no segment break between ``usaf`` and ``rica``.
        assert c.tier == "A"

    def test_usmc_segment_match(self) -> None:
        c = classify_host("piv.usmc.anduril.com")
        assert c.tier == "C"
        assert "usmc" in c.matched_tokens

    def test_pentagon_substring(self) -> None:
        c = classify_host("foo.pentagon.example.com")
        assert c.tier == "C"

    def test_darpa_substring(self) -> None:
        c = classify_host("api.darpa-program-x.example.com")
        assert c.tier == "C"

    def test_piv_prefix(self) -> None:
        # PIV (Personal Identity Verification) deployment marker.
        c = classify_host("piv.foo-deployment.anduril.com")
        assert c.tier == "C"
        assert "piv." in c.matched_tokens

    def test_cac_prefix(self) -> None:
        # CAC (Common Access Card, DoD smart-card) deployment.
        c = classify_host("cac.bar-program.example.com")
        assert c.tier == "C"
        assert "cac." in c.matched_tokens


class TestTierB:
    """Tier B — careful, skip cases."""

    def test_infosec_substring(self) -> None:
        c = classify_host("jira-stage-infosec.anduril.dev")
        assert c.tier == "B"
        assert "infosec" in c.matched_tokens

    def test_internal_substring(self) -> None:
        c = classify_host("internal.sentry.anduril.dev")
        assert c.tier == "B"

    def test_azuregov_substring(self) -> None:
        c = classify_host("anduril-development.anduril-azuregov-dev-1.andurildev.com")
        assert c.tier == "B"
        assert "azuregov" in c.matched_tokens

    def test_corp_segment(self) -> None:
        c = classify_host("foo.corp.anduril.com")
        assert c.tier == "B"

    def test_ad_segment_with_dash(self) -> None:
        c = classify_host("ad-dev.andurildev.com")
        assert c.tier == "B"

    def test_ad_segment_does_not_match_inside_word(self) -> None:
        # ``ad`` is segment-matched: should NOT fire on ``addons``
        # or ``readonly`` etc.
        c = classify_host("addons.example.com")
        assert c.tier == "A"

    def test_corp_segment_does_not_match_inside_word(self) -> None:
        # ``corp`` is segment-matched: should NOT fire on ``corporate``
        # or ``incorporate``.
        c = classify_host("incorporate-feature.example.com")
        assert c.tier == "A"


class TestAmbiguous:
    """Ambiguous cases that flag for operator review rather than auto-tiering."""

    def test_lonestar_alone_is_ambiguous(self) -> None:
        c = classify_host("lonestar.anduril.com")
        assert c.tier == "ambiguous"
        assert "lonestar" in c.matched_tokens

    def test_bogey_alone_is_ambiguous(self) -> None:
        c = classify_host("bogey.anduril.com")
        assert c.tier == "ambiguous"

    def test_afn_segment_is_ambiguous(self) -> None:
        c = classify_host("access-metrics.afn.anduril.com")
        assert c.tier == "ambiguous"

    def test_afn_substring_only_does_not_match(self) -> None:
        # ``afn`` is segment-matched; should NOT fire on
        # ``afnabout.example.com`` where ``afn`` is part of a word.
        c = classify_host("afnabout.example.com")
        assert c.tier == "A"


class TestTierA:
    """Tier A — probe-eligible cases. The default tier when no markers match."""

    def test_no_markers_means_tier_a(self) -> None:
        c = classify_host("foxglove.bunker.anduril.dev")
        assert c.tier == "A"
        assert c.matched_tokens == ()

    def test_armory_does_not_match_army(self) -> None:
        # ``armory`` does not contain ``army`` as a substring (the
        # ``o`` is between m and r), so the partition would correctly
        # classify it as Tier A. Pinned as a regression — historically
        # this was the kind of case that motivated explicit handling.
        c = classify_host("armory.anduril.com")
        assert c.tier == "A"

    def test_developer_okta_tier_a(self) -> None:
        c = classify_host("dev-okta.developer.anduril.com")
        assert c.tier == "A"


class TestPartitionHosts:
    """Aggregate partitioning of multiple hostnames."""

    def test_basic_partition(self) -> None:
        result = partition_hosts(
            [
                "armory.anduril.com",
                "africom.anduril.com",
                "internal.sentry.anduril.dev",
                "lonestar.anduril.com",
            ]
        )
        assert len(result.tier_a) == 1
        assert len(result.tier_b) == 1
        assert len(result.tier_c) == 1
        assert len(result.ambiguous) == 1
        assert result.total == 4

    def test_blank_lines_skipped(self) -> None:
        result = partition_hosts(["", "  ", "armory.anduril.com", ""])
        assert result.total == 1

    def test_comment_lines_skipped(self) -> None:
        result = partition_hosts(
            [
                "# this is a comment",
                "armory.anduril.com",
                "# another comment",
            ]
        )
        assert result.total == 1

    def test_duplicates_deduplicated_case_insensitive(self) -> None:
        result = partition_hosts(
            [
                "armory.anduril.com",
                "ARMORY.anduril.com",
                "armory.anduril.com",
            ]
        )
        assert result.total == 1

    def test_whitespace_stripped(self) -> None:
        result = partition_hosts(["  armory.anduril.com  ", "\tafricom.anduril.com\t"])
        assert result.total == 2

    def test_results_sorted_within_tier(self) -> None:
        result = partition_hosts(["zebra.anduril.com", "armory.anduril.com", "monster.anduril.com"])
        assert [c.hostname for c in result.tier_a] == [
            "armory.anduril.com",
            "monster.anduril.com",
            "zebra.anduril.com",
        ]


class TestRenderReview:
    """Markdown report formatting."""

    def test_report_includes_all_sections(self) -> None:
        result = partition_hosts(
            [
                "armory.anduril.com",
                "africom.anduril.com",
                "internal.sentry.anduril.dev",
                "lonestar.anduril.com",
            ]
        )
        out = render_review(result, source="subs-all.txt")
        assert "# Partition Review" in out
        assert "Source: `subs-all.txt`" in out
        assert "Tier C — DO NOT TOUCH (1 hosts)" in out
        assert "Tier B — careful, skip (1 hosts)" in out
        assert "Ambiguous — operator review required (1 hosts)" in out
        assert "Tier A — probe (1 hosts)" in out
        # Tier C / B / ambiguous get inline tables; Tier A is summarised.
        assert "africom.anduril.com" in out
        assert "internal.sentry.anduril.dev" in out
        assert "lonestar.anduril.com" in out
        # Tier A pointer to sibling file rather than inline dump.
        assert "tier-a.txt" in out

    def test_empty_tier_renders_none(self) -> None:
        result = partition_hosts(["armory.anduril.com"])
        out = render_review(result)
        # Tier C section exists but is empty.
        assert "Tier C — DO NOT TOUCH (0 hosts)" in out
        assert "_None._" in out


class TestPrecedence:
    """Precedence: Tier C > ambiguous > Tier B > Tier A."""

    def test_tier_c_beats_ambiguous(self) -> None:
        # Hostname matches both ``socom`` (Tier C) and ``lonestar``
        # (ambiguous). Tier C must win.
        c = classify_host("socom-lonestar-thing.example.com")
        assert c.tier == "C"

    def test_tier_c_beats_tier_b(self) -> None:
        # Matches both ``africom`` (Tier C) and ``corp`` segment (B).
        c = classify_host("foo.corp.africom-program.com")
        assert c.tier == "C"

    def test_ambiguous_beats_tier_b(self) -> None:
        # Matches both ``lonestar`` (ambiguous) and ``corp`` segment (B).
        c = classify_host("lonestar.corp.example.com")
        assert c.tier == "ambiguous"


class TestPartitionCli:
    """The `modus partition` subcommand end-to-end."""

    def test_partition_cli_writes_all_files(self, tmp_path: Path) -> None:
        input_path = tmp_path / "subs.txt"
        input_path.write_text(
            "\n".join(
                [
                    "armory.anduril.com",
                    "africom.anduril.com",
                    "internal.sentry.anduril.dev",
                    "lonestar.anduril.com",
                    "piv.usmc.anduril.com",
                    "",
                    "# trailing comment",
                ]
            )
        )
        output_dir = tmp_path / "partitioned"

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "partition",
                "--input",
                str(input_path),
                "--output-dir",
                str(output_dir),
            ],
        )
        assert result.exit_code == 0, result.output

        # All five output files materialised.
        assert (output_dir / "tier-a.txt").exists()
        assert (output_dir / "tier-b.txt").exists()
        assert (output_dir / "tier-c.txt").exists()
        assert (output_dir / "ambiguous.txt").exists()
        assert (output_dir / "review.md").exists()

        # Content sanity-checks.
        tier_a_lines = (output_dir / "tier-a.txt").read_text().splitlines()
        assert "armory.anduril.com" in tier_a_lines
        # africom + piv.usmc are Tier C.
        tier_c_lines = (output_dir / "tier-c.txt").read_text().splitlines()
        assert "africom.anduril.com" in tier_c_lines
        assert "piv.usmc.anduril.com" in tier_c_lines
        # lonestar is ambiguous.
        ambig_lines = (output_dir / "ambiguous.txt").read_text().splitlines()
        assert "lonestar.anduril.com" in ambig_lines
        # internal.sentry is Tier B.
        tier_b_lines = (output_dir / "tier-b.txt").read_text().splitlines()
        assert "internal.sentry.anduril.dev" in tier_b_lines

        # Console output mentions the ambiguous-review prompt.
        assert "review.md" in result.output.lower() or "Review" in result.output

    def test_partition_cli_json_output(self, tmp_path: Path) -> None:
        import json

        input_path = tmp_path / "subs.txt"
        input_path.write_text("armory.anduril.com\nafricom.anduril.com\n")
        output_dir = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "partition",
                "--input",
                str(input_path),
                "--output-dir",
                str(output_dir),
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["total"] == 2
        assert data["tier_a"] == 1
        assert data["tier_c"] == 1

    def test_partition_cli_missing_input(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "partition",
                "--input",
                str(tmp_path / "does-not-exist.txt"),
                "--output-dir",
                str(tmp_path / "out"),
            ],
        )
        # Click usage error → non-zero exit.
        assert result.exit_code != 0


class TestHostClassificationDataclass:
    """Sanity on the dataclass shape and immutability."""

    def test_classification_is_frozen(self) -> None:
        c = HostClassification(
            hostname="x.example.com",
            tier="A",
            matched_tokens=(),
            rationale="no match",
        )
        try:
            c.tier = "C"  # type: ignore[misc]
        except Exception:
            pass
        else:
            raise AssertionError("HostClassification should be frozen")
