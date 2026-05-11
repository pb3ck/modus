"""Tests for the source-review module.

These verify that curated PHP patterns detect their canonical
shapes, that the responses-shape JSONL output is well-formed, and
that the CLI argument handling rejects bad inputs cleanly.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from modus.source_review import (
    PATTERNS,
    Pattern,
    SourceFinding,
    finding_to_response_record,
    main,
    scan_plugin_source,
)


def _make_plugin(tmp_path: Path, files: dict[str, str]) -> Path:
    """Materialise a fake plugin directory from a path → contents map."""
    root = tmp_path / "fake-plugin"
    root.mkdir()
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


class TestCuratedPatterns:
    def test_every_pattern_has_required_fields(self) -> None:
        for p in PATTERNS:
            assert p.name
            assert p.bug_class in {
                "auth_bypass",
                "sqli",
                "rce",
                "info_disclosure",
                "idor",
                "tenant_isolation",
            }
            assert p.description.strip()
            assert p.regex.pattern

    def test_unauth_ajax_handler_pattern(self) -> None:
        sample = "add_action('wp_ajax_nopriv_process_applicant_form', [$this, 'go']);"
        p = next(p for p in PATTERNS if p.name == "unauth_ajax_handler")
        assert p.regex.search(sample)

    def test_permission_callback_return_true_pattern(self) -> None:
        sample = (
            "register_rest_route('mc4wp/v1', '/form', ["
            "'permission_callback' => '__return_true',"
            "'callback' => [$this, 'h']"
            "]);"
        )
        p = next(p for p in PATTERNS if p.name == "permission_callback_return_true")
        assert p.regex.search(sample)

    def test_unserialize_user_input_pattern(self) -> None:
        sample = "$data = unserialize($_POST['payload']);"
        p = next(p for p in PATTERNS if p.name == "unserialize_user_input")
        assert p.regex.search(sample)

    def test_wpdb_query_pattern(self) -> None:
        sample = '$wpdb->query("DELETE FROM x WHERE id=$_GET[id]");'
        p = next(p for p in PATTERNS if p.name == "wpdb_query_with_user_input")
        assert p.regex.search(sample)

    def test_wp_redirect_open_redirect(self) -> None:
        sample = "wp_redirect($_GET['return_url']);"
        p = next(p for p in PATTERNS if p.name == "wp_redirect_user_input")
        assert p.regex.search(sample)

    def test_safe_code_does_not_match(self) -> None:
        # A safe equivalent (using prepared statements / sanitised
        # output) shouldn't match the dangerous patterns.
        safe_samples = [
            "$wpdb->query($wpdb->prepare('DELETE FROM x WHERE id=%d', $id));",
            "register_rest_route('mc4wp/v1', '/form', ["
            "'permission_callback' => function() { return current_user_can('manage_options'); },"
            "'callback' => [$this, 'h']]);",
            "wp_redirect(esc_url_raw(home_url('/')));",
        ]
        dangerous = {
            "wpdb_query_with_user_input",
            "wpdb_get_results_with_user_input",
            "permission_callback_return_true",
            "wp_redirect_user_input",
        }
        for sample in safe_samples:
            for p in PATTERNS:
                if p.name in dangerous and p.regex.search(sample):
                    pytest.fail(f"safe sample matched dangerous pattern {p.name!r}: {sample!r}")


class TestScanPluginSource:
    def test_scans_php_files_in_directory(self, tmp_path: Path) -> None:
        root = _make_plugin(
            tmp_path,
            {
                "includes/ajax.php": (
                    "<?php\nadd_action('wp_ajax_nopriv_my_action', [$this, 'go']);\n"
                ),
            },
        )
        findings = list(scan_plugin_source(root))
        assert any(f.pattern_name == "unauth_ajax_handler" for f in findings)

    def test_emits_line_number_and_snippet(self, tmp_path: Path) -> None:
        root = _make_plugin(
            tmp_path,
            {
                "ajax.php": (
                    "<?php\n// header comment\n// another\nadd_action('wp_ajax_nopriv_foo', $cb);\n"
                ),
            },
        )
        findings = [f for f in scan_plugin_source(root) if f.pattern_name == "unauth_ajax_handler"]
        assert len(findings) == 1
        f = findings[0]
        assert f.line == 4
        assert "wp_ajax_nopriv_foo" in f.snippet
        # Context window includes surrounding lines.
        assert "header comment" in f.context

    def test_skips_vendor_and_tests(self, tmp_path: Path) -> None:
        root = _make_plugin(
            tmp_path,
            {
                "vendor/lib/something.php": (
                    "<?php\nadd_action('wp_ajax_nopriv_vendor_action', $cb);\n"
                ),
                "tests/test-thing.php": ("<?php\nadd_action('wp_ajax_nopriv_test_action', $cb);\n"),
                "includes/real.php": ("<?php\nadd_action('wp_ajax_nopriv_real_action', $cb);\n"),
            },
        )
        findings = list(scan_plugin_source(root))
        names = [f.path for f in findings]
        assert "includes/real.php" in names
        assert not any("vendor" in n for n in names)
        assert not any("tests" in n for n in names)

    def test_skips_oversized_files(self, tmp_path: Path) -> None:
        # File larger than _MAX_FILE_SIZE (1 MB) is skipped.
        big_content = "<?php\n" + ("// padding\n" * 200_000)  # ~2 MB
        root = _make_plugin(tmp_path, {"huge.php": big_content})
        findings = list(scan_plugin_source(root))
        assert findings == []

    def test_relative_paths_are_clean(self, tmp_path: Path) -> None:
        root = _make_plugin(
            tmp_path,
            {
                "includes/auth/login.php": ("<?php\nadd_action('wp_ajax_nopriv_login', $cb);\n"),
            },
        )
        findings = list(scan_plugin_source(root))
        assert findings[0].path == "includes/auth/login.php"
        assert not findings[0].path.startswith("/")


class TestFindingToResponseRecord:
    def test_record_shape_matches_quarry_responses_adapter(self) -> None:
        f = SourceFinding(
            pattern_name="unauth_ajax_handler",
            bug_class="auth_bypass",
            description="example description",
            path="ajax.php",
            line=42,
            snippet="add_action('wp_ajax_nopriv_foo', $cb);",
            context="// before\nadd_action('wp_ajax_nopriv_foo', $cb);\n// after",
        )
        record = finding_to_response_record(f, "my-plugin")
        # Required fields for Quarry's responses adapter.
        assert "url" in record
        assert "status" in record
        assert "headers" in record
        assert "body" in record
        # The synthetic URL embeds the location.
        assert record["url"] == "file:///plugins/my-plugin/ajax.php#L42"
        # Headers carry the pattern metadata for FTS retrieval.
        assert record["headers"]["X-Modus-Pattern"] == "unauth_ajax_handler"
        assert record["headers"]["X-Modus-Bug-Class"] == "auth_bypass"
        assert record["headers"]["X-Modus-Plugin-Slug"] == "my-plugin"
        # Body is FTS-indexable text containing the matched code.
        assert "wp_ajax_nopriv_foo" in record["body"]
        assert "example description" in record["body"]

    def test_record_is_json_serialisable(self) -> None:
        f = SourceFinding(
            pattern_name="dangerous_eval",
            bug_class="rce",
            description="d",
            path="x.php",
            line=1,
            snippet="eval($x);",
            context="eval($x);",
        )
        record = finding_to_response_record(f, "p")
        # Round-trip cleanly.
        assert json.loads(json.dumps(record))["url"] == record["url"]


class TestCLI:
    def test_writes_jsonl_to_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        plugin = _make_plugin(
            tmp_path,
            {
                "ajax.php": "<?php\nadd_action('wp_ajax_nopriv_x', $c);\n",
            },
        )
        out = tmp_path / "findings.jsonl"
        rc = main(
            [
                "--plugin-dir",
                str(plugin),
                "--slug",
                "test-plugin",
                "--output",
                str(out),
            ]
        )
        assert rc == 0
        lines = out.read_text().strip().splitlines()
        assert len(lines) >= 1
        rec = json.loads(lines[0])
        assert rec["headers"]["X-Modus-Plugin-Slug"] == "test-plugin"

    def test_missing_plugin_dir_returns_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "--plugin-dir",
                str(tmp_path / "nope"),
                "--slug",
                "test",
                "--output",
                str(tmp_path / "out.jsonl"),
            ]
        )
        assert rc == 2

    def test_no_php_in_dir_writes_empty_jsonl(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        plugin = _make_plugin(
            tmp_path,
            {"README.md": "no php here"},
        )
        out = tmp_path / "findings.jsonl"
        rc = main(["--plugin-dir", str(plugin), "--slug", "p", "--output", str(out)])
        assert rc == 0
        assert out.read_text() == ""


class TestPatternDataclass:
    """Sanity guards on the Pattern frozen dataclass."""

    def test_pattern_frozen(self) -> None:
        import re
        from dataclasses import FrozenInstanceError

        p = Pattern(
            name="x",
            regex=re.compile(r"x"),
            bug_class="auth_bypass",
            description="d",
        )
        with pytest.raises(FrozenInstanceError):
            p.name = "y"  # type: ignore[misc]
