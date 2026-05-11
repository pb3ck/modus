"""Source-review augmentation — grep a WordPress plugin's PHP for
high-signal patterns and emit them in a shape Quarry can ingest.

Every wp-bounty audit triage in the 2026-05-10/11 arc landed at the
same conclusion: the bug-payable findings live in PHP behaviour
(missing nonce, wrong capability check, unsafe deserialization) that
HTTP probing alone can't reach. The LLM proposer needs *source-side
context* to know where to probe and what response shape indicates
a real win.

This module closes that gap without making Modus a static analyzer.
It scans a plugin's PHP files for curated high-signal patterns
(``wp_ajax_nopriv_*`` handlers, ``permission_callback => __return_true``,
``unserialize($_*)``, raw ``$wpdb->query`` with user input, ``eval(``,
etc.) and emits a JSONL stream in Quarry's ``responses`` adapter
shape. Each finding becomes one artifact with a synthetic
``file:///`` URL pointing at the source location and a body
containing the matched code snippet plus surrounding context.

After ingestion, Modus's mining sub-agent surfaces the matches via
the ``search`` analytical tool (the curated bug-class queries —
``"permission_callback"``, ``"is_user_logged_in"``,
``"current_user_can"`` — hit on the ingested code chunks). The
proposer's next-step context renders mined signals as breadcrumbs
the LLM can pivot on.

Operator workflow:

    python -m modus.source_review \\
        --plugin-dir /var/www/html/wp-content/plugins/simple-job-board \\
        --slug simple-job-board \\
        --output /tmp/sjb-source-review.jsonl

    quarry ingest --source responses --target wp-bounty-sjb \\
        --corpus /path/to/corpus /tmp/sjb-source-review.jsonl

Then launch the autonomous run with ``seed_from_corpus=True``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


# --- Curated patterns ---------------------------------------------------------
#
# Each pattern is a single-line PHP shape that historically correlates
# with a specific bug class. Conservative on false positives: we'd
# rather miss a subtle bug than flood the corpus with code that
# happens to mention "wp_ajax_" in a comment.


@dataclass(frozen=True)
class Pattern:
    """One source-review pattern."""

    name: str
    """Short canonical name. Surfaces in search results so the LLM
    can correlate the code finding with the attack shape."""

    regex: re.Pattern[str]
    """Compiled regex matched against each line of PHP. Multiline
    matches aren't supported in v0.5 — the patterns of interest are
    single-line shapes."""

    bug_class: str
    """Modus bug-class label (``auth_bypass``, ``sqli``, ``rce``,
    ``info_disclosure``, ``idor``). Drives which search-mining
    query surfaces this finding."""

    description: str
    """Operator-readable description of WHY this pattern is high
    signal. Embedded in the synthetic artifact body so the LLM
    sees the rationale alongside the code."""


PATTERNS: tuple[Pattern, ...] = (
    # --- auth_bypass / broken access control ---
    Pattern(
        name="unauth_ajax_handler",
        regex=re.compile(r"add_action\s*\(\s*['\"]wp_ajax_nopriv_(\w+)['\"]", re.IGNORECASE),
        bug_class="auth_bypass",
        description=(
            "AJAX action registered with the ``wp_ajax_nopriv_`` "
            "prefix is callable by UNAUTHENTICATED users. The "
            "handler's permission_callback must reject the request "
            "unless the action is genuinely safe for anyone to "
            "invoke. Probe POST /wp-admin/admin-ajax.php?action=<name>."
        ),
    ),
    Pattern(
        name="permission_callback_return_true",
        regex=re.compile(
            r"['\"]permission_callback['\"]\s*=>\s*['\"]?__return_true",
            re.IGNORECASE,
        ),
        bug_class="auth_bypass",
        description=(
            "REST route registered with ``permission_callback => "
            "__return_true`` accepts ANY caller including unauth. "
            "The handler's logic must perform its own authorization "
            "check on the side-effect path; if it doesn't, this is "
            "the canonical CVE-2024-10924-shape pre-auth privilege "
            "escalation."
        ),
    ),
    Pattern(
        name="missing_check_ajax_referer",
        regex=re.compile(
            r"function\s+\w*(?:ajax|admin)\w*\s*\([^)]*\)\s*\{(?![^}]*check_ajax_referer)",
            re.IGNORECASE | re.DOTALL,
        ),
        bug_class="auth_bypass",
        description=(
            "AJAX-named function without a ``check_ajax_referer`` "
            "call in its body. Heuristic — may include false "
            "positives — but every match is worth a probe to see "
            "whether the action accepts unauth POSTs that change "
            "state."
        ),
    ),
    # --- sqli ---
    Pattern(
        name="wpdb_query_with_user_input",
        regex=re.compile(
            r"\$wpdb->query\s*\(\s*[\"']?[^\"'()]*\$_(GET|POST|REQUEST|COOKIE)",
            re.IGNORECASE,
        ),
        bug_class="sqli",
        description=(
            "Raw ``$wpdb->query()`` with user-controlled input "
            "concatenated into the SQL. Bypasses prepared statements; "
            "this is unauth SQLi if the surrounding AJAX/REST is "
            "unauth, authenticated SQLi otherwise."
        ),
    ),
    Pattern(
        name="wpdb_get_results_with_user_input",
        regex=re.compile(
            r"\$wpdb->(?:get_results|get_var|get_row|get_col)\s*\(\s*[\"']?[^\"'()]*\$_(GET|POST|REQUEST|COOKIE)",
            re.IGNORECASE,
        ),
        bug_class="sqli",
        description=(
            "Raw ``$wpdb->get_*()`` SELECT with user input "
            "concatenated. Same risk as ``->query`` — input must "
            "flow through ``$wpdb->prepare()`` to be safe."
        ),
    ),
    # --- rce ---
    Pattern(
        name="dangerous_eval",
        regex=re.compile(r"\beval\s*\(", re.IGNORECASE),
        bug_class="rce",
        description=(
            "``eval()`` of a PHP string. If any part of the argument "
            "flows from user input, this is direct PHP execution "
            "from an attacker-controlled string."
        ),
    ),
    Pattern(
        name="shell_exec_family",
        regex=re.compile(
            r"\b(?:shell_exec|system|exec|passthru|popen|proc_open)\s*\(",
            re.IGNORECASE,
        ),
        bug_class="rce",
        description=(
            "OS command-execution function. User input reaching the "
            "argument is OS command injection."
        ),
    ),
    Pattern(
        name="unserialize_user_input",
        regex=re.compile(
            r"unserialize\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)",
            re.IGNORECASE,
        ),
        bug_class="rce",
        description=(
            "``unserialize()`` of user input is the canonical PHP "
            "object-injection sink. If the plugin's namespace "
            "includes any class with a magic method "
            "(``__destruct``, ``__wakeup``, ``__toString``), this "
            "can be exploited for RCE via gadget chains."
        ),
    ),
    Pattern(
        name="file_put_contents_user_input",
        regex=re.compile(
            r"file_put_contents\s*\(\s*[^)]*\$_(GET|POST|REQUEST|FILES)",
            re.IGNORECASE,
        ),
        bug_class="rce",
        description=(
            "``file_put_contents()`` with user input in the path "
            "argument or content argument. Path-controlled writes "
            "to a web-served directory are RCE; content-controlled "
            "writes to a wp-config-shape file lift severity."
        ),
    ),
    Pattern(
        name="include_with_user_input",
        regex=re.compile(
            r"\b(?:include|require)(?:_once)?\s*[\(\s]+[^;]*\$_(GET|POST|REQUEST|COOKIE)",
            re.IGNORECASE,
        ),
        bug_class="rce",
        description=(
            "Local/remote file inclusion via ``include`` / "
            "``require`` with user-controlled path. Reads files "
            "the webserver has access to; executes any PHP file "
            "the attacker can write or already-existing file."
        ),
    ),
    # --- info_disclosure ---
    Pattern(
        name="hardcoded_credential_pattern",
        regex=re.compile(
            r"['\"](?:api[_-]?key|password|secret|token|access[_-]?key)['\"]\s*=>\s*['\"][a-zA-Z0-9_\-]{16,}",
            re.IGNORECASE,
        ),
        bug_class="info_disclosure",
        description=(
            "Hardcoded API key / password / token in the plugin's "
            "PHP. If the file is web-accessible (or the plugin "
            "leaks the option to public REST), this is direct "
            "credential disclosure."
        ),
    ),
    # --- idor / open redirect ---
    Pattern(
        name="wp_redirect_user_input",
        regex=re.compile(
            r"wp_redirect\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
            re.IGNORECASE,
        ),
        bug_class="idor",
        description=(
            "``wp_redirect()`` with user input as the destination. "
            "Open-redirect bypass — phishing payloads can land on "
            "the legitimate domain and bounce to an attacker host. "
            "(Not strictly IDOR; closest bug-class label in Modus's "
            "set.)"
        ),
    ),
    Pattern(
        name="update_user_meta_with_user_input",
        regex=re.compile(
            r"update_user_meta\s*\(\s*[^,]+,\s*\$_(GET|POST|REQUEST)",
            re.IGNORECASE,
        ),
        bug_class="auth_bypass",
        description=(
            "``update_user_meta()`` with a user-controlled meta_key. "
            "If the key is ``wp_capabilities`` or any other "
            "privilege-related meta, this is privilege escalation. "
            "Canonical CVE-2023-3460 (ultimate-member)-shape."
        ),
    ),
)


@dataclass(frozen=True)
class SourceFinding:
    """One source-review match against a plugin's PHP."""

    pattern_name: str
    bug_class: str
    description: str
    path: str  # relative to plugin_dir
    line: int
    snippet: str  # the matched line
    context: str  # +/- 3 lines around the match


# --- Scanner ------------------------------------------------------------------


_CONTEXT_LINES = 3
_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB per file — skip the rest


def scan_plugin_source(plugin_dir: Path) -> Iterator[SourceFinding]:
    """Walk ``plugin_dir`` for ``.php`` files and emit matches.

    Skips files larger than :data:`_MAX_FILE_SIZE` (vendored libraries
    that pollute the corpus more than they help). Skips ``vendor/``,
    ``node_modules/``, and ``tests/`` directories.
    """
    skip_dirs = {"vendor", "node_modules", "tests", "test", ".git"}
    for path in sorted(plugin_dir.rglob("*.php")):
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(plugin_dir))
        lines = text.splitlines()
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(text):
                # Find the line number for the match start.
                line_no = text.count("\n", 0, match.start()) + 1
                snippet_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                # Build context window.
                start = max(0, line_no - 1 - _CONTEXT_LINES)
                end = min(len(lines), line_no + _CONTEXT_LINES)
                context = "\n".join(lines[start:end])
                yield SourceFinding(
                    pattern_name=pattern.name,
                    bug_class=pattern.bug_class,
                    description=pattern.description,
                    path=rel,
                    line=line_no,
                    snippet=snippet_line.strip(),
                    context=context,
                )


# --- Quarry-responses-shape emitter ------------------------------------------


def finding_to_response_record(finding: SourceFinding, slug: str) -> dict[str, object]:
    """Render a :class:`SourceFinding` as a Quarry ``responses``-shape
    JSONL record.

    Synthetic URL points at the source location with a ``file://``
    scheme so it's clearly not a probed asset. Body contains the
    pattern name, bug class, description, and the matched code with
    context — every field is FTS-indexed by Quarry, so a search for
    ``"permission_callback"`` will surface this record.
    """
    url = f"file:///plugins/{slug}/{finding.path}#L{finding.line}"
    body_lines = [
        f"# Source-review finding: {finding.pattern_name}",
        f"# Bug class: {finding.bug_class}",
        f"# File: {finding.path}",
        f"# Line: {finding.line}",
        "",
        "## Description",
        "",
        finding.description,
        "",
        "## Matched line",
        "",
        finding.snippet,
        "",
        f"## Context (+/-{_CONTEXT_LINES} lines)",
        "",
        finding.context,
    ]
    return {
        "url": url,
        "status": 200,
        "method": "REVIEW",
        "headers": {
            "X-Modus-Source-Review": "1",
            "X-Modus-Plugin-Slug": slug,
            "X-Modus-Pattern": finding.pattern_name,
            "X-Modus-Bug-Class": finding.bug_class,
        },
        "body": "\n".join(body_lines),
    }


# --- CLI ----------------------------------------------------------------------


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="modus.source_review",
        description=(
            "Grep a WordPress plugin's PHP for high-signal patterns "
            "and emit them as a Quarry-responses JSONL the operator "
            "can ingest before launching an autonomous audit."
        ),
    )
    p.add_argument(
        "--plugin-dir",
        type=Path,
        required=True,
        help="Path to the plugin's source root (the directory containing the .php files).",
    )
    p.add_argument(
        "--slug",
        required=True,
        help="The plugin's wp.org slug. Used in synthetic URLs and headers.",
    )
    p.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSONL path. Pass to ``quarry ingest --source responses``.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)
    plugin_dir: Path = args.plugin_dir
    if not plugin_dir.exists() or not plugin_dir.is_dir():
        print(f"error: --plugin-dir {plugin_dir} does not exist", file=sys.stderr)
        return 2
    count = 0
    with args.output.open("w", encoding="utf-8") as out:
        for finding in scan_plugin_source(plugin_dir):
            record = finding_to_response_record(finding, args.slug)
            out.write(json.dumps(record) + "\n")
            count += 1
    print(
        f"wrote {count} source-review findings to {args.output} (plugin: {args.slug})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
