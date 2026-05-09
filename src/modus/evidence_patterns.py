"""Bug-class evidence pattern library.

Each entry describes, for one bug class:

* What the *win signal* looks like in the agent's recent action
  history — concrete enough that a small model can pattern-match it
  against the ``obs=...`` lines and ``body_excerpt=...`` snippets the
  agent loop emits in :func:`modus.agent._summarise_step`.
* The default ``severity_hint`` for the canonical instance of that
  bug class, with a short note on what bumps it up or down (admin vs
  single-user blast radius, sensitivity of disclosed data, etc.).

The proposer's per-step closing rule renders only the patterns whose
``bug_class`` the operator asked for via ``run_autonomous_session(...,
bug_classes=...)``. That keeps the prompt scoped — an
auth_bypass-only run shouldn't be flooded with SSRF and XSS templates
the model has no use for.

Adding a new bug class is one entry in :data:`PATTERNS`. Recognition
text should be substantive (a small model needs the concrete
"what does success look like" anchor); severity defaults should be
deliberate per the criteria in
:func:`modus.proposer._VOCABULARY_DESCRIPTION`'s ``severity_hint``
section.

Discovered as a real need during the 2026-05-07 Juice Shop work
(:issue:`5`): smaller models (qwen2.5-coder:7b, gemma2:9b) emit
``severity_hint: "info"`` on a clear admin auth bypass when the
prompt only described severity criteria abstractly. Bug-class-keyed
templates with explicit "this matches critical" cues fix that.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

from modus import cve_registry

if TYPE_CHECKING:
    from modus.session import SessionObservation


@dataclass(frozen=True)
class BugClassPattern:
    """One bug class's evidence-recognition template + severity guidance.

    Used by :func:`render_patterns` to build the closing-rule block
    of the proposer's per-step user prompt.
    """

    bug_class: str
    """The ``bug_class`` string the operator passes to
    ``run_autonomous_session`` and that ``Hypothesize.bug_class``
    will carry. Free-form lowercase identifier — no enum
    constraint at the action layer."""
    recognition: str
    """One paragraph describing what the win signal looks like in
    the agent's recent action history. Should reference concrete
    fields the proposer can match against:
    ``status``, ``body_excerpt``, ``req_body``, the contrast
    between two observations, etc. Substantive enough that a
    smaller model has a real anchor, not just a label."""
    severity_canonical: str
    """Default ``severity_hint`` for the canonical instance — what
    the model should pick if the evidence matches the
    recognition template at full strength. Operator picks
    something else when the evidence is weaker (e.g. auth_bypass
    that only bypasses to a non-privileged user, not admin)."""
    severity_notes: str
    """Short prose on what shifts severity up or down from the
    canonical default. Pinned to the criteria spelled out in
    :func:`modus.proposer._VOCABULARY_DESCRIPTION`."""


PATTERNS: dict[str, BugClassPattern] = {
    "auth_bypass": BugClassPattern(
        bug_class="auth_bypass",
        recognition=(
            "A `request` with a SQL-injection-shaped, parameter-tampering, "
            "or other auth-bypass-shaped input that returns HTTP 200 with "
            "an authentication token (JWT, session cookie, signed bearer) "
            "or admin-shaped principal in the response body, when a "
            "baseline `request` with the same endpoint and benign input "
            "returned 401/403. The contrast between the two observations "
            "is decisive."
        ),
        severity_canonical="critical",
        severity_notes=(
            "critical when the bypass yields admin or root-tier access; "
            "high when it yields a privileged but non-admin account; "
            "medium when the bypass affects a single non-privileged user."
        ),
    ),
    "idor": BugClassPattern(
        bug_class="idor",
        recognition=(
            "Two `request` observations to the same path-shaped URL "
            "(e.g. `/rest/basket/{id}`, `/api/Users/{id}`) with different "
            "identifiers — typically the operator's own and another "
            "user's — where both return HTTP 200 and the second response "
            "body shows fields belonging to the *other* user (different "
            "`UserId`, different email, different basket contents, etc.). "
            "The handler authenticated the request but didn't authorize "
            "the resource."
        ),
        severity_canonical="high",
        severity_notes=(
            "critical when the IDOR exposes admin-only or "
            "highly-sensitive fields (PII, financial, security answers); "
            "high for cross-tenant or cross-user reads of typical user "
            "data; medium when the IDOR is on a low-sensitivity resource "
            "or affects only one direction (read but not write)."
        ),
    ),
    "info_disclosure": BugClassPattern(
        bug_class="info_disclosure",
        recognition=(
            "A `request` returning HTTP 200 (or any non-error) with a "
            "body that contains material the application shouldn't "
            "expose at this trust level: source files, internal config, "
            "credentials/secrets/tokens, version metadata sufficient to "
            "fingerprint vulnerable components, directory listings, "
            "stack traces, schema dumps, internal URLs/hostnames, "
            "diagnostic dumps. The recognition often hinges on the "
            "body_excerpt — strings like `BEGIN PRIVATE KEY`, "
            "`Traceback`, `CREATE TABLE`, file:// URLs, customer PII."
        ),
        severity_canonical="medium",
        severity_notes=(
            "critical for credentials, private keys, or live API tokens; "
            "high for full schema dumps, source code, or PII at scale; "
            "medium for internal documents, version banners that map to "
            "known CVEs, or aggregate sensitive data; low for harmless "
            "version strings or internal paths with no exploit chain."
        ),
    ),
    "sqli": BugClassPattern(
        bug_class="sqli",
        recognition=(
            "A `request` whose `req_body` or query string contains a "
            "SQL-injection-shaped payload (single quote, `OR 1=1`, "
            "`UNION SELECT`, comment terminators) producing one of: "
            "(a) a verbose 5xx with a database-engine error string in "
            "the body — `SQLITE_ERROR`, `MySQL`, `ORA-`, `syntax error "
            "near` — that confirms input reaches the SQL engine; "
            "(b) a 200 whose `data[]` rows contain content the "
            "application's normal queries wouldn't produce, e.g. rows "
            "with `CREATE TABLE` statements (UNION against "
            "`sqlite_master`) or rows with mismatched column types "
            "(numeric placeholders in string columns)."
        ),
        severity_canonical="critical",
        severity_notes=(
            "critical when UNION-based exfil is demonstrable against "
            "any user-data table — the same primitive trivially extends "
            "to credentials, payment data, security answers; high for "
            "blind/error-only injection where no exfil has yet been "
            "demonstrated; medium for cases where the injection point "
            "is constrained (e.g. authenticated-only with limited "
            "table reach)."
        ),
    ),
    "ssrf": BugClassPattern(
        bug_class="ssrf",
        recognition=(
            "A `request` whose body or parameter directs the "
            "application to fetch a URL the attacker controls (or a "
            "reserved-range internal URL — `127.0.0.1`, `169.254.x.x`, "
            "`10.x.x.x`, `metadata.google.internal`, "
            "`169.254.169.254`, `localhost:<internal-port>`). The "
            "evidence is either: (a) a response body containing data "
            "the internal URL would return (cloud-metadata JSON, "
            "internal admin pages, internal version strings); "
            "(b) a measurable side-channel (DNS callback, timing "
            "differential, error string mentioning the internal "
            "address)."
        ),
        severity_canonical="high",
        severity_notes=(
            "critical when the SSRF reaches cloud metadata services "
            "and returns IAM credentials or instance metadata, or "
            "fetches a writable internal endpoint; high for internal "
            "data exposure; medium for blind SSRF where exfil hasn't "
            "been demonstrated."
        ),
    ),
    "xss": BugClassPattern(
        bug_class="xss",
        recognition=(
            "A `request` whose body or query parameter contains an "
            "HTML/JS-shaped payload (`<script>`, `<img onerror=>`, "
            '`javascript:` URI, raw `<` and `"`) and the response '
            "body excerpt shows the payload reflected without HTML "
            "encoding — i.e. the literal `<script>` survived into "
            "the response. Stored XSS shows up as the payload "
            "appearing in a *different* request's response body "
            "(persisted across requests/users)."
        ),
        severity_canonical="medium",
        severity_notes=(
            "high for stored XSS reaching admin pages or "
            "authentication flows, or for reflected XSS in a "
            "high-trust origin; medium for typical reflected XSS in "
            "user-content surfaces; low for self-XSS or XSS in a "
            "context with strong CSP."
        ),
    ),
    "csrf": BugClassPattern(
        bug_class="csrf",
        recognition=(
            "A state-changing `request` (POST/PUT/DELETE/PATCH) that "
            "succeeds without a CSRF token, anti-forgery header, or "
            "Origin/Referer check. Evidence: two requests of the same "
            "endpoint, one with the security header/token and one "
            "without, both returning the same successful status — the "
            "server didn't enforce origin binding."
        ),
        severity_canonical="medium",
        severity_notes=(
            "high when the CSRF target is a privileged action "
            "(password change, account creation, money movement); "
            "medium for typical state changes; low for non-sensitive "
            "writes."
        ),
    ),
    "business_logic": BugClassPattern(
        bug_class="business_logic",
        recognition=(
            "A `request` whose body bypasses an intended invariant "
            "the application *should* enforce: negative quantities, "
            "zero or negative prices, race conditions exploited via "
            "rapid duplicate requests, coupon stacking, role/state "
            "transitions skipping required steps. Evidence: a "
            "successful response (200/201/204) confirming the "
            "invariant-violating state was accepted, plus a baseline "
            "where the application correctly rejected a benign "
            "violation attempt."
        ),
        severity_canonical="medium",
        severity_notes=(
            "high when the bypass affects financial flows, billing, "
            "or auth state at scale; medium for typical "
            "business-logic flaws affecting one user; low for "
            "corner-case violations with no real-world exploit "
            "chain."
        ),
    ),
}


def render_patterns(bug_classes: tuple[str, ...]) -> str:
    """Render the closing-rule recognition templates for the asked
    bug classes only.

    Returns a markdown-flavoured block ready to splice into the
    proposer's per-step user prompt. Unknown bug classes (i.e.
    operators passing names not in :data:`PATTERNS`) are silently
    skipped — the closing rule still has the general "if you have
    evidence, hypothesize" instruction; the per-class template is
    a recognition aid, not a gate.

    Returns the empty string when no requested bug class is in the
    library, in which case the closing rule renders without the
    per-class block (general guidance only).
    """
    matched = [PATTERNS[c] for c in bug_classes if c in PATTERNS]
    if not matched:
        return ""
    lines = [
        "Recognition templates for the requested bug classes — "
        "the win signal you should be matching against in recent "
        "action history:"
    ]
    for p in matched:
        lines.append(f"- **{p.bug_class}**: {p.recognition}")
        lines.append(
            f"  *Severity (canonical instance):* `{p.severity_canonical}` — {p.severity_notes}"
        )
    return "\n".join(lines) + "\n"


# ============================================================
# inverse detection — "given observations, return matching patterns"
# ============================================================
#
# render_patterns above is the *guidance* path: it renders the
# canonical bug-class templates into the proposer's prompt so the
# LLM has anchors to reason against. detect_evidence_patterns below
# is the *fallback* path: it takes the same templates' decision
# rules and applies them deterministically to the run's
# observations, returning synthesized Hypothesize actions when
# matches are found.
#
# Why both: mid-size open-weight models (qwen2.5-coder:14b,
# phi4:14b, gemma2:9b) explore competently but won't commit to
# `hypothesize` even when their own action history contains
# textbook evidence. Live-tested 2026-05-08 on Juice Shop with a
# seeded corpus — three different 14b models produced sophisticated
# probes, comparisons, and 200-status responses on canonical
# unauth-info-disclosure endpoints, then refused to hypothesize
# and terminated `empty_pruning_streak`. The fallback proposer
# closes that commitment gap by emitting deterministic Hypothesize
# proposals when the LLM keeps abdicating; the agent loop's normal
# Z3-prune-rank-execute pipeline handles them like any other
# proposal, and the proposer's per-step prompt remains the primary
# path. Frontier models reach hypothesize on their own — the
# fallback only fires when local models won't.

# Common rationale-template for synthesized hypotheses. Four
# sections per the proposer's vocabulary description, but the
# wording is templated rather than reasoned — the operator
# reading the resulting Finding sees a clear "this fired
# deterministically from a pattern match against observations
# X and Y" framing, not a model-authored argument.
_FALLBACK_RATIONALE_TEMPLATE = """\
Vulnerability — {bug_class} on {endpoint}. Detected by Modus's \
deterministic pattern matcher against the run's observations \
because the proposing LLM did not emit a hypothesize action \
despite matching evidence in the action history.

Exploit — `curl -s {curl_target}`. The observation cited in \
evidence_refs reproduces the win signal directly.

Evidence — observation {obs_id} returned status {status} with \
body content matching the {bug_class} recognition template: \
{evidence_excerpt}.

Impact — {impact_note}. Operator review recommended; severity \
shifts up if the disclosed material is high-sensitivity (PII, \
credentials, admin-tier data) or down if the win signal is \
ambiguous on closer inspection.\
"""


_VERSION_BANNER_RE = re.compile(
    r'"(version|build|release|commit|sha)"\s*:\s*"([^"]{1,80})"',
    re.IGNORECASE,
)

# --- Secret detection ----------------------------------------------------
#
# The 2026-05-08 Anduril tool-validation run exposed that bare-keyword
# substring matching on words like ``password`` and ``secret`` fires on
# every HTML login form on the internet (form attributes
# ``<input name="password">`` etc. are not credential leaks). The
# detector now splits into three layers:
#
#   1. **Concrete-shape**: PEM private keys, AWS access keys, GitHub
#      and Slack tokens — these have unambiguous structural shapes
#      and don't need surrounding-keyword context. Critical severity.
#
#   2. **Keyword + value**: a credential keyword (api_key, password,
#      client_secret, etc.) followed by a JSON/form value-assignment
#      shape (``: "value"`` or ``= value``) where the value is
#      substantive (≥16 chars) and not a known placeholder. High
#      severity. Rejects matches inside HTML form attribute names
#      (e.g. ``<input name="password">``) by checking the preceding
#      context for an attribute-assignment pattern.
#
#   3. **Bearer + token**: ``Bearer <token>`` with the token at least
#      20 chars and non-placeholder. High severity.

_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# AWS access-key-id prefixes per AWS docs (AKIA = long-term, ASIA =
# session, AROA = role, AIDA = IAM user, etc.). The 16-char body
# is the standard length.
_AWS_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b")
# GitHub tokens use ghp_ (personal), ghs_ (server-to-server), gho_
# (OAuth user-to-server), ghu_ (user-to-server), ghr_ (refresh).
_GH_TOKEN_RE = re.compile(r"\bgh[psour]_[A-Za-z0-9_]{36,}\b")
# Slack legacy tokens (xox[abprs]-) — see api.slack.com docs.
_SLACK_TOKEN_RE = re.compile(r"\bxox[abprs]-[0-9a-zA-Z-]{10,}\b")

# Placeholder values that look secret-shaped but obviously aren't.
# Substring-based against the value, case-insensitively. The
# substring approach (rather than \b word-boundary) is deliberate:
# regex \b doesn't fire between `_` and a letter (since `_` is a
# word char), so doc fixtures like ``test_example_dummy_value``
# would slip past a word-boundary check on ``example``. The
# false-negative class — real secrets containing the literal
# substring ``example`` (or ``your`` / ``placeholder``) — is
# vanishingly rare for credentials of any meaningful entropy.
_PLACEHOLDER_SUBSTRINGS = (
    "your",
    "placeholder",
    "example",
    "todo",
    "tbd",
    "changeme",
    "change-me",
    "change_me",
    "...",
)
_PLACEHOLDER_FULL_VALUES = frozenset(
    {
        "test",
        "fake",
        "dummy",
        "sample",
        "demo",
        "null",
        "undefined",
        "none",
        "nil",
    }
)


def _is_placeholder_value(value: str) -> bool:
    """True if ``value`` looks like a documentation placeholder rather than a real secret.

    Caller has already pre-filtered to substrings that look
    secret-shaped (16+ alphanumeric chars). This filter rejects:

    * Standalone placeholder keywords (``test``, ``demo``, etc.)
    * Values containing common placeholder markers as substrings
      (``your``, ``example``, ``placeholder``, ``todo``).
    * Template-shaped values (``<YOUR_KEY>``, ``${API_KEY}``).
    * Repetitive single-character runs (``xxxxxx``, ``******``).
    """
    v = value.strip().lower()
    if v in _PLACEHOLDER_FULL_VALUES:
        return True
    if any(tok in v for tok in _PLACEHOLDER_SUBSTRINGS):
        return True
    # Template tag: <FOO>
    if v.startswith("<") and v.endswith(">"):
        return True
    # Template variable: ${FOO}
    if v.startswith("${") and v.endswith("}"):
        return True
    # Single repeated character ("xxxxxxxx", "********", etc.)
    return len(set(v)) <= 2


# Credential keyword + value-assignment. Two flavours captured:
#
#   - JSON / config: "<keyword>" : "<value>"  (or the unquoted-key
#     YAML/TOML variant)
#   - URL-encoded / form: <keyword>=<value>
#
# The value is captured separately so we can placeholder-check it.
# Min length 16 — shorter values are usually placeholders or test
# fixtures rather than real secrets.
_KEYWORD_VALUE_RE = re.compile(
    r"\b(api[_-]?key|access[_-]?token|client[_-]?secret|"
    r"aws[_-]?access[_-]?key|aws[_-]?secret|password|secret[_-]?key)"
    r'\b\s*["\']?\s*[:=]\s*["\']?([A-Za-z0-9._\-]{16,})',
    re.IGNORECASE,
)

# Bearer + substantive token. Standalone — the keyword "Bearer" is
# itself the credential-context cue.
_BEARER_RE = re.compile(r"\b[Bb]earer\s+([A-Za-z0-9._\-]{20,})\b")

# Form-attribute context for a keyword match: name="...", id="...",
# for="...", class="..." right before the match position. If the
# preceding ~80 chars match this, the keyword is a form field name,
# not a credential leak.
_FORM_ATTR_PRECEDING_RE = re.compile(
    r'\b(?:name|id|for|class|placeholder|aria-label|data-[\w-]+)\s*=\s*["\'][^"\']*$'
)
_USER_OBJECT_RE = re.compile(
    r'"(UserId|userId|user_id|email|username)"\s*:',
)
# Markers that prove a body is a REST API namespace/route listing rather
# than a user-record dump. WordPress's ``/wp-json/`` root, for example,
# returns a single object with ``"namespaces":[...]`` and ``"routes":{...}``
# whose route schemas mention ``"email":{"type":"string",...}`` dozens of
# times — enough to trip a naive email-count heuristic. The 2026-05-09
# wp-lab calibration baseline caught the regression: ``/wp-json/`` flagged
# as ``user_object_dump`` on both profiles. Now rejected explicitly.
_REST_NAMESPACE_MARKERS: tuple[str, ...] = (
    '"namespaces":[',
    '"routes":{',
)
# Field names that distinguish an actual user record from a route schema
# that happens to mention ``"email"``. A user record has a numeric id AND
# at least one user-distinctive field (slug, avatar_urls, username,
# display_name). Route schemas don't.
_USER_RECORD_DISTINCTIVE_RE = re.compile(
    r'"(?:slug|avatar_urls|username|display_name|nicename|UserId|comment)"\s*:'
)
_USER_RECORD_ID_RE = re.compile(r'"(?:id|ID|user_id|userId|UserId)"\s*:\s*\d+')
# Wrapper-array markers — patterns like ``{"data":[{...}], "status":"ok"}``
# (Juice Shop, Strapi, generic REST framings). These let the detector
# fire on the canonical wrapped-array shape without losing precision.
_USER_ARRAY_WRAPPER_MARKERS: tuple[str, ...] = (
    '"data":[{',
    '"users":[{',
    '"items":[{',
    '"results":[{',
)

# ---- static-artifact detector helpers (added 2026-05-09 from wp-lab v4) ----

# Path matches ``/wp-content/plugins/<slug>/readme.txt`` (any case for
# the segment names); slug captured for fingerprint-into-rationale use.
_PLUGIN_README_PATH_RE = re.compile(
    r"/wp-content/plugins/[^/]+/readme\.txt$",
    re.IGNORECASE,
)
_PLUGIN_SLUG_FROM_PATH_RE = re.compile(
    r"/wp-content/plugins/([^/]+)/readme\.txt$",
    re.IGNORECASE,
)
# WordPress plugin readme.txt convention surfaces the published version
# on a ``Stable tag:`` line. Capture the version string.
_STABLE_TAG_RE = re.compile(r"(?im)^Stable tag:\s*([\w.\-]+)\s*$")

# VCS metadata path: ``/.git/<file>``, ``/.svn/<file>``, ``/.hg/<file>``
# with at least one path segment under the dot-dir. Excludes bare
# ``/.git`` (no segment) which webserver listings sometimes 200 by
# accident on auto-redirect.
_VCS_PATH_RE = re.compile(r"/\.(?:git|svn|hg)/[\w.\-]+", re.IGNORECASE)

# Body looks like an actual VCS metadata file (config/HEAD/entries),
# not a 200 fallthrough. Tightly scoped — exact tokens these files emit.
_VCS_BODY_RE = re.compile(
    r"(?im)"
    r"(\[core\]|\[remote\b|^ref:\s+refs/|repositoryformatversion\s*=|"
    r"^entries\s*$|<wc-entries|hgrc)"
)

# Backup-file path. Trailing-extension variants like ``.bak``, ``.old``,
# ``~``, ``.swp`` AND well-known config files like ``.env`` regardless
# of extension.
_BACKUP_FILE_PATH_RE = re.compile(
    r"(?:\.(?:bak|old|orig|backup|save|swp|swo|tmp)$|~$|/\.env(?:\.[\w]+)?$)",
    re.IGNORECASE,
)


_DOTENV_LINE_RE = re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*=")

# WordPress's ``/readme.html`` is the canonical version-disclosure
# endpoint. The path regex is exact (only this filename, not e.g.
# ``readme.html.bak`` which would belong under ``config_backup_exposure``).
_WP_README_HTML_PATH_RE = re.compile(r"/readme\.html$", re.IGNORECASE)
# WordPress fingerprint markers in the readme body — at least one
# must appear before we treat the page as a WP version disclosure.
# Keeps the detector from firing on a generic ``/readme.html`` from
# some other project.
_WP_README_FINGERPRINT_MARKERS: tuple[str, ...] = (
    "<title>WordPress",
    "WordPress &rsaquo;",
    "wordpress.org",
)
# Version-string regex tuned for WP's readme: ``Version 6.4.2``,
# ``WordPress 6.4``, or a plain ``\d+\.\d+(\.\d+)?`` near a heading.
_WP_README_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")

# XML-RPC ``system.listMethods`` response. The 200 body contains a
# ``<methodResponse>`` envelope with an array of ``<string>`` method
# names. Path-gated to ``/xmlrpc.php`` to keep the detector tight.
_XMLRPC_PATH_RE = re.compile(r"/xmlrpc\.php$", re.IGNORECASE)
_XMLRPC_METHOD_RESPONSE_RE = re.compile(r"<methodResponse>", re.IGNORECASE)
_XMLRPC_METHOD_NAME_RE = re.compile(r"<string>([\w.]+)</string>", re.IGNORECASE)


def _looks_like_text_config(body: str) -> bool:
    """Conservative gate for "this looks like a config file response."

    Avoids firing on generic 404-fallthrough HTML (a webserver that
    returns 200 + an HTML error page for missing static files would
    otherwise false-positive every backup-path probe). The check is
    intentionally narrow: non-empty, not HTML, and either explicit
    config-keyword markers OR multiple ``KEY=value`` lines (env-file
    shape).
    """
    if not body or len(body) < 8:
        return False
    head_raw = body[:1024]
    head_l = head_raw.lstrip().lower()
    # Reject HTML error pages — the most common false-positive shape.
    if head_l.startswith("<!doctype") or head_l.startswith("<html") or head_l.startswith("<?xml"):
        return False
    # Explicit config-keyword markers (PHP, INI, well-known env vars).
    config_markers = (
        "<?php",
        "define(",
        "db_name",
        "db_password",
        "auth_key",
        "[core]",
        "[mysql]",
        "[server]",
        "database_url=",
        "secret_key=",
        "api_key=",
        "aws_",
        "export ",
    )
    if any(marker in head_l for marker in config_markers):
        return True
    # Env-file shape: at least 2 lines of ``UPPER_SNAKE=...``. Single
    # match is too lax (an HTML doc could have ``LANG=en`` somewhere).
    return len(_DOTENV_LINE_RE.findall(head_raw)) >= 2


def _looks_like_user_array(body: str) -> bool:
    """Stricter shape check for the ``user_object_dump`` detector.

    Returns True only when the body is plausibly an array of user
    records — not a REST-namespace listing that happens to mention
    ``"email"`` in route schemas.

    Two recognised shapes:

    * **Raw array**: body strips to start with ``[{``. The canonical
      response from ``/wp-json/wp/v2/users`` and similar.
    * **Wrapped array**: body strips to start with ``{`` AND contains
      one of ``"data":[{``, ``"users":[{``, ``"items":[{``,
      ``"results":[{``. Common shape from frameworks that wrap list
      responses (Juice Shop's ``{"status":"success","data":[...]}``,
      Strapi's ``{"data":[{...}]}``).

    Both shapes additionally require:
      * No REST-namespace marker (``"namespaces":[`` or ``"routes":{``)
        in the leading ~1KB. This rejects WordPress's ``/wp-json/`` root.
      * The first ~4KB contains a numeric id field AND a user-distinctive
        field (``slug``, ``avatar_urls``, ``username``, ``display_name``,
        ``nicename``, ``UserId``).

    The 4KB head covers a moderately-rich user record without scanning
    megabytes of unrelated payload.
    """
    stripped = body.lstrip()
    if any(marker in stripped[:1024] for marker in _REST_NAMESPACE_MARKERS):
        return False
    is_raw_array = stripped.startswith("[{")
    is_wrapped_array = stripped.startswith("{") and any(
        wrapper in stripped[:1024] for wrapper in _USER_ARRAY_WRAPPER_MARKERS
    )
    if not (is_raw_array or is_wrapped_array):
        return False
    head = stripped[:4096]
    if not _USER_RECORD_ID_RE.search(head):
        return False
    return bool(_USER_RECORD_DISTINCTIVE_RE.search(head))


_SQL_PAYLOAD_RE = re.compile(
    r"(\bUNION\s+SELECT\b|'\s*OR\s+1\s*=\s*1|--\s*$|'\)\)|"
    r"\bSELECT\s+\*\s+FROM\b|\bDROP\s+TABLE\b)",
    re.IGNORECASE,
)
_SQL_ERROR_RE = re.compile(
    r"(SQLITE_ERROR|sqlite3\.|sqlite_master|MySQL\b|ORA-\d{4,5}|"
    r"PostgreSQL|syntax error near|unrecognized token|"
    r"Error: SQLITE_)",
    re.IGNORECASE,
)
_PATH_ID_RE = re.compile(r"^(.*?)/(\d+)/?$")  # `/api/Users/3` → (`/api/Users`, `3`)


@dataclass(frozen=True)
class FallbackHypothesis:
    """A synthesized hypothesis emitted by the fallback proposer.

    Carries the parts an :class:`Action` constructor needs plus the
    detector's reasoning so the agent loop can log *why* the
    fallback fired (which is useful when reviewing whether the
    fallback caught real bugs or false positives).
    """

    bug_class: str
    severity_hint: str
    evidence_refs: tuple[str, ...]
    rationale: str
    detector: str  # e.g. "info_disclosure:version_banner"


def _request_payload_field(obs: SessionObservation, field: str) -> str:
    """Return the payload field as a string, defaulting to empty."""
    payload = obs.payload if isinstance(obs.payload, dict) else {}
    value = payload.get(field, "")
    if value is None:
        return ""
    return str(value)


def _request_url(obs: SessionObservation) -> str:
    return _request_payload_field(obs, "url")


def _request_status(obs: SessionObservation) -> int | None:
    payload = obs.payload if isinstance(obs.payload, dict) else {}
    value = payload.get("status")
    if isinstance(value, int):
        return value
    return None


def _response_body(obs: SessionObservation) -> str:
    return _request_payload_field(obs, "response_body")


def _request_headers(obs: SessionObservation) -> dict[str, str]:
    payload = obs.payload if isinstance(obs.payload, dict) else {}
    headers = payload.get("request_headers", {})
    return headers if isinstance(headers, dict) else {}


def _is_authenticated_request(obs: SessionObservation) -> bool:
    """True if the request carried any auth-bearing header.

    Used to distinguish "we hit this endpoint with a token and got
    200" (expected) from "we hit it unauthenticated and got 200"
    (potential auth_bypass / info_disclosure).
    """
    headers = _request_headers(obs)
    for k in headers:
        if k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token"):
            return True
    return False


def _curl_for(url: str) -> str:
    return f'"{url}"'


def _excerpt(body: str, limit: int = 240) -> str:
    return body.replace("\n", " ").replace("\r", " ").strip()[:limit]


def _path_only(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.path or url
    except Exception:
        return url


def _host_and_path(url: str) -> tuple[str, str] | None:
    """Return ``(host, path)`` for a URL, or ``None`` if unparseable.

    Used as the bucket key for cross-observation pattern detection
    (auth_bypass, IDOR) so that two observations on the same path
    but different hosts don't get merged into the same equivalence
    class. ``foxglove.chaos.anduril.dev/`` returning 200 and
    ``cyberchef.security.anduril.dev/`` returning 401 are not the
    "same endpoint with different auth states" — they're two
    unrelated services that happen to share a path.

    The hostname is lowercased so that ``HOST.example.com`` and
    ``host.example.com`` bucket together. Path is left case-sensitive
    (paths are case-sensitive per RFC 3986).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    return host, (parsed.path or "/")


@dataclass(frozen=True)
class _SecretMatch:
    """One secret-shaped match found in a response body."""

    severity: str  # "critical" | "high"
    detector_tag: str  # the sub-detector identifier (e.g. "aws_key", "keyword_value")
    matched_text: str  # the actual matching substring, for the audit excerpt


def _is_form_attribute_context(body: str, match_start: int) -> bool:
    """Return True if the match position is inside an HTML form attribute value.

    Used to suppress matches like ``<input name="password">`` — the
    keyword is the *name* of a form field, not a credential. Looks at
    the ~80 chars preceding the match position for an
    ``attr="`` shape.
    """
    window_start = max(0, match_start - 80)
    preceding = body[window_start:match_start]
    return bool(_FORM_ATTR_PRECEDING_RE.search(preceding))


def _find_secrets_in_body(body: str) -> list[_SecretMatch]:
    """Return concrete secret-shaped matches in ``body``.

    Layered: concrete-shape patterns (PEM, AWS, GitHub, Slack) fire
    on shape alone (critical); keyword+value patterns require a
    substantive non-placeholder value AND not be inside an HTML form
    attribute (high); Bearer requires a substantive token (high).
    Returns empty when nothing concrete is found — a body that
    merely contains the substring ``password`` (e.g. a login form)
    no longer fires on its own.
    """
    matches: list[_SecretMatch] = []

    for m in _PEM_PRIVATE_KEY_RE.finditer(body):
        matches.append(
            _SecretMatch(
                severity="critical",
                detector_tag="pem_private_key",
                matched_text=m.group(0),
            )
        )

    for m in _AWS_KEY_ID_RE.finditer(body):
        matches.append(
            _SecretMatch(
                severity="critical",
                detector_tag="aws_access_key",
                matched_text=m.group(0),
            )
        )

    for m in _GH_TOKEN_RE.finditer(body):
        matches.append(
            _SecretMatch(
                severity="critical",
                detector_tag="github_token",
                matched_text=m.group(0)[:20] + "…",  # truncate to avoid persisting the full token
            )
        )

    for m in _SLACK_TOKEN_RE.finditer(body):
        matches.append(
            _SecretMatch(
                severity="critical",
                detector_tag="slack_token",
                matched_text=m.group(0)[:20] + "…",
            )
        )

    for m in _KEYWORD_VALUE_RE.finditer(body):
        keyword = m.group(1)
        value = m.group(2)
        if _is_form_attribute_context(body, m.start()):
            continue
        if _is_placeholder_value(value):
            continue
        # Truncate the match to keep evidence excerpts compact and
        # avoid persisting the full secret to the audit record.
        excerpt = f"{keyword}=...{value[:8]}…"
        matches.append(
            _SecretMatch(
                severity="high",
                detector_tag="keyword_value",
                matched_text=excerpt,
            )
        )

    for m in _BEARER_RE.finditer(body):
        token = m.group(1)
        if _is_placeholder_value(token):
            continue
        matches.append(
            _SecretMatch(
                severity="high",
                detector_tag="bearer_token",
                matched_text=f"Bearer {token[:12]}…",
            )
        )

    return matches


def _detect_info_disclosure(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match unauthenticated 200s containing real secrets, version
    banners, or user-shaped payloads.

    Secret detection requires concrete shape (PEM, AWS, GitHub,
    Slack) or keyword+substantive-value with form-attribute and
    placeholder exclusion — the bare-keyword substring detector was
    too eager and fired on every HTML login form
    (regression captured in the 2026-05-08 Anduril run that
    promoted a false-positive HIGH on a stock Okta SAML login form
    because the form contained ``<input name="password">``).
    """
    out: list[FallbackHypothesis] = []
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for obs in observations:
        if obs.kind != "request":
            continue
        if _request_status(obs) != 200:
            continue
        if _is_authenticated_request(obs):
            continue
        body = _response_body(obs)
        url = _request_url(obs)
        if not body:
            continue
        secret_matches = _find_secrets_in_body(body)
        if secret_matches:
            best = max(secret_matches, key=lambda m: severity_rank[m.severity])
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint=best.severity,
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=_path_only(url),
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=(
                            f"concrete secret matched by "
                            f"{best.detector_tag} detector: "
                            f"{best.matched_text!r}"
                        ),
                        impact_note=(
                            "an unauthenticated reader of this endpoint "
                            "obtains credential-shaped material"
                        ),
                    ),
                    detector=f"info_disclosure:{best.detector_tag}",
                )
            )
            continue
        match = _VERSION_BANNER_RE.search(body)
        if match:
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="low",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=_path_only(url),
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=f"version banner {match.group(0)!r}",
                        impact_note=(
                            "the disclosed version may map to known CVEs for this component"
                        ),
                    ),
                    detector="info_disclosure:version_banner",
                )
            )
            continue
        if _looks_like_user_array(body):
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="medium",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=_path_only(url),
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=(
                            f"unauthenticated array response containing "
                            f"user-shaped fields ({_excerpt(body, 120)!r})"
                        ),
                        impact_note=(
                            "an unauthenticated reader obtains records "
                            "tied to other users' accounts"
                        ),
                    ),
                    detector="info_disclosure:user_object_dump",
                )
            )
            continue
        # ---- static-artifact detectors ----
        # The 2026-05-09 wp-lab v4 baseline showed scout would *probe*
        # high-signal misconfig paths but no detector recognized the
        # 200-with-textual-content shape, so the agent layer never
        # promoted them. These three detectors close that gap by
        # firing on path+content shape rather than just body content.
        path = _path_only(url)
        # 1. Plugin version disclosure — ``/wp-content/plugins/<slug>/
        #    readme.txt`` returning 200 with a ``Stable tag:`` line.
        #    Modus's hypothesizer can correlate this with a CVE database
        #    in a follow-up step; the candidate here just signals
        #    "version X.Y.Z fingerprinted on this host."
        if _PLUGIN_README_PATH_RE.search(path) and "stable tag:" in body.lower():
            slug_match = _PLUGIN_SLUG_FROM_PATH_RE.search(path)
            stable = _STABLE_TAG_RE.search(body)
            slug = slug_match.group(1) if slug_match else "?"
            version = stable.group(1).strip() if stable else "?"
            # Consult the curated CVE registry. If the (slug, version)
            # falls in a known CVE's affected range, escalate the
            # candidate: switch bug_class to the upstream exploit's
            # class, bump severity to the CVE's, append the CVE ID +
            # summary to the rationale. When the registry has no
            # entry, the candidate stays at ``info_disclosure / info``
            # — version disclosure is still useful evidence on its own.
            cve_matches = cve_registry.lookup_cves(slug, version)
            if cve_matches:
                # Pick the highest-severity CVE for the candidate's
                # bug_class + severity. Multiple CVEs may apply to
                # the same version range — operator triage gets the
                # most-severe one front-and-center, with the rest in
                # the rationale.
                rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                primary = max(cve_matches, key=lambda c: rank[c.severity])
                cve_summary = "; ".join(f"{c.cve} ({c.severity}): {c.summary}" for c in cve_matches)
                out.append(
                    FallbackHypothesis(
                        bug_class=primary.bug_class,
                        severity_hint=primary.severity,
                        evidence_refs=(obs.id,),
                        rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                            bug_class=primary.bug_class,
                            endpoint=path,
                            curl_target=url,
                            obs_id=obs.id,
                            status=200,
                            evidence_excerpt=(
                                f"WordPress plugin {slug!r} fingerprinted at "
                                f"version {version!r} via /readme.txt; "
                                f"version falls in the affected range of "
                                f"{len(cve_matches)} known CVE(s): "
                                f"{cve_summary}"
                            ),
                            impact_note=(
                                f"escalated from version disclosure to "
                                f"{primary.bug_class} ({primary.severity}) "
                                f"based on the matching CVE registry entry; "
                                f"fixed in {primary.fixed_in or 'unknown'}"
                            ),
                        ),
                        detector=f"info_disclosure:plugin_cve_match:{primary.cve}",
                    )
                )
            else:
                out.append(
                    FallbackHypothesis(
                        bug_class="info_disclosure",
                        severity_hint="info",
                        evidence_refs=(obs.id,),
                        rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                            bug_class="info_disclosure",
                            endpoint=path,
                            curl_target=url,
                            obs_id=obs.id,
                            status=200,
                            evidence_excerpt=(
                                f"WordPress plugin {slug!r} fingerprinted at "
                                f"version {version!r} via /readme.txt — "
                                f"no entry in the curated CVE registry for "
                                f"this version, but the fingerprint is still "
                                f"useful pivot evidence"
                            ),
                            impact_note=(
                                "version disclosure on its own is informational, "
                                "but pivots a hypothesizer toward exploit "
                                "selection if any CVE matches the version range"
                            ),
                        ),
                        detector="info_disclosure:plugin_version_disclosure",
                    )
                )
            continue
        # 2. VCS directory exposure — ``/.git/<file>``, ``/.svn/<file>``,
        #    ``/.hg/<file>`` returning 200 with their characteristic
        #    text shape. The body content gates the match: a 200 on
        #    ``/.git/config`` from a webserver that returns 200 to
        #    everything would otherwise false-positive.
        if _VCS_PATH_RE.search(path) and _VCS_BODY_RE.search(body):
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="medium",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=path,
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=(
                            f"VCS metadata file readable in webroot "
                            f"({_excerpt(body, 120)!r}) — a clone or "
                            f"directory traversal can recover internal "
                            f"source, branch history, and commit metadata"
                        ),
                        impact_note=(
                            "an unauthenticated attacker can reconstruct "
                            "internal source code and infrastructure secrets "
                            "committed to history"
                        ),
                    ),
                    detector="info_disclosure:vcs_directory_exposure",
                )
            )
            continue
        # 3. WordPress version disclosure via /readme.html.
        #    Tracked at issue #34. The page is the canonical WP
        #    version-disclosure endpoint; the body contains
        #    ``<title>WordPress &rsaquo; ReadMe</title>`` and a
        #    version string in the leading H1 / paragraph. The bare
        #    ``_VERSION_BANNER_RE`` doesn't match (it's JSON-shaped),
        #    and ``_looks_like_user_array`` correctly rejects HTML.
        if _WP_README_HTML_PATH_RE.search(path) and any(
            marker in body[:2048] for marker in _WP_README_FINGERPRINT_MARKERS
        ):
            version_match = _WP_README_VERSION_RE.search(body[:2048])
            version = version_match.group(1) if version_match else "?"
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="info",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=path,
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=(
                            f"WordPress version {version!r} disclosed via "
                            f"the canonical /readme.html endpoint — the "
                            f"page exposes core WP version, supported PHP "
                            f"version, and links to upgrade documentation"
                        ),
                        impact_note=(
                            "version disclosure on WordPress core is "
                            "informational on its own, but pivots toward "
                            "matching CVEs for the disclosed version and "
                            "indicates the rest of the WP recon arc "
                            "(plugins, REST API, xmlrpc) is in play"
                        ),
                    ),
                    detector="info_disclosure:wp_version_disclosure",
                )
            )
            continue
        # 4. XML-RPC enabled — methods listing returned. Tracked at
        #    issue #33. Fires when the body is an XML-RPC
        #    ``methodResponse`` (the answer to a POST
        #    ``system.listMethods`` call). Severity is low: enabled
        #    XML-RPC on its own is a minor exposure, but the surface
        #    opens up amplification + brute-force vectors that
        #    operators triage.
        if (
            _XMLRPC_PATH_RE.search(path)
            and _XMLRPC_METHOD_RESPONSE_RE.search(body[:512])
            and _XMLRPC_METHOD_NAME_RE.search(body)
        ):
            method_names = _XMLRPC_METHOD_NAME_RE.findall(body)[:8]
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="low",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=path,
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=(
                            f"XML-RPC enabled at {path} — "
                            f"system.listMethods returned an enumerated "
                            f"method set including: "
                            f"{', '.join(method_names)}"
                            f"{'...' if len(_XMLRPC_METHOD_NAME_RE.findall(body)) > 8 else ''}"
                        ),
                        impact_note=(
                            "enabled XML-RPC exposes pingback amplification "
                            "and brute-force vectors via system.multicall; "
                            "low-severity on its own but worth disabling on "
                            "modern WordPress deployments"
                        ),
                    ),
                    detector="info_disclosure:xmlrpc_methods_disclosure",
                )
            )
            continue
        # 5. Config-backup exposure — ``*.bak``/``*.old``/``*~``/
        #    ``*.swp``/``.env`` paths returning 200 with text body.
        #    Distinct from the secret-content detector above: this fires
        #    even when the body lacks a recognised secret shape (e.g.
        #    a ``wp-config.php.bak`` whose secrets are unique to the
        #    target). The body-shape gate (text-y, non-empty, no HTML
        #    error markers) keeps generic 404-fallthrough HTML out.
        if _BACKUP_FILE_PATH_RE.search(path) and _looks_like_text_config(body):
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="high",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=path,
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=(
                            f"config-backup file readable in webroot "
                            f"({_excerpt(body, 120)!r}) — typically "
                            f"contains DB credentials, auth keys/salts, "
                            f"or embedded API tokens"
                        ),
                        impact_note=(
                            "config backups commonly expose DB credentials "
                            "and authentication material that grants admin "
                            "access; severity is high pending content review "
                            "(critical if real secrets are present)"
                        ),
                    ),
                    detector="info_disclosure:config_backup_exposure",
                )
            )
            continue
    return out


def _detect_auth_bypass(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match same-path-different-status pairs where one is 401/403
    and one is 200 — the canonical auth_bypass differential.

    Bucketing is by ``(host, path)`` so that two observations on
    different hosts that happen to share a path don't get treated
    as the same endpoint. Two unrelated services both responding at
    ``/`` (one with 200, one with 401) is not auth_bypass — it's
    just two unrelated services. The differential only makes sense
    when the same handler is hit with and without the right auth
    material.
    """
    out: list[FallbackHypothesis] = []
    by_endpoint: dict[tuple[str, str], list[SessionObservation]] = {}
    for obs in observations:
        if obs.kind != "request":
            continue
        url = _request_url(obs)
        if not url:
            continue
        key = _host_and_path(url)
        if key is None:
            continue
        by_endpoint.setdefault(key, []).append(obs)
    for (host, path), group in by_endpoint.items():
        statuses = {_request_status(o): o for o in group}
        protected = next((o for s, o in statuses.items() if s in (401, 403)), None)
        open_ = next((o for s, o in statuses.items() if s == 200), None)
        if protected is None or open_ is None:
            continue
        out.append(
            FallbackHypothesis(
                bug_class="auth_bypass",
                severity_hint="high",
                evidence_refs=(open_.id, protected.id),
                rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                    bug_class="auth_bypass",
                    endpoint=f"{host}{path}",
                    curl_target=_request_url(open_),
                    obs_id=open_.id,
                    status=200,
                    evidence_excerpt=(
                        f"same host {host!r} same path {path!r} returned 200 and "
                        f"{_request_status(protected)} on different requests "
                        f"(this run's pool only — same-host same-path differential)"
                    ),
                    impact_note=(
                        "the protected variant correctly enforced auth "
                        "while the open variant did not, on the same "
                        "endpoint shape"
                    ),
                ),
                detector="auth_bypass:same_host_path_status_differential",
            )
        )
    return out


def _detect_idor(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match observations on path-shaped endpoints (`/x/{id}`) where
    different ids both return 200 with user-shaped data — the
    classic IDOR pattern.

    Bucketing is by ``(host, template)`` so that ``/users/1`` on
    one host and ``/users/2`` on a different host don't get treated
    as enumerable IDs of the same handler. IDOR requires that the
    same handler returns 200 for IDs the operator doesn't own;
    cross-host enumeration is two unrelated services with similar
    URL shapes, not a vulnerability.
    """
    out: list[FallbackHypothesis] = []
    by_handler: dict[tuple[str, str], list[tuple[str, SessionObservation]]] = {}
    for obs in observations:
        if obs.kind != "request":
            continue
        if _request_status(obs) != 200:
            continue
        url = _request_url(obs)
        host_path = _host_and_path(url)
        if host_path is None:
            continue
        host, path = host_path
        match = _PATH_ID_RE.match(path)
        if not match:
            continue
        template = match.group(1)
        ident = match.group(2)
        by_handler.setdefault((host, template), []).append((ident, obs))
    for (host, template), items in by_handler.items():
        if len({i for i, _ in items}) < 2:
            continue
        sample = items[0][1]
        body = _response_body(sample)
        if not _USER_OBJECT_RE.search(body):
            continue
        ids_seen = sorted({i for i, _ in items})
        out.append(
            FallbackHypothesis(
                bug_class="idor",
                severity_hint="high",
                evidence_refs=tuple(o.id for _, o in items[:4]),
                rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                    bug_class="idor",
                    endpoint=f"{host}{template}/{{id}}",
                    curl_target=_request_url(sample),
                    obs_id=sample.id,
                    status=200,
                    evidence_excerpt=(
                        f"same host {host!r} same handler {template!r} returned "
                        f"200 for ids {ids_seen!r} with user-shaped fields in body"
                    ),
                    impact_note=(
                        "IDs other than the operator's own resolve to "
                        "200 with user-tagged content; cross-user reads "
                        "are reachable"
                    ),
                ),
                detector="idor:enumerable_id_user_data",
            )
        )
    return out


def _detect_sqli(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match observations whose request URL contains a SQL-injection-
    shaped query payload AND whose response shows either a database
    error or an anomalous-shape JSON result.
    """
    out: list[FallbackHypothesis] = []
    # Index clean (non-SQLi) baselines by path-without-query so we
    # can spot result-set divergence on a tainted vs benign payload.
    # URL-decode each URL once so the regex matches both raw payloads
    # (e.g. ``apple'))``) and percent-encoded ones
    # (``apple%27%29%29``) — the recon driver tends to URL-encode.
    baselines: dict[str, str] = {}
    for obs in observations:
        if obs.kind != "request":
            continue
        url = _request_url(obs)
        decoded_url = unquote(url)
        body = _response_body(obs)
        path = _path_only(url)
        if not _SQL_PAYLOAD_RE.search(decoded_url) and _request_status(obs) == 200 and body:
            try:
                doc = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(doc, dict) and isinstance(doc.get("data"), list) and doc["data"]:
                baselines.setdefault(path, body)
    for obs in observations:
        if obs.kind != "request":
            continue
        url = _request_url(obs)
        decoded_url = unquote(url)
        if not _SQL_PAYLOAD_RE.search(decoded_url):
            continue
        body = _response_body(obs)
        status = _request_status(obs)
        if status and status >= 500 and _SQL_ERROR_RE.search(body):
            out.append(
                FallbackHypothesis(
                    bug_class="sqli",
                    severity_hint="high",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="sqli",
                        endpoint=_path_only(url),
                        curl_target=url,
                        obs_id=obs.id,
                        status=status,
                        evidence_excerpt=(
                            f"DB engine error in response confirms SQL "
                            f"injection reaches the engine: "
                            f"{_excerpt(body, 120)!r}"
                        ),
                        impact_note=(
                            "input reaches the SQL engine; UNION-based "
                            "exfil is the natural follow-up"
                        ),
                    ),
                    detector="sqli:db_error_in_response",
                )
            )
            continue
        if status == 200 and body:
            try:
                doc = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                continue
            path = _path_only(url)
            if (
                isinstance(doc, dict)
                and isinstance(doc.get("data"), list)
                and len(doc["data"]) == 0
                and path in baselines
            ):
                out.append(
                    FallbackHypothesis(
                        bug_class="sqli",
                        severity_hint="medium",
                        evidence_refs=(obs.id,),
                        rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                            bug_class="sqli",
                            endpoint=path,
                            curl_target=url,
                            obs_id=obs.id,
                            status=200,
                            evidence_excerpt=(
                                "SQL-shaped payload changed the response "
                                "shape vs a benign baseline on the same "
                                "path (tainted: empty data array; "
                                "baseline: non-empty)"
                            ),
                            impact_note=(
                                "the SQL-shaped input meaningfully alters "
                                "the result set, indicating injection "
                                "into the underlying query"
                            ),
                        ),
                        detector="sqli:differential_empty_on_taint",
                    )
                )
    return out


_DETECTORS = {
    "info_disclosure": _detect_info_disclosure,
    "auth_bypass": _detect_auth_bypass,
    "idor": _detect_idor,
    "sqli": _detect_sqli,
}


def detect_evidence_patterns(
    observations: list[SessionObservation],
    bug_classes: tuple[str, ...] = (),
) -> list[FallbackHypothesis]:
    """Run deterministic pattern detectors over the run's observations.

    Returns synthesized :class:`FallbackHypothesis` entries for any
    matched bug-class evidence. Restricted to the operator's
    requested ``bug_classes`` when non-empty; runs all detectors
    when empty.

    Order of matches is detector-deterministic (info_disclosure
    first, then auth_bypass, idor, sqli) so the agent loop's
    ranking heuristic sees a stable order across re-runs.

    The fallback proposer (in :mod:`modus.agent`) calls this each
    step and merges the results into the LLM proposer's batch
    when activation conditions are met (see
    :func:`modus.agent.AgentLoop._fallback_proposals`). Detectors
    that match the same observation by different rules each emit
    their own entry — the agent loop's dedup gate handles the rest.
    """
    requested = set(bug_classes) if bug_classes else set(_DETECTORS.keys())
    out: list[FallbackHypothesis] = []
    for name, detector in _DETECTORS.items():
        if name not in requested:
            continue
        out.extend(detector(observations))
    return out


__all__ = [
    "PATTERNS",
    "BugClassPattern",
    "FallbackHypothesis",
    "detect_evidence_patterns",
    "render_patterns",
]
