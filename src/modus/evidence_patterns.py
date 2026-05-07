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

from dataclasses import dataclass


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


__all__ = ["PATTERNS", "BugClassPattern", "render_patterns"]
