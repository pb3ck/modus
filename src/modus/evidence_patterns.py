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
_SECRET_HINT_RE = re.compile(
    r"(BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key|secret|password|"
    r"bearer\s+[A-Za-z0-9._\-]+|aws_access_key|"
    r"-----BEGIN|client_secret)",
    re.IGNORECASE,
)
_USER_OBJECT_RE = re.compile(
    r'"(UserId|userId|user_id|email|username)"\s*:',
)
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


def _detect_info_disclosure(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match unauthenticated 200s containing version banners,
    secrets, or user-shaped payloads.
    """
    out: list[FallbackHypothesis] = []
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
        if _SECRET_HINT_RE.search(body):
            out.append(
                FallbackHypothesis(
                    bug_class="info_disclosure",
                    severity_hint="high",
                    evidence_refs=(obs.id,),
                    rationale=_FALLBACK_RATIONALE_TEMPLATE.format(
                        bug_class="info_disclosure",
                        endpoint=_path_only(url),
                        curl_target=url,
                        obs_id=obs.id,
                        status=200,
                        evidence_excerpt=f"secret/credential token detected ({_excerpt(body, 120)!r})",
                        impact_note=(
                            "an unauthenticated reader of this endpoint "
                            "obtains credential-shaped material"
                        ),
                    ),
                    detector="info_disclosure:secret",
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
        if (
            _USER_OBJECT_RE.search(body)
            and "[" in body
            and body.count('"UserId"') + body.count('"userId"') + body.count('"email"') >= 2
        ):
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
    return out


def _detect_auth_bypass(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match same-path-different-status pairs where one is 401/403
    and one is 200 — the canonical auth_bypass differential.
    """
    out: list[FallbackHypothesis] = []
    by_path: dict[str, list[SessionObservation]] = {}
    for obs in observations:
        if obs.kind != "request":
            continue
        url = _request_url(obs)
        if not url:
            continue
        path = _path_only(url)
        by_path.setdefault(path, []).append(obs)
    for path, group in by_path.items():
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
                    endpoint=path,
                    curl_target=_request_url(open_),
                    obs_id=open_.id,
                    status=200,
                    evidence_excerpt=(
                        f"same path returned 200 and "
                        f"{_request_status(protected)} on different requests "
                        f"(this run's pool only — same-path differential)"
                    ),
                    impact_note=(
                        "the protected variant correctly enforced auth "
                        "while the open variant did not, on the same "
                        "endpoint shape"
                    ),
                ),
                detector="auth_bypass:same_path_status_differential",
            )
        )
    return out


def _detect_idor(
    observations: list[SessionObservation],
) -> list[FallbackHypothesis]:
    """Match observations on path-shaped endpoints (`/x/{id}`) where
    different ids both return 200 with user-shaped data — the
    classic IDOR pattern.
    """
    out: list[FallbackHypothesis] = []
    by_template: dict[str, list[tuple[str, SessionObservation]]] = {}
    for obs in observations:
        if obs.kind != "request":
            continue
        if _request_status(obs) != 200:
            continue
        url = _request_url(obs)
        path = _path_only(url)
        match = _PATH_ID_RE.match(path)
        if not match:
            continue
        template = match.group(1)
        ident = match.group(2)
        by_template.setdefault(template, []).append((ident, obs))
    for template, items in by_template.items():
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
                    endpoint=f"{template}/{{id}}",
                    curl_target=_request_url(sample),
                    obs_id=sample.id,
                    status=200,
                    evidence_excerpt=(
                        f"same handler returned 200 for ids "
                        f"{ids_seen!r} with user-shaped fields in body"
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
