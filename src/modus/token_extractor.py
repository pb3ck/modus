"""Multi-step state extraction — harvest tokens from response bodies.

The 2026-05-10 wp-bounty-lab user-registration audit (issue #36) made
the design problem concrete. Modus correctly identified the
privilege-escalation attack against the registration form:

    POST /register/
    body: username=test&...&role=administrator&wp_capabilities=administrator

…but the request didn't include the form's CSRF nonce because the
nonce sits at the *head* of the form HTML and the agent loop's
history excerpt is the *tail* 240 chars. The LLM never saw the
nonce and couldn't embed it.

This module is the architectural answer (ADR 0007). Curated regex
patterns extract well-known token shapes from response bodies after
each step. Extracted tokens land in ``StepContext.extracted_tokens``
so the proposer's prompt can render an "available tokens" block, and
the LLM can embed token values literally in the next request.

Trust posture matches :mod:`modus.evidence_patterns`: read-only,
deterministic, no operator-authored regex (curated patterns only).
The pattern catalog ships in source for auditability; per-target
extension hooks are deferred to a future ADR.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modus.session import SessionObservation


@dataclass(frozen=True)
class ExtractorPattern:
    """One curated regex pattern that extracts a named token.

    Two shapes are supported:

    * **Fixed-name** (default): the regex has exactly one capture
      group containing the token value. The :attr:`name` field is
      the canonical token name and surfaces in the proposer's
      prompt verbatim. Use this for tokens with a single
      well-known name (``_wpnonce``, ``X-WP-Nonce``, etc.).

    * **Dynamic-name** (``dynamic_name=True``): the regex has two
      *named* capture groups, ``(?P<name>...)`` and
      ``(?P<value>...)``. Each match emits a separate
      :class:`ExtractedToken` whose ``name`` is the captured name
      group. Use this for whole *families* of tokens that share a
      shape — e.g. WordPress plugin-specific nonces, where every
      plugin emits ``<slug>_<context>_nonce`` form fields and we
      want to harvest each one without enumerating the slug list.
    """

    name: str
    """Canonical token name (fixed-name mode) or fallback name
    (dynamic-name mode, used when the regex doesn't capture a
    ``name`` group). Used as the key in
    :attr:`StepContext.extracted_tokens` and in the proposer's
    "available tokens" prompt block. Stable across runs so the LLM
    can learn to reference specific names."""

    pattern: re.Pattern[str]
    """Compiled regex. In fixed-name mode: one capture group = the
    token value. In dynamic-name mode: two named groups
    ``(?P<name>)`` and ``(?P<value>)``."""

    description: str
    """One-line operator-readable description of what this token
    is for. Renders in the proposer's prompt block so the LLM
    knows when to use which token."""

    dynamic_name: bool = False
    """When True, :attr:`pattern` is expected to have named groups
    ``name`` and ``value``; one :class:`ExtractedToken` is emitted
    per match using the captured name. When False (default), the
    pattern is treated as fixed-name with a single value-capture
    group."""


@dataclass(frozen=True)
class ExtractedToken:
    """A token successfully extracted from one observation's body."""

    name: str
    value: str
    source_observation_id: str
    source_url: str
    extracted_at: datetime


# --- Curated pattern catalog --------------------------------------------------
#
# Each pattern is anchored on the surrounding context (HTML attribute,
# JSON key, etc.) so the regex doesn't match arbitrary 32-char strings.
# Add new patterns conservatively — false positives here cause the LLM
# to embed garbage in requests, which breaks subsequent flows silently.


DEFAULT_PATTERNS: tuple[ExtractorPattern, ...] = (
    # WordPress form CSRF nonce. Standard 10-char hex value embedded
    # in form HTML via ``wp_nonce_field()``.
    ExtractorPattern(
        name="_wpnonce",
        pattern=re.compile(r'name=["\']_wpnonce["\']\s+value=["\']([a-f0-9]{10})["\']'),
        description=(
            "WordPress form CSRF nonce (10 hex chars). Embed as ``_wpnonce`` "
            "in form-encoded request bodies for any wp-admin or wp-login.php "
            "POST."
        ),
    ),
    # WordPress REST API nonce. Stored in a JS settings object on
    # rendered admin pages and surfaces via the ``X-WP-Nonce`` header
    # for REST calls.
    ExtractorPattern(
        name="wp_rest_nonce",
        pattern=re.compile(r'"nonce"\s*:\s*"([a-f0-9]{10})"'),
        description=(
            "WordPress REST API nonce (10 hex chars). Send as the "
            "``X-WP-Nonce`` HTTP header for any /wp-json/ POST/PUT/DELETE."
        ),
    ),
    # Plugin-specific data-token attribute. WPForms and several other
    # form plugins emit a data-token containing an HMAC for anti-spam
    # protection.
    ExtractorPattern(
        name="data_token",
        pattern=re.compile(r'data-token=["\']([a-f0-9]{32})["\']'),
        description=(
            "Plugin form data-token attribute (32 hex chars). Used by "
            "WPForms / similar plugins as anti-spam token; embed as a "
            "form field if the plugin's submission flow validates it."
        ),
    ),
    # WP redirect-to / referer field — often paired with _wpnonce. Not
    # a CSRF token in itself but plugins sometimes treat its presence
    # as a UI-came-from-WP-admin signal.
    ExtractorPattern(
        name="_wp_http_referer",
        pattern=re.compile(r'name=["\']_wp_http_referer["\']\s+value=["\']([^"\']+)["\']'),
        description=(
            "WordPress hidden ``_wp_http_referer`` field. Embed alongside "
            "``_wpnonce`` in form POSTs that the plugin expects to come "
            "from a rendered admin/form page."
        ),
    ),
    # Generic CSRF token used by Laravel, Symfony, Yii, and a few WP
    # security plugins. Pattern is broader because the names vary;
    # restricted to the canonical ``csrf_token`` / ``_token`` shapes.
    ExtractorPattern(
        name="csrf_token",
        pattern=re.compile(
            r'name=["\'](?:csrf_token|_token|csrfmiddlewaretoken)["\']'
            r'\s+value=["\']([A-Za-z0-9+/=_\-]{16,64})["\']'
        ),
        description=(
            "Generic CSRF token from Laravel/Symfony/Django-style apps. "
            "Embed under the same field name (``_token`` is most common) "
            "in subsequent form POSTs against the same host."
        ),
    ),
    # WordPress plugin-specific nonces (form-field shape). Captures
    # the FULL field name so the LLM embeds it under the correct
    # parameter. Covers every plugin's ``<slug>_<context>_nonce``
    # without enumerating the slug list — observed shapes include
    # ``swpm_registration_nonce`` (Simple Membership),
    # ``user_registration_profile_picture_nonce`` (User Registration
    # & Membership), ``forminator_nonce``, ``wpcode_nonce``, etc.
    # Anchored on the 10-hex-char value so it doesn't match arbitrary
    # ``_nonce``-named fields with non-WP-shaped values. 2026-05-10
    # simple-membership audit (wpcode/swpm iterations) caught the
    # gap: the LLM hit nonce-protected endpoints with ``test`` as
    # the nonce because the form-field name didn't match the
    # single-name ``_wpnonce`` pattern.
    ExtractorPattern(
        name="plugin_nonce_form",
        pattern=re.compile(
            r'name=["\'](?P<name>[a-zA-Z][\w]*_nonce)["\']'
            r'\s+value=["\'](?P<value>[a-f0-9]{10})["\']'
        ),
        description=(
            "WordPress plugin-specific CSRF nonce form field "
            "(``<plugin>_<context>_nonce``, 10 hex chars). Embed "
            "under the captured field name in form-encoded POSTs to "
            "the plugin's submission endpoints. Common shapes: "
            "``swpm_registration_nonce``, "
            "``user_registration_*_nonce``, ``forminator_nonce``."
        ),
        dynamic_name=True,
    ),
    # WordPress plugin-specific nonces (JSON-key shape). Same name
    # family, surfaced when the plugin embeds the nonce in a
    # JS-settings object via ``wp_localize_script()`` rather than a
    # hidden form field. Companion to ``plugin_nonce_form``.
    ExtractorPattern(
        name="plugin_nonce_json",
        pattern=re.compile(r'"(?P<name>[a-zA-Z][\w]*_nonce)"\s*:\s*"(?P<value>[a-f0-9]{10})"'),
        description=(
            "WordPress plugin-specific CSRF nonce JSON key "
            "(``<plugin>_<context>_nonce``, 10 hex chars). Embed "
            "either as a header (e.g. ``X-WP-Nonce`` for REST) or "
            "as a body field under the captured key for AJAX POSTs. "
            "Common shapes match the form-field variant."
        ),
        dynamic_name=True,
    ),
)


def extract_tokens(
    observations: list[SessionObservation],
    patterns: tuple[ExtractorPattern, ...] = DEFAULT_PATTERNS,
) -> dict[str, ExtractedToken]:
    """Walk ``observations`` newest-to-oldest. Return a dict mapping
    each pattern name to the most-recent extracted token, when matched.

    Newest-first iteration so a pattern that matches in step 8 wins
    over the same pattern matching in step 3 — tokens often rotate or
    expire, and the freshest one is the most likely to be valid for
    a follow-up request.
    """
    out: dict[str, ExtractedToken] = {}
    seen_names: set[str] = set()
    for obs in reversed(observations):
        if obs.kind != "request":
            continue
        payload = obs.payload if isinstance(obs.payload, dict) else {}
        body = payload.get("response_body", "")
        if not isinstance(body, str) or not body:
            continue
        url = str(payload.get("url", ""))
        for pattern in patterns:
            if pattern.dynamic_name:
                # Iterate every match so one observation can yield
                # multiple tokens (a registration page commonly has
                # both ``swpm_login_nonce`` and ``swpm_register_nonce``).
                for match in pattern.pattern.finditer(body):
                    resolved = match.group("name")
                    if not resolved or resolved in seen_names:
                        continue
                    value = match.group("value")
                    if not value:
                        continue
                    seen_names.add(resolved)
                    out[resolved] = ExtractedToken(
                        name=resolved,
                        value=value,
                        source_observation_id=obs.id,
                        source_url=url,
                        extracted_at=datetime.now(UTC),
                    )
                continue
            # Fixed-name path: at most one extraction per pattern.
            if pattern.name in seen_names:
                continue
            fixed_match = pattern.pattern.search(body)
            if fixed_match is None:
                continue
            seen_names.add(pattern.name)
            out[pattern.name] = ExtractedToken(
                name=pattern.name,
                value=fixed_match.group(1),
                source_observation_id=obs.id,
                source_url=url,
                extracted_at=datetime.now(UTC),
            )
        # No early-exit: dynamic patterns can keep harvesting names
        # we haven't seen yet on later observations (a page from
        # step 3 may emit nonces the latest page doesn't). Per-name
        # dedup via ``seen_names`` ensures the freshest wins, and
        # the observation count for any audit run is bounded.
    return out


def render_token_block(extracted: dict[str, ExtractedToken]) -> str:
    """Render the proposer's "available extracted tokens" prompt block.

    Returns an empty string when no tokens have been extracted, so the
    proposer's prompt stays compact on early steps before any
    token-bearing observation has landed.
    """
    if not extracted:
        return ""
    lines = [
        "## Available extracted tokens",
        "",
        (
            "Tokens harvested from prior observations. Embed these literal "
            "values directly in your proposed Request's body, headers, or "
            "query string when the target endpoint requires them. Each "
            "token's source observation ID is shown so you can cite it in "
            "a hypothesize action's evidence_refs if relevant."
        ),
        "",
        "| Name | Value | Source obs |",
        "| --- | --- | --- |",
    ]
    for name in sorted(extracted):
        token = extracted[name]
        lines.append(f"| `{name}` | `{token.value}` | `{token.source_observation_id}` |")
    return "\n".join(lines) + "\n"


__all__ = [
    "DEFAULT_PATTERNS",
    "ExtractedToken",
    "ExtractorPattern",
    "extract_tokens",
    "render_token_block",
]
