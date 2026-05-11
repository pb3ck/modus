"""Tests for the multi-step state extraction module (ADR 0007).

The 2026-05-10 wp-bounty-lab user-registration audit (issue #36)
identified that Modus's autonomous loop couldn't extract a CSRF
nonce from one observation's body and use it in a follow-up
request — blocking the canonical WordPress form-attack flow. ADR
0007 added curated-pattern token harvesting; these tests pin the
contract.
"""

from __future__ import annotations

from modus.token_extractor import (
    DEFAULT_PATTERNS,
    ExtractedToken,
    ExtractorPattern,
    extract_tokens,
    render_token_block,
)


def _obs(obs_id: str, url: str, body: str):
    """Build a SessionObservation with response_body."""
    from modus.session import SessionObservation

    return SessionObservation(
        id=obs_id,
        kind="request",
        payload={"url": url, "response_body": body, "status": 200},
    )


class TestExtractTokens:
    def test_wp_nonce_extracted_from_form(self) -> None:
        # The canonical WP form CSRF nonce shape from
        # ``wp_nonce_field()``. 2026-05-10 user-registration audit
        # would have benefited from this had it landed.
        body = (
            '<form method="post"><input name="_wpnonce" value="a3b91c8d04" />'
            '<input name="user_email" /></form>'
        )
        result = extract_tokens([_obs("o1", "http://t/register/", body)])
        assert "_wpnonce" in result
        token = result["_wpnonce"]
        assert token.value == "a3b91c8d04"
        assert token.source_observation_id == "o1"
        assert token.source_url == "http://t/register/"

    def test_wp_rest_nonce_from_settings_object(self) -> None:
        # WP REST nonce shows up in the ``wpApiSettings`` JS object on
        # admin pages. 10-char hex value.
        body = '<script>var wpApiSettings = {"root":"...","nonce":"f7e228919c"};</script>'
        result = extract_tokens([_obs("o2", "http://t/wp-admin/", body)])
        assert "wp_rest_nonce" in result
        assert result["wp_rest_nonce"].value == "f7e228919c"

    def test_data_token_attribute_extracted(self) -> None:
        # WPForms / similar plugins put a 32-char data-token on the
        # form root for anti-spam.
        body = '<div data-token="dcb007b7b01c8f407a3e52cf4aadc08f"></div>'
        result = extract_tokens([_obs("o3", "http://t/contact/", body)])
        assert "data_token" in result
        assert result["data_token"].value == "dcb007b7b01c8f407a3e52cf4aadc08f"

    def test_generic_csrf_token(self) -> None:
        # Laravel/Symfony/Django-style apps use ``_token`` /
        # ``csrf_token`` / ``csrfmiddlewaretoken``. Pattern accepts
        # any of those names with a 16-64 char value.
        body = '<input name="_token" value="abcdef1234567890ABCDEFXYZ_=-" />'
        result = extract_tokens([_obs("o4", "http://t/", body)])
        assert "csrf_token" in result
        assert result["csrf_token"].value == "abcdef1234567890ABCDEFXYZ_=-"

    def test_newest_observation_wins(self) -> None:
        # If two observations both contain a nonce, the most-recent
        # value wins. Tokens often rotate; freshest is most likely
        # valid for the next request.
        old = '<input name="_wpnonce" value="0000000000" />'
        new = '<input name="_wpnonce" value="ffffffffff" />'
        result = extract_tokens(
            [_obs("o-old", "http://t/x", old), _obs("o-new", "http://t/y", new)]
        )
        assert result["_wpnonce"].value == "ffffffffff"
        assert result["_wpnonce"].source_observation_id == "o-new"

    def test_empty_observations_returns_empty(self) -> None:
        assert extract_tokens([]) == {}

    def test_no_match_returns_empty(self) -> None:
        body = "<html><body>Nothing token-shaped here.</body></html>"
        result = extract_tokens([_obs("o1", "http://t/", body)])
        assert result == {}

    def test_skips_non_request_observations(self) -> None:
        # Defensive: an observation of kind != "request" shouldn't
        # contribute tokens (no body to extract from).
        from modus.session import SessionObservation

        non_request = SessionObservation(
            id="o-not-request",
            kind="probe",
            payload={"hits": []},
        )
        # And a real request observation that DOES have a token
        body = '<input name="_wpnonce" value="abcdef1234" />'
        request_obs = _obs("o-req", "http://t/", body)
        result = extract_tokens([non_request, request_obs])
        assert result["_wpnonce"].value == "abcdef1234"
        assert result["_wpnonce"].source_observation_id == "o-req"

    def test_anchor_required_no_naked_match(self) -> None:
        # Defensive: a 10-char hex string in plain prose body should
        # NOT match the _wpnonce pattern. The pattern requires the
        # surrounding ``name="_wpnonce" value=...`` HTML context. A
        # false positive here would cause the LLM to embed garbage
        # into requests.
        body = "<p>Contact our support team. Reference number 1234567890 (10 hex digits-ish).</p>"
        result = extract_tokens([_obs("o1", "http://t/", body)])
        # No _wpnonce because the surrounding ``name="_wpnonce"
        # value="..."`` context is absent.
        assert "_wpnonce" not in result

    def test_dynamic_pattern_extracts_swpm_registration_nonce(self) -> None:
        # The 2026-05-10 simple-membership audit observed
        # ``swpm_registration_nonce`` in form fields and the LLM hit
        # the validation endpoint with ``nonce=test`` because the
        # fixed-name patterns didn't catch this plugin-specific
        # field name. The dynamic plugin-nonce pattern closes it.
        body = (
            '<form id="swpm-registration-form" method="post">'
            '<input name="swpm_registration_nonce" value="b761c3f88e" />'
            '<input name="user_name" /></form>'
        )
        result = extract_tokens([_obs("o1", "http://t/?swpm_login=1", body)])
        assert "swpm_registration_nonce" in result
        token = result["swpm_registration_nonce"]
        assert token.value == "b761c3f88e"
        assert token.source_observation_id == "o1"

    def test_dynamic_pattern_extracts_user_registration_nonce(self) -> None:
        # User Registration & Membership uses
        # ``user_registration_profile_picture_*_nonce``. Same
        # extractor catches it without enumerating the slug.
        body = (
            '<input type="hidden" '
            'name="user_registration_profile_picture_remove_nonce" '
            'value="9f8c1a2b34" />'
        )
        result = extract_tokens([_obs("o1", "http://t/account/", body)])
        assert "user_registration_profile_picture_remove_nonce" in result
        assert result["user_registration_profile_picture_remove_nonce"].value == "9f8c1a2b34"

    def test_dynamic_pattern_extracts_multiple_nonces_from_one_page(self) -> None:
        # A registration page often emits multiple plugin nonces in
        # one HTML response. The dynamic pattern must emit one
        # token per match, not stop after the first.
        body = (
            '<input name="swpm_login_nonce" value="aaaaaaaaaa" />'
            '<input name="swpm_register_nonce" value="bbbbbbbbbb" />'
        )
        result = extract_tokens([_obs("o1", "http://t/", body)])
        assert "swpm_login_nonce" in result
        assert "swpm_register_nonce" in result
        assert result["swpm_login_nonce"].value == "aaaaaaaaaa"
        assert result["swpm_register_nonce"].value == "bbbbbbbbbb"

    def test_dynamic_pattern_extracts_from_json_settings_object(self) -> None:
        # Plugins sometimes localise their nonce into a JS settings
        # object via wp_localize_script. The JSON variant catches it.
        body = (
            "<script>var swpmSettings = "
            '{"ajaxurl":"\\/wp-admin\\/admin-ajax.php",'
            '"swpm_ajax_nonce":"e3a4b1c2d5"};</script>'
        )
        result = extract_tokens([_obs("o1", "http://t/", body)])
        assert "swpm_ajax_nonce" in result
        assert result["swpm_ajax_nonce"].value == "e3a4b1c2d5"

    def test_dynamic_pattern_does_not_match_non_wp_nonce_values(self) -> None:
        # Anchored on the 10-hex-char value shape. A field named
        # ``something_nonce`` with a longer or non-hex value should
        # NOT match — those aren't WP-shape nonces and embedding
        # them would corrupt the request.
        body_too_long = '<input name="custom_nonce" value="abcdef1234567890" />'
        body_non_hex = '<input name="custom_nonce" value="HELLOWORLD" />'
        assert "custom_nonce" not in extract_tokens([_obs("o1", "http://t/", body_too_long)])
        assert "custom_nonce" not in extract_tokens([_obs("o2", "http://t/", body_non_hex)])

    def test_dynamic_pattern_does_not_collide_with_fixed_wp_rest_nonce(self) -> None:
        # ``wp_rest_nonce`` is a fixed-name pattern, but
        # ``"nonce": "..."`` shape would NOT be caught by the
        # dynamic JSON pattern (it requires a trailing ``_nonce``
        # suffix on the key). Verify they don't fight over the same
        # JSON shape.
        body = '<script>var wpApiSettings = {"nonce":"f7e228919c"};</script>'
        result = extract_tokens([_obs("o1", "http://t/", body)])
        assert "wp_rest_nonce" in result
        # No collision-prefix name extracted from this shape.
        assert not any(k.endswith("_nonce") and k != "wp_rest_nonce" for k in result)

    def test_custom_pattern_set(self) -> None:
        # Operator can pass their own pattern set if they want to test
        # a custom token shape.
        import re

        custom = (
            ExtractorPattern(
                name="custom_secret",
                pattern=re.compile(r"X-Custom-Token:\s*([A-Z0-9]{8})"),
                description="custom test pattern",
            ),
        )
        body = "Some response. X-Custom-Token: ABCD1234. End."
        result = extract_tokens([_obs("o1", "http://t/", body)], patterns=custom)
        assert result["custom_secret"].value == "ABCD1234"


class TestDefaultPatternCatalog:
    def test_all_patterns_have_required_fields(self) -> None:
        # Sanity check on the curated pattern set. A misconfigured
        # entry (empty regex, missing capture group) would crash at
        # extract_tokens time. Fixed-name patterns must have exactly
        # one capture group; dynamic-name patterns must have two
        # named groups (``name`` and ``value``).
        for pattern in DEFAULT_PATTERNS:
            assert pattern.name
            assert pattern.description.strip()
            if pattern.dynamic_name:
                assert pattern.pattern.groups == 2, (
                    f"dynamic pattern {pattern.name!r} must have two capture groups"
                )
                group_names = set(pattern.pattern.groupindex)
                assert {"name", "value"}.issubset(group_names), (
                    f"dynamic pattern {pattern.name!r} must have named groups "
                    f"'name' and 'value' (got {group_names!r})"
                )
            else:
                assert pattern.pattern.groups == 1, (
                    f"pattern {pattern.name!r} must have exactly one capture group"
                )

    def test_canonical_token_names_present(self) -> None:
        # The names referenced in ADR 0007 + the WP-flow design must
        # be in the catalog.
        names = {p.name for p in DEFAULT_PATTERNS}
        for required in (
            "_wpnonce",
            "wp_rest_nonce",
            "csrf_token",
            "plugin_nonce_form",
            "plugin_nonce_json",
        ):
            assert required in names, f"DEFAULT_PATTERNS missing {required!r}"


class TestRenderTokenBlock:
    def test_empty_returns_empty_string(self) -> None:
        # Early steps before any token has been extracted produce no
        # block — the proposer's prompt stays compact.
        assert render_token_block({}) == ""

    def test_renders_table_with_token_values(self) -> None:
        from datetime import UTC, datetime

        token = ExtractedToken(
            name="_wpnonce",
            value="a3b91c8d04",
            source_observation_id="http-abc",
            source_url="http://t/register/",
            extracted_at=datetime.now(UTC),
        )
        out = render_token_block({"_wpnonce": token})
        assert "## Available extracted tokens" in out
        # Table row carries the literal value the LLM should embed.
        assert "`_wpnonce`" in out
        assert "`a3b91c8d04`" in out
        assert "`http-abc`" in out

    def test_render_is_sorted_by_name_for_determinism(self) -> None:
        # Token order should be stable across runs so prompt-cache
        # behavior is deterministic.
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        tokens = {
            "csrf_token": ExtractedToken("csrf_token", "z123", "h2", "http://t/2", now),
            "_wpnonce": ExtractedToken("_wpnonce", "a456", "h1", "http://t/1", now),
        }
        out = render_token_block(tokens)
        # ``_`` sorts before ``c`` lexicographically, so _wpnonce
        # appears first in the rendered table.
        assert out.index("_wpnonce") < out.index("csrf_token")
