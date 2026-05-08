"""Tests for the scope policy."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from modus.scope import ScopePolicy

if TYPE_CHECKING:
    from pathlib import Path


class TestScopePolicy:
    def test_minimal_valid(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        assert "GET" in policy.allowed_methods
        assert "DELETE" not in policy.allowed_methods

    def test_wildcards_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(target_name="t", allowed_assets=frozenset({"*.example.com"}))

    def test_unknown_methods_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                allowed_methods=frozenset({"GET", "FOO"}),
            )

    def test_from_json(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        path.write_text(
            json.dumps(
                {
                    "target_name": "demo",
                    "allowed_assets": ["a.example.com", "b.example.com"],
                    "allowed_methods": ["GET", "HEAD"],
                }
            )
        )
        policy = ScopePolicy.from_json(path)
        assert policy.target_name == "demo"
        assert "a.example.com" in policy.allowed_assets

    def test_policy_is_frozen(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        with pytest.raises(ValidationError):
            policy.target_name = "other"  # type: ignore[misc]

    def test_default_user_agent_is_conservative(self) -> None:
        from modus.scope import DEFAULT_USER_AGENT

        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        # Default should identify the tool generically without leaking
        # the project URL or any operator-specific details.
        assert policy.user_agent == DEFAULT_USER_AGENT
        assert policy.user_agent.startswith("Modus/")
        assert "github" not in policy.user_agent
        assert "(" not in policy.user_agent  # no parenthetical UA comment in default

    def test_custom_user_agent_round_trips(self) -> None:
        policy = ScopePolicy(
            target_name="acme-bbp",
            allowed_assets=frozenset({"a.example.com"}),
            user_agent="ResearcherX/Modus (acme-bbp)",
        )
        assert policy.user_agent == "ResearcherX/Modus (acme-bbp)"

    def test_user_agent_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                user_agent="",
            )


class TestScopeDefaultHeaders:
    """Operator-pinned headers sent on every outbound request.

    The motivating case is bug-bounty researcher-identifying headers
    (``X-HackerOne-Research``, ``X-Bugcrowd-Researcher``, etc.) the
    program requires on every probe. Pinning them in scope means
    the agent cannot accidentally omit them.
    """

    def test_default_is_empty_dict(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        assert policy.default_headers == {}

    def test_h1_research_header_round_trips(self) -> None:
        policy = ScopePolicy(
            target_name="anduril",
            allowed_assets=frozenset({"foxglove.bunker.anduril.dev"}),
            default_headers={"X-HackerOne-Research": "pb3ck"},
        )
        assert policy.default_headers == {"X-HackerOne-Research": "pb3ck"}

    def test_from_json_with_default_headers(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        path.write_text(
            json.dumps(
                {
                    "target_name": "anduril",
                    "allowed_assets": ["foxglove.bunker.anduril.dev"],
                    "default_headers": {"X-HackerOne-Research": "pb3ck"},
                }
            )
        )
        policy = ScopePolicy.from_json(path)
        assert policy.default_headers["X-HackerOne-Research"] == "pb3ck"

    def test_empty_header_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"": "value"},
            )

    def test_empty_header_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"X-Researcher": ""},
            )

    def test_header_name_with_space_rejected(self) -> None:
        # RFC 7230 token chars exclude whitespace.
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"X Researcher": "pb3ck"},
            )

    def test_header_name_with_colon_rejected(self) -> None:
        # Colon is the field separator; rejecting it prevents the
        # operator from accidentally pasting a full header line.
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"X-Researcher: x": "pb3ck"},
            )

    def test_header_value_with_crlf_rejected(self) -> None:
        # CR/LF in header values would let an operator (or, more
        # importantly, a config-file-injection attacker) inject
        # additional headers — classic header-injection vector.
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"X-Researcher": "pb3ck\r\nX-Inject: y"},
            )

    def test_user_agent_in_default_headers_rejected(self) -> None:
        # User-Agent has a dedicated field; allowing both surfaces
        # would let them disagree silently.
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"User-Agent": "Custom/1.0"},
            )

    def test_user_agent_lowercase_in_default_headers_also_rejected(self) -> None:
        # Header names are case-insensitive per RFC 7230; the
        # User-Agent guard must too.
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset({"a.example.com"}),
                default_headers={"user-agent": "Custom/1.0"},
            )

    def test_multiple_headers_round_trip(self) -> None:
        policy = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"a.example.com"}),
            default_headers={
                "X-HackerOne-Research": "pb3ck",
                "X-Engagement-ID": "anduril-2026-05-08",
            },
        )
        assert len(policy.default_headers) == 2
        assert policy.default_headers["X-HackerOne-Research"] == "pb3ck"
        assert policy.default_headers["X-Engagement-ID"] == "anduril-2026-05-08"


class TestScopeWildcards:
    """ADR 0005: scope_wildcards is the program-published wildcard
    authorization (e.g. ``*.anduril.com``). Used as the substrate
    for recon-mode enumeration. NOT a probe-mode allow-list —
    Request still requires exact-match allowed_assets.
    """

    def test_default_empty(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        assert policy.scope_wildcards == frozenset()

    def test_valid_wildcard_round_trips(self) -> None:
        policy = ScopePolicy(
            target_name="anduril",
            allowed_assets=frozenset(),
            scope_wildcards=frozenset({"*.anduril.com", "*.anduril.dev"}),
        )
        assert "*.anduril.com" in policy.scope_wildcards

    def test_rejects_pattern_without_leading_star_dot(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset(),
                scope_wildcards=frozenset({"anduril.com"}),  # missing *.
            )

    def test_rejects_embedded_wildcard(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset(),
                scope_wildcards=frozenset({"*.foo.*.com"}),
            )

    def test_rejects_empty_label_in_parent_zone(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset(),
                scope_wildcards=frozenset({"*..com"}),
            )

    def test_rejects_label_starting_with_hyphen(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset(),
                scope_wildcards=frozenset({"*.-foo.com"}),
            )

    def test_rejects_invalid_character_in_label(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(
                target_name="t",
                allowed_assets=frozenset(),
                scope_wildcards=frozenset({"*.foo bar.com"}),  # space invalid
            )


class TestReconMode:
    """ADR 0005: recon_mode flag toggles read-only OSINT behaviour."""

    def test_default_false(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        assert policy.recon_mode is False

    def test_round_trip_true(self) -> None:
        policy = ScopePolicy(
            target_name="anduril",
            allowed_assets=frozenset(),
            scope_wildcards=frozenset({"*.anduril.com"}),
            recon_mode=True,
        )
        assert policy.recon_mode is True


class TestDeniedPatterns:
    """ADR 0005: denied_patterns is a defence-in-depth deny set."""

    def test_default_empty(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"a.example.com"}))
        assert policy.denied_patterns == ()

    def test_substring_pattern_round_trips(self) -> None:
        from modus.scope import DeniedPattern

        policy = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"a.example.com"}),
            denied_patterns=(DeniedPattern(token="africom", mode="substring"),),
        )
        assert policy.denied_patterns[0].token == "africom"
        assert policy.denied_patterns[0].mode == "substring"

    def test_segment_pattern_round_trips(self) -> None:
        from modus.scope import DeniedPattern

        p = DeniedPattern(token="usmc", mode="segment")
        assert p.mode == "segment"

    def test_prefix_pattern_round_trips(self) -> None:
        from modus.scope import DeniedPattern

        p = DeniedPattern(token="piv.", mode="prefix")
        assert p.mode == "prefix"

    def test_infix_pattern_round_trips(self) -> None:
        from modus.scope import DeniedPattern

        p = DeniedPattern(token=".gov.", mode="infix")
        assert p.mode == "infix"

    def test_default_mode_is_substring(self) -> None:
        from modus.scope import DeniedPattern

        p = DeniedPattern(token="africom")
        assert p.mode == "substring"

    def test_rejects_unknown_mode(self) -> None:
        from modus.scope import DeniedPattern

        with pytest.raises(ValidationError):
            DeniedPattern(token="africom", mode="not-a-real-mode")  # type: ignore[arg-type]

    def test_rejects_empty_token(self) -> None:
        from modus.scope import DeniedPattern

        with pytest.raises(ValidationError):
            DeniedPattern(token="", mode="substring")

    def test_denied_pattern_is_frozen(self) -> None:
        from modus.scope import DeniedPattern

        p = DeniedPattern(token="x", mode="substring")
        with pytest.raises(ValidationError):
            p.token = "y"  # type: ignore[misc]


class TestHostMatchesDeniedPattern:
    """The matcher used by the consistency layer's Request precondition."""

    def test_substring_match(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="africom", mode="substring"),)
        result = host_matches_denied_pattern("africom.example.com", patterns)
        assert result == ("africom",)

    def test_substring_does_not_match(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="africom", mode="substring"),)
        result = host_matches_denied_pattern("example.com", patterns)
        assert result == ()

    def test_segment_match_with_dot_boundary(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="usmc", mode="segment"),)
        result = host_matches_denied_pattern("piv.usmc.example.com", patterns)
        assert result == ("usmc",)

    def test_segment_match_with_hyphen_boundary(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="ad", mode="segment"),)
        result = host_matches_denied_pattern("ad-dev.example.com", patterns)
        assert result == ("ad",)

    def test_segment_does_not_match_inside_word(self) -> None:
        # ``usaf`` segment-bounded must NOT match ``usafrica``
        # (regression on the partition slip class).
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="usaf", mode="segment"),)
        result = host_matches_denied_pattern("usafrica.example.com", patterns)
        assert result == ()

    def test_prefix_match(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="piv.", mode="prefix"),)
        result = host_matches_denied_pattern("piv.foo.example.com", patterns)
        assert result == ("piv.",)

    def test_prefix_does_not_match_in_middle(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="piv.", mode="prefix"),)
        result = host_matches_denied_pattern("foo.piv.example.com", patterns)
        assert result == ()

    def test_infix_match(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token=".gov.", mode="infix"),)
        result = host_matches_denied_pattern("foo.gov.example.com", patterns)
        assert result == (".gov.",)

    def test_returns_all_matched_tokens(self) -> None:
        # A host can match multiple patterns; the matcher returns all.
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (
            DeniedPattern(token="usmc", mode="segment"),
            DeniedPattern(token="piv.", mode="prefix"),
        )
        result = host_matches_denied_pattern("piv.usmc.example.com", patterns)
        assert "usmc" in result
        assert "piv." in result

    def test_case_insensitive(self) -> None:
        from modus.scope import DeniedPattern, host_matches_denied_pattern

        patterns = (DeniedPattern(token="AFRICOM", mode="substring"),)
        result = host_matches_denied_pattern("africom.example.com", patterns)
        assert result == ("AFRICOM",)

    def test_empty_patterns_returns_empty(self) -> None:
        from modus.scope import host_matches_denied_pattern

        assert host_matches_denied_pattern("any.example.com", ()) == ()


class TestAllowedEndpointParsing:
    def test_bare_hostname_is_wildcard(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"example.com"}))
        eps = policy.endpoints()
        assert len(eps) == 1
        ep = eps[0]
        assert ep.host == "example.com"
        assert ep.port is None
        assert ep.tls is None
        # Matches any concrete (port, tls) combination.
        assert ep.matches("example.com", port=443, tls=True)
        assert ep.matches("example.com", port=80, tls=False)
        assert ep.matches("example.com", port=8080, tls=False)
        assert not ep.matches("other.example.com", port=443, tls=True)

    def test_url_with_scheme_constrains_tls(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"http://localhost:13000"}))
        ep = policy.endpoints()[0]
        assert ep.host == "localhost"
        assert ep.port == 13000
        assert ep.tls is False
        assert ep.matches("localhost", port=13000, tls=False)
        assert not ep.matches("localhost", port=13000, tls=True)
        assert not ep.matches("localhost", port=3000, tls=False)

    def test_https_without_port_keeps_tls_constrained_port_open(self) -> None:
        policy = ScopePolicy(target_name="t", allowed_assets=frozenset({"https://example.com"}))
        ep = policy.endpoints()[0]
        assert ep.host == "example.com"
        assert ep.port is None
        assert ep.tls is True
        assert ep.matches("example.com", port=443, tls=True)
        assert ep.matches("example.com", port=8443, tls=True)
        assert not ep.matches("example.com", port=80, tls=False)

    def test_request_in_scope_helper(self) -> None:
        policy = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://localhost:13000", "https://api.example.com"}),
        )
        # in-scope: matches the http+13000 entry
        assert policy.request_in_scope("localhost", 13000, False)
        # in-scope: matches the https+any-port entry
        assert policy.request_in_scope("api.example.com", 443, True)
        # out-of-scope: same host as one entry but wrong scheme
        assert not policy.request_in_scope("localhost", 13000, True)
        # out-of-scope: same host as one entry but wrong port
        assert not policy.request_in_scope("localhost", 3000, False)
        # out-of-scope: hostname not in any entry
        assert not policy.request_in_scope("evil.example.com", 443, True)

    def test_invalid_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(target_name="t", allowed_assets=frozenset({"http://localhost:99999"}))

    def test_non_integer_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopePolicy(target_name="t", allowed_assets=frozenset({"http://localhost:abc"}))

    def test_hosts_aggregates_unique_hostnames(self) -> None:
        policy = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset(
                {
                    "http://localhost:13000",
                    "https://localhost",
                    "https://api.example.com",
                }
            ),
        )
        assert policy.hosts() == frozenset({"localhost", "api.example.com"})
