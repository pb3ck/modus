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
