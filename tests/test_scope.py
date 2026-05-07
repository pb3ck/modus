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
