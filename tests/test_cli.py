"""Tests for the Modus CLI."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner

from modus.cli import main

if TYPE_CHECKING:
    from pathlib import Path


class TestStatusCommand:
    def test_status_runs(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "modus" in result.output


class TestActionValidate:
    def _spec(self, tmp_path: Path, payload: dict[str, object]) -> Path:
        path = tmp_path / "spec.json"
        path.write_text(json.dumps(payload))
        return path

    def test_all_accepted_exits_zero(self, tmp_path: Path) -> None:
        spec = self._spec(
            tmp_path,
            {
                "state": {
                    "in_scope_assets": ["target.example.com"],
                    "allowed_methods": ["GET"],
                },
                "actions": [
                    {"kind": "probe", "target": "target.example.com"},
                    {
                        "kind": "request",
                        "target": "target.example.com",
                        "method": "GET",
                        "path": "/",
                    },
                ],
            },
        )
        runner = CliRunner()
        result = runner.invoke(main, ["action", "validate", str(spec)])
        assert result.exit_code == 0, result.output

    def test_any_rejected_exits_one(self, tmp_path: Path) -> None:
        spec = self._spec(
            tmp_path,
            {
                "state": {
                    "in_scope_assets": ["target.example.com"],
                    "allowed_methods": ["GET"],
                },
                "actions": [
                    {"kind": "probe", "target": "target.example.com"},
                    {"kind": "probe", "target": "evil.example.com"},
                ],
            },
        )
        runner = CliRunner()
        result = runner.invoke(main, ["action", "validate", str(spec)])
        assert result.exit_code == 1

    def test_json_output(self, tmp_path: Path) -> None:
        spec = self._spec(
            tmp_path,
            {
                "state": {"in_scope_assets": ["target.example.com"]},
                "actions": [{"kind": "probe", "target": "target.example.com"}],
            },
        )
        runner = CliRunner()
        result = runner.invoke(main, ["action", "validate", "--json", str(spec)])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload[0]["accepted"] is True

    def test_invalid_action_exits_two(self, tmp_path: Path) -> None:
        spec = self._spec(
            tmp_path,
            {
                "state": {"in_scope_assets": ["target.example.com"]},
                "actions": [{"kind": "shell", "command": "id"}],
            },
        )
        runner = CliRunner()
        result = runner.invoke(main, ["action", "validate", str(spec)])
        assert result.exit_code == 2

    def test_missing_file_exits_two(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["action", "validate", str(tmp_path / "missing.json")])
        assert result.exit_code == 2


class TestRunCommand:
    def test_run_is_stub(self, tmp_path: Path) -> None:
        scope = tmp_path / "scope.json"
        scope.write_text(
            json.dumps(
                {
                    "target_name": "demo",
                    "allowed_assets": ["a.example.com"],
                    "allowed_methods": ["GET"],
                }
            )
        )
        runner = CliRunner()
        result = runner.invoke(main, ["run", "--target", "demo", "--scope", str(scope)])
        assert result.exit_code == 2
