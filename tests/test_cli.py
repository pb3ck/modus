"""Tests for the Modus CLI."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from click.testing import CliRunner

from modus import cli as cli_module
from modus.cli import main
from modus.corpus import (
    CorpusError,
    CorpusStatus,
    CorpusToolsMissingError,
    CorpusUnavailableError,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


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


class TestMcpCommand:
    def test_help_lists_mcp_subcommand(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "mcp" in result.output

    def test_mcp_requires_scope(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["mcp"])
        assert result.exit_code != 0
        assert "scope" in result.output.lower()


class _FakeQuarryClient:
    """Stand-in injected at import sites of QuarryMcpClient.

    Configurable to either return a status payload or raise one of the
    corpus errors the CLI must distinguish in its exit codes.
    """

    def __init__(
        self,
        *,
        status: CorpusStatus | None = None,
        raise_on_enter: BaseException | None = None,
        raise_on_status: BaseException | None = None,
    ) -> None:
        self._status = status
        self._raise_on_enter = raise_on_enter
        self._raise_on_status = raise_on_status

    def factory(self, **_: Any) -> _FakeQuarryClient:
        return self

    async def __aenter__(self) -> _FakeQuarryClient:
        if self._raise_on_enter is not None:
            raise self._raise_on_enter
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def status(self) -> CorpusStatus:
        if self._raise_on_status is not None:
            raise self._raise_on_status
        assert self._status is not None
        return self._status


class TestCorpusStatus:
    @staticmethod
    def _patch(monkeypatch: pytest.MonkeyPatch, fake: _FakeQuarryClient) -> None:
        monkeypatch.setattr(cli_module, "QuarryMcpClient", fake.factory)

    def test_success_human_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeQuarryClient(
            status=CorpusStatus(
                schema_version=8,
                current_target="demo",
                targets=3,
                assets=42,
                runs=7,
                artifacts=17,
                evidence=119,
                findings=2,
                sessions=5,
                last_run_started_at="2026-05-01T12:00:00Z",
            )
        )
        self._patch(monkeypatch, fake)
        result = CliRunner().invoke(main, ["corpus", "status"])
        assert result.exit_code == 0, result.output
        assert "schema_version" in result.output
        assert "demo" in result.output

    def test_success_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeQuarryClient(
            status=CorpusStatus(
                schema_version=8,
                current_target=None,
                targets=0,
                assets=0,
                runs=0,
                artifacts=0,
                evidence=0,
                findings=0,
                sessions=0,
                last_run_started_at=None,
            )
        )
        self._patch(monkeypatch, fake)
        result = CliRunner().invoke(main, ["corpus", "status", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["schema_version"] == 8
        assert payload["current_target"] is None

    def test_unavailable_exits_three(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeQuarryClient(raise_on_enter=CorpusUnavailableError("quarry binary not found"))
        self._patch(monkeypatch, fake)
        result = CliRunner().invoke(main, ["corpus", "status"])
        assert result.exit_code == 3

    def test_tools_missing_exits_four(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeQuarryClient(
            raise_on_enter=CorpusToolsMissingError(
                missing={"analyze_regression"},
                available={"status"},
            )
        )
        self._patch(monkeypatch, fake)
        result = CliRunner().invoke(main, ["corpus", "status"])
        assert result.exit_code == 4

    def test_other_corpus_error_exits_five(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeQuarryClient(raise_on_status=CorpusError("something else"))
        # The status error path requires entering the context, so allow that
        # before raising on the actual call.
        fake._status = CorpusStatus(
            schema_version=0,
            current_target=None,
            targets=0,
            assets=0,
            runs=0,
            artifacts=0,
            evidence=0,
            findings=0,
            sessions=0,
            last_run_started_at=None,
        )
        self._patch(monkeypatch, fake)
        result = CliRunner().invoke(main, ["corpus", "status"])
        assert result.exit_code == 5
