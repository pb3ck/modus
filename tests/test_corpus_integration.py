"""Integration tests against a real ``quarry mcp`` subprocess.

These tests are gated behind the ``integration`` pytest marker and
skipped by default. Run them locally with::

    pytest -m integration tests/test_corpus_integration.py

They require:

* A ``quarry`` binary on ``PATH`` (or via ``MODUS_QUARRY_BIN``).
* Permission to spawn a child process and write to a tmpdir.

Each test seeds its own corpus via ``quarry init`` in a tmpdir, points
``$QUARRY_HOME`` at it, then drives the client through real MCP
JSON-RPC. Don't rely on these tests in CI unless the runner has Quarry
installed; the contract tests in ``test_corpus.py`` carry the load.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from modus.corpus import QuarryMcpClient

pytestmark = pytest.mark.integration


def _quarry_binary() -> str | None:
    explicit = os.environ.get("MODUS_QUARRY_BIN")
    if explicit:
        return explicit if Path(explicit).is_file() else None
    return shutil.which("quarry")


@pytest.fixture
def quarry_corpus(tmp_path: Path) -> str:
    """Spin up a fresh Quarry corpus in a tmpdir and return its path."""
    binary = _quarry_binary()
    if binary is None:
        pytest.skip("quarry binary not found on PATH or in MODUS_QUARRY_BIN")
    corpus = tmp_path / "quarry-home"
    env = {**os.environ, "QUARRY_HOME": str(corpus)}
    result = subprocess.run([binary, "init"], env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.skip(f"`quarry init` failed (exit {result.returncode}): {result.stderr.strip()}")
    return str(corpus)


class TestRealQuarry:
    async def test_status_reports_empty_corpus(self, quarry_corpus: str) -> None:
        binary = _quarry_binary()
        assert binary is not None  # the fixture would have skipped otherwise
        env = {**os.environ, "QUARRY_HOME": quarry_corpus}
        client = QuarryMcpClient(command=binary, env=env, call_timeout_seconds=15.0)
        async with client:
            status = await client.status()
            targets = await client.list_targets()
        assert status.targets == 0
        assert status.current_target is None
        assert targets == []

    async def test_round_trip_target_creation(self, quarry_corpus: str, tmp_path: Path) -> None:
        binary = _quarry_binary()
        assert binary is not None
        env = {**os.environ, "QUARRY_HOME": quarry_corpus}
        # Operator action — Modus does not wrap CLI ops; we shell out
        # exactly like an operator would.
        result = subprocess.run(
            [binary, "target", "add", "demo", "--kind", "lab"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("quarry target add failed: " + result.stderr.strip())
        client = QuarryMcpClient(command=binary, env=env, call_timeout_seconds=15.0)
        async with client:
            status = await client.status()
            targets = await client.list_targets()
        assert status.targets == 1
        assert any(t.name == "demo" and t.is_current for t in targets)
