"""Smoke test for the package itself.

This is a placeholder until real tests land. It exists so that the
test suite is non-empty from the first commit and CI has something
to run.
"""

from __future__ import annotations

import modus


def test_version_is_set() -> None:
    assert modus.__version__ == "0.0.0"


def test_version_is_string() -> None:
    assert isinstance(modus.__version__, str)
