"""Smoke test for the package itself.

This is a placeholder until real tests land. It exists so that the
test suite is non-empty from the first commit and CI has something
to run.
"""

from __future__ import annotations

import modus


def test_version_is_set() -> None:
    assert modus.__version__ == "0.4.0"


def test_version_is_string() -> None:
    assert isinstance(modus.__version__, str)


def test_version_matches_pep440_form() -> None:
    # Loose check that we're shipping a recognisable PEP 440 version.
    # Accepts the non-prerelease form (``0.4.0``) plus ``aN`` / ``bN`` /
    # ``rcN`` pre-releases for any future alphas/betas before the next
    # minor or major bump.
    import re

    assert re.match(r"^\d+\.\d+\.\d+((a|b|rc)\d+)?$", modus.__version__)
