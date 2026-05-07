"""Modus CLI entry point.

The CLI surface is intentionally minimal at this stage. Subcommands
will be added as the v0.1 milestones land. See ROADMAP.md.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from modus import __version__

console = Console()


@click.group()
@click.version_option(__version__, prog_name="modus")
def main() -> None:
    """Modus — offensive agent with formally checked actions."""


@main.command()
def status() -> None:
    """Print Modus status. Placeholder until M1 lands."""
    console.print(f"[bold]modus[/bold] version {__version__}")
    console.print("[yellow]pre-alpha — no functionality yet[/yellow]")


if __name__ == "__main__":
    sys.exit(main())
