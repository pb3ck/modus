"""Modus CLI entry point.

Subcommands land alongside the milestones in ROADMAP.md:

* ``modus status`` — placeholder, always works.
* ``modus action validate <spec.json>`` — Milestone 1 deliverable;
  runs the consistency layer against a static action + state spec
  and prints a per-action verdict.
* ``modus run`` — Milestone 4 deliverable; launches the autonomous
  agent loop. Currently a stub that explains what it would do.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from pydantic import TypeAdapter, ValidationError
from rich.console import Console
from rich.table import Table

from modus import __version__
from modus.actions import Action
from modus.consistency import ConsistencyChecker, CorpusState

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(__version__, prog_name="modus")
def main() -> None:
    """Modus — autonomous offensive agent with formally checked actions."""


@main.command()
def status() -> None:
    """Print Modus status. Placeholder until the agent loop lands."""
    console.print(f"[bold]modus[/bold] version {__version__}")
    console.print("[yellow]pre-alpha — agent loop lands at Milestone 4[/yellow]")


@main.group()
def action() -> None:
    """Inspect and validate proposed actions."""


@action.command("validate")
@click.argument("spec", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of the human table.",
)
def action_validate(spec: Path, as_json: bool) -> None:
    """Validate proposed actions against a corpus state spec.

    SPEC is a JSON file with the shape:

        {"state": {...CorpusState fields...},
         "actions": [{"kind": "probe", ...}, ...]}

    Exit code is 0 if every action is accepted, 1 otherwise.
    """
    payload = _load_spec(spec)
    state = _state_from_payload(payload.get("state", {}))
    actions = _actions_from_payload(payload.get("actions", []))

    checker = ConsistencyChecker()
    results = checker.prune(actions, state)

    if as_json:
        out = [
            {
                "action": json.loads(action_obj.model_dump_json()),
                "accepted": verdict.accepted,
                "rationale": verdict.rationale,
                "failed_preconditions": list(verdict.failed_preconditions),
            }
            for action_obj, verdict in results
        ]
        console.print_json(data=out)
    else:
        _render_results_table(results)

    rejected = sum(1 for _, verdict in results if not verdict.accepted)
    sys.exit(1 if rejected else 0)


@main.command("run")
@click.option("--target", required=True, help="Quarry target name.")
@click.option(
    "--scope",
    "scope_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a scope policy JSON file.",
)
def run(target: str, scope_path: Path) -> None:
    """Run the autonomous agent loop. Stub until Milestone 4."""
    err_console.print(
        "[yellow]modus run[/yellow] is a stub at Milestone 0. "
        "The autonomous loop lands at Milestone 4 — see ROADMAP.md."
    )
    err_console.print(f"  target: {target}")
    err_console.print(f"  scope:  {scope_path}")
    sys.exit(2)


def _load_spec(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        err_console.print(f"[red]not valid JSON:[/red] {path} — {exc}")
        sys.exit(2)
    if not isinstance(loaded, dict):
        raise click.UsageError("spec file must contain a JSON object at the top level")
    return loaded


def _state_from_payload(payload: dict[str, Any]) -> CorpusState:
    def _frozenset(key: str) -> frozenset[str]:
        value = payload.get(key, [])
        if not isinstance(value, list):
            raise click.UsageError(f"state.{key} must be a list of strings")
        return frozenset(str(item) for item in value)

    return CorpusState(
        in_scope_assets=_frozenset("in_scope_assets"),
        allowed_methods=_frozenset("allowed_methods"),
        known_observations=_frozenset("known_observations"),
        known_evidence=_frozenset("known_evidence"),
        known_referents=_frozenset("known_referents"),
    )


_ACTION_ADAPTER: TypeAdapter[Action] = TypeAdapter(Action)


def _actions_from_payload(payload: list[Any]) -> list[Action]:
    if not isinstance(payload, list):
        raise click.UsageError("actions must be a list")
    out: list[Action] = []
    for index, entry in enumerate(payload):
        try:
            out.append(_ACTION_ADAPTER.validate_python(entry))
        except ValidationError as exc:
            err_console.print(f"[red]invalid action #{index}:[/red]\n{exc}")
            sys.exit(2)
    return out


def _render_results_table(results: list[tuple[Action, Any]]) -> None:
    table = Table(title="Consistency check")
    table.add_column("#", style="dim")
    table.add_column("kind")
    table.add_column("verdict")
    table.add_column("rationale", overflow="fold")
    for index, (action_obj, verdict) in enumerate(results):
        verdict_color = "green" if verdict.accepted else "red"
        verdict_label = "accept" if verdict.accepted else "reject"
        table.add_row(
            str(index),
            action_obj.kind,
            f"[{verdict_color}]{verdict_label}[/{verdict_color}]",
            verdict.rationale,
        )
    console.print(table)


if __name__ == "__main__":
    sys.exit(main())
