"""Modus CLI entry point.

Subcommands land alongside the milestones in ROADMAP.md:

* ``modus status`` — placeholder, always works.
* ``modus action validate <spec.json>`` — Milestone 1 deliverable;
  runs the consistency layer against a static action + state spec
  and prints a per-action verdict.
* ``modus corpus status`` — Milestone 2 deliverable; opens a Quarry
  MCP session, prints schema version and per-entity counts, exits.
* ``modus mcp --scope <path>`` — Milestone 3 deliverable; starts
  the Modus MCP server over stdio. Designed to be spawned by an
  MCP-aware host; not for interactive use.
"""

from __future__ import annotations

import asyncio
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
from modus.corpus import (
    CorpusError,
    CorpusToolsMissingError,
    CorpusUnavailableError,
    QuarryMcpClient,
)

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


@main.group()
def corpus() -> None:
    """Inspect the Quarry corpus Modus is reading from."""


@corpus.command("status")
@click.option(
    "--quarry",
    "quarry_command",
    default="quarry",
    show_default=True,
    help="Path to the Quarry binary. Must be on PATH or absolute.",
)
@click.option(
    "--timeout",
    "timeout_seconds",
    default=10.0,
    show_default=True,
    type=float,
    help="Per-call timeout in seconds.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of the human table.",
)
def corpus_status(quarry_command: str, timeout_seconds: float, as_json: bool) -> None:
    """Print Quarry corpus status.

    Opens a fresh ``quarry mcp`` subprocess, runs the MCP initialize
    handshake, calls the ``status`` tool, prints the result, and
    exits. Useful as a sanity check that Modus can reach Quarry
    before launching an agent session.
    """
    sys.exit(asyncio.run(_corpus_status(quarry_command, timeout_seconds, as_json)))


async def _corpus_status(quarry_command: str, timeout_seconds: float, as_json: bool) -> int:
    client = QuarryMcpClient(command=quarry_command, call_timeout_seconds=timeout_seconds)
    try:
        async with client:
            status_result = await client.status()
    except CorpusUnavailableError as exc:
        err_console.print(f"[red]corpus unavailable:[/red] {exc}")
        return 3
    except CorpusToolsMissingError as exc:
        err_console.print(f"[red]Quarry schema mismatch:[/red] {exc}")
        return 4
    except CorpusError as exc:
        err_console.print(f"[red]corpus error:[/red] {exc}")
        return 5

    if as_json:
        console.print_json(
            data={
                "schema_version": status_result.schema_version,
                "current_target": status_result.current_target,
                "targets": status_result.targets,
                "assets": status_result.assets,
                "runs": status_result.runs,
                "artifacts": status_result.artifacts,
                "evidence": status_result.evidence,
                "findings": status_result.findings,
                "sessions": status_result.sessions,
                "last_run_started_at": status_result.last_run_started_at,
            }
        )
    else:
        table = Table(title="Quarry corpus status")
        table.add_column("field")
        table.add_column("value", overflow="fold")
        table.add_row("schema_version", str(status_result.schema_version))
        table.add_row("current_target", status_result.current_target or "(none)")
        table.add_row("targets", str(status_result.targets))
        table.add_row("assets", str(status_result.assets))
        table.add_row("runs", str(status_result.runs))
        table.add_row("artifacts", str(status_result.artifacts))
        table.add_row("evidence", str(status_result.evidence))
        table.add_row("findings", str(status_result.findings))
        table.add_row("sessions", str(status_result.sessions))
        table.add_row("last_run_started_at", status_result.last_run_started_at or "(none)")
        console.print(table)
    return 0


@main.command("mcp")
@click.option(
    "--scope",
    "scope_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="MODUS_SCOPE_PATH",
    help="Path to a scope policy JSON file.",
)
def mcp_serve(scope_path: Path) -> None:
    """Run the Modus MCP server over stdio.

    Speaks JSON-RPC on stdout; logs go to stderr. Designed to be
    spawned by an MCP-aware host (Claude Desktop, Claude Code,
    Cursor, etc.) — not to be run interactively. See
    docs/mcp-host-integration.md for host configuration.
    """
    from modus.server import serve

    sys.exit(asyncio.run(serve(scope_path)))


@main.command("partition")
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Hostname-per-line input file. Pass `-` to read from stdin.",
)
@click.option(
    "--output-dir",
    "output_dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to write tier-a.txt, tier-b.txt, tier-c.txt, ambiguous.txt, review.md.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Print machine-readable JSON summary on stdout instead of the human table.",
)
def partition_command(input_path: Path, output_dir: Path, as_json: bool) -> None:
    """Partition recon hostnames into Tier A/B/C with operator review.

    Reads a list of hostnames (one per line, blanks and ``#``
    comments skipped), applies the maintained DO-NOT-TOUCH /
    careful-skip / probe partition, and writes:

    \b
    * ``tier-a.txt`` — probe-eligible hosts (operator authors
      ``allowed_assets`` from this list)
    * ``tier-b.txt`` — careful, skip this engagement
    * ``tier-c.txt`` — DO NOT TOUCH (military, government, ITAR,
      credential-gated customer deployments)
    * ``ambiguous.txt`` — operator review required (markers that
      could be defense or product codenames)
    * ``review.md`` — Markdown report with matched tokens and
      rationale per non-A host

    Closes the partition-slip class of bug surfaced by the 2026-05-02
    ``testsocom.anduril.com`` and 2026-05-08 ``piv.usmc.anduril.com``
    incidents — the maintained token list under
    ``modus.partition._MARKERS`` is the central place engagement
    learnings accrete.

    The structural firewall stays load-bearing: this is a
    *recommendation* tool. The operator authors
    ``ScopePolicy.allowed_assets`` from ``tier-a.txt`` (with optional
    manual adjustment); the consistency-layer allow-list check is
    what actually keeps the agent in scope.
    """
    from modus.partition import partition_hosts, render_review

    raw_lines = _read_partition_input(input_path)
    result = partition_hosts(raw_lines)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tier-a.txt").write_text("\n".join(c.hostname for c in result.tier_a) + "\n")
    (output_dir / "tier-b.txt").write_text("\n".join(c.hostname for c in result.tier_b) + "\n")
    (output_dir / "tier-c.txt").write_text("\n".join(c.hostname for c in result.tier_c) + "\n")
    (output_dir / "ambiguous.txt").write_text(
        "\n".join(c.hostname for c in result.ambiguous) + "\n"
    )
    source_label = "stdin" if str(input_path) == "-" else str(input_path)
    (output_dir / "review.md").write_text(render_review(result, source=source_label))

    if as_json:
        console.print_json(
            data={
                "total": result.total,
                "tier_a": len(result.tier_a),
                "tier_b": len(result.tier_b),
                "tier_c": len(result.tier_c),
                "ambiguous": len(result.ambiguous),
                "output_dir": str(output_dir),
            }
        )
    else:
        table = Table(title=f"Partition: {result.total} hosts")
        table.add_column("tier")
        table.add_column("count", justify="right")
        table.add_column("output", overflow="fold")
        table.add_row("[red]C — DO NOT TOUCH[/red]", str(len(result.tier_c)), "tier-c.txt")
        table.add_row("[yellow]ambiguous[/yellow]", str(len(result.ambiguous)), "ambiguous.txt")
        table.add_row("[yellow]B — skip[/yellow]", str(len(result.tier_b)), "tier-b.txt")
        table.add_row("[green]A — probe[/green]", str(len(result.tier_a)), "tier-a.txt")
        console.print(table)
        console.print(
            f"[dim]Review: {output_dir / 'review.md'}[/dim]",
        )
        if result.ambiguous:
            console.print(
                f"[yellow]Operator review required for "
                f"{len(result.ambiguous)} ambiguous host(s).[/yellow]"
            )


def _read_partition_input(input_path: Path) -> list[str]:
    """Read partition input from a file path, or from stdin if ``-``."""
    if str(input_path) == "-":
        return sys.stdin.read().splitlines()
    if not input_path.exists():
        raise click.UsageError(f"input file does not exist: {input_path}")
    return input_path.read_text().splitlines()


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
