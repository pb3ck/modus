"""Modus MCP server.

This is the v0.1 delivery boundary: ``modus mcp`` runs this server
over stdio, and any MCP-aware host (Claude Desktop, Claude Code,
Cursor, etc.) connects to it as it would any other MCP server.

The server registers three classes of tools, all always present:

* **Verified-action tools** — one per Action variant in
  :mod:`modus.actions`. Each call is Z3-gated against the current
  :class:`~modus.consistency.CorpusState` before any side effect.
* **Quarry passthroughs** — Modus proxies Quarry's read tools and
  analytical tools so the operator configures one MCP endpoint, not
  two.
* **Autonomous-session tools** — ``run_autonomous_session`` and
  ``propose_actions``. Always listed; require ``MODUS_LLM_PROVIDER``
  to be configured. Without it, the call returns ``isError=True``
  with a message naming the missing env var. The implementation
  itself lands at Milestone 4 — at Milestone 3 these tools are
  registered and gate-checked, and they error pointing at M4 once
  the gate is satisfied.

Per ADR-0003, the autonomous-session tools are the primary surface
— that's what Modus *is*. The verified-action tools are the
transparency surface for operators who want to drive each step from
the host's conversation.
"""

from __future__ import annotations

import json
import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp import types as mcp_types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from pydantic import TypeAdapter, ValidationError

from modus import __version__
from modus.actions import (
    Action,
    Annotate,
    Compare,
    Differential,
    Hypothesize,
    Probe,
    Request,
)
from modus.consistency import ConsistencyChecker, Verdict
from modus.corpus import CorpusClient, CorpusError
from modus.executor import HttpExecutor
from modus.session import ServerSession, SessionCandidate, SessionObservation

if TYPE_CHECKING:
    from pathlib import Path


_LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------- tool list


_ACTION_TOOL_DESCRIPTIONS: dict[str, str] = {
    "probe": (
        "Read what the corpus already knows about a target asset — its "
        "latest httpx record, its jsbundle catalogue, its endpoint list, "
        "or its tech stack. Passive: no network traffic is generated. "
        "Verified by the consistency layer: the target must be in scope."
    ),
    "request": (
        "Send one HTTP request to a target asset and persist the "
        "request/response pair as a session observation. Verified by "
        "the consistency layer: the target must be in scope and the "
        "method must be in the session's allowed-methods set."
    ),
    "compare": (
        "Compare two existing observations (in this session or in "
        "Quarry) along the named dimensions. Produces a comparison "
        "result. Verified by the consistency layer: both observations "
        "must exist and be distinct."
    ),
    "differential": (
        "Differential test across observations along a single dimension "
        "(identity / auth / role / tenant) for a given bug class "
        "(idor / auth_bypass / tenant_isolation). Verified by the "
        "consistency layer: every observation must exist."
    ),
    "annotate": (
        "Attach an operator-visible note to a corpus referent (target, "
        "asset, observation, or evidence). Notes are FTS-indexed."
    ),
    "hypothesize": (
        "Author a Candidate of a given bug class with evidence "
        "references and a rationale. The terminal action — every "
        "successful Modus session ends with one or more `hypothesize` "
        "calls. Modus never promotes Candidates to Findings; that's "
        "the operator's `quarry finding promote`."
    ),
}


_QUARRY_PASSTHROUGH_TOOLS: dict[str, str] = {
    "corpus_status": "Quarry corpus status — schema version, current target, per-entity counts.",
    "list_targets": "List every target in the Quarry corpus, with the current one flagged.",
    "search": "FTS retrieval over evidence and notes in the Quarry corpus.",
    "list_assets": "Structured query over assets — filter by source, status, tech, etc.",
    "diff": "Assets first seen during the most recent run for a target.",
    "coverage": "Recon coverage gap — assets some discovery source surfaced but no probe touched.",
    "recall": "Cross-target recall — where else has this hostname/tech/webserver been seen.",
    "analyze_regression": (
        "Run Quarry's regression analytical module: persists Candidate rows for "
        "URLs whose probed fields changed between the latest two runs."
    ),
    "analyze_jsdelta": (
        "Run Quarry's jsdelta analytical module: persists Candidate rows per "
        "category whose extracted-token set changed between bundle ingestions."
    ),
    "analyze_interesting": (
        "Run Quarry's interesting analytical module: ranks hosts by 5xx, "
        "version-leak, and name-pattern signals."
    ),
}


def _action_input_schema(action_cls: type[Action]) -> dict[str, Any]:
    """Derive an MCP-compatible inputSchema from an Action variant.

    Pydantic produces a fully-resolved JSON Schema for a model; we
    pass it through verbatim. The host's LLM uses this as the
    grammar for its tool-use sampling, so emitted calls are
    grammatically valid Action instances by construction.
    """
    schema = action_cls.model_json_schema()
    # MCP tools want a JSON Schema "object" type at the top level,
    # which Pydantic already produces for BaseModel subclasses.
    schema.setdefault("type", "object")
    return schema


def _autonomous_tool_schemas() -> dict[str, dict[str, Any]]:
    """Return inputSchemas for the autonomous-session tools."""
    return {
        "run_autonomous_session": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Quarry target name to operate against.",
                },
                "bug_classes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Bug classes to focus the search on.",
                },
                "budget": {
                    "type": "object",
                    "description": "Optional budget override for the loop.",
                    "properties": {
                        "max_steps": {"type": "integer", "minimum": 1},
                        "max_wall_seconds": {"type": "number", "minimum": 1},
                    },
                },
            },
            "required": ["target", "bug_classes"],
        },
        "propose_actions": {
            "type": "object",
            "properties": {
                "context": {
                    "type": "string",
                    "description": "What the proposer should focus on this step.",
                },
                "sample_count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 32,
                    "description": "Number of candidate actions to sample.",
                },
            },
            "required": ["context"],
        },
    }


def _build_tool_list() -> list[mcp_types.Tool]:
    """Assemble the full MCP tool list (always-registered)."""
    tools: list[mcp_types.Tool] = []

    action_classes: dict[str, type[Action]] = {
        "probe": Probe,
        "request": Request,
        "compare": Compare,
        "differential": Differential,
        "annotate": Annotate,
        "hypothesize": Hypothesize,
    }
    for name, cls in action_classes.items():
        tools.append(
            mcp_types.Tool(
                name=name,
                description=_ACTION_TOOL_DESCRIPTIONS[name],
                inputSchema=_action_input_schema(cls),
            )
        )

    for name, description in _QUARRY_PASSTHROUGH_TOOLS.items():
        tools.append(
            mcp_types.Tool(
                name=name,
                description=description,
                inputSchema=_quarry_input_schema(name),
            )
        )

    autonomous_schemas = _autonomous_tool_schemas()
    autonomous_descriptions = {
        "run_autonomous_session": (
            "Run Modus's autonomous offensive loop end-to-end against a "
            "Quarry target for a bounded budget. Returns the Candidates "
            "produced. Requires MODUS_LLM_PROVIDER and the matching "
            "API key in the server's environment. This is Modus's "
            "primary surface — call it when you want the agent to do "
            "the work."
        ),
        "propose_actions": (
            "Sample N candidate actions for the current corpus state, "
            "with each one's Z3 verdict, but execute none. Useful when "
            "the host wants to delegate proposal generation but keep "
            "execution on its side. Requires MODUS_LLM_PROVIDER."
        ),
    }
    for name, schema in autonomous_schemas.items():
        tools.append(
            mcp_types.Tool(
                name=name,
                description=autonomous_descriptions[name],
                inputSchema=schema,
            )
        )

    return tools


def _quarry_input_schema(tool_name: str) -> dict[str, Any]:
    """Hand-built schemas for the Quarry passthrough tools.

    We keep these narrow rather than mirroring Quarry's full schema
    one-to-one, because (a) Quarry's own schema is alpha and shifts
    between minor releases (M2.5 analytical commands flagged in
    Quarry's README), and (b) the host's LLM benefits from a
    narrower, more documented surface.
    """
    if tool_name == "corpus_status":
        return {"type": "object", "properties": {}, "additionalProperties": False}
    if tool_name == "list_targets":
        return {"type": "object", "properties": {}, "additionalProperties": False}
    if tool_name == "search":
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "target": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
                "full": {"type": "boolean", "default": False},
            },
            "required": ["query"],
        }
    if tool_name == "list_assets":
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "filters": {"type": "object"},
            },
        }
    if tool_name in {"diff", "coverage"}:
        return {"type": "object", "properties": {"target": {"type": "string"}}}
    if tool_name == "recall":
        return {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "tech": {"type": "string"},
                "webserver": {"type": "string"},
            },
            "description": "Provide exactly one of value, tech, or webserver.",
        }
    if tool_name in {"analyze_regression", "analyze_jsdelta", "analyze_interesting"}:
        return {"type": "object", "properties": {"target": {"type": "string"}}}
    raise KeyError(f"unknown Quarry passthrough tool: {tool_name}")


# --------------------------------------------------------------------- routing


_ACTION_ADAPTER: TypeAdapter[Action] = TypeAdapter(Action)


def _verdict_to_payload(verdict: Verdict) -> dict[str, Any]:
    return {
        "accepted": verdict.accepted,
        "rationale": verdict.rationale,
        "failed_preconditions": list(verdict.failed_preconditions),
    }


@dataclass
class ModusServer:
    """The MCP server lifecycle wrapped around a :class:`ServerSession`."""

    session: ServerSession
    executor: HttpExecutor
    checker: ConsistencyChecker

    def _server(self) -> Server:
        server: Server = Server(name="modus", version=__version__)

        # The mcp SDK's `list_tools()` and `call_tool()` decorators are
        # typed loosely (they accept `Any` and return `Any`); mypy in
        # strict mode flags the decorator-application calls. The
        # behaviour is well-defined per the SDK docs — silence the
        # decorator-typing warning rather than wrapping in a no-op cast
        # that would hide real type errors in our handlers.
        @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
        async def _list_tools() -> list[mcp_types.Tool]:
            return _build_tool_list()

        @server.call_tool()  # type: ignore[untyped-decorator]
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[mcp_types.ContentBlock]:
            payload = await self._dispatch(name, arguments or {})
            return [mcp_types.TextContent(type="text", text=json.dumps(payload))]

        return server

    async def _dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name in _ACTION_TOOL_DESCRIPTIONS:
            return await self._handle_action_tool(name, arguments)
        if name in _QUARRY_PASSTHROUGH_TOOLS:
            return await self._handle_quarry_tool(name, arguments)
        if name in {"run_autonomous_session", "propose_actions"}:
            return await self._handle_autonomous_tool(name, arguments)
        return {"error": f"unknown tool: {name!r}"}

    async def _handle_action_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # Inject the discriminator so the discriminated-union adapter dispatches
        # to the right Action variant.
        action_args = dict(arguments)
        action_args.setdefault("kind", name)
        try:
            action = _ACTION_ADAPTER.validate_python(action_args)
        except ValidationError as exc:
            return {"error": "invalid action input", "details": exc.errors()}

        verdict = self.checker.check(action, self.session.corpus_state())
        if not verdict.accepted:
            return {"action": name, "verdict": _verdict_to_payload(verdict)}

        # Execute by action kind. The verified-action surface terminates in
        # session-local state; persistence to Quarry beyond Quarry's own
        # writes (analyze_*) is deferred to a future Quarry MCP capability.
        try:
            result = await self._execute_action(action)
        except CorpusError as exc:
            return {"error": f"corpus error: {exc}"}
        return {
            "action": name,
            "verdict": _verdict_to_payload(verdict),
            "result": result,
        }

    async def _execute_action(self, action: Action) -> dict[str, Any]:
        if isinstance(action, Probe):
            return await self._execute_probe(action)
        if isinstance(action, Request):
            observation = await self.executor.execute(action)
            self.session.observations.append(
                SessionObservation(
                    id=observation.id, kind="request", payload=observation.as_payload()
                )
            )
            return {"observation_id": observation.id, **observation.as_payload()}
        if isinstance(action, Compare):
            return self._execute_compare(action)
        if isinstance(action, Differential):
            return self._execute_differential(action)
        if isinstance(action, Annotate):
            obs_id = f"note-{len(self.session.observations)}"
            self.session.observations.append(
                SessionObservation(
                    id=obs_id,
                    kind="annotate",
                    payload={"referent": action.referent, "note": action.note},
                )
            )
            return {"observation_id": obs_id, "referent": action.referent}
        if isinstance(action, Hypothesize):
            self.session.candidates.append(
                SessionCandidate(
                    bug_class=action.bug_class,
                    evidence_refs=action.evidence_refs,
                    rationale=action.rationale,
                    severity_hint=action.severity_hint,
                )
            )
            return {
                "candidate_index": len(self.session.candidates) - 1,
                "bug_class": action.bug_class,
                "rationale": action.rationale,
            }
        raise TypeError(f"unhandled action type: {type(action).__name__}")

    async def _execute_probe(self, action: Probe) -> dict[str, Any]:
        async with self.session.with_quarry() as quarry:
            if action.aspect == "httpx":
                assets = await quarry.list_assets(filters={"name_pattern": action.target})
                return {"aspect": action.aspect, "assets": assets}
            if action.aspect == "endpoints":
                hits = await quarry.search(
                    query=action.target, target=self.session.scope.target_name, limit=20
                )
                return {"aspect": action.aspect, "hits": [h.snippet for h in hits]}
            if action.aspect == "jsbundle":
                hits = await quarry.search(
                    query=f"{action.target} jsbundle",
                    target=self.session.scope.target_name,
                    limit=10,
                )
                return {"aspect": action.aspect, "hits": [h.snippet for h in hits]}
            # action.aspect == "tech"
            assets = await quarry.list_assets(filters={"name_pattern": action.target})
            return {"aspect": action.aspect, "assets": assets}

    def _execute_compare(self, action: Compare) -> dict[str, Any]:
        a = next((o for o in self.session.observations if o.id == action.observation_a), None)
        b = next((o for o in self.session.observations if o.id == action.observation_b), None)
        if a is None or b is None:
            return {"error": "observations not in this session's pool"}
        diffs: dict[str, Any] = {}
        for dim in action.dimensions:
            diffs[dim] = {"a": a.payload.get(dim), "b": b.payload.get(dim)}
        return {"observation_a": a.id, "observation_b": b.id, "diffs": diffs}

    def _execute_differential(self, action: Differential) -> dict[str, Any]:
        present_ids = {obs.id for obs in self.session.observations}
        missing = [ref for ref in action.observations if ref not in present_ids]
        if missing:
            return {"error": "observations not in session pool", "missing": missing}
        return {
            "observations": list(action.observations),
            "dimension": action.dimension,
            "bug_class": action.bug_class,
            "summary": (
                f"differential test across {len(action.observations)} observations "
                f"on dimension {action.dimension!r} for bug class {action.bug_class!r}"
            ),
        }

    async def _handle_quarry_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            async with self.session.with_quarry() as quarry:
                return await self._dispatch_quarry_tool(quarry, name, arguments)
        except CorpusError as exc:
            return {"error": f"corpus error: {exc}"}

    async def _dispatch_quarry_tool(
        self, quarry: CorpusClient, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            if name == "corpus_status":
                status = await quarry.status()
                return {
                    "schema_version": status.schema_version,
                    "current_target": status.current_target,
                    "targets": status.targets,
                    "assets": status.assets,
                    "runs": status.runs,
                    "artifacts": status.artifacts,
                    "evidence": status.evidence,
                    "findings": status.findings,
                    "sessions": status.sessions,
                    "last_run_started_at": status.last_run_started_at,
                }
            if name == "list_targets":
                rows = await quarry.list_targets()
                return {
                    "targets": [
                        {
                            "id": t.id,
                            "name": t.name,
                            "kind": t.kind,
                            "is_current": t.is_current,
                            "notes": t.notes,
                        }
                        for t in rows
                    ]
                }
            if name == "search":
                hits = await quarry.search(
                    query=arguments["query"],
                    target=arguments.get("target"),
                    limit=int(arguments.get("limit", 10)),
                    full=bool(arguments.get("full", False)),
                )
                return {
                    "hits": [
                        {
                            "kind": h.kind,
                            "target_id": h.target_id,
                            "snippet": h.snippet,
                            "full_text_len": h.full_text_len,
                            "truncated": h.truncated,
                        }
                        for h in hits
                    ]
                }
            if name == "list_assets":
                return {
                    "assets": await quarry.list_assets(
                        target=arguments.get("target"),
                        filters=arguments.get("filters"),
                    )
                }
            if name == "diff":
                return await quarry.diff(target=arguments.get("target"))
            if name == "coverage":
                return await quarry.coverage(target=arguments.get("target"))
            if name == "recall":
                return {
                    "rows": await quarry.recall(
                        value=arguments.get("value"),
                        tech=arguments.get("tech"),
                        webserver=arguments.get("webserver"),
                    )
                }
            if name == "analyze_regression":
                return _candidates_to_payload(
                    await quarry.analyze_regression(target=arguments.get("target"))
                )
            if name == "analyze_jsdelta":
                return _candidates_to_payload(
                    await quarry.analyze_jsdelta(target=arguments.get("target"))
                )
            if name == "analyze_interesting":
                return _candidates_to_payload(
                    await quarry.analyze_interesting(target=arguments.get("target"))
                )
        except CorpusError as exc:
            return {"error": f"quarry tool {name!r} failed: {exc}"}
        return {"error": f"unhandled passthrough tool: {name!r}"}

    async def _handle_autonomous_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.session.llm is None:
            return {
                "error": (
                    "autonomous-session tools require Modus's internal LLM "
                    "provider to be configured. Set MODUS_LLM_PROVIDER "
                    "(anthropic | openai | openai-compatible) and the "
                    "matching API key in the MCP server's env. See "
                    "docs/mcp-host-integration.md."
                ),
                "missing": ["MODUS_LLM_PROVIDER"],
            }
        # Milestone 4 wiring lands here. Until then, surface a deliberate
        # not-yet-implemented marker rather than an opaque traceback.
        return {
            "error": (
                f"{name!r} is not yet implemented at Milestone 3. The "
                "autonomous loop lands at Milestone 4 — see ROADMAP.md."
            ),
            "milestone": "M4",
        }


def _candidates_to_payload(candidates: list[Any]) -> dict[str, Any]:
    return {
        "candidates": [
            {
                "id": c.id,
                "target_id": c.target_id,
                "module": c.module,
                "key": c.key,
                "score": c.score,
                "rationale": c.rationale,
                "evidence_refs": list(c.evidence_refs),
                "was_new": c.was_new,
            }
            for c in candidates
        ],
        "count": len(candidates),
    }


# --------------------------------------------------------------------- entry point


async def serve(scope_path: Path) -> int:
    """Run the MCP server until the host disconnects.

    Called by the ``modus mcp`` CLI. Returns an exit code: 0 on
    clean shutdown, non-zero if the scope file fails to load.
    """
    try:
        session = ServerSession.from_scope_file(scope_path)
    except (FileNotFoundError, ValidationError) as exc:
        _LOG.error("failed to load scope policy from %s: %s", scope_path, exc)
        return 2
    except ValueError as exc:
        _LOG.error("invalid scope policy at %s: %s", scope_path, exc)
        return 2

    if session.llm is None:
        _LOG.warning(
            "MODUS_LLM_PROVIDER not set — autonomous-session tools will "
            "return errors. Verified-action tools and Quarry passthroughs "
            "are unaffected."
        )
    else:
        _LOG.info(
            "Modus internal LLM provider: %s (model=%s, base_url=%s)",
            session.llm.provider,
            session.llm.model or "<default>",
            session.llm.base_url or "<default>",
        )

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(session)
        executor = await stack.enter_async_context(HttpExecutor())
        modus = ModusServer(session=session, executor=executor, checker=ConsistencyChecker())
        server = modus._server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    return 0


__all__ = ["ModusServer", "serve"]
