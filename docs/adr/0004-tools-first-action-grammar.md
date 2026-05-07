# ADR 0004: Tools-first action grammar with an open registry

- **Status:** accepted
- **Date:** 2026-05-07
- **Supersedes:** —
- **Extends:** ADR 0001 (typed action vocabulary)
- **Amends:** ADR 0002 §4 (the submission line is storage-enforced),
  ADR 0003 §2 (Quarry passthroughs as a separate tool class),
  ADR 0003 §6 (typed grammar as the structural firewall)

## Context

ADR 0001 committed to a closed typed-action vocabulary
(`Probe | Request | Compare | Differential | Annotate |
Hypothesize`). That decision delivered the audit, prompt-injection,
and consistency-check guarantees Modus is built around. It also
turned out to scope what "autonomous" could mean to *autonomous
within the focused-attack stage*. Operations that obviously belong
in an autonomous offensive agent — subdomain enumeration, content
discovery, vuln scanning, JS-bundle harvesting, calling
host-provided MCP tools, custom shell scripts — were structurally
unreachable. The agent could only do things the closed grammar
spelled out.

Real engagement work (DoD VDP, bug-bounty programmes with broad
scope, anything beyond a single warm target) needs the agent to
drive the full recon → exploit → evidence pipeline itself. With
the closed grammar that meant operators ran recon manually with
shell tools, ingested results into Quarry, then handed warm
targets to Modus's focused-attack loop. That split:

1. Pushes orchestration work back onto the operator that the
   autonomous agent was supposed to absorb.
2. Makes "Modus is autonomous" a context-dependent claim — true
   inside one stage, false across the engagement.
3. Conflicts with the operator's expectation that Modus can use
   *any* tool the operator can use, subject to the same scope
   discipline.

The four invariants from ADR 0001 — typed actions, formal
consistency check, Quarry-backed corpus, storage-enforced
submission line — were committed with a closed grammar in mind.
Three of them generalise cleanly to an open grammar; the fourth
(the closed vocabulary itself) is the one that needs revisiting.

## Decision

Replace the closed typed-action union with an open, registry-keyed
vocabulary. The structural primitive is a single new action type:

```python
class Tool(_ActionBase):
    kind: Literal["tool"] = "tool"
    name: str  # registry key, validated against ^[a-z][a-z0-9_.-]*$
    args: dict[str, Any]  # free-form, validated per-tool
```

A `ToolRegistry` is the trust boundary. Each registered tool is a
`ToolSpec` declaring:

- **Dispatch backend** — `shell` (`subprocess`),
  `mcp` (passthrough to a foreign MCP server), or `builtin` (a
  Modus-internal callable).
- **Argument schema** — JSON Schema. The consistency layer
  validates `Tool.args` against this before invoking preconditions.
- **Per-tool preconditions** — a function that returns
  `(label, value)` pairs the Z3 layer encodes. Each tool brings
  its own scope-and-state gating; there is no central
  `_preconditions` switch the agent must edit to add a new tool.
- **Side-effect tier** — `read` / `write` / `active`, surfaced to
  the proposer's prompt for guidance on rate-limiting and
  reversibility.

The typed actions from ADR 0001 stay as fast paths during the
v0.3 transition — they continue to dispatch through the legacy
isinstance switch in `_execute_action`, and their existing
preconditions in `_preconditions` are unchanged. Each is also
registered as a first-party builtin entry in the default
registry so the seam between "typed" and "tool" is one-way visible
from day one. A follow-up subsumes the typed actions into the
registry fully and deletes the legacy switch; the architectural
commitment to one-execution-path is met after that.

The default registry contains:

- **Six typed-action builtins** (`probe`, `request`, `compare`,
  `differential`, `annotate`, `hypothesize`) — `BuiltinInvocation`
  pointing at the existing handlers.
- **Two recon shell builtins** (`amass.enum`, `nuclei.scan`) —
  `ShellInvocation` with argv templates that placeholder-
  substitute from the action's `args`. Each carries scope-gating
  preconditions (domain in `scope.hosts()` for amass, URL's
  `(host, port, tls)` in `scope.allowed_endpoints` for nuclei).

Operators extend the registry per-engagement via a `tools` block
in the scope JSON. Each declaration is a Pydantic model
(`ShellToolDeclaration` / `McpToolDeclaration`); the session's
`from_scope_file` validates and registers them on top of the
default registry. Duplicate names — intra-block or against
builtins — surface at session construction, not silently at
dispatch.

## Submission line — preserved structurally

ADR 0002 §4 commits to "the submission line is storage-enforced."
That commitment is now: **no `submit`, `publish`, `post`, or
`report` tool exists in the registry, and adding one is
off-limits.** The default registry never registers them; the
operator's `tools` block can technically declare anything, but
adding a submit-shaped tool is a project policy violation
(equivalent to forking and removing the firewall — possible, not
supported).

The "what does this firewall stop" question reframes:

- **Old firewall:** the closed grammar has no `submit`-shaped
  variant; the agent cannot emit one.
- **New firewall:** the registry has no `submit`-shaped entry;
  the agent cannot dispatch one. The `Tool` action's grammar
  validates at the Pydantic layer; the consistency layer rejects
  with `tool_registered:<name>` if the name isn't registered.

Same guarantee, surfaced through the registry's trust boundary
rather than the action union's discriminator.

## Consequences

### Positive

- The agent can use any tool the operator registers. Recon, content
  discovery, vuln scanning, host-side MCP servers, custom shell
  scripts — all live on the same surface, all gated through the
  same Z3 layer, all observed via the same `ToolObservation` shape
  in `ServerSession.observations`.
- Quarry stops being the dominant abstraction. Quarry's MCP
  passthrough tools (`corpus_status`, `search`, `analyze_*`,
  etc.) are still first-party, but they live in the same registry
  as everything else. The "is this a Quarry tool or a shell
  tool?" distinction is gone — they're all tools.
- The autonomous loop runs end-to-end. A single
  `start_autonomous_session` call can drive recon (amass), surface
  candidates (nuclei), exploit findings (request), differentiate
  (compare/differential), and close with `hypothesize`. No
  operator hand-off mid-engagement.
- Adding a new tool is one entry in the operator's scope JSON
  (or one `ToolSpec` in code for first-party additions). It does
  not require editing the consistency layer, the executor, or
  the proposer's prompt.

### Negative

- The trust boundary is wider. The closed grammar made "what can
  the agent do" inspectable from one Pydantic union; the registry
  makes it inspectable from one config file plus the default
  registry. Operators *must* understand their `tools` block as
  load-bearing as their `allowed_assets`.
- Per-tool preconditions are operator-authored when the tool is
  operator-declared. Built-in tools (amass, nuclei) ship with
  ours; everything else gets `_accept_all_preconditions` by
  default (passes after JSON Schema args validation). That's a
  pragmatic trade-off: stricter defaults would reject every
  operator-declared tool until the operator wrote a preconditions
  function in code. The cost lives on the operator: scope your
  tools' `argv_template` so the args can't escape scope, or
  decline to declare the tool.
- The stub MCP-passthrough backend is a known gap. Operators can
  declare MCP tools today but dispatch surfaces
  ``error="mcp-passthrough not yet implemented"``; the real
  backend (Modus acting as MCP client to a foreign server the
  host has configured) is a follow-up.
- The proposer's prompt grows: rendering the registry into the
  system prompt adds tokens. We ship the default registry's eight
  entries in v0.3.0; operators with large `tools` blocks pay the
  cost.

### Neutral

- The four invariants from ADR 0001 still hold:
  1. **Typed actions:** Tool actions are still typed (Pydantic);
     the `args` field is permissive but every action emission is
     validated at the grammar layer.
  2. **Formal consistency check:** Z3 still gates every action;
     per-tool preconditions are evaluated through the same
     `assert_and_track` machinery as the typed-action
     preconditions, with the same unsat-core surface in
     `Verdict.failed_preconditions`.
  3. **Quarry-backed corpus:** observations still terminate in
     storage; the in-memory pool still flushes (eventually) into
     Quarry. Quarry's role is "default storage backend," not
     "the substrate" — the difference is rhetorical, not
     structural.
  4. **Storage-enforced submission line:** see above. The
     guarantee moves from "no submit variant in the grammar" to
     "no submit entry in the registry," with project policy
     forbidding adding one.

## Open follow-ups

These don't block ADR-0004 acceptance but should land before the
next major release:

- **Subsume typed actions into the registry fully.** The legacy
  `_preconditions` switch and the isinstance ladder in
  `_execute_action` should disappear. Once the typed actions
  dispatch through the registry, the entire consistency and
  execution path goes through one code path.
- **MCP-passthrough backend.** Real implementation, not the stub.
- **Tool prompt rendering.** The proposer's prompt should render
  the registry (descriptions, args schemas, side-effect tiers)
  so the host's LLM emits grammatical Tool actions by
  construction. v0.3.0 ships this for the static action grammar
  but doesn't yet render the registry contents.
- **Operator-tooling around scope-file `tools` blocks.** Real
  operators want template repos for common engagements (DoD VDP,
  H1 standard programmes, etc.) with pre-vetted tool registrations.
  Belongs above this layer.
