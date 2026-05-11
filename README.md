# Modus

> Autonomous offensive agent — typed action vocabulary, formal
> consistency checking, Quarry-backed corpus, delivered as an MCP
> server.

[![CI](https://github.com/pb3ck/modus/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pb3ck/modus/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](./pyproject.toml)

Modus is an autonomous offensive security agent for authorized bug
bounty and penetration-testing work. The agent reasons over a Quarry
corpus, proposes typed actions against in-scope targets, formally
verifies each action before execution, and writes its findings as
Candidates into the corpus. Modus is delivered as an **MCP server**:
the operator drives it from any MCP-aware host (Claude Desktop,
Claude Code, Cursor, anything that speaks the Model Context Protocol).
The agent's autonomous loop runs end-to-end inside Modus — the host
just kicks it off and reads the result. The autonomous loop closes
the Candidate→Finding lifecycle inside the corpus: severity-medium-
or-higher Candidates auto-promote to Findings via `corpus.promote_finding`,
backed by Quarry's MCP `finding_promote` write tool. The single hard
human gate is on bug-bounty submission: **Modus never submits to a
bounty programme.** No `submit`, `publish`, `post`, `report-to-h1`,
or equivalent tool exists in the registry, and adding one is
off-limits. Submission of a Finding to a programme is the operator's,
performed outside Modus.

> **Status: 0.5.0 (early release).** The autonomous loop runs
> end-to-end against authorized targets *and* closes the
> Candidate→Finding lifecycle inside the run — see
> [`docs/quickstart.md`](./docs/quickstart.md). The 0.5 line adds:
> a mining sub-agent that pumps Quarry's analytical and retrieval
> surfaces during the autonomous loop; fail-fast on missing
> corpus; ToolRegistry visible to the LLM; the `auth.wp_login`
> builtin that unlocks the authenticated attack surface; the
> `modus.source_review` augmentation that pre-ingests a plugin's
> PHP into the corpus so the LLM can pivot on source-side
> signal; the dynamic plugin-nonce extractor; the `raw.http`
> opt-in curl-equivalent for free mode; `ScopePolicy.scope_intent`
> (`plugin` mode suppresses WordPress-core FPs); and URL-keyed
> detector dedup. See [`CHANGELOG.md`](./CHANGELOG.md) for the
> full list. The action vocabulary (open `ToolRegistry` per ADR-0004), the formal
> consistency check, the corpus interface, the submission-line
> invariant, and the autonomous-session MCP tool surface are
> committed surfaces; everything else may shift between minor
> releases until 1.0. v0.4.0 was the first non-pre-release tag —
> alphas precede it back to 0.1.0a1.

## Operating modes

Modus has two operating positions, toggled via the `MODUS_MODE`
environment variable (or the `mode` argument to `AgentLoop`).
Both modes preserve scope enforcement, per-run observation
isolation, the typed-action grammar, Z3 consistency preconditions,
and the deterministic detector library — the toggle only adjusts
**how much context the LLM sees and how much tool surface it can
reach**, never the safety perimeter.

### `free` — productive bug-hunting mode (default)

The LLM gets larger response-body excerpts in history (4 KB head)
so it can extract CSRF nonces, parse error messages, and identify
response-embedded URLs without needing extra probes. Wrapped
scanner tools (nuclei, etc.) and free-form curl land here in
follow-on commits. This is the position the 2026-05-10 calibration
arc identified as productive against modern hardened plugins —
where `claude-bug-bounty`-style agents win on raw flexibility.

Default. No env var needed.

### `strict` — audit-defensible mode (opt-in)

Original Modus invariants exactly: 240-char tail-only body
excerpts, no scanner-tool wrapping, every action passes through
the typed-grammar + Z3 + detector pipeline with the smallest
possible LLM context surface. Use this when the operator needs to
defend the methodology in a triage call, an attack-of-the-week
post-mortem, or a regulatory review — `strict` mode minimises
LLM emergence so the audit trail is fully explainable from
deterministic rules.

```bash
export MODUS_MODE=strict
```

### What both modes guarantee

| Property | Free | Strict |
| --- | --- | --- |
| Scope policy (`ScopePolicy`) enforcement | yes | yes |
| Per-run observation isolation (no cross-run evidence) | yes | yes |
| Typed action grammar (`Request`, `Probe`, `Hypothesize`, …) | yes | yes |
| Z3 consistency precondition checks | yes | yes |
| Deterministic detector library | yes | yes |
| Submission-line invariant (no `submit`/`publish`/`post`) | yes | yes |
| Body excerpt size (LLM context per response) | 4096 chars (head) | 240 chars (tail) |
| Wrapped scanner tools (nuclei, etc.) | planned | no |
| `raw.http` curl-equivalent builtin | available with opt-in (`MODUS_ALLOW_RAW_HTTP=1`) | no |

### `raw.http` — opt-in curl-equivalence in free mode

The `raw.http` builtin lets the LLM dispatch arbitrary HTTP requests
when the typed `Request` action's shape isn't enough — multipart
bodies, unusual content types, multi-step chains where the LLM
needs to compose the wire format directly. Doubly gated:

1. Mode must be `free`.
2. Operator must opt in via `MODUS_ALLOW_RAW_HTTP=1`.

Even when registered, the scope perimeter still holds: the URL's
`(host, port, tls)` triple must be in scope and the method must
be in `allowed_methods`. The `raw.http` tool has no more reach
than the typed `Request` action; the difference is only in
ergonomics for the LLM and operator visibility into the call
shape.

```bash
export MODUS_ALLOW_RAW_HTTP=1   # default mode (free) auto-on
```

Strict mode never registers `raw.http`, regardless of the env
var — the audit-defensibility property is preserved without
operator forethought.

## What this is

- **An autonomous agent with an open tool registry.** The operator
  points their MCP host at Modus and invokes the autonomous-session
  tool. Modus runs the propose-prune-rank-execute loop internally,
  reaching every tool the operator's registered: recon shells
  (`amass`, `nuclei`), the typed-action surface (`probe`,
  `request`, `compare`, `differential`, `annotate`, `hypothesize`),
  Quarry's corpus tools, host-side MCP servers, and any custom
  shell or MCP tool the operator declares in their scope file's
  `tools` block. The agent isn't bounded by a closed grammar; it's
  bounded by what the registry exposes. (See ADR-0004 for the
  pivot from the closed v0.1 vocabulary.)
- **An MCP server**, in delivery. The full tool surface — typed
  actions, the generic `tool` dispatch, Quarry passthroughs,
  autonomous-session controls (start / poll / cancel /
  run / propose) — is registered as MCP tools. Operators who want
  full transparency drive individual tools step-by-step from the
  host; operators who want agency invoke `start_autonomous_session`
  and let the loop run.
- **Quarry-aware, not Quarry-native.** Quarry's analytical modules
  and read surface are first-party tool registrations
  (`corpus.search`, `analyze_jsdelta`, etc., proxied through
  Modus's MCP server). Quarry is the default storage backend and
  the cross-engagement memory; Modus depends on it but isn't
  subordinate to its data model. Other tools' observations live
  alongside Quarry rows in the same in-session pool.
- **A submission firewall enforced by registry membership.** No
  `submit`, `report`, `publish`, `post`, or `report-to-h1` tool
  is registered in the default registry, and adding one is
  project-policy off-limits. The agent can emit a `Tool` action
  with any name, but the consistency layer rejects with
  `tool_registered:<name>` if it isn't in the registry. The
  firewall covers *external submission* (to bug-bounty
  platforms), not internal promotion: the
  `corpus.promote_finding` builtin closes the Candidate→Finding
  lifecycle inside the local corpus on severity-medium-or-higher
  Candidates, which is corpus-internal, not an outbound action.
  Submission of a Finding to a programme is the operator's,
  performed outside Modus.

## What this isn't

- Not a scanner. Modus reasons about what to do next given
  current corpus state, and it can drive scanners as registered
  tools (`nuclei.scan`, `amass.enum`, anything operator-declared).
  The scanner is the *muscle*; Modus's autonomous loop is the
  *direction*. Without the loop, a scanner just generates noise.
- Not a corpus. Quarry is the default storage backend; Modus's
  in-session observation pool flushes to Quarry for cross-session
  memory. Modus does not duplicate Quarry's ingestion or its
  Finding lifecycle.
- Not a model wrapper. Modus has its own LLM provider for the
  autonomous loop, but it is provider-portable: direct API
  (Anthropic, OpenAI), OpenAI-compatible (Ollama, vLLM,
  OpenRouter via `base_url`), MCP host sampling (when the host
  supports it), or `claude-cli` — a subscription-billed path
  that shells out to Claude Code's `claude --print` so
  operators with a Claude Pro/Max subscription don't pay
  per-token. The host's LLM and Modus's LLM are independent
  choices the operator makes separately.
- Not a chatbot. Modus's autonomous tool returns a structured
  batch of Candidates, not a narrative response. The host's
  conversation is between the operator and the host's LLM;
  Modus is the offensive engine bolted to the side.
- Not a submitter. Ever. The line between observation and
  recommendation is enforced by storage, not by prompt: there
  is no "publish" path in Modus, and there will not be one.

## Why this exists

The autonomous offensive tooling space has converged on a shape:
LLM in a free-form ReAct loop, shell-string tool dispatch,
session-scoped memory, chain-of-thought traces as the audit
surface, operator approval per step as the safety gate. That
shape works for demos. It doesn't compose with professional
operator discipline because the agent's reasoning is locked
inside the model, the system of record is a flat log file, and
the safety gate is the same person whose attention the agent is
supposed to multiply.

Modus takes a different bet, in five parts.

- The action surface is a **typed registry**. Every action the
  agent emits is a Pydantic-validated `Tool(name, args)` (or one
  of the typed-action fast paths — `Probe`, `Request`, etc.).
  The registry declares what `name` values are dispatchable and
  what each tool's `args` shape is; adding a new capability is
  one operator-authored entry in the scope file's `tools` block.
  The closed v0.1 vocabulary is gone; the trust boundary is the
  registry's contents.
- The consistency check is **formal and per-tool**. Each proposed
  action is validated against scope and corpus state via an SMT
  solver before any side effect. Each tool spec declares its own
  preconditions function (the registry is the dispatch table for
  Z3); built-in tools ship scope-gating preconditions
  (`amass.enum` requires the domain in scope, `nuclei.scan`
  requires the URL's `(host, port, tls)` in
  `allowed_endpoints`). The autonomous loop uses Z3 as a *pruner
  over sampled proposals*.
- The corpus is **Quarry**, and Modus actively pumps it. Cross-
  engagement memory, structured storage, and the analytical
  modules (`analyze_regression` / `analyze_jsdelta` /
  `analyze_interesting`, plus `recall` / `coverage` / `search` /
  `diff`) live in Quarry. A mining sub-agent inside the
  autonomous loop calls those tools every five steps and folds
  the resulting Candidates into the LLM's next-step context as
  breadcrumbs — Quarry's signal-extraction layer drives the
  agent's exploration rather than waiting for the LLM to remember
  it exists. Reviewing what Modus did is `quarry session show`
  or a SQLite query, not a log scrape.
- The agent is **delivered through MCP**. The operator picks
  the host (Claude Desktop, Claude Code, Cursor, any MCP-aware
  host); the host picks the model the *host* runs. Modus's own
  internal LLM (used by the autonomous loop) is a separate,
  provider-portable choice the operator makes via env vars.
  Modus is not locked to any provider on either side.
- The submission line is **structural**. No `submit`, `publish`,
  `post`, `report`, or `report-to-h1` tool is registered in the
  default registry, and adding one is project-policy off-limits.
  The agent can emit a `Tool` action with any name, but the
  consistency layer rejects with `tool_registered:<name>` if it
  isn't in the registry. The firewall covers *external
  submission* (to bug-bounty platforms), not internal promotion:
  Candidate→Finding promotion is corpus-internal and the
  autonomous loop closes it via `corpus.promote_finding` on
  severity-medium-or-higher Candidates. Submission to a
  programme is the operator's, performed outside Modus.

These five commitments are the invariants. The specific MCP
host, the specific LLM provider, the specific Z3 encoding, the
bug classes in v0.1 scope — all of that can change. The
invariants don't.

## How it fits

```
              operator
                 │
                 ▼
        ┌────────────────────┐          ┌─────────────────────────┐
        │  MCP host          │          │  modus-side LLM         │
        │  (Claude Desktop,  │          │  (Anthropic API,        │
        │   Claude Code,     │          │   OpenAI API,           │
        │   Cursor, ...)     │          │   OpenAI-compat: Ollama,│
        │                    │          │     vLLM, OpenRouter,   │
        │                    │          │   Claude Code           │
        │                    │          │     subscription)       │
        └────────┬───────────┘          └────────▲────────────────┘
                 │                               │
                 │ MCP (stdio, JSON-RPC)         │ used inside
                 ▼                               │ autonomous loop
        ┌────────────────────────────────────────┴─────────┐
        │                   modus mcp                      │
        │                                                  │
        │  autonomous-session tools          typed-action  │
        │  (start / poll / cancel / run /     surface +    │
        │   propose)                          generic tool │
        │             │                       │            │
        │             ▼                       ▼            │
        │       ┌────────────────────────────────────┐     │
        │       │  Z3 consistency check  ──┐         │     │
        │       │  (per-tool preconds)     ▼         │     │
        │       │                  ┌──────────────┐  │     │
        │       │                  │ ToolRegistry │  │     │
        │       │                  └──────┬───────┘  │     │
        │       └─────────────────────────┼──────────┘     │
        │                                 ▼                │
        │                         ┌─────────────────┐      │
        │                         │  ToolExecutor   │      │
        │                         └─┬──────┬──────┬─┘      │
        │                           │      │      │        │
        │                           ▼      ▼      ▼        │
        │                       shell  builtin   mcp       │
        │           (amass, nuclei, …) (request, hypoth) (host MCP)
        │                                                  │
        │       ┌────────────────────────────────────┐     │
        │       │  Miner (every N steps)             │     │
        │       │  analyze_regression / interesting  │     │
        │       │  / jsdelta / recall / coverage /   │     │
        │       │  search / diff                     │     │
        │       └─────────────┬──────────────────────┘     │
        │                     │ mining_signals             │
        │                     ▼ into next StepContext      │
        └───────────────┬──────────────────┬───────────────┘
                        ▼                  ▼
                 in-scope target       quarry mcp
                                          │
                                          ▼
                                  Quarry corpus (SQLite)
                                          │
                                          ▼
                                      Candidates
                                          │
                                          ▼
                                  corpus.promote_finding
                                  (severity ≥ medium, in-loop)
                                          │
                                          ▼
                                       Findings
                                          │
                                          ▼
                       (operator submits to programme — outside Modus)
```

Every action — typed-action fast path or generic `tool` dispatch —
flows through the same registry-driven Z3 check, then through the
`ToolExecutor`, then to one of three backends. Quarry is one
backend (`builtin` invocations targeting `corpus.*` registry
entries) among many; recon shells (`amass`, `nuclei`) and any
operator-declared tools share the path. ADR-0004 documents the
pivot from the closed v0.1 vocabulary to this shape.

The operator configures Modus as an MCP server in their host's
settings. The two common shapes:

```json
// Per-token API billing (any MCP host)
{
  "mcpServers": {
    "modus": {
      "command": "modus",
      "args": ["mcp", "--scope", "/path/to/scope.json"],
      "env": {
        "QUARRY_HOME": "/path/to/quarry/home",
        "MODUS_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

```json
// Subscription billing via Claude Pro/Max (requires Claude Code installed)
{
  "mcpServers": {
    "modus": {
      "command": "modus",
      "args": ["mcp", "--scope", "/path/to/scope.json"],
      "env": {
        "QUARRY_HOME": "/path/to/quarry/home",
        "MODUS_LLM_PROVIDER": "claude-cli",
        "MODUS_LLM_BASE_URL": "/path/to/claude"
      }
    }
  }
}
```

The `claude-cli` provider shells out to `claude --print` per
proposer call. Adds ~3 seconds of Node startup overhead per
step but bills against a Claude Pro/Max subscription rather
than API tokens. Workaround for MCP hosts that don't yet
implement the `sampling/createMessage` capability — Anthropic's
clients (Claude Desktop and Claude Code) are in this category
as of 2026-05-08.

The host then sees Modus's tool surface — autonomous-session
tools and verified-action tools — and the operator drives via
ordinary host conversation. See
[`docs/mcp-host-integration.md`](./docs/mcp-host-integration.md)
for full setup.

## Quarry integration

Quarry isn't an optional backend Modus *can* use — Quarry **is**
the corpus dependency, and Modus is built around the assumption
that its analytical and retrieval surfaces are live. Two
guarantees follow from that.

### Fail-fast on session start

When an autonomous session starts (`run_autonomous_session` or
`start_autonomous_session`), Modus probes Quarry with a
`list_targets` call as a read-only no-op that completes the MCP
handshake. If the corpus directory isn't initialised — `quarry
init` never ran, `$QUARRY_HOME` points at a missing path, the
Quarry binary isn't installed — the session refuses to start
with a `RuntimeError` that names the remediation
(`quarry init --corpus <path>`). The autonomous loop produces
persistent state; running against an unreachable corpus would
mean every candidate the loop emits silently fails to persist,
the operator sees per-session output but loses cross-engagement
recall, and the cross-session memory promise Quarry's README
makes ("the corpus remembers Monday's recon") is broken without
the operator noticing. Refusing at session start is the only
way to keep that invariant honest.

Per-callsite soft-fail still applies for narrower failures
(older Quarry servers missing a specific tool, transient MCP
hiccups) — only the session-level corpus-not-reachable
condition becomes a hard error.

### Mining sub-agent

Quarry's MCP surface exposes seven analytical / retrieval tools:
`analyze_regression`, `analyze_interesting`, `analyze_jsdelta`,
`recall`, `coverage`, `search`, and `diff`. Without the mining
sub-agent, those tools are merely *available* to the LLM
proposer — they show up in the system-prompt tool catalog, but
empirically the LLM rarely thinks to invoke them. Quarry becomes
a write-only logbook while its signal-extraction layer sits
dark.

The mining sub-agent closes that gap. The autonomous loop's
`AgentLoop` instantiates a `Miner` at session start and calls
`Miner.mine()` synchronously every `mining_cadence` steps
(default 5). Per call:

- **`analyze_regression` / `analyze_interesting` / `analyze_jsdelta`**
  run against the current target. Each Candidate they return
  becomes a `MiningSignal`.
- **`recall(host)`** fires once per new hostname the loop has
  observed since the previous mining pass. Cross-engagement
  matches surface as breadcrumbs.
- **`coverage(target)`** surfaces unprobed assets — entries in
  the corpus's discovery side that have no probe artifact yet.
  Most useful when the operator runs `quarry ingest httpx.jsonl`
  before launching: the URLs httpx surfaced become a checklist
  the autonomous loop systematically closes.
- **`search(query)`** fires once per session with a curated
  query set per declared bug class
  (`auth_bypass` → "permission_callback", "is_user_logged_in",
  …; `idor` → "user_id", "owner_id"; etc.). Hits surface
  cross-engagement evidence chunks or operator notes whose text
  matches the class's canonical keywords.
- **`diff(target)`** fires once per session, returning the
  latest-ingest assets first-seen during that run. Pairs with
  the operator's pre-launch `quarry ingest` step.

The signals flow into the next step's `StepContext.mining_signals`
and surface as a markdown block in the proposer's user prompt
("Quarry analytical layer — mined signals"). The LLM can pivot
to re-probe the flagged assets and emit fresh `Hypothesize`
actions citing this-run evidence_refs.

Per-run isolation stays intact: mining-derived evidence_refs
point into Quarry's corpus-wide artifact pool, NOT into this
run's observation pool. The consistency layer continues to gate
`hypothesize.evidence_refs` to this-run observations only —
mining surfaces breadcrumbs, the LLM re-probes, fresh
evidence_refs come from the new observations. The firewall is
preserved while the signal flows.

Per-tool failure tolerance: any `CorpusToolsMissingError`
(older Quarry servers without one of the analytical tools),
`CorpusError`, or unexpected exception in a specific mining
pass is logged at INFO and skipped. The autonomous run survives
a partially-missing analytical surface — useful during Quarry
upgrades or when running against an older corpus.

Disable mining entirely by setting `mining_cadence=0` on the
`AgentLoop`. The autonomous-session MCP tools don't expose this
yet; it's primarily for testing.

## Operator tooling

Beyond the MCP server, Modus ships a small CLI for operator
prep work that doesn't belong inside the agent loop:

- `modus action validate <spec.json>` — run the consistency
  layer against a static action + state spec; prints a per-
  action verdict. Useful for testing scope policies offline.
- `modus corpus status` — sanity-check that Modus can reach
  the Quarry binary and that the corpus is in a healthy state.
- `modus partition --input <subs.txt> --output-dir <dir>` —
  classify recon hostnames into Tier A/B/C using a maintained
  DO-NOT-TOUCH token list (combatant commands, ITAR, `.gov.`,
  PIV/CAC deployment prefixes). The operator authors
  `allowed_assets` from `tier-a.txt` manually; this is a
  recommendation tool, not a substitute for the consistency
  layer's allow-list. Closes the partition-slip class of bug
  surfaced in two consecutive engagements.
- `modus mcp --scope <path>` — start the MCP server (this is
  what the host launches via `mcpServers.modus.command`).

`--help` on any subcommand for the full option list.

## Scope

### Bug classes

Modus's evidence-pattern library covers eight bug classes with
canonical recognition templates and severity defaults:
`auth_bypass`, `idor`, `info_disclosure`, `sqli`, `ssrf`, `xss`,
`csrf`, `business_logic`. The pattern fallback proposer fires
on the first four when the LLM keeps abdicating; the prompt
templates render for all eight when the operator passes
`bug_classes` to `run_autonomous_session`. Modus is web-only —
no binary exploitation, no priv-esc, no smart contracts.

### v0.1 MCP hosts

Claude Desktop is the primary host target — that's the shape
Modus is designed against. Any other MCP-aware host (Claude
Code, Cursor, Continue, Zed) works to the extent that it
implements the standard MCP stdio transport. Setup snippets for
the common ones are in
[`docs/mcp-host-integration.md`](./docs/mcp-host-integration.md).

### LLM providers (Modus-internal, for autonomous sessions)

Five provider modes via `MODUS_LLM_PROVIDER`:

- `anthropic` — direct Anthropic API. Per-token cost. Recommended
  default for operators with an API key and an engagement budget.
- `openai` / `openai-compatible` — covers OpenAI proper plus any
  OpenAI-compatible endpoint via `base_url` (Ollama, vLLM,
  OpenRouter). Local-model operators use this mode pointed at
  Ollama; the M7 pattern fallback proposer bridges the
  decisiveness gap that mid-size open-weight models hit on
  multi-step reasoning.
- `host` — delegates each proposer call to the MCP host's LLM via
  `sampling/createMessage`. Subscription-billed in principle.
  Not viable through Anthropic's clients today (verified
  2026-05-08: Claude Desktop and Claude Code v2.1.136 both
  return JSON-RPC `-32601 "Method not found"`); usable when an
  MCP host that supports sampling becomes available.
- `claude-cli` — subprocess workaround for the `host` mode gap.
  Shells out to `claude --print` per proposer call, using
  Claude Code's OAuth/keychain auth for subscription billing.
  Adds ~3 seconds of Node startup overhead per step but bills
  flat against Claude Pro/Max.

The provider-portable proposer is the only Modus-internal LLM
choice; the host's LLM choice is separate and outside Modus's
control.

### Corpus

Quarry is the corpus dependency, not an interchangeable backend.
Modus consumes the seven analytical / retrieval tools
(`analyze_regression`, `analyze_interesting`, `analyze_jsdelta`,
`recall`, `coverage`, `search`, `diff`) plus the write surface
(`create_candidate`, `promote_finding`, `list_response_artifacts`)
via the documented MCP interface in
[`docs/corpus-interface.md`](./docs/corpus-interface.md). A
third-party corpus server can substitute for Quarry only by
implementing that same surface — but autonomous sessions
fail-fast at start if any of the read surface is unreachable,
so a partial implementation isn't a usable substitute.

## Non-goals

- Competing with commercial autonomous pentesters on benchmark
  scores. Modus is a different bet on the agent's *shape*, not
  on raw recall.
- Submitting Findings to bug-bounty programmes automatically.
  Ever. At any milestone. Under any flag. No `submit`, `publish`,
  `post`, `report`, or `report-to-h1` tool exists in the
  registry, and none will be added. The submission line is
  *external* — Modus closes the Candidate→Finding lifecycle
  inside the local corpus on severity-medium-or-higher
  Candidates, but submission of a Finding to a programme is the
  operator's, performed outside Modus.
- Generating finished, submission-ready report text without
  operator review. Findings carry the structured rationale the
  operator triages; turning a triaged set into a programme-ready
  submission package is the operator's job.
- Running outside operator-defined scope. Scope is encoded as
  preconditions in the consistency layer; the agent cannot
  propose, much less execute, an action against an out-of-scope
  asset.
- Replacing Quarry. Modus depends on Quarry; it does not
  duplicate ingestion, retrieval, analytical modules, or the
  Finding lifecycle.
- Replacing the host. Modus does not implement a chat UI, an
  approval-prompt UX, or a model-selection menu. Those are the
  host's job.

## Status and roadmap

The v0.1 skeleton is being laid down. The action vocabulary,
consistency layer, MCP corpus client, and proposer abstractions
are landing first; the MCP server and the autonomous-session
tool close the loop. See [`ROADMAP.md`](./ROADMAP.md) for
milestone planning and [`docs/adr/`](./docs/adr/) for the
architectural decisions that got us here.

## License

AGPL-3.0-or-later. See [`LICENSE`](./LICENSE).

The AGPL choice is deliberate: Modus is offensive security
infrastructure, and modifications that get deployed as services
should be returned to the community. Modus is pure FOSS — there
is no dual-license model and no commercial-license offering.

## Contributing

Not yet. The repository is in initial layout; PRs will be
welcomed once v0.1 has a working baseline. Issues and design
discussion are welcome in the meantime. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Authorized use only

Modus is built for authorized security testing — bug bounty
programs with written safe-harbor terms, penetration tests with
written authorization, and your own infrastructure. Using Modus
against systems you don't have explicit permission to test is
illegal in most jurisdictions and is not supported by this
project.
