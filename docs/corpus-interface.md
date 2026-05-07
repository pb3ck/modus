# Corpus interface

Modus depends on an external corpus substrate. This document
specifies the contract Modus places on that substrate. The
reference dependency is [Quarry](https://github.com/pb3ck/quarry);
in principle any MCP server that implements the surface below
could substitute, but in practice we are coupled to Quarry until
someone needs otherwise.

The corpus is *not* a Modus-internal data structure. Modus does
not own a corpus schema; it consumes one. Reading this document
should not give the impression that Modus has its own database.
Modus does not.

## Why this is a separate document

ADR-0001 commits to "the audit surface is the corpus, not the
trace" and ADR-0002 commits to "the agent's terminal state is a
Candidate in the corpus." Both ADRs depend on a specific
external surface existing. Pinning that surface here lets the
ADRs stay about decisions and lets the contract evolve with
Quarry's MCP surface as Quarry's alpha matures.

## Transport

The corpus is accessed over the [Model Context
Protocol](https://modelcontextprotocol.io) using the stdio
transport. Modus runs (or attaches to) a corpus server process
and drives it via JSON-RPC over its stdin/stdout.

The reference command is:

```sh
quarry mcp
```

The server expects the corpus root (`$QUARRY_HOME` or
`~/.quarry/`) to already be initialised. Modus does not
initialise the corpus; that is an out-of-band operator action
(`quarry init`).

## Required tools

The following MCP tools must be exposed by the corpus server.
Modus will not start a session if any of these is missing.

### Read-only retrieval

| Tool | Purpose |
|---|---|
| `status` | Schema version, current target, per-entity counts. Modus uses this as the session's stable target context (cached prefix, see ADR-0002). |
| `list_targets` | Every Target in the corpus with the current one flagged. Modus uses this to validate the operator's `--target` argument against what's actually in the corpus. |
| `search` | FTS retrieval over evidence chunks and operator notes. Modus uses this as its primary "what does the corpus already know about X" surface, fed by the proposer for per-step retrieval. |
| `list_assets` | Structured query over Assets — filter by source, status, tech, webserver, name pattern, severity, CVE. Modus uses this for non-text queries the proposer needs ("which assets in scope returned 5xx in the last week"). |
| `diff` | Assets first seen during the most recent run for a Target. Modus uses this to bias the proposer toward the freshly-discovered surface. |
| `coverage` | Recon coverage gap — assets surfaced by some discovery source but never live-probed. Modus uses this to bias the proposer toward stranded assets that recon never resolved. |
| `recall` | Cross-target lookup — "where have I seen this hostname/tech/webserver before, in any prior Target." Modus uses this when the proposer hits a fingerprint it might have seen on another engagement. |

### Analytical (write Candidates)

| Tool | Purpose |
|---|---|
| `analyze_regression` | Diff the latest two runs of httpx/katana/burp and persist Candidates. Modus invokes this so the deterministic regression signal is in the corpus before the proposer reasons over it. |
| `analyze_jsdelta` | Pair the latest two ingestions of each JS bundle, persist Candidates per category. Same pattern: deterministic structural signal first, then LLM reasoning. |
| `analyze_interesting` | Single-snapshot heuristics (5xx, version leaks, name patterns). Modus invokes this on session start when no second snapshot exists yet. |

The analytical tools mutate the corpus only by adding
Candidates, which are derived state — re-running the same
module against the same corpus produces the same Candidates by
construction. Modus treats them as idempotent.

## Candidate write path

Modus's `Hypothesize` action terminates in a Candidate row. As
of Quarry alpha-8, the Candidate-write surface exposed via MCP
is limited to the `analyze_*` tools above; direct
agent-authored Candidate creation is gated on a Quarry-side
addition. Until that lands, Modus's `Hypothesize` action is
implemented as:

1. The agent emits a structured Candidate payload.
2. Modus persists the payload as an `Annotate` against the
   target plus a structured note that Quarry's evidence
   indexer surfaces.
3. The operator runs `quarry finding promote` against the
   resulting note (or against an analytical Candidate that the
   agent's note references) to lift it to a Finding.

This is a transitional shape and is documented as such in the
v0.1 release notes. The target shape is direct Candidate
writes once Quarry exposes them; the agent contract does not
change when that happens.

## What Modus does *not* require

The corpus contract is deliberately narrow. Modus does *not*
require the substrate to:

- Implement scope enforcement. Scope is encoded in Modus's
  consistency layer, not in the corpus. The corpus serves
  data; the agent decides what's in scope.
- Persist Modus's session state. Modus's session state is its
  own concern; what survives the session into the corpus is
  exactly the actions Modus ran and the rows Quarry already
  models.
- Generate report text. Submission text is the operator's job
  and is explicitly out of scope for Modus and for any corpus
  Modus depends on.
- Run analytical modules other than the three listed above.
  Quarry's roadmap includes additional modules; Modus can
  consume them when they exist but does not require them at
  v0.1.
- Write back to upstream tools. The corpus is one-way; tools
  produce evidence, evidence becomes corpus rows, the corpus
  is read-only against the source tools.

## Versioning

Quarry is alpha (currently 0.1.0-alpha.8 per Quarry's own
README). Modus pins a tested Quarry version range in
`pyproject.toml` once the integration is real (Milestone 2).
Before then the contract here is read against Quarry main.

The two pieces of Quarry's surface most likely to shift, per
its README:

- The CLI shape (irrelevant to Modus — Modus depends on the
  MCP surface, not the CLI).
- The M2.5 analytical commands (`analyze_*`). Modus avoids
  coupling tightly to their specific output schemas; the
  Candidate rows they produce go through Quarry's normal
  Candidate model, which is stable.

When Quarry tightens its MCP surface (direct Candidate writes,
new analytical modules, additional retrieval verbs), this
document gets a corresponding update and a new ADR if the
contract change is architectural.

## Failure modes

The following failure modes are handled by Modus rather than
by the corpus:

- **Corpus server not running.** Modus starts the server
  itself if `quarry mcp` is on PATH; otherwise it surfaces a
  setup error to the operator.
- **Schema version mismatch.** Modus reads `status`'s schema
  version on startup and refuses to run against an
  unrecognised version rather than risking a corrupt write.
- **Tool missing.** Modus's MCP client lists tools at startup
  and refuses to run if any required tool from the table
  above is absent.
- **Tool latency or timeout.** Each tool call has a per-call
  timeout; a timed-out call is encoded as a non-entailment
  in the consistency layer (the action whose precondition
  needed that tool's data is rejected for this step rather
  than retried indefinitely).
