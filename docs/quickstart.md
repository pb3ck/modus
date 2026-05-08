# Quickstart

This is the shortest path from "git clone" to "Modus runs an
autonomous session against a target." Five steps, ~10 minutes.

## What you'll need

- Python 3.12+.
- An MCP-aware host: **Claude Desktop** is the primary target;
  Claude Code, Cursor, and other MCP-aware hosts work the same way.
- **Quarry** installed and a corpus initialised. Quarry is Modus's
  corpus dependency — see [Quarry's quickstart](https://github.com/pb3ck/quarry/blob/main/docs/quickstart.md).
  If you want to test Modus without Quarry, you can: the
  verified-action surface still works, but Quarry-passthrough tools
  return errors.
- A target you have authorisation to test against. For learning,
  spin up [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
  in Docker (`docker run -d -p 13000:3000 bkimminich/juice-shop`).
  Real bug-bounty engagements need their own scope policy.

## 1. Install Modus

```sh
git clone https://github.com/pb3ck/modus.git
cd modus
uv sync
```

Verify:

```sh
uv run modus --help
```

You should see the CLI help with subcommands `status`, `action`,
`corpus`, and `mcp`.

## 2. Author a scope policy

Scope is what makes Modus's autonomy ethically defensible — the
agent runs without per-step approval, but it cannot exceed the
scope you author. Write a JSON file at any path you like; we'll
use `~/modus-scope.json`:

```json
{
  "target_name": "juice-shop",
  "allowed_assets": [
    "http://localhost:13000"
  ],
  "allowed_methods": [
    "GET", "HEAD", "OPTIONS", "POST"
  ],
  "user_agent": "Modus/0.1 (researcher@example.com)"
}
```

Allowed-asset entries can be:

- bare hostnames (`"example.com"`) — any scheme, any port allowed.
- URL forms (`"http://localhost:13000"`, `"https://api.example.com"`)
  — scheme and (optionally) port constrained. Use this form for
  local labs or when a host runs multiple services on different
  ports and only one is in scope.

Allowed methods default to `["GET", "HEAD", "OPTIONS"]` if you
omit the field — read-only. Add `POST`, `PUT`, `PATCH`, or
`DELETE` only when you specifically want the agent to send write
traffic.

Validate the file:

```sh
uv run modus action validate <(echo '{"state": {"in_scope_assets": ["localhost"], "allowed_methods": ["GET"]}, "actions": [{"kind": "probe", "target": "localhost"}]}')
```

If it returns `accept`, your environment is wired correctly.

## 3. Configure your MCP host

This is where Modus becomes reachable from Claude Desktop / Claude
Code. Add Modus as an MCP server in the host's config. Full
walkthrough lives in
[`mcp-host-integration.md`](./mcp-host-integration.md), but the
short form for Claude Desktop on macOS:

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "modus": {
      "command": "/path/to/modus/.venv/bin/modus",
      "args": ["mcp", "--scope", "/Users/you/modus-scope.json"],
      "env": {
        "MODUS_LLM_PROVIDER": "host",
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        "HOME": "/Users/you"
      }
    }
  }
}
```

`MODUS_LLM_PROVIDER=host` is the recommended setting. It tells
Modus to delegate every proposer call back to the host's LLM via
MCP `sampling/createMessage` — no second API key, no double-billing.
For other provider options (direct Anthropic / OpenAI / Ollama),
see [`mcp-host-integration.md`](./mcp-host-integration.md#picking-the-modus-internal-llm-provider).

If your Quarry runs in a container (Exegol, Docker), add:

```json
"MODUS_QUARRY_COMMAND": "docker",
"MODUS_QUARRY_ARGS": "exec -i -e QUARRY_HOME=/path/in/container my-container /path/to/quarry mcp"
```

Restart the host application (fully quit and reopen, not just
close-window). Modus's tools should appear in the host's tool
surface — eighteen of them, prefixed with the server name you
chose (e.g. `modus.run_autonomous_session`).

## 4. Run an autonomous session

### 4a. (Optional but strongly recommended) Seed the run with recon

The autonomous loop reasons over a *corpus*. On a cold corpus
with no assets ingested, the agent has nothing to anchor against
and tends to thrash on guessed paths. Doing recon first — even
a small probe sweep — gives the agent real evidence to commit
hypotheses against, and is what makes mid-size local models
(qwen2.5-coder:14b, phi4:14b) reach `hypothesize` reliably
instead of exploring indefinitely.

The recon output should be a JSONL file of
`{url, status, headers, body}` records — the same shape Quarry's
`responses` ingest adapter accepts. A 30-line Python script with
`aiohttp` covers it:

```python
# /tmp/seed.py
import asyncio, json, aiohttp
PATHS = [
    "/", "/robots.txt", "/api-docs",
    "/rest/admin/application-version",
    "/api/Users", "/api/Feedbacks", "/rest/products/search?q=apple",
    # ... whatever paths matter for your target
]
async def main():
    async with aiohttp.ClientSession() as s:
        with open("/tmp/recon.jsonl", "w") as f:
            for p in PATHS:
                async with s.get(f"http://localhost:13000{p}") as r:
                    f.write(json.dumps({
                        "url": str(r.url), "status": r.status,
                        "headers": dict(r.headers),
                        "body": (await r.read()).decode("utf-8", "replace")[:256_000],
                    }) + "\n")
asyncio.run(main())
```

Then ingest it into Quarry so the corpus has assets / evidence /
artifacts to reason over:

```sh
quarry ingest --target juice-shop --source responses /tmp/recon.jsonl
```

`quarry status` should now show non-zero `assets`, `runs`,
`artifacts`, `evidence`. (Real engagements would use `httpx`,
`katana`, or Burp output via the matching ingest sources; the
JSONL form above is just the simplest path to get started.)

### 4b. Run the loop

In a Claude Desktop conversation:

> Use Modus to look for IDOR or info-disclosure vulnerabilities
> on the juice-shop target. Pass `recon_jsonl_path` =
> `/tmp/recon.jsonl` so the loop seeds its evidence pool from
> the recon I just did. Budget max_steps=25.

The host's LLM will call `modus.run_autonomous_session` with the
target name, the bug classes, the budget, and the
`recon_jsonl_path`. Modus reads the JSONL, materializes one
`SessionObservation` per record into the run's evidence pool
(so the agent can cite them in `hypothesize` actions and the
deterministic fallback proposer can pattern-match against them),
then runs the propose-prune-rank-execute loop end-to-end —
sampling candidate actions from the host's LLM (or Modus's
configured provider), Z3-pruning the inconsistent ones,
executing the survivors via its HTTP executor, accumulating
observations and Candidates in the session pool. The tool
returns a structured `SessionRecord` with every sampled
proposal, every Z3 verdict, every executed action, any
Candidates the agent authored, and any Findings the loop
auto-promoted.

The result also reports `seeded_observation_count` so you can
verify the recon JSONL was loaded; if the path was wrong or
unreadable the result includes a `recon_warning` explaining why
no observations were seeded.

Expect the session to take 5–20 minutes for a 25-step budget,
mostly LLM round-trip latency. The host's UX during the call is
"tool in progress"; you can keep reading the conversation while
it runs. For longer runs, use `start_autonomous_session` +
`poll_autonomous_session` (escapes the host's per-tool-call
timeout).

## 5. Read the result and review the Findings

The MCP tool result is a JSON payload with three top-level fields:

- `session` — the full audit record (every step, every proposal,
  every verdict, every executed action).
- `candidates` — the Candidates the agent authored via
  `hypothesize` actions.
- `findings` — the Findings the agent auto-promoted from those
  Candidates. The autonomous loop calls `corpus.promote_finding`
  on the step after a `hypothesize` whose `severity_hint` was
  `medium`, `high`, or `critical`. Severity-`low` and severity-
  `info` Candidates stay un-promoted in the corpus for your
  review.

Each promoted Finding lands in Quarry with status `hypothesis`.
The Finding lifecycle (`hypothesis` → `confirmed` → `reported` →
`accepted`/`rejected`/`duplicate`) is Quarry's; you drive it from
the CLI as you reproduce, escalate, and submit:

```sh
quarry finding list                       # see all Findings (auto-promoted + manual)
quarry finding show <finding-id>          # render a Finding for review
quarry finding update <id> --status confirmed   # after you reproduce it
quarry finding promote <candidate-id>     # manual promotion (low/info, or older runs)
```

Submission to a bug-bounty programme is yours — Modus has no
`submit`/`publish`/`post`/`report-to-h1` tool in its registry,
and none will be added. See [Quarry's findings doc](https://github.com/pb3ck/quarry/blob/main/docs/findings.md).

## What to do if it doesn't work

- **`modus mcp` not in the host's tool list.** The host's
  launcher doesn't see the binary. Use an absolute path in the
  config, not just `modus`. Restart the host fully.
- **Autonomous tools return `MODUS_LLM_PROVIDER not set`.** Add
  `"MODUS_LLM_PROVIDER": "host"` to the env block in the host
  config. Restart the host.
- **`corpus_status` returns `corpus unavailable`.** Quarry isn't
  reachable — either the binary isn't on `PATH`, or the corpus
  isn't initialised, or the docker-exec command in
  `MODUS_QUARRY_ARGS` is wrong. Run `modus corpus status` from
  the terminal to debug.
- **`run_autonomous_session` times out in the host.** Hosts have
  their own MCP tool-call timeouts that are usually shorter than
  Modus's `max_wall_seconds` budget. Either reduce the budget,
  or run a longer session from the CLI (see
  [`mcp-host-integration.md`](./mcp-host-integration.md)).
- **Z3 rejects every proposal.** The agent is proposing actions
  that violate scope — most often, hitting a port not listed in
  your scope's URL form. Look at the `failed_preconditions` field
  on each step's verdicts; an `endpoint_in_scope:...` rejection
  tells you exactly which (host, port, tls) tuple was disallowed.
  Either tighten the agent's objective with the right URL, or
  widen the scope.

## Where to next

- [`mcp-host-integration.md`](./mcp-host-integration.md) — full
  reference for host configuration, including non-Claude-Desktop
  hosts, direct-API LLM providers, and containerised Quarry.
- [`corpus-interface.md`](./corpus-interface.md) — the contract
  Modus places on Quarry. Useful when troubleshooting corpus
  passthroughs.
- [`adr/`](./adr/) — design decisions, including ADR-0004 (the
  v0.3 pivot from a closed typed-action vocabulary to an open
  tool registry).
- [`../ROADMAP.md`](../ROADMAP.md) — what's next for Modus.
