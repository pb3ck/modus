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

In a Claude Desktop conversation:

> Use Modus to look for IDOR vulnerabilities on the juice-shop
> target. Run an autonomous session with budget max_steps=15.

The host's LLM will call `modus.run_autonomous_session` with the
target name from your scope, the bug class, and a budget. Modus
runs the propose-prune-rank-execute loop end-to-end — sampling
candidate actions from the host's LLM, Z3-pruning the inconsistent
ones, executing the survivors via its HTTP executor, accumulating
observations and Candidates in the session pool. The tool returns
a structured `SessionRecord` with every sampled proposal, every
Z3 verdict, every executed action, and any Candidates the agent
authored.

Expect the session to take 1–5 minutes for a 15-step budget,
mostly LLM round-trip latency. The host's UX during the call is
"tool in progress"; you can keep reading the conversation while
it runs.

## 5. Read the result and promote findings

The MCP tool result is a JSON payload with two top-level fields:

- `session` — the full audit record (every step, every proposal,
  every verdict, every executed action).
- `candidates` — the Candidates the agent authored via
  `hypothesize` actions.

Modus does not promote Candidates to Findings. Modus does not
recommend submission. If a Candidate looks defensible, you
promote it via Quarry's own CLI:

```sh
quarry finding list                       # see the corpus's candidates
quarry finding promote <candidate-id>     # promote a candidate to a Finding
quarry finding show <finding-id>          # render the finding for review
```

The Finding lifecycle (hypothesis → confirmed → reported →
accepted/rejected/duplicate) is Quarry's, run by you, outside
Modus. See [Quarry's findings doc](https://github.com/pb3ck/quarry/blob/main/docs/findings.md).

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
- [`adr/`](./adr/) — the design decisions behind the four
  invariants (typed vocabulary, formal consistency, Quarry-as-
  corpus, storage-enforced submission line).
- [`../ROADMAP.md`](../ROADMAP.md) — what's next for Modus.
