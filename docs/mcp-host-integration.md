# MCP host integration

Modus is an MCP server. The operator drives it from any
MCP-aware host. This page covers the common ones and the
config they need.

The host's job is the conversation, the model, the tool-use
sampling, the user approval UX, and rendering tool results.
Modus's job is the typed action grammar, the formal consistency
check, the autonomous loop (when invoked), the HTTP executor,
and the corpus passthrough to Quarry. The two are separate
concerns; the host's choice of model is independent of Modus's
choice of model.

## Prerequisites

* Modus installed and on `PATH` (or available at an absolute
  path you'll reference in the host config).
* Quarry installed and on `PATH`. Modus launches `quarry mcp`
  as a child subprocess, so it needs to be reachable.
* A Quarry corpus initialised at `$QUARRY_HOME` (or the default
  `~/.quarry/`) — `quarry init` creates one. See Quarry's
  `docs/quickstart.md`.
* A scope policy JSON file describing the assets the agent is
  allowed to touch. Example shape:

  ```json
  {
    "target_name": "demo",
    "allowed_assets": ["target.example.com"],
    "allowed_methods": ["GET", "HEAD", "OPTIONS"]
  }
  ```

* A Modus-internal LLM provider configured via env, if you want
  to invoke the autonomous-session tool. Without it, the
  verified-action surface still works end-to-end via the host's
  LLM. With it, `run_autonomous_session` becomes available.

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS (or the equivalent on your platform):

```json
{
  "mcpServers": {
    "modus": {
      "command": "modus",
      "args": ["mcp", "--scope", "/path/to/scope.json"],
      "env": {
        "QUARRY_HOME": "/path/to/quarry-home",
        "MODUS_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

Restart Claude Desktop. Modus's tools appear under the `modus`
namespace alongside whatever else you have configured. The
verified-action tools (`probe`, `request`, `compare`,
`differential`, `annotate`, `hypothesize`) and the Quarry
passthroughs (`search`, `list_targets`, etc.) work
immediately. The autonomous-session tools
(`run_autonomous_session`, `propose_actions`) work iff
`MODUS_LLM_PROVIDER` is set.

If `modus` isn't on Claude Desktop's `PATH` (the GUI launcher
doesn't read your shell rc), use an absolute path:

```json
"command": "/Users/you/.local/bin/modus"
```

## Claude Code

Add to `~/.claude/settings.json` (or workspace
`.claude/settings.json`):

```json
{
  "mcpServers": {
    "modus": {
      "command": "modus",
      "args": ["mcp", "--scope", "/path/to/scope.json"],
      "env": {
        "QUARRY_HOME": "/path/to/quarry-home",
        "MODUS_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

Restart Claude Code. The tools appear in your tool surface.

## Other MCP-aware hosts

Any host that speaks the MCP stdio transport works. The command
is `modus mcp`, the args include `--scope <path>` and any
provider-specific env. Cursor, Continue, Zed, and the various
custom MCP-client agents have their own config files; consult
their docs for where to put the snippet above.

## Pointing Modus at a containerised Quarry

By default Modus spawns ``quarry mcp`` directly on the host, expecting
the binary on ``PATH`` and a corpus at ``$QUARRY_HOME`` (or
``~/.quarry``). Operators whose Quarry runs in a container (Exegol,
Docker, etc.) override the spawn command via env:

| Env var | Purpose |
|---|---|
| ``MODUS_QUARRY_COMMAND`` | The binary Modus invokes to start the Quarry MCP subprocess. Defaults to ``quarry``. |
| ``MODUS_QUARRY_ARGS`` | The arguments, shell-quoted (``shlex``-parsed). Defaults to ``mcp`` when ``MODUS_QUARRY_COMMAND`` is the default. |

Example: Quarry running inside an Exegol container, where the host
talks to it via ``docker exec``:

```json
"env": {
  "MODUS_QUARRY_COMMAND": "docker",
  "MODUS_QUARRY_ARGS": "exec -i -e QUARRY_HOME=/workspace/.quarry exegol-default /root/.cargo/bin/quarry mcp"
}
```

Modus speaks MCP stdio with whatever process this command spawns,
the same way it would if it had launched a host-side ``quarry``
binary. The corpus is whatever the launched Quarry sees — Modus
doesn't care which side of the container boundary it lives on.

## Picking the Modus-internal LLM provider

Modus's autonomous loop needs an LLM to generate proposals at
each step. The choice is via environment, set in the MCP server's
`env` block:

| Provider | `MODUS_LLM_PROVIDER` | Other env required |
|---|---|---|
| **Host sampling (recommended)** | `host` | none |
| Anthropic direct | `anthropic` | `ANTHROPIC_API_KEY`, optionally `MODUS_LLM_MODEL` |
| OpenAI direct | `openai` | `OPENAI_API_KEY`, optionally `MODUS_LLM_MODEL` |
| OpenAI-compatible (Ollama, vLLM, OpenRouter, ...) | `openai-compatible` | `MODUS_LLM_BASE_URL`, optionally `OPENAI_API_KEY`, `MODUS_LLM_MODEL` |

### Why `host` is the recommended default

With `MODUS_LLM_PROVIDER=host`, Modus delegates each proposer
call back to the host's LLM via the standard MCP
`sampling/createMessage` request. The Claude that's already
running your conversation in Claude Desktop / Claude Code is
the same Claude that generates Modus's proposals — no second
API key, no second billing surface, no model-version mismatch
between host and agent.

The MCP spec lets hosts prompt the user to approve each
sampling call. Claude Desktop and Claude Code show the
sampling traffic in their existing approval UX, so the
operator gets transparency over what the autonomous loop is
asking the model to do without paying for two LLM endpoints.

### When to use direct API providers

* The operator's host doesn't support sampling (older MCP
  hosts may not).
* The operator wants Modus's internal LLM to be a *different*
  model than the host's — e.g. Claude Desktop on Sonnet for
  the conversation but Modus internally on Opus for the
  autonomous search, or Modus internally on a local Ollama
  for cost reasons.
* The operator wants to bypass the host's per-call sampling
  approval UX entirely (e.g. running a long unsupervised
  session).

If `MODUS_LLM_PROVIDER` is unset, Modus's autonomous-session
tools return `isError=True` with a message naming the env
variable. The verified-action surface and the Quarry
passthroughs are unaffected. The simplest config is just
`MODUS_LLM_PROVIDER=host` with no other LLM env — the host
does the rest.

## Picking a scope

Scope is operator-owned. Modus does not let the host's LLM
modify scope at runtime — the policy is loaded once at
`modus mcp` startup and held immutably. Each MCP server
process corresponds to one scope. To work on a different
target, restart the server with a different `--scope`.

Wildcards in `allowed_assets` are deliberately rejected. If a
program's scope includes `*.example.com`, the operator expands
the wildcard locally (out of band) and lists the exact
hostnames. This keeps the consistency layer's reasoning
finite and prevents the agent from inferring its way into
hosts the operator never approved.

## Verifying the wiring

After updating the host config, restart the host and look for
Modus's tools in its tool surface. If they don't appear:

1. Run `modus mcp --scope /path/to/scope.json` directly in a
   terminal. It should start (the process stays running and
   reads JSON-RPC from stdin). Ctrl-C to stop. If the command
   isn't found, `modus` isn't on `PATH` for the host's launcher.
2. Run `modus corpus status` to verify Modus can reach Quarry.
   That command initialises an MCP client to `quarry mcp`,
   reads the corpus state, and exits. If it fails, the
   underlying Quarry config is wrong; see Quarry's
   troubleshooting before touching the Modus config.
3. Read the host's MCP server logs (Claude Desktop logs to
   `~/Library/Logs/Claude/mcp.log` on macOS; other hosts have
   their own paths). Look for "Modus" and check for stderr
   output from the Modus subprocess.

## Authorization flow during a session

The host's UX during a session:

* The operator types a request in the host conversation.
* The host's LLM decides to call a Modus tool.
* The host shows an approval dialog (Claude Desktop, Claude
  Code) — operator clicks Allow.
* Modus's tool handler runs: Z3 consistency check, then
  whatever the tool does (HTTP request, Quarry read,
  Candidate write, autonomous loop, ...).
* The result returns to the host's conversation.

The approval dialog is the host's, not Modus's. Hosts let you
configure auto-allow per tool name; that's an operator-side
choice. Modus itself never asks for per-step approval.

## When to use which surface

| Goal | Tool to call |
|---|---|
| Run a full autonomous session and get back Candidates | `run_autonomous_session(target, bug_classes, budget)` |
| Generate N candidate actions for the current corpus state, with verdicts, but execute none | `propose_actions(context, sample_count)` |
| Make one specific scope-checked HTTP request | `request(target, method, path, ...)` |
| Compare two observations | `compare(observation_a, observation_b, dimensions)` |
| Differential test (IDOR, auth bypass, tenant isolation) | `differential(observations, dimension, bug_class)` |
| Probe an asset for what the corpus already knows | `probe(target, aspect)` |
| Annotate a corpus row with a note | `annotate(referent, note)` |
| Write a Candidate | `hypothesize(bug_class, evidence_refs, rationale)` |
| Search the corpus | `search(query, target, ...)` |
| Run Quarry's deterministic analytical modules | `analyze_regression`, `analyze_jsdelta`, `analyze_interesting` |

The autonomous-session tools are the primary surface — the
operator who wants Modus to *do offensive security* calls
those. The verified-action tools are the transparency surface
— the operator who wants to drive each step from the host's
conversation calls those.
