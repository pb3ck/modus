# ADR 0007: Multi-step state extraction (token harvesting)

- **Status:** proposed
- **Date:** 2026-05-10
- **Supersedes:** —
- **Extends:** ADR 0001 (typed action vocabulary), ADR 0002 (autonomous
  loop)
- **Issue:** [#36](https://github.com/pb3ck/modus/issues/36) — part 2

## Context

Modus's autonomous loop is single-shot per step: the proposer emits
an action, the executor runs it, the observation lands in the run
pool, the next proposer call sees a *summarised* form of the
observation in `recent_history`. The summary is built by
`modus.agent._summarise_step` and includes a 240-char tail excerpt
of the response body.

The 2026-05-10 wp-bounty-lab user-registration audit made the cost
of this design concrete. Modus correctly identified the privilege-
escalation attack against the registration form:

```
POST /register/
body: username=modusprobe2&user_email=...&role=administrator
       &user_role=administrator&wp_capabilities=administrator
```

The response was 200 (form re-rendered) but no user got created.
WordPress silently rejected the POST because **it didn't include the
form's CSRF nonce**. The nonce sits in the form's HTML at the *head*
of the response body — never reaches the LLM's prompt because the
history excerpt is only the *tail* 240 chars.

This is the canonical attack flow against any modern web app:

1. GET a form / token-issuing endpoint
2. Extract a token (nonce / CSRF / JWT) from the response
3. POST the next request with the extracted token

Modus today supports steps 1 and 3 trivially (every step is an HTTP
action). Step 2 — extracting a value from one observation and using
it in the next request — has no architectural support. The LLM
cannot see the token in the prompt, and even if it could, the
proposer has no way to encode "use the value extracted from
observation X" in a typed `Request` action.

The cost is large. Black-box probing of any nonce-protected web
surface requires this primitive. Without it, Modus is restricted to:

* Endpoints that don't enforce nonces (rare on modern WP plugins)
* Read-only probes (most of the AJAX surface is gated)
* One-shot exploits where the bug is observable from a single
  unauthenticated request (the easy bugs are taken)

The 2026-05-10 audit cycle found zero Wordfence-payable bugs across
three popular plugins (WPForms Lite, user-registration, wp-statistics).
Each plugin's most-promising attack surface required nonce-bearing
multi-step flows that Modus couldn't follow.

## Design problem

**How does Modus extract structured tokens from observations and feed
them into subsequent requests, without breaking the typed-action
invariant from ADR 0001 or the single-shot-step rhythm from ADR
0002?**

Specifically:

* The extracted state has to flow through `StepContext` (the
  proposer's input) and through the agent loop's history.
* The Request action grammar has to accept extracted-token references
  in some form — either as inline string references (LLM substitutes)
  or as templated parameters (agent loop substitutes).
* The extraction itself needs to be deterministic and read-only — same
  trust posture as `evidence_patterns`, so a misbehaving plugin can't
  corrupt the run pool by emitting a string that re-parses as a token.
* The token catalog has to be open enough to extend per-target
  (different platforms have different token shapes) without becoming
  a footgun (operator-authored regex with malicious lookaheads).

## Sketch of options

### Option A — larger body excerpts in history

Push the body excerpt up from 240 chars to (say) 4096 chars. The
LLM sees more body content; it might extract the nonce on its own
and embed the literal value in the next request's body string.

* **Pros:** zero code change beyond a constant; immediate effect.
* **Cons:** token-budget cost is real (8 hosts × 4 KB tail = 32 KB
  per step in the prompt). The LLM still has to *recognize* the token
  shape and *correctly substitute* it without typos. Empirical
  reliability is poor on small models. Doesn't scale to flows that
  need 3+ tokens chained across observations.

### Option B — `extract_followup` action shape

Add a new action kind to the typed grammar:

```python
class ExtractFollowup(_ActionBase):
    kind: Literal["extract_followup"] = "extract_followup"
    source_observation: str         # observation_id to extract from
    extract_pattern: str            # regex with one capture group
    followup: Request               # the next request, with placeholder
    placeholder: str                # token in `followup.body` to substitute
```

The action chains atomically — agent loop runs the extract + the
followup as one observation pair.

* **Pros:** explicit and auditable. Each chain is one action. The LLM
  can author the regex itself if it spots the pattern in history.
* **Cons:** complex new action type. Operator-authored regex is a
  classic ReDoS / over-match vector. Coupling the extract and the
  followup into one action breaks the propose-prune-execute rhythm
  ADR 0002 commits to.

### Option C — Stateful proposer wrapper (preferred)

A new `TokenExtractingProposer` wraps any `Proposer`. After each
step, it walks the run's observations and runs a curated set of
extractor patterns over response bodies. Recognized tokens land in
a new `StepContext.extracted_tokens` field — a `dict[str, ExtractedToken]`
keyed by canonical token name (e.g. `"_wpnonce"`, `"wp_rest_nonce"`,
`"csrf_token"`). The proposer's user prompt renders an "available
tokens" block listing the names + values + source observation IDs.

The LLM then references tokens by literal value in its proposed
`Request`'s body / headers / query — same as if the LLM had read
them from the body. The agent loop doesn't substitute anything; the
LLM does. The typed-action grammar is unchanged.

The extractor patterns ship in source as a curated set per target
class:

```python
WP_TOKEN_PATTERNS = (
    ExtractorPattern("_wpnonce",     r'name="_wpnonce"\s+value="([a-f0-9]{10})"'),
    ExtractorPattern("wp_rest_nonce", r'"nonce":\s*"([a-f0-9]{10})"'),
    ExtractorPattern("data_token",   r'data-token="([a-f0-9]{32})"'),
    ExtractorPattern("login_nonce",  r'name="_wp_http_referer"\s+value="([^"]+)"'),
)
```

Operators can extend the catalog via `scope.extractor_patterns`
(future enhancement; out of scope for v0.5).

* **Pros:** narrow scope (one new field on StepContext, one new
  module, one prompt-block addition). No grammar changes. No
  operator-authored regex (curated patterns only). Multi-token
  chains work because every step's tokens are available, not just
  the immediately-prior. Same trust posture as `evidence_patterns`
  (read-only, deterministic).
* **Cons:** the LLM has to embed the literal value correctly. Same
  reliability concern as Option A but mitigated because the prompt
  block is explicit and short.

### Option D — Headless-browser executor

Replace the `httpx`-based executor with a Playwright/Puppeteer
driver. Tokens propagate via the browser's session/cookie/local-storage;
forms get submitted with their actual nonces because the browser
rendered the form. JS-driven nonce regeneration handled.

* **Pros:** correct by construction for any browser-flow attack.
* **Cons:** massive scope. Heavy executor (browser per session).
  Slow (seconds per step). Doesn't compose with non-browser surfaces
  (REST APIs called directly without a UI). Out of scope for v0.5.

## Decision

**Option C — `TokenExtractingProposer` wrapper.** Adopted because:

1. It's the smallest change that closes the architectural gap: one
   new module, one new field on `StepContext`, one prompt block
   addition to `_LlmProposerBase._user_prompt`.
2. It composes with the existing typed-action grammar — no Action
   subclass changes, no new precondition logic.
3. The curated-pattern model matches the precedent set by
   `evidence_patterns` (read-only deterministic detectors).
4. Multi-token chains work because every prior observation
   contributes to the available tokens, not just the immediate
   predecessor.
5. Extension hooks for operator-authored patterns can come in a
   later ADR if the curated set proves insufficient.

Rejected:

* Option A (larger excerpts) — token-budget cost real, reliability
  poor, doesn't scale to multi-token chains.
* Option B (`extract_followup` action) — couples extract + followup
  into one action, which breaks the propose-prune-execute rhythm.
  Also requires operator-authored regex which is a footgun.
* Option D (headless browser) — out of scope for v0.5; tracked as a
  future ADR for browser-required surfaces.

## Implementation sketch

```python
# src/modus/token_extractor.py
@dataclass(frozen=True)
class ExtractorPattern:
    name: str          # canonical token name, e.g. "_wpnonce"
    pattern: re.Pattern  # compiled regex with one capture group
    description: str   # for the proposer prompt block

@dataclass(frozen=True)
class ExtractedToken:
    name: str
    value: str
    source_observation_id: str
    source_url: str
    extracted_at: datetime

# Curated default patterns. Operators can extend via scope (future).
DEFAULT_PATTERNS: tuple[ExtractorPattern, ...] = (
    ExtractorPattern(
        name="_wpnonce",
        pattern=re.compile(r'name="_wpnonce"\s+value="([a-f0-9]{10})"'),
        description="WordPress form CSRF nonce (10 hex chars).",
    ),
    # ... more
)

def extract_tokens(
    observations: list[SessionObservation],
    patterns: tuple[ExtractorPattern, ...] = DEFAULT_PATTERNS,
) -> dict[str, ExtractedToken]:
    """Walk observations newest-to-oldest. Return name -> most-recent
    extracted token for each pattern that matched somewhere."""
```

`StepContext` gains:

```python
extracted_tokens: dict[str, ExtractedToken] = field(default_factory=dict)
```

`_LlmProposerBase._user_prompt` gains a section:

```
## Available extracted tokens

The following tokens have been extracted from prior observations.
Embed their values directly in your proposed Request's body / headers /
query string when the target endpoint requires them.

| Name             | Value             | Source obs |
| ---------------- | ----------------- | ---------- |
| _wpnonce         | a3b91c8d04        | http-...   |
| wp_rest_nonce    | f7e228919c        | http-...   |
```

`make_proposer` wraps the inner provider with `TokenExtractingProposer`
by default (parallel to the existing `ReconAugmentedProposer` wrap).
Operators can opt out via `token_extraction=False`.

## Out of scope for v0.5

* Operator-authored `ExtractorPattern` extensions (future ADR).
* Headless-browser executor for JS-driven flows (future ADR).
* Token validity windows / expiration tracking (current design uses
  most-recent; refinement if real targets need it).
* Token rotation across user-role contexts (when Modus eventually
  supports authenticated probing as different users).

## Success criterion

After implementation, an iteration against
``user-registration v5.1.6`` (the 2026-05-10 audit target) produces
a candidate that cites a successful registration with admin-tier
role parameters AND a valid `_wpnonce` in the request body. Either:

* The plugin's nonce check is sound and the user was rejected — but
  for a *different* reason (e.g., the role parameter was filtered
  server-side). Useful information either way.
* The plugin's role filtering is the bug, and a candidate gets
  promoted with concrete evidence (created user_id with admin role
  in the response).

## Inputs

* ``src/modus/agent.py:_summarise_step`` (current 240-char tail
  excerpt — gets extended or replaced by extracted-token surface)
* ``src/modus/proposer.py:StepContext`` (new field)
* ``src/modus/proposer.py:_LlmProposerBase._user_prompt`` (new
  prompt block)
* ``src/modus/proposer.py:make_proposer`` (new wrap layer)
* 2026-05-10 wp-bounty-lab iteration logs at
  ``/tmp/wp-bounty-run.json``

## Risks

* **LLM substitution reliability.** The LLM has to copy a 10-char hex
  string from the prompt into the request body without typo. Empirical
  validation needed. Mitigation: tight token-name vocabulary so the LLM
  doesn't invent variants; consider templated substitution (e.g.,
  ``${_wpnonce}``) as a fallback if literal-copy fails.
* **Pattern false positives.** A regex that matches a string that
  isn't actually a token would cause the LLM to embed garbage in
  requests. Mitigation: tightly-anchored patterns (look for the
  surrounding HTML attribute name, not just the value shape).
* **Token-validity drift.** Some tokens expire on use; subsequent
  requests get the same expired token from history. Mitigation:
  the agent loop's existing dedup makes re-using a single token
  for repeated requests a no-op anyway. If real-world targets show
  expired-token issues, refine the design.
