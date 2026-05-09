"""Deterministic recon proposals — paths the LLM proposer often forgets.

Modus's LLM proposer drives recon by asking the model "what should we probe
next?" and trusting its judgment. That works for novel paths (the model is
creative) but underperforms on the long tail of well-known misconfigured
paths and CMS plugin fingerprints — the model rarely thinks to probe
``/.git/config`` on every host or sweep ``/wp-content/plugins/<slug>/readme.txt``
across a curated list of popular slugs. The 2026-05-09 wp-lab calibration
baseline made this concrete: 20% recall, with the entire plugin-CVE category
and several misconfig categories missed because the LLM didn't think to
probe their paths.

This module supplies a deterministic floor — a curated set of high-signal
paths the proposer always considers. They're emitted as additional
``Request`` action proposals each step; the agent loop's "first novel
survivor" ranking lets the LLM lead with creative probes and falls back to
these when LLM proposals duplicate prior actions. Net effect: the LLM still
drives novelty, but the floor ensures every common misconfig path lands
within the session's step budget.

Design choices:

* **Append rather than prepend.** The fallback hypothesizer prepends so its
  ``hypothesize`` actions win ranking when both fire (the loop wants the
  decision committed). Recon proposals are different — we want the LLM's
  next creative choice to win when it's novel, and only fall back to the
  curated list when the LLM's ideas have all been tried. So they go after
  the LLM's batch in :class:`ReconAugmentedProposer`.

* **History-mirrored endpoints.** Bare hostnames in ``allowed_assets``
  parse to ``(host, port=None, tls=None)`` — any port matches. The LLM
  discovers concrete (host, port, tls) triples on its first probe, which
  shows up in ``recent_history``. We mirror those triples for the scout
  so paths land on the same transport the LLM has been using. Falls back
  to scope's parsed endpoints when no history exists yet (step 0).

* **WordPress fingerprint gating.** The plugin-readme sweep is gated on
  evidence that the target is WordPress — if no WP marker has appeared in
  history yet, the slug list isn't proposed. Saves the budget on
  non-WordPress targets without requiring the operator to opt in.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from modus.actions import Action, Request

if TYPE_CHECKING:
    from modus.scope import ScopePolicy


# ----------------------------------------------------------- curated lists


# Ordered by signal density: VCS exposure first (single-shot exfil of the
# whole source tree), then secret-bearing backup files, then logs, then
# version-disclosure / fingerprint endpoints. Within each group, tighten
# from most-common to less-common so a step-budgeted run gets the
# highest-signal coverage first.
WP_MISCONFIG_PATHS: tuple[str, ...] = (
    # VCS directory exposure — highest impact when present.
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    # Backup-of-config files in webroot — second-highest impact (DB creds,
    # auth salts, embedded API tokens).
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php~",
    "/wp-config.php.swp",
    "/.env",
    "/.env.bak",
    "/.env.old",
    # Database dumps.
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    # Log files commonly left readable.
    "/wp-content/debug.log",
    "/error.log",
    "/debug.log",
    # WP-specific high-signal recon.
    "/readme.html",  # version disclosure
    "/xmlrpc.php",  # XML-RPC enabled signal (responds 405 to GET)
    "/wp-json/",  # REST API root — namespaces hint
    "/wp-json/wp/v2/users",  # REST user enumeration
    "/wp-login.php",  # login form (later: weak-cred probe)
    # Common admin / status endpoints (Apache, nginx, generic).
    "/server-status",
    "/server-info",
    "/.htaccess",
    # Filesystem leak indicators.
    "/.DS_Store",
    # Discovery endpoints (low-impact but cheap).
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
)

# Curated WordPress plugin slugs. Selected for installed-base scale +
# historical CVE density. Each one we probe is one observation; with a
# 40-step budget probing one per host this is cheap. Ordered by
# rough installed-base size so the highest-coverage slugs get probed
# first under tight budgets.
WP_POPULAR_PLUGIN_SLUGS: tuple[str, ...] = (
    "akismet",
    "jetpack",
    "wordfence",
    "yoast-seo",
    "wordpress-seo",  # Yoast SEO's actual slug
    "elementor",
    "contact-form-7",
    "woocommerce",
    "woocommerce-payments",
    "all-in-one-seo-pack",
    "wpforms-lite",
    "classic-editor",
    "wp-statistics",
    "redirection",
    "advanced-custom-fields",
    "wp-rocket",
    "autoptimize",
    "w3-total-cache",
    "wp-super-cache",
    "wp-fastest-cache",
    "litespeed-cache",
    "updraftplus",
    "duplicator",
    "wp-mail-smtp",
    "really-simple-ssl",
    "google-analytics-for-wordpress",
    "the-events-calendar",
    "ninja-forms",
    "gravityforms",
    "ithemes-security",
    "sucuri-scanner",
)


# --------------------------------------------------------- history parsing


# Match the URL portion of a history entry produced by
# ``modus.agent._summarise_step``. Format example:
# ``step 0: request target=foo obs=http-... GET http://foo:8080/path status=200 body_len=...``
_HISTORY_URL_RE = re.compile(
    r"\b(?P<scheme>https?)://(?P<host>[A-Za-z0-9._\-]+)(?::(?P<port>\d+))?(?P<path>/[^\s]*)"
)

# Markers that prove a response body (or a content excerpt) came from a
# WordPress site. Restricted to high-precision tokens — generic words like
# "wordpress" alone are too noisy because they appear in unrelated
# documentation.
_WP_FINGERPRINT_MARKERS: tuple[str, ...] = (
    "/wp-content/",
    "/wp-includes/",
    "/wp-json/",
    "wp-emoji-release",
    "WordPress.org",
    "<meta name=\"generator\" content=\"WordPress",
)
# Response-header tokens that prove a WP backend.
_WP_HEADER_MARKERS: tuple[str, ...] = (
    "x-redirect-by: WordPress",
    "x-pingback:",  # Only WP serves this header by default
)


def discover_endpoints(
    scope: ScopePolicy, recent_history: tuple[str, ...]
) -> tuple[tuple[str, int, bool], ...]:
    """Return concrete ``(host, port, tls)`` triples worth probing.

    Per-host policy:

    * If the host has appeared in history with at least one
      ``(port, tls)`` triple, mirror those — the LLM has established
      the right transport.
    * If the host hasn't appeared in history but the scope entry has
      an explicit port (e.g. ``http://hostname:8080``), use it. The
      operator told us the right transport.
    * If the host hasn't appeared in history AND the scope entry is
      a bare hostname (no port — ``port=None``), return nothing for
      this host. The right transport is unknown; let the LLM
      establish it on its first probe rather than burning budget on
      port 80 / 443 guesses that can return ``Connection refused``.

    The third rule is the lesson from the 2026-05-09 wp-lab v3 run:
    20 of 38 steps were wasted probing ``http://corp.lab.test:80/...``
    because the bare hostname defaulted to port 80, but the lab runs
    on 8080. With the scout silent on step 0, the LLM probes the
    correct port (the objective told it 8080), history populates, and
    scout starts contributing in step 1+ on the right transport.
    """
    seen_per_host: dict[str, set[tuple[int, bool]]] = {}
    scope_hosts = {ep.host for ep in scope.endpoints()}
    for line in recent_history:
        for match in _HISTORY_URL_RE.finditer(line):
            host = match.group("host")
            if host not in scope_hosts:
                continue
            port_s = match.group("port")
            tls = match.group("scheme") == "https"
            port = int(port_s) if port_s else (443 if tls else 80)
            seen_per_host.setdefault(host, set()).add((port, tls))

    out: set[tuple[str, int, bool]] = set()
    for ep in scope.endpoints():
        host = ep.host
        if host in seen_per_host:
            # Mirror the (port, tls) triples actually probed for this host.
            for port, tls in seen_per_host[host]:
                out.add((host, port, tls))
        elif ep.port is not None:
            # Scope is explicit about the port — safe to use.
            tls = ep.tls if ep.tls is not None else (ep.port == 443)
            out.add((host, ep.port, tls))
        # else: bare hostname, no history. Stay silent for this host.
    return tuple(sorted(out))


def looks_like_wordpress(recent_history: tuple[str, ...]) -> bool:
    """Has any observation in this run shown a WordPress fingerprint?

    Inspects history strings for response-body excerpts and headers that
    only WordPress emits. Conservative — generic mentions of "wordpress"
    don't trip this. Used to gate the plugin-slug sweep so we don't burn
    the step budget on slug probes against a non-WP target.
    """
    for line in recent_history:
        if any(m in line for m in _WP_FINGERPRINT_MARKERS):
            return True
        lower = line.lower()
        if any(m in lower for m in _WP_HEADER_MARKERS):
            return True
    return False


def _executed_action_keys(recent_history: tuple[str, ...]) -> set[str]:
    """Reconstruct the set of executed-action keys from history strings.

    Uses the same key shape :func:`modus.agent._action_dedup_key` produces:
    ``request:METHOD:scheme://host:port/path``. Matters because the agent
    loop's ranker dedups against recently-executed actions; recon proposals
    that duplicate already-tried paths waste a slot in the proposal list.
    Pre-filtering here keeps ``ReconAugmentedProposer.propose`` returning
    a tight, novel batch.
    """
    keys: set[str] = set()
    for line in recent_history:
        method_match = re.search(
            r"\b(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+(?P<rest>https?://\S+)",
            line,
        )
        if not method_match:
            continue
        method = method_match.group(1)
        url = method_match.group("rest")
        url_match = _HISTORY_URL_RE.match(url)
        if not url_match:
            continue
        scheme = url_match.group("scheme")
        host = url_match.group("host")
        port_s = url_match.group("port")
        path = url_match.group("path")
        port_part = f":{port_s}" if port_s else ""
        keys.add(f"request:{method}:{scheme}://{host}{port_part}{path}")
    return keys


# --------------------------------------------------------- proposal builders


def build_misconfig_proposals(
    scope: ScopePolicy,
    recent_history: tuple[str, ...],
    *,
    paths: tuple[str, ...] = WP_MISCONFIG_PATHS,
    limit: int | None = None,
) -> list[Action]:
    """Emit ``Request`` actions for high-signal misconfig paths on each
    in-scope endpoint, skipping any path already executed this session.

    ``limit`` caps the returned batch size. Caller (the recon-augmented
    proposer) sets a small cap (e.g. 4) per step so the scout doesn't
    crowd out LLM creativity in the proposer batch — only the top-N
    unprobed paths in curated priority order are emitted. Each step's
    "first novel survivor" then drains the curated list across steps.
    ``None`` means no cap (used by tests and for diagnostic dumps).
    """
    executed = _executed_action_keys(recent_history)
    out: list[Action] = []
    # Outer loop is paths so that the scout drains highest-priority
    # paths across all hosts before moving to the next path. Mixing in
    # round-robin host order would bury the per-host coverage of e.g.
    # `/.git/config` behind 30 lower-priority paths on the first host.
    for path in paths:
        for host, port, tls in discover_endpoints(scope, recent_history):
            scheme = "https" if tls else "http"
            key = f"request:GET:{scheme}://{host}:{port}{path}"
            if key in executed:
                continue
            out.append(
                Request(
                    target=host,
                    method="GET",
                    path=path,
                    port=port,
                    tls=tls,
                )
            )
            if limit is not None and len(out) >= limit:
                return out
    return out


def build_wp_plugin_proposals(
    scope: ScopePolicy,
    recent_history: tuple[str, ...],
    *,
    slugs: tuple[str, ...] = WP_POPULAR_PLUGIN_SLUGS,
    limit: int | None = None,
) -> list[Action]:
    """Emit ``Request`` actions for plugin-readme fingerprinting once a
    WordPress signal is detected. Empty list if no WP signal yet — saves
    the step budget on non-WP targets without operator opt-in.

    ``limit`` caps the returned batch size. Same rationale as
    :func:`build_misconfig_proposals` — small per-step caps preserve
    LLM creativity slots while letting the curated list drain across
    steps in priority order.
    """
    if not looks_like_wordpress(recent_history):
        return []
    executed = _executed_action_keys(recent_history)
    out: list[Action] = []
    for slug in slugs:
        for host, port, tls in discover_endpoints(scope, recent_history):
            scheme = "https" if tls else "http"
            path = f"/wp-content/plugins/{slug}/readme.txt"
            key = f"request:GET:{scheme}://{host}:{port}{path}"
            if key in executed:
                continue
            out.append(
                Request(
                    target=host,
                    method="GET",
                    path=path,
                    port=port,
                    tls=tls,
                )
            )
            if limit is not None and len(out) >= limit:
                return out
    return out


__all__ = [
    "WP_MISCONFIG_PATHS",
    "WP_POPULAR_PLUGIN_SLUGS",
    "build_misconfig_proposals",
    "build_wp_plugin_proposals",
    "discover_endpoints",
    "looks_like_wordpress",
]
