"""Tests for the deterministic recon-floor module.

The recon module supplies a curated set of high-signal probe paths the
LLM proposer often forgets — VCS exposure, backup files, common log
files, WordPress plugin readme.txt fingerprints. The 2026-05-09 wp-lab
calibration baseline made the gap concrete: 20% recall, with the entire
plugin-CVE category and several misconfig categories missed because the
LLM didn't think to probe their paths.

These tests cover the contract:

* History-mirroring picks up (host, port, tls) triples the LLM has
  established, falls back to scope endpoints when no history exists.
* Misconfig proposals emit one Request per (path x endpoint) tuple,
  skipping any path already executed.
* WordPress fingerprint gating — plugin slug sweep stays empty until
  a WP marker appears in history.
* :class:`ReconAugmentedProposer` returns inner-proposer's batch first
  (LLM keeps primacy) followed by scout proposals.
"""

from __future__ import annotations

import pytest

from modus.actions import Probe, Request
from modus.consistency import CorpusState
from modus.proposer import FixedProposer, ReconAugmentedProposer, StepContext
from modus.recon import (
    WP_MISCONFIG_PATHS,
    WP_POPULAR_PLUGIN_SLUGS,
    build_misconfig_proposals,
    build_wp_plugin_proposals,
    discover_endpoints,
    looks_like_wordpress,
)
from modus.scope import ScopePolicy


def _scope(*assets: str) -> ScopePolicy:
    return ScopePolicy(
        target_name="t",
        allowed_assets=frozenset(assets or ("target.example.com",)),
        allowed_methods=frozenset({"GET", "HEAD", "POST"}),
    )


def _ctx(scope: ScopePolicy, history: tuple[str, ...] = ()) -> StepContext:
    return StepContext(
        corpus_state=CorpusState(
            in_scope_assets=scope.hosts(),
            allowed_methods=scope.allowed_methods,
        ),
        scope=scope,
        recent_history=history,
    )


# ----------------------------------------------------------- discover_endpoints


class TestDiscoverEndpoints:
    def test_falls_back_to_scope_when_no_history(self) -> None:
        scope = _scope("foo.example.com", "bar.example.com")
        triples = discover_endpoints(scope, ())
        # Bare hostnames default to (port=80, tls=False) per the
        # docstring — Modus probes plain HTTP first when nothing else
        # is known. The consistency layer will reject these if scope
        # turns out to require TLS.
        assert ("foo.example.com", 80, False) in triples
        assert ("bar.example.com", 80, False) in triples

    def test_mirrors_endpoints_from_history(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request target=foo.example.com obs=http-x "
            "GET http://foo.example.com:8080/ status=301 body_len=0",
        )
        triples = discover_endpoints(scope, history)
        assert triples == (("foo.example.com", 8080, False),)

    def test_history_overrides_scope_default(self) -> None:
        scope = _scope("foo.example.com")
        # If history shows a concrete (host, port, tls), the scope-derived
        # default isn't included — the LLM has already established the
        # right transport.
        history = (
            "step 0: request target=foo.example.com obs=http-x "
            "GET https://foo.example.com:8443/ status=200 body_len=100",
        )
        triples = discover_endpoints(scope, history)
        assert triples == (("foo.example.com", 8443, True),)

    def test_dedupes_repeated_history_observations(self) -> None:
        scope = _scope("foo.example.com")
        history = tuple(
            f"step {i}: request target=foo.example.com obs=h-{i} "
            f"GET http://foo.example.com:8080/p{i} status=200 body_len=10"
            for i in range(5)
        )
        triples = discover_endpoints(scope, history)
        assert triples == (("foo.example.com", 8080, False),)

    def test_ignores_out_of_scope_hosts_in_history(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request target=foo.example.com obs=h GET "
            "http://foo.example.com:8080/ status=301 body_len=0",
            # Operator pivoted to follow a redirect to a host not in scope.
            # We mustn't mirror that endpoint into the scout.
            "step 1: request target=other.example.org obs=h2 GET "
            "http://other.example.org/ status=200 body_len=10",
        )
        triples = discover_endpoints(scope, history)
        assert triples == (("foo.example.com", 8080, False),)


# ----------------------------------------------------------- looks_like_wordpress


class TestLooksLikeWordpress:
    def test_no_signal_returns_false(self) -> None:
        assert looks_like_wordpress(()) is False
        assert looks_like_wordpress(("step 0: probe target=foo aspect=tech",)) is False

    def test_wp_content_path_in_excerpt_fires(self) -> None:
        history = (
            "step 0: request GET http://foo/ status=200 body_excerpt='"
            "<link rel=\"stylesheet\" href=\"/wp-content/themes/astra/style.css\"'",
        )
        assert looks_like_wordpress(history) is True

    def test_wp_json_path_in_excerpt_fires(self) -> None:
        history = (
            "step 0: request GET http://foo/ status=200 body_excerpt='"
            "<link rel=\"https://api.w.org/\" href=\"/wp-json/\" />'",
        )
        assert looks_like_wordpress(history) is True

    def test_x_pingback_header_fires(self) -> None:
        history = (
            "step 0: request GET http://foo/ status=200 "
            "headers={'X-Pingback: http://foo/xmlrpc.php'}",
        )
        assert looks_like_wordpress(history) is True

    def test_generic_word_wordpress_does_not_fire(self) -> None:
        # The string "wordpress" alone in a doc page or marketing copy
        # shouldn't trigger plugin-slug sweeping. We require precision.
        history = (
            "step 0: request GET http://foo/ status=200 body_excerpt='"
            "We support multiple platforms including wordpress, joomla, drupal'",
        )
        assert looks_like_wordpress(history) is False


# ----------------------------------------------------------- misconfig proposals


class TestBuildMisconfigProposals:
    def test_emits_request_per_path_per_endpoint(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",
        )
        proposals = build_misconfig_proposals(scope, history)
        # 1 host x 1 endpoint x len(WP_MISCONFIG_PATHS) paths
        assert len(proposals) == len(WP_MISCONFIG_PATHS)
        for p in proposals:
            assert isinstance(p, Request)
            assert p.target == "foo.example.com"
            assert p.method == "GET"
            assert p.port == 8080
            assert p.tls is False

    def test_skips_already_executed_paths(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",
            # Already probed /readme.html and /xmlrpc.php — these should
            # not appear in the next batch of scout proposals.
            "step 1: request GET http://foo.example.com:8080/readme.html status=200 body_len=3000",
            "step 2: request GET http://foo.example.com:8080/xmlrpc.php status=405 body_len=42",
        )
        proposals = build_misconfig_proposals(scope, history)
        proposed_paths = {p.path for p in proposals}
        assert "/readme.html" not in proposed_paths
        assert "/xmlrpc.php" not in proposed_paths
        # And things we haven't probed should still be there:
        assert "/wp-config.php.bak" in proposed_paths
        assert "/.git/config" in proposed_paths

    def test_multi_host_emits_paths_per_host(self) -> None:
        scope = _scope("a.example.com", "b.example.com")
        history = (
            "step 0: request GET http://a.example.com:8080/ status=301 body_len=0",
            "step 1: request GET http://b.example.com:8080/ status=301 body_len=0",
        )
        proposals = build_misconfig_proposals(scope, history)
        targets = {p.target for p in proposals}
        assert targets == {"a.example.com", "b.example.com"}
        # 2 hosts x len(paths)
        assert len(proposals) == 2 * len(WP_MISCONFIG_PATHS)


# ----------------------------------------------------------- WP plugin proposals


class TestBuildWpPluginProposals:
    def test_empty_when_no_wp_signal(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",
        )
        proposals = build_wp_plugin_proposals(scope, history)
        assert proposals == []

    def test_emits_readme_paths_when_wp_detected(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=200 "
            "body_excerpt='<link href=\"/wp-content/themes/x/style.css\" />'",
        )
        proposals = build_wp_plugin_proposals(scope, history)
        # 1 host x 1 endpoint x len(slugs)
        assert len(proposals) == len(WP_POPULAR_PLUGIN_SLUGS)
        for p in proposals:
            assert isinstance(p, Request)
            assert p.path.startswith("/wp-content/plugins/")
            assert p.path.endswith("/readme.txt")
            assert p.method == "GET"

    def test_skips_already_probed_slugs(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=200 "
            "body_excerpt='/wp-content/themes/x/style.css'",
            "step 1: request GET http://foo.example.com:8080"
            "/wp-content/plugins/elementor/readme.txt status=200 body_len=8000",
        )
        proposals = build_wp_plugin_proposals(scope, history)
        proposed_paths = {p.path for p in proposals}
        assert "/wp-content/plugins/elementor/readme.txt" not in proposed_paths


# ----------------------------------------------------------- ReconAugmentedProposer


class TestReconAugmentedProposer:
    @pytest.mark.asyncio
    async def test_appends_scout_after_inner_proposals(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=200 "
            "body_excerpt='/wp-content/themes/x/style.css'",
        )
        # Inner proposer always returns one Probe. Test that scout
        # proposals are appended (not prepended), so LLM keeps primacy.
        inner_action = Probe(target="foo.example.com", aspect="httpx")
        inner = FixedProposer([inner_action])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, history)
        result = await wrapped.propose(ctx)
        assert result[0] == inner_action
        # Tail is scout (mix of misconfig + WP plugin proposals).
        scout = result[1:]
        assert all(isinstance(a, Request) for a in scout)
        # Should include both categories.
        misconfig_paths = {a.path for a in scout if not a.path.startswith("/wp-content/plugins/")}
        plugin_paths = {a.path for a in scout if a.path.startswith("/wp-content/plugins/")}
        assert "/wp-config.php.bak" in misconfig_paths
        assert any(p.endswith("/readme.txt") for p in plugin_paths)

    @pytest.mark.asyncio
    async def test_no_wp_signal_skips_plugin_proposals(self) -> None:
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",
        )
        inner = FixedProposer([])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, history)
        result = await wrapped.propose(ctx)
        # Misconfig paths still appear; plugin readme paths don't.
        plugin_paths = [a for a in result if isinstance(a, Request) and "/wp-content/plugins/" in a.path]
        assert plugin_paths == []
        misconfig_paths = [a for a in result if isinstance(a, Request)]
        assert any(a.path == "/.git/config" for a in misconfig_paths)
