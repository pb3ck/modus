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
    build_weak_credential_proposals,
    build_wp_plugin_proposals,
    build_xmlrpc_followup_proposals,
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
    def test_bare_hostname_with_no_history_is_silent(self) -> None:
        # The 2026-05-09 wp-lab v3 baseline showed why: with bare
        # hostnames in scope and no history, scout would default to
        # port 80, but the lab actually runs on 8080. 20 of 38 steps
        # got burned probing :80 paths that returned status=0. Now
        # scout stays silent until the LLM discovers the right port.
        scope = _scope("foo.example.com", "bar.example.com")
        triples = discover_endpoints(scope, ())
        assert triples == ()

    def test_uses_scope_port_when_explicit(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET"}),
        )
        triples = discover_endpoints(scope, ())
        assert triples == (("foo.example.com", 8080, False),)

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
            '<link rel="stylesheet" href="/wp-content/themes/astra/style.css"\'',
        )
        assert looks_like_wordpress(history) is True

    def test_wp_json_path_in_excerpt_fires(self) -> None:
        history = (
            "step 0: request GET http://foo/ status=200 body_excerpt='"
            '<link rel="https://api.w.org/" href="/wp-json/" />\'',
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
        history = ("step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",)
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
        history = ("step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",)
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


class TestXmlrpcFollowup:
    """Issue #33: when ``GET /xmlrpc.php`` returns 405, queue a
    ``POST`` with ``system.listMethods`` to confirm enablement."""

    def test_emits_post_when_get_returned_405(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/xmlrpc.php status=405 body_len=42",
        )
        proposals = build_xmlrpc_followup_proposals(scope, history)
        assert len(proposals) == 1
        assert isinstance(proposals[0], Request)
        assert proposals[0].method == "POST"
        assert proposals[0].path == "/xmlrpc.php"
        assert proposals[0].port == 8080
        assert proposals[0].tls is False
        assert "system.listMethods" in (proposals[0].body or "")

    def test_skips_when_post_already_executed(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/xmlrpc.php status=405 body_len=42",
            "step 1: request POST http://foo.example.com:8080/xmlrpc.php status=200 body_len=4000",
        )
        proposals = build_xmlrpc_followup_proposals(scope, history)
        assert proposals == []

    def test_silent_when_get_was_not_405(self) -> None:
        # GET returned 404 instead of 405 → endpoint isn't there →
        # no POST follow-up.
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/xmlrpc.php status=404 body_len=10",
        )
        proposals = build_xmlrpc_followup_proposals(scope, history)
        assert proposals == []

    def test_silent_when_post_not_in_allowed_methods(self) -> None:
        # Scope only allows GET → no POST proposals (consistency would
        # reject anyway, but we don't even propose).
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/xmlrpc.php status=405 body_len=42",
        )
        proposals = build_xmlrpc_followup_proposals(scope, history)
        assert proposals == []

    def test_emits_per_host_with_405(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://a.example.com:8080", "http://b.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://a.example.com:8080/xmlrpc.php status=405 body_len=42",
            "step 1: request GET http://b.example.com:8080/xmlrpc.php status=405 body_len=42",
        )
        proposals = build_xmlrpc_followup_proposals(scope, history)
        targets = {p.target for p in proposals}
        assert targets == {"a.example.com", "b.example.com"}


class TestWeakCredentialFollowup:
    """Issue #35: when ``GET /wp-login.php`` returned 200 with the
    login form, queue a single ``POST`` with a curated weak credential.
    Single attempt per host (the agent's identity-only dedup key
    doesn't differentiate by body)."""

    def test_emits_post_when_get_returned_200(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/wp-login.php status=200 body_len=3000",
        )
        proposals = build_weak_credential_proposals(scope, history)
        assert len(proposals) == 1
        p = proposals[0]
        assert isinstance(p, Request)
        assert p.method == "POST"
        assert p.path == "/wp-login.php"
        # Body has the WP-form-shape with weak creds.
        assert p.body is not None
        assert "log=admin" in p.body
        assert "pwd=admin123" in p.body
        # Cookie header sets the test cookie so WP doesn't reject the
        # POST as cookies-blocked.
        assert "wordpress_test_cookie" in (p.headers or {}).get("Cookie", "")

    def test_skips_when_post_already_executed(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/wp-login.php status=200 body_len=3000",
            "step 1: request POST http://foo.example.com:8080/wp-login.php status=200 body_len=4000",
        )
        proposals = build_weak_credential_proposals(scope, history)
        assert proposals == []

    def test_silent_when_get_returned_404(self) -> None:
        # No login form → no POST follow-up.
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET", "POST"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/wp-login.php status=404 body_len=10",
        )
        proposals = build_weak_credential_proposals(scope, history)
        assert proposals == []

    def test_silent_when_post_not_in_allowed_methods(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET"}),
        )
        history = (
            "step 0: request GET http://foo.example.com:8080/wp-login.php status=200 body_len=3000",
        )
        proposals = build_weak_credential_proposals(scope, history)
        assert proposals == []


class TestReconAugmentedProposer:
    """The wrapper schedules at two interleave levels:

    1. **LLM vs scout** by history-length parity (even → LLM-led).
    2. **Misconfig vs plugin** within scout-led steps, alternating by
       scout-step index. The 2026-05-09 v5 baseline caught the
       motivation: without bucket alternation, plugin proposals always
       sat after misconfig and never won a slot — plugin-CVE coverage
       stayed at 0%.

    Tests pin both levels.
    """

    @pytest.mark.asyncio
    async def test_passes_through_inner_on_even_parity_step(self) -> None:
        # Even-parity (history length 0, 2, 4, ...) → LLM-led: scout
        # is silent so the inner proposer keeps the slot.
        scope = _scope("foo.example.com")
        inner_action = Probe(target="foo.example.com", aspect="httpx")
        inner = FixedProposer([inner_action])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, ())  # length 0 → even
        result = await wrapped.propose(ctx)
        assert result == [inner_action]

    @pytest.mark.asyncio
    async def test_first_scout_led_step_is_misconfig(self) -> None:
        # First scout-led step (history length 1, scout_step_index 0)
        # → misconfig bucket. Scout prepends 1 misconfig path; LLM
        # batch follows.
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=200 "
            "body_excerpt='/wp-content/themes/x/style.css'",
        )
        inner_action = Probe(target="foo.example.com", aspect="httpx")
        inner = FixedProposer([inner_action])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, history)  # length 1, scout_step 0 → misconfig
        result = await wrapped.propose(ctx)
        assert len(result) == 2
        assert isinstance(result[0], Request)
        # Highest-priority misconfig path leads — /.git/config.
        assert result[0].path == "/.git/config"
        # No plugin path on a misconfig step.
        assert "/wp-content/plugins/" not in result[0].path
        assert result[-1] == inner_action

    @pytest.mark.asyncio
    async def test_second_scout_led_step_is_plugin(self) -> None:
        # Second scout-led step (history length 3, scout_step_index 1)
        # → plugin bucket. Scout prepends 1 plugin readme path.
        scope = _scope("foo.example.com")
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=200 "
            "body_excerpt='/wp-content/themes/x/style.css'",
            "step 1: request GET http://foo.example.com:8080/.git/config status=200 body_len=200",
            "step 2: request GET http://foo.example.com:8080/readme.html status=200 body_len=8",
        )
        inner_action = Probe(target="foo.example.com", aspect="httpx")
        inner = FixedProposer([inner_action])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, history)  # length 3, scout_step 1 → plugin
        result = await wrapped.propose(ctx)
        assert len(result) == 2
        assert isinstance(result[0], Request)
        # Plugin readme path leads.
        assert result[0].path.startswith("/wp-content/plugins/")
        assert result[0].path.endswith("/readme.txt")
        assert result[-1] == inner_action

    @pytest.mark.asyncio
    async def test_third_scout_led_step_returns_to_misconfig(self) -> None:
        # Third scout-led step (history length 5, scout_step_index 2)
        # → misconfig again. Bucket alternation cycles through
        # misconfig → plugin → misconfig → plugin → ...
        scope = _scope("foo.example.com")
        history = tuple(
            f"step {i}: request GET http://foo.example.com:8080/p{i} "
            f"status=200 body_excerpt='/wp-content/themes/x/style.css'"
            for i in range(5)
        )
        inner = FixedProposer([])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, history)  # length 5, scout_step 2 → misconfig
        result = await wrapped.propose(ctx)
        assert len(result) == 1
        assert isinstance(result[0], Request)
        # Misconfig path. /.git/config still novel since /p0../p4 are
        # what's been probed.
        assert not result[0].path.startswith("/wp-content/plugins/")

    @pytest.mark.asyncio
    async def test_plugin_step_silent_without_wp_signal(self) -> None:
        # On a plugin scout step, if no WP marker has appeared in
        # history, the plugin sweep is gated off. Result: scout
        # contributes nothing, LLM owns the slot. Important for
        # non-WordPress targets — we don't waste budget probing
        # plugin readmes that can't exist.
        scope = _scope("foo.example.com")
        # Length 3 → scout_step 1 → plugin step. But no WP marker
        # in history.
        history = (
            "step 0: request GET http://foo.example.com:8080/ status=301 body_len=0",
            "step 1: probe target=foo.example.com aspect=httpx",
            "step 2: request GET http://foo.example.com:8080/api status=404 body_len=10",
        )
        inner_action = Probe(target="foo.example.com", aspect="httpx")
        inner = FixedProposer([inner_action])
        wrapped = ReconAugmentedProposer(inner, scope=scope)
        ctx = _ctx(scope, history)
        result = await wrapped.propose(ctx)
        # Plugin gate failed → scout silent → only inner's batch.
        assert result == [inner_action]

    @pytest.mark.asyncio
    async def test_explicit_caps_misconfig_step(self) -> None:
        scope = ScopePolicy(
            target_name="t",
            allowed_assets=frozenset({"http://foo.example.com:8080"}),
            allowed_methods=frozenset({"GET"}),
        )
        inner = FixedProposer([])
        wrapped = ReconAugmentedProposer(
            inner,
            scope=scope,
            misconfig_per_step=3,
            plugin_per_step=0,
        )
        # Force odd parity, scout_step 0 → misconfig step.
        ctx = _ctx(scope, ("step 0: dummy",))
        result = await wrapped.propose(ctx)
        # cap=3 misconfig (plugin step would have 0).
        assert len(result) == 3
        assert all(isinstance(a, Request) for a in result)
