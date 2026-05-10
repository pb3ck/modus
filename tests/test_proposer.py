"""Tests for the LLM proposer.

Provider implementations are tested through duck-typed fake clients
so the test suite doesn't need API keys or network. The shared
:class:`_LlmProposerBase` logic — prompt building, response parsing,
graceful failure on malformed model output — is exercised here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from modus.actions import Action, Probe, Request
from modus.consistency import CorpusState
from modus.proposer import (
    AnthropicProposer,
    FixedProposer,
    OpenAICompatibleProposer,
    Proposer,
    StepContext,
    _parse_actions,
    make_proposer,
)
from modus.scope import ScopePolicy
from modus.session import LlmProviderConfig

# ------------------------------------------------------------ fakes


@dataclass
class _FakeAnthropicMessages:
    text: str
    last_kwargs: dict[str, Any] | None = None

    async def create(self, **kwargs: Any) -> Any:
        self.last_kwargs = kwargs
        return _FakeAnthropicResponse(self.text)


@dataclass
class _FakeAnthropicClient:
    text: str

    def __post_init__(self) -> None:
        self.messages = _FakeAnthropicMessages(text=self.text)


@dataclass
class _FakeAnthropicResponse:
    text: str

    @property
    def content(self) -> list[Any]:
        return [_FakeAnthropicTextBlock(self.text)]


@dataclass
class _FakeAnthropicTextBlock:
    text: str


@dataclass
class _FakeOpenAIChoice:
    message: Any


@dataclass
class _FakeOpenAIMessage:
    content: str


@dataclass
class _FakeOpenAIResponse:
    choices: list[Any]


@dataclass
class _FakeOpenAICompletions:
    text: str
    last_kwargs: dict[str, Any] | None = None
    fail_on_response_format: bool = False

    async def create(self, **kwargs: Any) -> Any:
        self.last_kwargs = kwargs
        if self.fail_on_response_format and "response_format" in kwargs:
            raise TypeError("server doesn't support response_format")
        return _FakeOpenAIResponse(
            choices=[_FakeOpenAIChoice(message=_FakeOpenAIMessage(content=self.text))]
        )


@dataclass
class _FakeOpenAIChatNamespace:
    completions: _FakeOpenAICompletions


@dataclass
class _FakeOpenAIClient:
    text: str
    fail_on_response_format: bool = False

    def __post_init__(self) -> None:
        self.chat = _FakeOpenAIChatNamespace(
            completions=_FakeOpenAICompletions(
                text=self.text, fail_on_response_format=self.fail_on_response_format
            )
        )


def _scope() -> ScopePolicy:
    return ScopePolicy(
        target_name="demo",
        allowed_assets=frozenset({"target.example.com"}),
        allowed_methods=frozenset({"GET", "HEAD"}),
    )


def _step_context(*, sample_count: int = 4) -> StepContext:
    return StepContext(
        corpus_state=CorpusState(
            in_scope_assets=frozenset({"target.example.com"}),
            allowed_methods=frozenset({"GET", "HEAD"}),
        ),
        scope=_scope(),
        sample_count=sample_count,
    )


# ------------------------------------------------------------ tool registry rendering


class TestRenderToolRegistry:
    """The 2026-05-10 wp-bounty-lab iteration 2 caught the gap: the
    LLM's prompt described the typed-action grammar but never
    enumerated the tool registry's contents. ``raw.http`` was
    correctly registered but the LLM never invoked it because it
    didn't know the name. ``_render_tool_registry`` closes that gap.
    """

    def test_none_returns_empty(self) -> None:
        from modus.proposer import _render_tool_registry

        assert _render_tool_registry(None) == ""

    def test_empty_registry_returns_empty(self) -> None:
        # A registry with only the typed-action specs (probe/request/...)
        # also renders empty — those are already covered by the action
        # grammar block, listing them again is noise.
        from modus.proposer import _render_tool_registry
        from modus.tools import ToolRegistry, builtin_typed_action_specs

        registry = ToolRegistry()
        for spec in builtin_typed_action_specs():
            registry.register(spec)
        assert _render_tool_registry(registry) == ""

    def test_renders_corpus_promote_finding(self) -> None:
        from modus.proposer import _render_tool_registry
        from modus.tools import build_default_registry

        # Default registry includes corpus.promote_finding +
        # amass.enum + nuclei.scan. None are typed actions; all
        # should render.
        out = _render_tool_registry(build_default_registry())
        assert "## `corpus.promote_finding`" in out
        assert "## `amass.enum`" in out
        assert "## `nuclei.scan`" in out
        # The Action-grammar's typed actions are NOT duplicated here.
        assert "## `request`" not in out
        assert "## `probe`" not in out
        assert "## `hypothesize`" not in out

    def test_renders_raw_http_when_opt_in(self) -> None:
        # Issue #36 part 2 / Path B: the whole reason this rendering
        # exists. raw.http only appears when the operator opts in via
        # MODUS_ALLOW_RAW_HTTP=1; when registered, the LLM has to see
        # it in the prompt to invoke it.
        import os

        from modus.proposer import _render_tool_registry
        from modus.tools import build_default_registry

        prior = os.environ.get("MODUS_ALLOW_RAW_HTTP")
        os.environ["MODUS_ALLOW_RAW_HTTP"] = "1"
        try:
            out = _render_tool_registry(build_default_registry())
        finally:
            if prior is None:
                os.environ.pop("MODUS_ALLOW_RAW_HTTP", None)
            else:
                os.environ["MODUS_ALLOW_RAW_HTTP"] = prior
        assert "## `raw.http`" in out
        # The args schema is rendered so the LLM knows what to pass.
        assert "method" in out
        assert "url" in out

    def test_args_schema_truncated_for_huge_specs(self) -> None:
        # Defensive: a tool spec with a multi-KB args schema shouldn't
        # bloat the prompt unboundedly. Schemas larger than 600 chars
        # are truncated with an ellipsis.
        import re

        from modus.proposer import _render_tool_registry
        from modus.tools import (
            BuiltinInvocation,
            ToolRegistry,
            ToolSpec,
        )

        # Build a synthetic spec with an enormous args schema.
        big_schema = {
            "type": "object",
            "properties": {f"field_{i}": {"type": "string"} for i in range(50)},
        }
        spec = ToolSpec(
            name="custom.huge",
            kind="builtin",
            description="A test tool with a very large args schema.",
            args_schema=big_schema,
            side_effect="read",
            invocation=BuiltinInvocation(callable_dotted_path="x.y"),
        )
        registry = ToolRegistry()
        registry.register(spec)
        out = _render_tool_registry(registry)
        # Schema output line should be present but truncated.
        match = re.search(r"args: `(.+?)`", out)
        assert match is not None
        rendered = match.group(1)
        assert rendered.endswith("…"), f"expected ellipsis truncation, got: {rendered!r}"
        assert len(rendered) <= 605  # 600 + ellipsis


class TestParser:
    def test_parses_clean_json_object(self) -> None:
        text = json.dumps(
            {
                "actions": [
                    {"kind": "probe", "target": "a.example.com"},
                    {"kind": "probe", "target": "b.example.com"},
                ]
            }
        )
        actions = _parse_actions(text, sample_count=8)
        assert len(actions) == 2
        assert all(isinstance(a, Probe) for a in actions)

    def test_handles_markdown_fence(self) -> None:
        text = (
            "```json\n"
            + json.dumps({"actions": [{"kind": "probe", "target": "a.example.com"}]})
            + "\n```"
        )
        actions = _parse_actions(text, sample_count=8)
        assert len(actions) == 1

    def test_extracts_json_from_narration(self) -> None:
        text = (
            "Here are my proposals:\n\n"
            + json.dumps({"actions": [{"kind": "probe", "target": "a.example.com"}]})
            + "\n\nLet me know if you need different ones."
        )
        actions = _parse_actions(text, sample_count=8)
        assert len(actions) == 1

    def test_drops_invalid_actions_keeps_valid_ones(self) -> None:
        text = json.dumps(
            {
                "actions": [
                    {"kind": "probe", "target": "a.example.com"},
                    {"kind": "request"},  # missing required fields
                    {"kind": "shell", "command": "id"},  # unknown action
                    {"kind": "probe", "target": "b.example.com"},
                ]
            }
        )
        actions = _parse_actions(text, sample_count=8)
        assert len(actions) == 2

    def test_truncates_to_sample_count(self) -> None:
        text = json.dumps(
            {"actions": [{"kind": "probe", "target": f"asset-{i}.example.com"} for i in range(20)]}
        )
        actions = _parse_actions(text, sample_count=4)
        assert len(actions) == 4

    def test_empty_text_returns_empty_batch(self) -> None:
        assert _parse_actions("", sample_count=8) == []
        assert _parse_actions("not json at all", sample_count=8) == []

    def test_missing_actions_field_returns_empty(self) -> None:
        text = json.dumps({"hypotheses": []})
        assert _parse_actions(text, sample_count=8) == []


# ------------------------------------------------------------ AnthropicProposer


class TestAnthropicProposer:
    async def test_round_trip_with_fake_client(self) -> None:
        client = _FakeAnthropicClient(
            text=json.dumps(
                {
                    "actions": [
                        {"kind": "probe", "target": "target.example.com"},
                        {
                            "kind": "request",
                            "target": "target.example.com",
                            "method": "GET",
                            "path": "/",
                        },
                    ]
                }
            )
        )
        proposer = AnthropicProposer(scope=_scope(), client=client, model="claude-test")
        actions = await proposer.propose(_step_context())
        assert len(actions) == 2
        kwargs = client.messages.last_kwargs
        assert kwargs is not None
        # The system prompt is sent with cache_control attached.
        system_block = kwargs["system"][0]
        assert system_block["cache_control"] == {"type": "ephemeral"}
        # The vocabulary description and scope block are in the system prompt.
        assert "Action grammar" in system_block["text"]
        assert "target_name='demo'" in system_block["text"]

    async def test_returns_empty_on_invalid_model_output(self) -> None:
        client = _FakeAnthropicClient(text="garbage that isn't JSON")
        proposer = AnthropicProposer(scope=_scope(), client=client, model="claude-test")
        actions = await proposer.propose(_step_context())
        assert actions == []

    async def test_system_prompt_describes_promotion_policy(self) -> None:
        """The system prompt must contain the severity-gated auto-promotion
        policy and the ban on bug-bounty submission tools.

        Regression guard for #13 — the policy is what produces the
        autonomous Candidate→Finding loop close. Drift here is a
        product-behaviour drift, not a stylistic one.
        """
        client = _FakeAnthropicClient(text='{"actions": []}')
        proposer = AnthropicProposer(scope=_scope(), client=client, model="claude-test")
        await proposer.propose(_step_context())
        kwargs = client.messages.last_kwargs
        assert kwargs is not None
        system_text = kwargs["system"][0]["text"]
        # Auto-promotion policy: medium/high/critical → promote.
        assert "corpus.promote_finding" in system_text
        assert "medium" in system_text and "critical" in system_text
        # The submission firewall stays — no submit tool, none coming.
        assert "submit" in system_text.lower()
        assert "bug-bounty" in system_text or "bounty" in system_text

    async def test_returns_empty_on_client_error(self) -> None:
        class _Boom:
            class _Messages:
                async def create(self, **_: Any) -> Any:
                    raise RuntimeError("api down")

            messages = _Messages()

        proposer = AnthropicProposer(scope=_scope(), client=_Boom(), model="claude-test")
        # Should swallow the exception and return [], not crash the loop.
        actions = await proposer.propose(_step_context())
        assert actions == []


# ------------------------------------------------------------ OpenAICompatibleProposer


class TestOpenAICompatibleProposer:
    async def test_round_trip_with_fake_client(self) -> None:
        client = _FakeOpenAIClient(
            text=json.dumps({"actions": [{"kind": "probe", "target": "target.example.com"}]})
        )
        proposer = OpenAICompatibleProposer(scope=_scope(), client=client, model="gpt-test")
        actions = await proposer.propose(_step_context())
        assert len(actions) == 1
        kwargs = client.chat.completions.last_kwargs
        assert kwargs is not None
        # Prefers JSON mode by default.
        assert kwargs.get("response_format") == {"type": "json_object"}

    async def test_falls_back_when_response_format_unsupported(self) -> None:
        client = _FakeOpenAIClient(
            text=json.dumps({"actions": [{"kind": "probe", "target": "target.example.com"}]}),
            fail_on_response_format=True,
        )
        proposer = OpenAICompatibleProposer(scope=_scope(), client=client, model="ollama-test")
        actions = await proposer.propose(_step_context())
        assert len(actions) == 1


# ------------------------------------------------------------ factory


class TestMakeProposer:
    """``make_proposer`` returns the inner provider wrapped in
    :class:`ReconAugmentedProposer` by default — that wrapper adds the
    deterministic recon floor (#2 / #3 from the 2026-05-09 wp-lab
    calibration baseline). Operators measuring pure-LLM recon can opt
    out via ``recon_floor=False``."""

    def test_anthropic_provider(self) -> None:
        from modus.proposer import ReconAugmentedProposer

        cfg = LlmProviderConfig(provider="anthropic", model=None, api_key="sk-test", base_url=None)
        # Don't actually instantiate the upstream client — just verify dispatch.
        # Use a sentinel client to bypass network init.
        from unittest.mock import patch

        with patch("modus.proposer.AsyncAnthropic"):
            proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, ReconAugmentedProposer)
        assert isinstance(proposer._inner, AnthropicProposer)

    def test_anthropic_provider_opt_out(self) -> None:
        cfg = LlmProviderConfig(provider="anthropic", model=None, api_key="sk-test", base_url=None)
        from unittest.mock import patch

        with patch("modus.proposer.AsyncAnthropic"):
            proposer = make_proposer(llm=cfg, scope=_scope(), recon_floor=False)
        assert isinstance(proposer, AnthropicProposer)

    def test_openai_provider(self) -> None:
        from modus.proposer import ReconAugmentedProposer

        cfg = LlmProviderConfig(provider="openai", model=None, api_key="sk-test", base_url=None)
        from unittest.mock import patch

        with patch("modus.proposer.AsyncOpenAI"):
            proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, ReconAugmentedProposer)
        assert isinstance(proposer._inner, OpenAICompatibleProposer)

    def test_openai_compatible_provider(self) -> None:
        from modus.proposer import ReconAugmentedProposer

        cfg = LlmProviderConfig(
            provider="openai-compatible",
            model="llama3",
            api_key=None,
            base_url="http://localhost:11434/v1",
        )
        from unittest.mock import patch

        with patch("modus.proposer.AsyncOpenAI"):
            proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, ReconAugmentedProposer)
        assert isinstance(proposer._inner, OpenAICompatibleProposer)

    def test_unknown_provider_rejected(self) -> None:
        cfg = LlmProviderConfig(
            provider="made-up",  # bypassed env validation by direct construct
            model=None,
            api_key=None,
            base_url=None,
        )
        with pytest.raises(ValueError):
            make_proposer(llm=cfg, scope=_scope())

    def test_host_provider_requires_mcp_session(self) -> None:
        cfg = LlmProviderConfig(provider="host", model=None, api_key=None, base_url=None)
        with pytest.raises(ValueError, match="active MCP session"):
            make_proposer(llm=cfg, scope=_scope())

    def test_host_provider_constructs_with_session(self) -> None:
        from modus.proposer import HostSamplingProposer, ReconAugmentedProposer

        cfg = LlmProviderConfig(provider="host", model=None, api_key=None, base_url=None)

        class _FakeMcpSession:
            async def create_message(self, **_: Any) -> Any: ...

        proposer = make_proposer(llm=cfg, scope=_scope(), mcp_session=_FakeMcpSession())
        assert isinstance(proposer, ReconAugmentedProposer)
        assert isinstance(proposer._inner, HostSamplingProposer)


class TestHostSamplingProposer:
    async def test_round_trips_through_host_session(self) -> None:
        from modus.proposer import HostSamplingProposer

        captured: dict[str, Any] = {}

        class _FakeResult:
            class content:  # noqa: N801 - mimicking SDK shape
                text = json.dumps({"actions": [{"kind": "probe", "target": "target.example.com"}]})

        class _FakeMcpSession:
            async def create_message(self, **kwargs: Any) -> Any:
                captured.update(kwargs)
                return _FakeResult()

        proposer = HostSamplingProposer(scope=_scope(), mcp_session=_FakeMcpSession())
        actions = await proposer.propose(_step_context())
        assert len(actions) == 1
        assert isinstance(actions[0], Probe)
        # Sampling call carried system + user prompts to the host.
        assert "Action grammar" in captured["system_prompt"]
        assert captured["max_tokens"] > 0
        assert len(captured["messages"]) == 1

    async def test_returns_empty_on_session_error(self) -> None:
        from modus.proposer import HostSamplingProposer

        class _Boom:
            async def create_message(self, **_: Any) -> Any:
                raise RuntimeError("host disconnected")

        proposer = HostSamplingProposer(scope=_scope(), mcp_session=_Boom())
        actions = await proposer.propose(_step_context())
        assert actions == []


class TestLlmProviderConfigHost:
    def test_host_provider_no_api_key_required(self) -> None:
        cfg = LlmProviderConfig.from_env({"MODUS_LLM_PROVIDER": "host"})
        assert cfg is not None
        assert cfg.provider == "host"
        assert cfg.api_key is None


class TestLlmProviderConfigClaudeCli:
    """Subscription-billed CLI workaround for the host-sampling gap."""

    def test_claude_cli_provider_no_api_key_required(self) -> None:
        cfg = LlmProviderConfig.from_env({"MODUS_LLM_PROVIDER": "claude-cli"})
        assert cfg is not None
        assert cfg.provider == "claude-cli"
        assert cfg.api_key is None

    def test_claude_cli_provider_picks_up_base_url_as_binary_path(self) -> None:
        cfg = LlmProviderConfig.from_env(
            {
                "MODUS_LLM_PROVIDER": "claude-cli",
                "MODUS_LLM_BASE_URL": "/Users/paulbeck/.local/bin/claude",
            }
        )
        assert cfg is not None
        assert cfg.base_url == "/Users/paulbeck/.local/bin/claude"


# ------------------------------------------------------------ ClaudeCliProposer


class TestClaudeCliProposer:
    """Subprocess-based CLI proposer.

    Uses a fake claude binary (a tiny shell script) so the tests are
    deterministic and don't require subscription auth.
    """

    @staticmethod
    def _make_fake_claude(
        tmp_path: Path,
        *,
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        delay_seconds: float = 0.0,
    ) -> Path:
        """Generate a fake claude binary that emits stdout/stderr and exits.

        Writes the canned outputs to sibling files and ``cat``s them
        from the script — avoids any shell-quoting issues with JSON
        payloads that contain quotes, backslashes, etc.
        """
        binary = tmp_path / "fake-claude"
        stdout_file = tmp_path / "fake-claude-stdout"
        stderr_file = tmp_path / "fake-claude-stderr"
        stdout_file.write_text(stdout)
        stderr_file.write_text(stderr)
        sleep_line = f"sleep {delay_seconds}\n" if delay_seconds > 0 else ""
        script = (
            f"#!/bin/sh\n{sleep_line}cat {stdout_file}\ncat {stderr_file} >&2\nexit {exit_code}\n"
        )
        binary.write_text(script)
        binary.chmod(0o755)
        return binary

    async def test_round_trip_via_subprocess(self, tmp_path: Path) -> None:
        from modus.proposer import ClaudeCliProposer

        canned_inner = json.dumps({"actions": [{"kind": "probe", "target": "target.example.com"}]})
        # claude --print --output-format json wraps the model output in a
        # ``result`` field; mimic that shape.
        canned_outer = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": canned_inner,
                "duration_ms": 1500,
            }
        )
        fake = self._make_fake_claude(tmp_path, stdout=canned_outer)
        proposer = ClaudeCliProposer(scope=_scope(), claude_bin=str(fake))

        actions = await proposer.propose(_step_context())
        assert len(actions) == 1
        assert isinstance(actions[0], Probe)
        assert actions[0].target == "target.example.com"

    async def test_returns_empty_when_subprocess_exits_nonzero(self, tmp_path: Path) -> None:
        from modus.proposer import ClaudeCliProposer

        fake = self._make_fake_claude(
            tmp_path,
            stdout="",
            stderr="claude: not authenticated\\n",
            exit_code=1,
        )
        proposer = ClaudeCliProposer(scope=_scope(), claude_bin=str(fake))
        actions = await proposer.propose(_step_context())
        assert actions == []

    async def test_returns_empty_on_non_json_output(self, tmp_path: Path) -> None:
        from modus.proposer import ClaudeCliProposer

        fake = self._make_fake_claude(tmp_path, stdout="not json at all")
        proposer = ClaudeCliProposer(scope=_scope(), claude_bin=str(fake))
        actions = await proposer.propose(_step_context())
        assert actions == []

    async def test_returns_empty_on_is_error_payload(self, tmp_path: Path) -> None:
        from modus.proposer import ClaudeCliProposer

        # claude --print returns is_error=true on auth failures, rate
        # limits, etc. — surface as an empty proposer result so the
        # autonomous loop's pattern fallback can still fire.
        canned = json.dumps(
            {
                "type": "result",
                "is_error": True,
                "api_error_status": "rate_limit_exceeded",
                "result": None,
            }
        )
        fake = self._make_fake_claude(tmp_path, stdout=canned)
        proposer = ClaudeCliProposer(scope=_scope(), claude_bin=str(fake))
        actions = await proposer.propose(_step_context())
        assert actions == []

    async def test_returns_empty_on_missing_binary(self) -> None:
        from modus.proposer import ClaudeCliProposer

        proposer = ClaudeCliProposer(scope=_scope(), claude_bin="/nonexistent/path/to/claude-cli")
        actions = await proposer.propose(_step_context())
        assert actions == []

    async def test_timeout_kills_subprocess(self, tmp_path: Path) -> None:
        from modus.proposer import ClaudeCliProposer

        # Fake claude that sleeps longer than the timeout.
        fake = self._make_fake_claude(tmp_path, stdout="", delay_seconds=5.0)
        proposer = ClaudeCliProposer(
            scope=_scope(),
            claude_bin=str(fake),
            timeout_seconds=0.5,
        )
        actions = await proposer.propose(_step_context())
        assert actions == []


class TestMakeProposerClaudeCli:
    def test_claude_cli_provider_constructs(self) -> None:
        from modus.proposer import ClaudeCliProposer, ReconAugmentedProposer

        cfg = LlmProviderConfig(
            provider="claude-cli",
            model=None,
            api_key=None,
            base_url="/usr/local/bin/claude",
        )
        proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, ReconAugmentedProposer)
        assert isinstance(proposer._inner, ClaudeCliProposer)

    def test_claude_cli_provider_default_binary_when_no_base_url(self) -> None:
        from modus.proposer import ClaudeCliProposer

        cfg = LlmProviderConfig(
            provider="claude-cli",
            model=None,
            api_key=None,
            base_url=None,
        )
        # Use recon_floor=False here so we can reach the inner ClaudeCliProposer
        # directly and verify the binary-resolution behavior — that's the
        # specific concern this test guards.
        proposer = make_proposer(llm=cfg, scope=_scope(), recon_floor=False)
        assert isinstance(proposer, ClaudeCliProposer)
        # Default binary name "claude" (relies on PATH at run time).
        assert proposer._claude_bin == "claude"  # type: ignore[attr-defined]


# ------------------------------------------------------------ FixedProposer


class TestFixedProposer:
    async def test_returns_pre_loaded_actions_capped_at_sample_count(self) -> None:
        actions: list[Action] = [
            Probe(target="a.example.com"),
            Probe(target="b.example.com"),
            Request(target="c.example.com", method="GET", path="/"),
        ]
        proposer: Proposer = FixedProposer(actions)
        out = await proposer.propose(_step_context(sample_count=2))
        assert len(out) == 2
