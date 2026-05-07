"""Tests for the LLM proposer.

Provider implementations are tested through duck-typed fake clients
so the test suite doesn't need API keys or network. The shared
:class:`_LlmProposerBase` logic — prompt building, response parsing,
graceful failure on malformed model output — is exercised here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

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


# ------------------------------------------------------------ parser


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
    def test_anthropic_provider(self) -> None:
        cfg = LlmProviderConfig(provider="anthropic", model=None, api_key="sk-test", base_url=None)
        # Don't actually instantiate the upstream client — just verify dispatch.
        # Use a sentinel client to bypass network init.
        from unittest.mock import patch

        with patch("modus.proposer.AsyncAnthropic"):
            proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, AnthropicProposer)

    def test_openai_provider(self) -> None:
        cfg = LlmProviderConfig(provider="openai", model=None, api_key="sk-test", base_url=None)
        from unittest.mock import patch

        with patch("modus.proposer.AsyncOpenAI"):
            proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, OpenAICompatibleProposer)

    def test_openai_compatible_provider(self) -> None:
        cfg = LlmProviderConfig(
            provider="openai-compatible",
            model="llama3",
            api_key=None,
            base_url="http://localhost:11434/v1",
        )
        from unittest.mock import patch

        with patch("modus.proposer.AsyncOpenAI"):
            proposer = make_proposer(llm=cfg, scope=_scope())
        assert isinstance(proposer, OpenAICompatibleProposer)

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
        from modus.proposer import HostSamplingProposer

        cfg = LlmProviderConfig(provider="host", model=None, api_key=None, base_url=None)

        class _FakeMcpSession:
            async def create_message(self, **_: Any) -> Any: ...

        proposer = make_proposer(llm=cfg, scope=_scope(), mcp_session=_FakeMcpSession())
        assert isinstance(proposer, HostSamplingProposer)


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
