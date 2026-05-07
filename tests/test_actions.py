"""Tests for the typed action vocabulary."""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from modus.actions import (
    Action,
    Annotate,
    Compare,
    Differential,
    Hypothesize,
    Probe,
    Request,
)

ACTION_ADAPTER: TypeAdapter[Action] = TypeAdapter(Action)


class TestProbe:
    def test_minimal_valid(self) -> None:
        action = Probe(target="example.com")
        assert action.kind == "probe"
        assert action.aspect == "httpx"

    def test_aspect_must_be_known(self) -> None:
        with pytest.raises(ValidationError):
            Probe(target="example.com", aspect="bogus")  # type: ignore[arg-type]

    def test_target_required(self) -> None:
        with pytest.raises(ValidationError):
            Probe()  # type: ignore[call-arg]


class TestRequest:
    def test_minimal_valid(self) -> None:
        action = Request(target="example.com", method="GET", path="/")
        assert action.method == "GET"

    def test_path_must_start_with_slash(self) -> None:
        with pytest.raises(ValidationError):
            Request(target="example.com", method="GET", path="api/v1")

    def test_method_must_be_known(self) -> None:
        with pytest.raises(ValidationError):
            Request(target="example.com", method="FOO", path="/")  # type: ignore[arg-type]

    def test_port_and_tls_defaults(self) -> None:
        action = Request(target="example.com", method="GET", path="/")
        assert action.port is None
        assert action.tls is True

    def test_port_must_be_in_valid_range(self) -> None:
        with pytest.raises(ValidationError):
            Request(target="example.com", method="GET", path="/", port=0)
        with pytest.raises(ValidationError):
            Request(target="example.com", method="GET", path="/", port=70000)

    def test_plaintext_http_with_port(self) -> None:
        action = Request(target="localhost", method="GET", path="/", port=13000, tls=False)
        assert action.port == 13000
        assert action.tls is False


class TestCompare:
    def test_minimal_valid(self) -> None:
        action = Compare(
            observation_a="obs-1",
            observation_b="obs-2",
            dimensions=("status", "headers"),
        )
        assert action.dimensions == ("status", "headers")

    def test_dimensions_must_be_unique(self) -> None:
        with pytest.raises(ValidationError):
            Compare(
                observation_a="obs-1",
                observation_b="obs-2",
                dimensions=("status", "status"),
            )

    def test_dimensions_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            Compare(observation_a="obs-1", observation_b="obs-2", dimensions=())


class TestDifferential:
    def test_minimal_valid(self) -> None:
        action = Differential(
            observations=("obs-1", "obs-2"),
            dimension="identity",
            bug_class="idor",
        )
        assert action.bug_class == "idor"

    def test_requires_at_least_two_observations(self) -> None:
        with pytest.raises(ValidationError):
            Differential(
                observations=("obs-1",),
                dimension="identity",
                bug_class="idor",
            )

    def test_dimension_must_be_known(self) -> None:
        with pytest.raises(ValidationError):
            Differential(
                observations=("obs-1", "obs-2"),
                dimension="weather",  # type: ignore[arg-type]
                bug_class="idor",
            )


class TestAnnotate:
    def test_minimal_valid(self) -> None:
        action = Annotate(referent="ref-1", note="something")
        assert action.note == "something"

    def test_note_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            Annotate(referent="ref-1", note="")


class TestHypothesize:
    def test_minimal_valid(self) -> None:
        action = Hypothesize(
            bug_class="idor",
            evidence_refs=("obs-1",),
            rationale="200 with another tenant's data",
        )
        assert action.severity_hint == "info"

    def test_evidence_refs_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            Hypothesize(
                bug_class="idor",
                evidence_refs=(),
                rationale="anything",
            )

    def test_rationale_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            Hypothesize(
                bug_class="idor",
                evidence_refs=("obs-1",),
                rationale="",
            )


class TestDiscriminatedUnion:
    def test_dispatches_on_kind(self) -> None:
        action = ACTION_ADAPTER.validate_python({"kind": "probe", "target": "example.com"})
        assert isinstance(action, Probe)

    def test_unknown_kind_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ACTION_ADAPTER.validate_python({"kind": "shell", "command": "id"})

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ACTION_ADAPTER.validate_python(
                {"kind": "probe", "target": "example.com", "rogue": "field"}
            )

    def test_round_trip(self) -> None:
        original = Probe(target="example.com")
        dumped = original.model_dump_json()
        restored = ACTION_ADAPTER.validate_json(dumped)
        assert restored == original

    def test_actions_are_frozen(self) -> None:
        action = Probe(target="example.com")
        with pytest.raises(ValidationError):
            action.target = "other.example.com"  # type: ignore[misc]
