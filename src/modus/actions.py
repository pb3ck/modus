"""Typed action vocabulary.

Each :class:`Action` is a Pydantic model with a ``kind`` discriminator
field. The :data:`Action` alias is the discriminated union over every
action type Modus knows about; the LLM proposer emits values of this
type via provider-native structured output, so the proposer's output
is grammatical against this module by construction.

The preconditions for each action live alongside the action type.
:mod:`modus.consistency` walks an :class:`Action` and asks each
variant for its preconditions, then encodes them as Z3 constraints
against the current corpus state.

This module is the canonical reference for the action grammar. ADR
0001 commits to "actions are typed"; ADR 0002 commits to "the
proposer samples ``N`` candidate actions and the consistency layer
prunes them." Both depend on this file being the single source of
truth.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# A reference to a corpus row. Quarry uses UUIDv7 strings; Modus
# treats them as opaque tokens.
CorpusRef = Annotated[str, Field(min_length=1, max_length=64)]

# An asset — typically a hostname. Modus does not validate the
# hostname format here; that's the scope policy's job. We do reject
# the obviously bad shapes.
Asset = Annotated[str, Field(min_length=1, max_length=255)]


class _ActionBase(BaseModel):
    """Shared configuration for every action variant.

    The ``model_config`` settings make every action immutable
    (frozen) so the same proposed action can be safely shared
    between the consistency check and the executor without any
    risk of one mutating it under the other.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class Probe(_ActionBase):
    """Passive observation of a target asset.

    A ``Probe`` reads what the corpus already knows about the
    target — the most recent httpx record, the current jsbundle
    catalogue, the endpoint list. It does not generate network
    traffic of its own; that's :class:`Request`.

    Preconditions:
      * ``target`` is in scope.
    """

    kind: Literal["probe"] = "probe"
    target: Asset
    aspect: Literal["httpx", "jsbundle", "endpoints", "tech"] = "httpx"


class Request(_ActionBase):
    """Active HTTP request to a target asset.

    Generates one HTTP request and persists the resulting
    request/response pair as an observation. Method must be in
    the operator-approved set for the session; the consistency
    layer enforces this.

    The default transport is HTTPS on the standard port. For
    local labs / non-standard ports, set ``port`` and/or
    ``tls=False``: ``Request(target='localhost', port=13000,
    tls=False, method='GET', path='/')`` produces
    ``http://localhost:13000/``.

    Preconditions:
      * ``target`` is in scope.
      * ``method`` is in the session's allowed-methods set.
    """

    kind: Literal["request"] = "request"
    target: Asset
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    path: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    tls: bool = True

    @field_validator("path")
    @classmethod
    def _path_starts_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        return value


class Compare(_ActionBase):
    """Structural diff between two existing observations.

    Surfaces what changed between two observations of the same
    asset (or across two different assets, depending on the
    dimensions). Produces a comparison row in the corpus.

    Preconditions:
      * ``observation_a`` and ``observation_b`` are both in the
        corpus.
      * The two observations are distinct.
    """

    kind: Literal["compare"] = "compare"
    observation_a: CorpusRef
    observation_b: CorpusRef
    dimensions: tuple[str, ...] = Field(min_length=1, max_length=16)

    @field_validator("dimensions")
    @classmethod
    def _dimensions_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("dimensions must be unique")
        return value


class Differential(_ActionBase):
    """Differential test across observations along a single dimension.

    The bug-class oracle for IDOR / auth-bypass / SQLi shapes:

    * **Identity-class oracles** (``dimension`` in ``identity / auth /
      role / tenant``) — same path, different caller; same response
      shape ⇒ access-control bypass. Drives ``idor / auth_bypass /
      tenant_isolation`` candidates.

    * **Payload-class oracles** (``dimension="payload"``) — same path
      and caller, different query/body payload; differing response
      shape OR timing ⇒ the input reaches a sink. Drives ``sqli``
      candidates via time-based oracle (one observation with
      ``SLEEP(5)`` measurably slower than baseline) or
      content-based oracle (UNION SELECT shifts the response). The
      2026-05-10 CVE-2022-25148 calibration run caught the gap:
      the LLM tried to construct a SQLi differential and the
      ``bug_class`` literal rejected it.

    Preconditions:
      * Every observation in ``observations`` exists in the corpus.
      * At least two observations are provided.
    """

    kind: Literal["differential"] = "differential"
    observations: tuple[CorpusRef, ...] = Field(min_length=2, max_length=8)
    dimension: Literal["identity", "auth", "role", "tenant", "payload"]
    bug_class: Literal["idor", "auth_bypass", "tenant_isolation", "sqli"]


class Annotate(_ActionBase):
    """Attach an operator-visible note to a corpus row.

    Notes are FTS-indexed and surface in subsequent searches. The
    referent can be a Target, an Asset, an Evidence row, or an
    observation — anything Quarry already models.

    Preconditions:
      * ``referent`` exists in the corpus.
      * ``note`` is non-empty.
    """

    kind: Literal["annotate"] = "annotate"
    referent: CorpusRef
    note: str = Field(min_length=1, max_length=8192)


_TOOL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


class Tool(_ActionBase):
    """Invoke a registered tool by name with structured arguments.

    The agent's open-ended dispatch primitive. Where the typed-action
    variants (:class:`Probe`, :class:`Request`, ...) hard-code one
    specific operation per class, ``Tool`` lets the proposer reach
    anything the operator has registered: shell tools (``amass``,
    ``nuclei``, ``ffuf``), MCP-passthrough tools exposed by the host,
    or built-in fast-paths registered as the same registry's first-
    party entries. The registry is the trust boundary; the
    consistency layer dispatches preconditions by ``name`` lookup.

    Preconditions (evaluated by the consistency layer in v0.3+ via
    ``ToolSpec.preconditions`` from the registry):
      * ``name`` is registered.
      * Per-tool args satisfy that tool's declared scope constraints.

    This action is the structural step that makes Modus an
    open-vocabulary agent rather than a closed-grammar one. ADR-0004
    documents the pivot.
    """

    kind: Literal["tool"] = "tool"
    name: str = Field(min_length=1, max_length=128)
    """Registry name. Lowercase identifier, optionally
    ``.``-namespaced (``amass.enum``, ``nuclei.scan``,
    ``corpus.search``). Validated against
    ``^[a-z][a-z0-9_.-]*$`` so registry lookups never collide
    with shell metacharacters or path separators."""
    args: dict[str, Any] = Field(default_factory=dict)
    """Free-form structured arguments. Each tool's ``ToolSpec``
    declares its own JSON Schema; the consistency layer validates
    ``args`` against that schema and runs the tool's
    preconditions function. This field is permissive at the
    grammar level by design — closing it would re-introduce the
    closed-vocabulary problem this primitive was built to solve."""

    @field_validator("name")
    @classmethod
    def _name_lowercase_dotted(cls, value: str) -> str:
        if not _TOOL_NAME_PATTERN.fullmatch(value):
            raise ValueError(
                "tool name must match ^[a-z][a-z0-9_.-]*$ — "
                "lowercase, starts with a letter, may contain "
                "digits, dots, underscores, hyphens"
            )
        return value


class Hypothesize(_ActionBase):
    """Propose a Candidate of a given bug class.

    The terminal action — every successful Modus session ends with
    one or more ``Hypothesize`` actions. The Candidate row that
    results is what the operator promotes (or doesn't) via Quarry's
    own ``quarry finding promote`` lifecycle. Modus has no
    ``Promote`` action and never will.

    Preconditions:
      * Every entry in ``evidence_refs`` exists in the corpus.
      * ``rationale`` is non-empty.
    """

    kind: Literal["hypothesize"] = "hypothesize"
    bug_class: str = Field(min_length=1, max_length=64)
    evidence_refs: tuple[CorpusRef, ...] = Field(min_length=1, max_length=32)
    rationale: str = Field(min_length=1, max_length=4096)
    severity_hint: Literal["info", "low", "medium", "high", "critical"] = "info"


# The discriminated union. Pydantic dispatches on the ``kind`` field;
# adding a new action type means adding it to this union and
# extending :mod:`modus.consistency`.
Action = Annotated[
    Probe | Request | Compare | Differential | Annotate | Hypothesize | Tool,
    Field(discriminator="kind"),
]


__all__ = [
    "Action",
    "Annotate",
    "Asset",
    "Compare",
    "CorpusRef",
    "Differential",
    "Hypothesize",
    "Probe",
    "Request",
    "Tool",
]
