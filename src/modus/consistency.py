"""Z3-backed consistency layer.

The proposer samples ``N`` candidate actions per step. This module
turns each candidate into a set of Z3 constraints over the current
:class:`CorpusState`, asks the solver whether the constraints are
satisfiable, and returns a :class:`Verdict`. Proposals whose
preconditions are not entailed are rejected before any execution.

The Z3 use here is honest but light at v0.1: most preconditions are
membership checks that don't strictly need a solver. The
architectural commitment is to the solver being the layer that
gates execution, so we use it from the start; non-trivial
preconditions (transitive closure for plan-then-verify, mutually
exclusive state across competing hypotheses) plug in without
reshaping the layer.

ADR 0002 is the load-bearing document for this module's shape:
the public surface is :meth:`ConsistencyChecker.prune`, which takes
``N`` proposals and returns the survivors. The single-action
:meth:`ConsistencyChecker.check` is a convenience for tests and the
``modus action validate`` CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from modus.actions import (
    Action,
    Annotate,
    Compare,
    Differential,
    Hypothesize,
    Probe,
    Request,
    Tool,
)

if TYPE_CHECKING:
    from modus.scope import AllowedEndpoint


@dataclass(frozen=True)
class CorpusState:
    """The slice of corpus state the consistency layer reasons over.

    A :class:`CorpusState` is built by reading from the Quarry MCP
    surface (``status``, ``list_assets``, ``search``) at the start
    of each agent step, plus the session's static scope policy
    (operator-approved hostnames and HTTP methods).

    The state is intentionally narrow. We don't pull the entire
    corpus through the consistency layer — only the predicates the
    action vocabulary's preconditions actually reference.
    """

    in_scope_assets: frozenset[str] = field(default_factory=frozenset)
    allowed_endpoints: tuple[AllowedEndpoint, ...] = ()
    """Parsed scope entries — used to gate ``Request`` actions on the
    full ``(host, port, tls)`` triple, not just the hostname. Empty
    tuple means "no endpoint constraint beyond ``in_scope_assets`` host
    membership", which is the default for tests and the
    ``modus action validate`` CLI flow."""
    allowed_methods: frozenset[str] = field(default_factory=frozenset)
    known_observations: frozenset[str] = field(default_factory=frozenset)
    """All observation IDs visible to this session (process-lifetime
    pool on the ``ServerSession``). The looser
    ``evidence_known:<ref>`` precondition on ``Hypothesize`` checks
    against this set — the verified-action surface uses this path."""
    known_evidence: frozenset[str] = field(default_factory=frozenset)
    known_referents: frozenset[str] = field(default_factory=frozenset)
    session_observations: frozenset[str] | None = None
    """Observation IDs produced *in the current autonomous run*, or
    ``None`` for non-autonomous code paths.

    Three-state semantics:

      * ``None`` (default) — non-autonomous mode. The verified-action
        surface and the ``modus action validate`` CLI flow leave this
        unset, and the looser ``evidence_known:<ref>`` precondition
        applies (citing any ``known_observation`` /
        ``known_evidence`` is fine).
      * ``frozenset()`` — autonomous mode, no observations produced
        this run yet. ``Hypothesize.evidence_refs`` *must* be empty;
        any cited observation is a bleed from a prior run.
      * ``frozenset({...})`` — autonomous mode mid-run. Citations
        must be a subset of this set; observations from the broader
        ``known_observations`` pool that aren't here are bleed.

    Populated by :meth:`AgentLoop._step_context`."""

    @classmethod
    def empty(cls) -> CorpusState:
        return cls()


@dataclass(frozen=True)
class Verdict:
    """Outcome of a consistency check on a single proposed action."""

    accepted: bool
    rationale: str
    failed_preconditions: tuple[str, ...] = ()


# A single precondition: a label and the boolean value it carries
# *given the corpus state*. The Z3 layer asserts each label as a
# tracked atom whose truth is the boolean we provide; the unsat
# core (when the assertion fails) gives us the failed labels back
# for the rationale string.
_Precondition = tuple[str, bool]


class ConsistencyChecker:
    """Verifier over proposed actions.

    Methods:
      * :meth:`check` — verdict on a single proposal.
      * :meth:`prune` — verdict on a batch of proposals (the
        propose-prune-rank-execute step's pruning stage).
    """

    def check(self, action: Action, state: CorpusState) -> Verdict:
        preconds = _preconditions(action, state)

        # Encode each precondition as a Z3 Bool whose truth is the
        # actual boolean value computed from the state. Track each
        # by name so that on UNSAT we recover the failing names.
        solver = z3.Solver()
        for name, value in preconds:
            atom = z3.Bool(name)
            solver.add(atom == z3.BoolVal(value))
            solver.assert_and_track(atom, name)

        result = solver.check()
        if result == z3.sat:
            return Verdict(accepted=True, rationale="all preconditions satisfied")

        core = solver.unsat_core()
        names = tuple(str(item) for item in core)
        return Verdict(
            accepted=False,
            rationale="failed preconditions: " + ", ".join(names),
            failed_preconditions=names,
        )

    def prune(self, actions: list[Action], state: CorpusState) -> list[tuple[Action, Verdict]]:
        """Return one verdict per proposed action.

        Survivors are those whose verdict is ``accepted``. The
        caller (the proposer's ranking stage) decides what to do
        with rejected proposals — typically logged and discarded.
        """
        return [(action, self.check(action, state)) for action in actions]


def _preconditions(action: Action, state: CorpusState) -> list[_Precondition]:
    """Walk an :class:`Action` and return its named preconditions.

    The set of preconditions per action type is pinned by the docstring
    on each variant in :mod:`modus.actions`. Any change here must be
    reflected there.
    """
    if isinstance(action, Probe):
        return [
            (f"target_in_scope:{action.target}", action.target in state.in_scope_assets),
        ]

    if isinstance(action, Request):
        # Two checks: hostname-only membership (for back-compat with
        # scopes that don't specify port/tls) AND full-endpoint
        # membership (when allowed_endpoints is populated, which
        # tightens scope down to specific scheme+port combinations).
        # Tests and CLI flows that don't populate allowed_endpoints
        # see only the hostname check, matching the original
        # behaviour.
        scheme = "https" if action.tls else "http"
        port_part = f":{action.port}" if action.port is not None else ""
        endpoint_label = f"endpoint_in_scope:{scheme}://{action.target}{port_part}"
        endpoint_ok = (
            any(
                ep.matches(action.target, action.port, action.tls) for ep in state.allowed_endpoints
            )
            if state.allowed_endpoints
            else action.target in state.in_scope_assets
        )
        return [
            (endpoint_label, endpoint_ok),
            (f"method_allowed:{action.method}", action.method in state.allowed_methods),
        ]

    if isinstance(action, Compare):
        return [
            (
                f"observation_a_known:{action.observation_a}",
                action.observation_a in state.known_observations,
            ),
            (
                f"observation_b_known:{action.observation_b}",
                action.observation_b in state.known_observations,
            ),
            (
                "observations_distinct",
                action.observation_a != action.observation_b,
            ),
        ]

    if isinstance(action, Differential):
        out: list[_Precondition] = []
        for ref in action.observations:
            out.append((f"observation_known:{ref}", ref in state.known_observations))
        out.append(
            (
                "observations_distinct",
                len(set(action.observations)) == len(action.observations),
            )
        )
        return out

    if isinstance(action, Annotate):
        return [
            (
                f"referent_known:{action.referent}",
                (
                    action.referent in state.known_referents
                    or action.referent in state.in_scope_assets
                    or action.referent in state.known_observations
                    or action.referent in state.known_evidence
                ),
            ),
        ]

    if isinstance(action, Hypothesize):
        # Two paths:
        #   * Autonomous-run path: ``session_observations`` is a
        #     ``frozenset`` (possibly empty) set by
        #     ``AgentLoop._step_context``. Hypothesize must cite
        #     only observations from this run — prevents prior-run
        #     bleed where the proposer picks an obs_id from
        #     ``known_observations`` that wasn't evidenced in the
        #     current run. An empty per-run pool means *no*
        #     citations are valid; the agent must produce evidence
        #     before hypothesizing.
        #   * Verified-action / CLI path: ``session_observations``
        #     is ``None`` (default). The looser ``evidence_known``
        #     check applies — the operator drives manually and is
        #     presumed to know what they're citing.
        if state.session_observations is not None:
            return [
                (
                    f"evidence_in_session:{ref}",
                    ref in state.session_observations,
                )
                for ref in action.evidence_refs
            ]
        return [
            (
                f"evidence_known:{ref}",
                ref in state.known_evidence or ref in state.known_observations,
            )
            for ref in action.evidence_refs
        ]

    if isinstance(action, Tool):
        # Placeholder: the registry-driven per-tool preconditions
        # land in #9. Until then, ``Tool`` actions are gated only
        # on a single placeholder precondition that's always False
        # — the action validates via Pydantic but the consistency
        # layer rejects every Tool emission so the agent loop can't
        # accidentally execute one before #8/#9 are wired. This
        # ships with the action grammar (#6) so the discriminated
        # union is complete; the real dispatch comes next.
        return [("tool_dispatch_not_yet_implemented", False)]

    raise TypeError(f"unhandled action type: {type(action).__name__}")


__all__ = ["ConsistencyChecker", "CorpusState", "Verdict"]
