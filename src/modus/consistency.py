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
    known_evidence: frozenset[str] = field(default_factory=frozenset)
    known_referents: frozenset[str] = field(default_factory=frozenset)

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
        return [
            (
                f"evidence_known:{ref}",
                ref in state.known_evidence or ref in state.known_observations,
            )
            for ref in action.evidence_refs
        ]

    raise TypeError(f"unhandled action type: {type(action).__name__}")


__all__ = ["ConsistencyChecker", "CorpusState", "Verdict"]
