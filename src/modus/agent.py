"""Autonomous agent loop.

The propose-prune-rank-execute step from ADR 0002, run inside a
single MCP tool handler per ADR 0003. The host calls Modus's
``run_autonomous_session`` tool with a target name, a list of bug
classes, and an optional budget; the loop runs until the budget is
exhausted or three consecutive empty pruning rounds happen, then
returns the accumulated audit record.

The loop's collaborators are dependency-injected:

* :class:`Proposer` — emits N candidate actions per step.
* :class:`ConsistencyChecker` — Z3-prunes the batch.
* ``execute_action`` callable — runs a single action and returns
  its result. The Modus server passes its own ``_execute_action``
  method here, so the autonomous loop and the per-step verified
  surface share one executor implementation.
* :class:`ServerSession` — the working corpus state, the
  in-memory observation/Candidate pool.

The loop's *value heuristic* is intentionally simple at v0.1:
"first survivor wins." The ranking shape is in place; the heuristic
is a research target for v0.2+.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from modus.actions import Hypothesize, Tool
from modus.evidence_patterns import detect_evidence_patterns
from modus.proposer import StepContext

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from modus.actions import Action
    from modus.consistency import ConsistencyChecker, Verdict
    from modus.proposer import Proposer
    from modus.session import ServerSession, SessionObservation


_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Budget:
    """Hard limits on what an autonomous session may consume."""

    max_steps: int = 50
    max_wall_seconds: float = 1800.0  # 30 minutes
    max_consecutive_empty_steps: int = 3


@dataclass
class StepRecord:
    """Audit row for one step of the loop.

    Every sampled proposal and every Z3 verdict is captured here.
    The session's :class:`SessionRecord` is what the autonomous-
    session tool returns to the host so the audit surface is
    queryable from the host's conversation transcript.
    """

    step_index: int
    started_at: datetime
    proposals: tuple[Action, ...]
    verdicts: tuple[Verdict, ...]
    executed: tuple[Action, ...] = field(default_factory=tuple)
    execution_results: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    finished_at: datetime | None = None


@dataclass
class SessionRecord:
    """Audit record for one whole agent session."""

    target_name: str
    bug_classes: tuple[str, ...]
    started_at: datetime
    steps: list[StepRecord] = field(default_factory=list)
    finished_at: datetime | None = None
    termination_reason: str | None = None
    corpus_seeded_observation_count: int = 0
    """Number of observations the loop materialised from Quarry's
    corpus at run start (via ``list_response_artifacts``). Distinct
    from the operator-supplied ``initial_observation_ids`` count
    and the ``recon_jsonl_path`` count — this counts only the
    auto-load path. Zero when ``seed_from_corpus=False``, when
    Quarry is unreachable, or when the corpus has no
    responses-shape evidence for the target."""

    def to_payload(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict for an MCP tool result."""
        return {
            "target_name": self.target_name,
            "bug_classes": list(self.bug_classes),
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at.isoformat() if self.finished_at else None),
            "termination_reason": self.termination_reason,
            "step_count": len(self.steps),
            "executed_count": sum(len(s.executed) for s in self.steps),
            "corpus_seeded_observation_count": self.corpus_seeded_observation_count,
            "steps": [
                {
                    "step_index": s.step_index,
                    "started_at": s.started_at.isoformat(),
                    "finished_at": (s.finished_at.isoformat() if s.finished_at else None),
                    "proposal_count": len(s.proposals),
                    "rejected_count": sum(1 for v in s.verdicts if not v.accepted),
                    "executed": [a.model_dump() for a in s.executed],
                    "execution_results": list(s.execution_results),
                }
                for s in self.steps
            ],
        }


@dataclass
class AgentLoop:
    """Autonomous propose-prune-rank-execute loop.

    Use as a one-shot: construct, ``await loop.run(...)``, read the
    returned :class:`SessionRecord`. The loop is stateless across
    invocations — call it again to start a fresh session.
    """

    proposer: Proposer
    checker: ConsistencyChecker
    session: ServerSession
    execute_action: Callable[[Action], Awaitable[dict[str, Any]]]
    budget: Budget = field(default_factory=Budget)

    async def run(
        self,
        *,
        target_name: str,
        bug_classes: list[str],
        objective: str | None = None,
        record: SessionRecord | None = None,
        initial_observation_ids: frozenset[str] = frozenset(),
        seed_from_corpus: bool = True,
    ) -> SessionRecord:
        """Run the loop end-to-end and return the session record.

        ``objective`` is an optional natural-language framing the
        proposer can use to bias its sampling — typically the
        bug-class focus expressed as a sentence ("find IDOR on the
        ``demo`` target's user-scoped endpoints").

        ``record`` lets the caller pre-build the
        :class:`SessionRecord` and hold a reference to it before
        the loop starts. The loop mutates that same instance in
        place: ``record.steps`` grows, ``record.termination_reason``
        and ``record.finished_at`` are written when the loop exits.
        Used by ``start_autonomous_session`` to expose the
        in-progress run to ``poll_autonomous_session`` while the
        loop is still executing as a background task. When omitted
        (the synchronous path), the loop builds its own record.

        ``initial_observation_ids`` seeds the run's evidence pool
        with operator-provided observation ids — typically the ids
        of session observations the operator preloaded from prior
        recon (httpx, katana, manual probes ingested into Quarry as
        a ``responses`` source). The autonomous loop's ``Hypothesize``
        precondition gates evidence_refs to "this run's pool only"
        to prevent cross-run bleed between sequential autonomous
        sessions; treating operator recon as part of *this* run's
        starting state keeps the firewall meaningful while letting
        the agent cite the recon data the operator did up front.
        Empty by default (the agent reasons only over what it
        observes itself this run).

        ``seed_from_corpus`` (default ``True``) auto-loads
        responses-shape evidence for ``target_name`` from Quarry
        via the ``list_response_artifacts`` MCP read tool and
        materialises each artifact into a SessionObservation
        before the main loop starts. Operator-friendly default —
        if the operator already ingested recon into Quarry, the
        agent uses it without any explicit args. Older Quarry
        versions that don't expose ``list_response_artifacts``
        surface as a soft warning logged at INFO; the loop
        proceeds with whatever pool the caller provided. Set to
        ``False`` to opt out (cold-start runs, regression tests).
        """
        if record is None:
            record = SessionRecord(
                target_name=target_name,
                bug_classes=tuple(bug_classes),
                started_at=_utcnow(),
            )
        objective_text = objective or self._default_objective(target_name, bug_classes)
        # Auto-load from Quarry corpus, if enabled. Materialised
        # observations get added to ``session.observations`` and
        # their ids fold into ``initial_observation_ids`` so the
        # run pool starts with both the explicit caller-provided
        # ids and the corpus-sourced ones.
        if seed_from_corpus:
            corpus_seeded = await self._seed_from_corpus(target_name)
            record.corpus_seeded_observation_count = len(corpus_seeded)
            initial_observation_ids = frozenset(initial_observation_ids | corpus_seeded)
        empty_streak = 0
        wall_started = time.monotonic()
        # Cumulative one-line summaries of executed actions and their
        # results, fed back to the proposer each step so it doesn't
        # re-propose actions that already ran. Capped at the most
        # recent ``HISTORY_TAIL`` entries to keep the prompt bounded.
        history: list[str] = []
        # Observation IDs produced *in this run*. The Hypothesize
        # consistency precondition gates evidence_refs to this set
        # so the proposer can't cite observations bleeding in from
        # prior ``run_autonomous_session`` calls that share the
        # same ``ServerSession`` instance. Populated as the loop
        # executes actions; passed into each step's CorpusState via
        # ``_step_context``.
        run_observations: set[str] = set(initial_observation_ids)
        # Quarry Candidate IDs produced by ``hypothesize`` actions
        # this run. Feeds CorpusState.run_candidates so the
        # ``corpus.promote_finding`` precondition can gate promotion
        # on "this run's candidates only" — cross-run promotion is
        # the operator's CLI verb, not the agent's.
        run_candidates: set[str] = set()
        # Step indices at which a hypothesize executed. Drives the
        # fallback proposer's "give the LLM room first" gate.
        hypothesize_steps_so_far: list[int] = []
        # Dedup keys for synthesized fallback hypotheses already
        # offered. Each ``(bug_class, sorted-evidence-refs)`` tuple
        # only fires once per run — re-emitting the same fallback
        # would just be re-rejected as a duplicate downstream.
        synthesized_keys: set[str] = set()
        # ``(bug_class, observation_id)`` pairs that have been covered
        # by ANY hypothesize action this run — both LLM-emitted and
        # fallback-emitted. The fallback proposer suppresses a candidate
        # whose evidence_refs are *fully* covered (every ref already in
        # this set for the same bug_class), preventing duplicate
        # candidates that name the same observation. The 2026-05-09
        # wp-lab calibration baseline caught the gap: the LLM hypothesized
        # ``info_disclosure`` on ``[user-enum-obs, readme-obs]`` and the
        # fallback then re-fired ``info_disclosure`` on ``[user-enum-obs]``.
        # Different ``synthesized_keys`` strings, both passed dedup, the
        # operator got a duplicate candidate to triage. Tracking
        # (bug_class, ref) pairs across LLM+fallback closes the gap.
        hypothesized_pairs: set[tuple[str, str]] = set()
        # ``(candidate_id, severity_hint)`` of hypothesizes whose
        # severity meets the auto-promotion threshold (medium /
        # high / critical) and that have NOT yet been promoted via
        # ``corpus.promote_finding``. The fallback proposer emits
        # synthesized promote proposals against this queue when the
        # LLM doesn't follow the auto-promotion rule on its own.
        pending_promotions: list[tuple[str, str]] = []
        # Candidate ids the fallback has already synthesized a
        # promote proposal for — single-fire so we don't spam the
        # ranking layer with duplicates.
        synthesized_promotion_ids: set[str] = set()

        for step_index in range(self.budget.max_steps):
            if (time.monotonic() - wall_started) > self.budget.max_wall_seconds:
                record.termination_reason = "wall_time_exhausted"
                break

            step_started = _utcnow()
            context = self._step_context(
                objective_text,
                history=history,
                bug_classes=tuple(bug_classes),
                run_observations=frozenset(run_observations),
                run_candidates=frozenset(run_candidates),
            )

            # 1. Propose
            proposals = await self.proposer.propose(context)

            # 1b. Fallback proposals — deterministic pattern matches
            # against the run's observations. Only fires when the LLM
            # has been given enough room to commit on its own and
            # hasn't. Local mid-size models (qwen2.5-coder:14b,
            # phi4:14b, gemma2:9b) reliably hit a "decisiveness gap":
            # they explore competently but won't emit ``hypothesize``
            # even when their own action history contains textbook
            # evidence. The fallback closes that gap deterministically;
            # the LLM keeps primacy when it commits on its own.
            fallback = self._fallback_proposals(
                step_index=step_index,
                bug_classes=tuple(bug_classes),
                hypothesize_steps=hypothesize_steps_so_far,
                synthesized_keys=synthesized_keys,
                pending_promotions=pending_promotions,
                synthesized_promotion_ids=synthesized_promotion_ids,
                run_observation_ids=frozenset(run_observations),
                hypothesized_pairs=hypothesized_pairs,
            )
            # Prepend fallbacks so they win the "first novel survivor"
            # ranking when both fire — the fallback only emits when the
            # LLM has been given room and is still abdicating, so it's
            # the action the loop wants to take. The LLM's batch keeps
            # its own internal order; this just guarantees a synthesized
            # ``hypothesize`` or ``corpus.promote_finding`` that passes
            # Z3 isn't shadowed by an exploratory request the LLM
            # happened to emit first.
            proposals = list(fallback) + list(proposals)

            # 2. Prune
            verdicts = self.checker.prune(proposals, context.corpus_state)
            survivors = [(a, v) for a, v in verdicts if v.accepted]

            # 3. Rank — v0.1 heuristic: first novel survivor wins.
            #    Deduplicate against actions executed in the last
            #    ``DEDUP_TAIL`` steps so the agent doesn't re-run a
            #    failing action just because the proposer keeps
            #    putting it first.
            recently_executed = self._recent_action_keys(record.steps)
            chosen: Action | None = None
            for candidate, _ in survivors:
                if _action_dedup_key(candidate) not in recently_executed:
                    chosen = candidate
                    break
            all_duplicates = chosen is None and bool(survivors)
            if all_duplicates:
                # Every Z3-accepted survivor duplicates an action this
                # session already executed. Treat the step as empty
                # rather than re-running the duplicate — running it
                # again wastes budget and pollutes the corpus with a
                # near-identical observation row. The WARNING is
                # appended now (before the next step's _step_context
                # builds), so the proposer sees its stuckness in
                # recent_history on the very next iteration. If the
                # proposer keeps emitting only duplicates, the empty
                # pruning streak will terminate the loop.
                dup_keys = sorted({_action_dedup_key(c) for c, _ in survivors})
                sample = dup_keys[0]
                history.append(
                    f"step {step_index}: WARNING all {len(survivors)} Z3-accepted "
                    f"proposals duplicate actions executed earlier this session "
                    f"(e.g. `{sample}`). Step skipped — running the duplicate "
                    "again would waste budget. Try a different action kind, "
                    "path, parameter, or — if you have evidence — emit "
                    "`hypothesize` to close the loop."
                )

            # 4. Execute the top-K (K=1 at v0.1)
            executed: list[Action] = []
            execution_results: list[dict[str, Any]] = []
            if chosen is not None:
                try:
                    result = await self.execute_action(chosen)
                except Exception as exc:  # broad: don't kill the session on a tool error
                    _LOG.warning("execute_action raised: %s", exc)
                    result = {"error": f"executor raised: {exc}"}
                executed.append(chosen)
                execution_results.append(result)
                history.append(_summarise_step(step_index, chosen, result))
                # Track observation IDs produced this run so the
                # next step's Hypothesize precondition can gate
                # evidence_refs to "this run only" — see #4.
                obs_id = result.get("observation_id") or result.get("id")
                if isinstance(obs_id, str) and obs_id:
                    run_observations.add(obs_id)
                # Track Quarry Candidate IDs produced by hypothesize
                # actions this run so the next step's
                # corpus.promote_finding precondition can gate on
                # "this run's candidates only".
                cand_id = result.get("candidate_id")
                if isinstance(cand_id, str) and cand_id:
                    run_candidates.add(cand_id)
                # Note that a hypothesize executed — feeds the
                # fallback proposer's "did the LLM commit recently?"
                # gate so the fallback stays quiet when the LLM is
                # productively closing the loop on its own.
                if chosen.kind == "hypothesize":
                    hypothesize_steps_so_far.append(step_index)
                    # Track every (bug_class, evidence_ref) pair this
                    # candidate covers, so the fallback proposer
                    # suppresses overlapping hypotheses on the same
                    # observation. Both LLM and fallback hypotheses
                    # write here — the fallback's own check happens
                    # before this update, so the fallback can't
                    # accidentally suppress its own emissions.
                    for ref in getattr(chosen, "evidence_refs", ()):
                        hypothesized_pairs.add((chosen.bug_class, ref))
                    severity = result.get("severity_hint")
                    if (
                        isinstance(severity, str)
                        and severity in ("medium", "high", "critical")
                        and isinstance(cand_id, str)
                        and cand_id
                    ):
                        # Queue this candidate for auto-promotion. The
                        # fallback proposer will synthesize a
                        # ``corpus.promote_finding`` Tool proposal on a
                        # subsequent step if the LLM doesn't follow the
                        # auto-promotion rule itself.
                        pending_promotions.append((cand_id, severity))
                # When a Tool action invoked corpus.promote_finding,
                # remove the candidate from the pending queue so the
                # fallback doesn't re-emit a duplicate promote.
                if (
                    chosen.kind == "tool"
                    and getattr(chosen, "name", "") == "corpus.promote_finding"
                ):
                    cand_arg = (chosen.args or {}).get("candidate_id")
                    if isinstance(cand_arg, str):
                        pending_promotions[:] = [
                            (cid, sev) for cid, sev in pending_promotions if cid != cand_arg
                        ]
                empty_streak = 0
            else:
                if not all_duplicates:
                    # Distinct from the all-duplicates branch above:
                    # either Z3 rejected every survivor, or the
                    # proposer returned no actions at all. The
                    # all-duplicates branch already logged its own
                    # WARNING; don't double-log here.
                    history.append(
                        f"step {step_index}: all {len(proposals)} proposals rejected by Z3"
                    )
                empty_streak += 1

            step_record = StepRecord(
                step_index=step_index,
                started_at=step_started,
                proposals=tuple(proposals),
                verdicts=tuple(v for _, v in verdicts),
                executed=tuple(executed),
                execution_results=tuple(execution_results),
                finished_at=_utcnow(),
            )
            record.steps.append(step_record)

            if empty_streak >= self.budget.max_consecutive_empty_steps:
                record.termination_reason = "empty_pruning_streak"
                break

        if record.termination_reason is None:
            record.termination_reason = "step_budget_exhausted"
        record.finished_at = _utcnow()
        return record

    HISTORY_TAIL = 16  # how many recent steps to feed back to the proposer
    DEDUP_TAIL = 50  # how far back to look when deduplicating proposals
    # ^ DEDUP_TAIL is effectively "the whole session" at v0.1 budgets.
    # The proposer often re-emits the same URL after 8-10 steps even
    # though it failed earlier; full-session dedup makes the agent
    # spend budget on novel actions instead. If the agent legitimately
    # wants to retry an URL, it can vary the method, headers, or body.
    FALLBACK_AFTER_STEP = 5
    # ^ The fallback proposer stays quiet for the first N steps so
    # the LLM has room to commit ``hypothesize`` on its own. After
    # that, deterministic pattern matchers fire when the LLM keeps
    # abdicating despite evidence-shaped observations being in the
    # run's pool. Set deliberately conservative — the LLM proposer
    # is the primary path; the fallback is the safety net.
    FALLBACK_QUIET_AFTER_HYPOTHESIZE = 2
    # ^ When a hypothesize *did* execute recently (LLM-emitted or
    # fallback-emitted), the fallback stays quiet for this many
    # steps. Keeps the loop from spamming the same fallback over
    # and over once the loop is productively closing.

    async def _seed_from_corpus(self, target_name: str) -> frozenset[str]:
        """Auto-load responses-shape evidence from Quarry into the run pool.

        Calls Quarry's ``list_response_artifacts`` MCP read tool for
        ``target_name``, materialises each artifact into a
        :class:`SessionObservation` appended to ``session.observations``,
        and returns the set of observation ids the caller folds into
        ``initial_observation_ids``.

        Failure modes are non-fatal — the autonomous loop should still
        run if the corpus seeding doesn't work:

        * ``CorpusToolsMissingError`` (older Quarry) → logged at INFO,
          empty set returned. Operator gets a friendly upgrade hint
          via the warning.
        * ``CorpusToolError`` (target doesn't exist or other tool-
          surface error) → logged at WARNING, empty set returned.
        * ``CorpusUnavailableError`` (Quarry binary missing or stuck) →
          logged at WARNING, empty set returned. The loop's existing
          per-step ``with_quarry`` calls will surface the same error
          through their handlers, so the operator sees the failure
          without us having to re-raise here.
        """
        from modus.corpus import CorpusError
        from modus.session import SessionObservation

        try:
            async with self.session.with_quarry() as quarry:
                artifacts = await quarry.list_response_artifacts(target=target_name)
        except CorpusError as exc:
            _LOG.info(
                "seed_from_corpus skipped for target=%r: %s "
                "(autonomous run will rely on caller-provided "
                "initial_observation_ids and step-by-step observations)",
                target_name,
                exc,
            )
            return frozenset()
        except Exception as exc:  # broad: don't kill the run on unexpected errors
            _LOG.warning(
                "seed_from_corpus unexpectedly failed for target=%r: %s",
                target_name,
                exc,
            )
            return frozenset()

        seeded: set[str] = set()
        for art in artifacts:
            payload: dict[str, Any] = {
                "id": art.observation_id,
                "observation_id": art.observation_id,
                "url": art.url,
                "method": "GET",
                "status": art.status,
                "request_headers": {},
                "request_body": None,
                "response_headers": dict(art.response_headers),
                "response_body": art.response_body,
                "elapsed_ms": 0.0,
                "error": None,
                "redirect_chain": [],
                "ingested_at": art.ingested_at,
                "sha256": art.sha256,
            }
            self.session.observations.append(
                SessionObservation(id=art.observation_id, kind="request", payload=payload)
            )
            seeded.add(art.observation_id)
        if seeded:
            _LOG.info(
                "seed_from_corpus loaded %d responses-shape observations for target=%r",
                len(seeded),
                target_name,
            )
        return frozenset(seeded)

    def _fallback_proposals(
        self,
        *,
        step_index: int,
        bug_classes: tuple[str, ...],
        hypothesize_steps: list[int],
        synthesized_keys: set[str],
        pending_promotions: list[tuple[str, str]],
        synthesized_promotion_ids: set[str],
        run_observation_ids: frozenset[str],
        hypothesized_pairs: set[tuple[str, str]],
    ) -> list[Action]:
        """Synthesize fallback proposals when the LLM keeps abdicating.

        Two layers, both deterministic:

        1. **Hypothesize fallback** — pattern-match the run's
           observations against bug-class evidence templates; emit
           a :class:`Hypothesize` for each match the LLM hasn't
           committed itself. Activation gated by
           :attr:`FALLBACK_AFTER_STEP` and
           :attr:`FALLBACK_QUIET_AFTER_HYPOTHESIZE` so the LLM
           gets first crack.

        2. **Promote fallback** — for each pending candidate
           (severity ≥ medium, hypothesize executed, no promotion
           emitted yet), synthesize a
           ``Tool(name="corpus.promote_finding", args=...)`` to
           close the auto-promotion lifecycle the v0.4.0 policy
           describes. Required because the same commitment gap
           that suppresses ``hypothesize`` also suppresses the
           policy-mandated next-step promotion: the LLM lands a
           medium-severity Candidate and then keeps probing
           instead of emitting the promote.

        Both flow through the same Z3-prune-rank-execute pipeline
        as the LLM's proposals. Single-fire dedup on each path.
        """
        out: list[Action] = []

        # --- 2. Promote fallback (no step gate — fires
        # immediately after a qualifying hypothesize, since the
        # auto-promotion rule says "next step MUST promote")
        for cand_id, severity in pending_promotions:
            if cand_id in synthesized_promotion_ids:
                continue
            synthesized_promotion_ids.add(cand_id)
            try:
                promote_action = Tool(
                    name="corpus.promote_finding",
                    args={"candidate_id": cand_id, "severity": severity},
                )
            except Exception as exc:
                _LOG.warning(
                    "fallback promote rejected by Pydantic validation: %s",
                    exc,
                )
                continue
            _LOG.info(
                "fallback proposer emitting corpus.promote_finding for candidate=%s (severity=%s)",
                cand_id,
                severity,
            )
            out.append(promote_action)

        # --- 1. Hypothesize fallback
        if step_index < self.FALLBACK_AFTER_STEP:
            return out
        if hypothesize_steps:
            steps_since_last = step_index - hypothesize_steps[-1]
            if steps_since_last <= self.FALLBACK_QUIET_AFTER_HYPOTHESIZE:
                return out

        observations = self._this_run_observations(run_observation_ids)
        if not observations:
            return out
        matches = detect_evidence_patterns(observations, bug_classes)
        for m in matches:
            key = f"{m.bug_class}:{','.join(sorted(m.evidence_refs))}"
            if key in synthesized_keys:
                continue
            # Suppress when every observation this fallback would cite
            # is already in a prior hypothesize for the same bug_class.
            # Closes the dedup gap from the 2026-05-09 wp-lab baseline:
            # the LLM hypothesized info_disclosure on [obs-A, obs-B] and
            # the fallback then re-fired info_disclosure on [obs-A] with
            # a different ``synthesized_keys`` string. Now blocked.
            if all((m.bug_class, ref) in hypothesized_pairs for ref in m.evidence_refs):
                continue
            synthesized_keys.add(key)
            for ref in m.evidence_refs:
                hypothesized_pairs.add((m.bug_class, ref))
            try:
                action = Hypothesize(
                    bug_class=m.bug_class,
                    evidence_refs=m.evidence_refs,
                    rationale=m.rationale,
                    severity_hint=m.severity_hint,  # type: ignore[arg-type]
                )
            except Exception as exc:  # broad: validation
                _LOG.warning(
                    "fallback hypothesis rejected by Pydantic validation: %s (detector=%s)",
                    exc,
                    m.detector,
                )
                continue
            _LOG.info(
                "fallback proposer emitting hypothesize for %s "
                "(detector=%s, severity=%s, evidence_refs=%d)",
                m.bug_class,
                m.detector,
                m.severity_hint,
                len(m.evidence_refs),
            )
            out.append(action)
        return out

    def _this_run_observations(
        self, run_observation_ids: frozenset[str]
    ) -> list[SessionObservation]:
        """The session's observations whose ids are in the run pool.

        Filters ``self.session.observations`` (the process-lifetime
        pool, which accumulates across multiple
        ``run_autonomous_session`` calls within one Modus process
        and across calls to the verified-action surface) down to
        just the ones produced *this run*. The run pool is the
        set the loop builds up step-by-step plus any caller-
        supplied ``initial_observation_ids`` and corpus seeds.

        Pinned by the per-run observation isolation invariant from
        v0.1.0 issue #4 — Hypothesize is gated on
        ``state.session_observations`` (the per-run set) at the
        consistency layer; the fallback proposer's input must
        respect the same gate or it can synthesize Hypothesize
        actions citing prior-run observations the agent never
        produced. Surfaced 2026-05-08 by an Anduril/juice-shop
        engagement when a fallback Candidate cited an observation
        ID timestamped from a previous Modus session.
        """
        return [obs for obs in self.session.observations if obs.id in run_observation_ids]

    def _recent_action_keys(self, steps: list[StepRecord]) -> set[str]:
        """Set of dedup keys for actions executed in the last few steps.

        Used by the ranking step to skip survivors that are exact
        duplicates of recently-executed actions. Keeps the loop from
        stalling on a single proposal Claude keeps re-emitting.
        """
        keys: set[str] = set()
        for step in steps[-self.DEDUP_TAIL :]:
            for action in step.executed:
                keys.add(_action_dedup_key(action))
        return keys

    def _step_context(
        self,
        objective: str,
        *,
        history: list[str],
        bug_classes: tuple[str, ...] = (),
        run_observations: frozenset[str] | None = None,
        run_candidates: frozenset[str] = frozenset(),
    ) -> StepContext:
        from dataclasses import replace as _dc_replace

        # Wrap the session-wide corpus state with the per-run
        # observation subset, so the consistency layer's Hypothesize
        # precondition can gate evidence_refs to observations
        # produced this autonomous run only. ``None`` means
        # "non-autonomous code path" and falls back to the looser
        # check; the autonomous loop always passes a frozenset
        # (possibly empty), which selects the strict path.
        base_state = self.session.corpus_state()
        run_state = _dc_replace(
            base_state,
            session_observations=run_observations,
            run_candidates=run_candidates,
        )
        return StepContext(
            corpus_state=run_state,
            scope=self.session.scope,
            objective=objective,
            bug_classes=bug_classes,
            recent_history=tuple(history[-self.HISTORY_TAIL :]),
            sample_count=8,
        )

    @staticmethod
    def _default_objective(target_name: str, bug_classes: list[str]) -> str:
        classes = ", ".join(bug_classes) if bug_classes else "any in-scope bug class"
        return (
            f"Find vulnerabilities of class(es) [{classes}] on Quarry target "
            f"{target_name!r}. Use the verified-action vocabulary to gather "
            f"evidence and end with one or more `hypothesize` actions when "
            f"you have a defensible Candidate."
        )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _action_dedup_key(action: Action) -> str:
    """Stable key for "is this the same action I just ran?".

    Identity-only: ignores headers, body, and other request-shaping
    fields — two requests to the same URL are the same action even if
    the body differs slightly. This is intentionally aggressive on the
    deduplication side; the proposer has plenty of room to vary the
    URL itself when it wants something distinct.
    """
    if action.kind == "request":
        scheme = "https" if getattr(action, "tls", True) else "http"
        port = getattr(action, "port", None)
        port_part = f":{port}" if port is not None else ""
        target = getattr(action, "target", "")
        return f"request:{action.method}:{scheme}://{target}{port_part}{action.path}"
    if action.kind == "probe":
        return f"probe:{action.target}:{action.aspect}"
    if action.kind == "compare":
        a, b = sorted([action.observation_a, action.observation_b])
        return f"compare:{a}:{b}"
    if action.kind == "differential":
        return f"differential:{action.bug_class}:{action.dimension}:{','.join(sorted(action.observations))}"
    if action.kind == "annotate":
        return f"annotate:{action.referent}:{hash(action.note)}"
    if action.kind == "hypothesize":
        return f"hypothesize:{action.bug_class}:{','.join(sorted(action.evidence_refs))}"
    return f"{action.kind}:{hash(action.model_dump_json())}"


def _summarise_step(step_index: int, action: Action, result: dict[str, Any]) -> str:
    """One-line history entry the proposer sees on the next step.

    Compact by design — the proposer doesn't need the full payload,
    just enough to know "I already tried X and it returned Y" so
    next-step proposals don't duplicate work. Long fields (response
    bodies, search hit lists) are summarised to a count or a length.
    """
    base = f"step {step_index}: {action.kind}"
    parts: list[str] = []
    # Action-specific identity fields the proposer cares about.
    target = getattr(action, "target", None) or getattr(action, "referent", None)
    if target:
        parts.append(f"target={target}")
    # Surface the observation_id in history so the proposer can cite it
    # in `evidence_refs` when it emits a `hypothesize` action. Without
    # this, the model has nothing to reference and can't close the loop.
    obs_id = result.get("observation_id") or result.get("id")
    if isinstance(obs_id, str) and obs_id:
        parts.append(f"obs={obs_id}")
    if action.kind == "request":
        method = getattr(action, "method", None)
        path = getattr(action, "path", None)
        port = getattr(action, "port", None)
        tls = getattr(action, "tls", None)
        # Carry the full URL shape through history so the proposer can
        # tell working transports from failing ones — plain ``GET /path``
        # hides whether port=13000 + tls=False were the difference.
        scheme = "https" if tls else "http"
        port_part = f":{port}" if port is not None else ""
        parts.append(f"{method} {scheme}://{target}{port_part}{path}")
        # Carry the request body excerpt too. Without it the proposer
        # sees "POST /login → 200 with JWT" but not what was POSTed —
        # it can't tell a successful SQLi from a successful normal
        # login, and won't recognise the bug-class evidence pattern.
        # Trimmed to 240 chars to match the response excerpt budget.
        req_body = getattr(action, "body", None)
        if isinstance(req_body, str) and req_body.strip():
            req_excerpt = req_body.replace("\n", " ").replace("\r", " ").strip()[:240]
            parts.append(f"req_body={req_excerpt!r}")
        status = result.get("status")
        if status is not None:
            parts.append(f"status={status}")
        body = result.get("response_body")
        if isinstance(body, str):
            parts.append(f"body_len={len(body)}")
            # Tail excerpt of the response body so the proposer can spot
            # win signals (auth tokens, error messages, version strings)
            # without us shipping kilobyte payloads back into the prompt.
            # 240 chars is plenty for a JWT prefix or a pithy 401 body.
            excerpt = body.replace("\n", " ").replace("\r", " ").strip()[:240]
            if excerpt:
                parts.append(f"body_excerpt={excerpt!r}")
    elif action.kind == "probe":
        aspect = getattr(action, "aspect", None)
        parts.append(f"aspect={aspect}")
        hits = result.get("hits")
        assets = result.get("assets")
        if hits is not None:
            parts.append(f"hits={len(hits) if isinstance(hits, list) else hits}")
        if assets is not None:
            parts.append(f"assets={len(assets) if isinstance(assets, list) else assets}")
    elif action.kind == "hypothesize":
        parts.append(f"bug_class={getattr(action, 'bug_class', '?')}")
    if "error" in result:
        parts.append(f"error={str(result['error'])[:120]}")
    return base + (" " + " ".join(parts) if parts else "")


__all__ = ["AgentLoop", "Budget", "SessionRecord", "StepRecord"]
