"""Modus's first-party builtin tool callables.

Each ``ToolSpec`` with a ``BuiltinInvocation`` declares its
implementation by dotted path. The :class:`ToolExecutor` resolves
those paths via :func:`importlib.import_module` and ``getattr``,
so the names declared in :func:`modus.tools.builtin_typed_action_specs`
and :func:`modus.tools.builtin_corpus_tool_specs` resolve to
attributes of submodules in this package.

Submodules:

* :mod:`modus.builtins.corpus` — Quarry-backed write tools
  (``corpus.promote_finding``).

The six typed-action callables (``probe``, ``request``, etc.) are
registered as builtin specs but their dispatch path is currently
the legacy :func:`modus.consistency._preconditions` switch — see
ADR-0004 §"Open follow-ups" for the migration plan.
"""

from __future__ import annotations

__all__: list[str] = []
