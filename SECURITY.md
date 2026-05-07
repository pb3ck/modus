# Security Policy

Modus is offensive security infrastructure. This document covers
two distinct concerns:

1. **Vulnerabilities in Modus itself.** Modus parses untrusted
   data (HTTP responses, JS bundles, tool output), invokes LLMs
   with that data, and dispatches actions based on model output.
   Any of those paths can have bugs that affect the safety of the
   operator. Report these privately.
2. **Misuse of Modus against unauthorized targets.** Modus is
   not designed to prevent intentional misuse — it is designed
   to support authorized testing. Misuse is a legal matter, not
   a security-policy matter. The operator is responsible for
   confirming authorization before running Modus against any
   target.

## Reporting a vulnerability in Modus

Email security reports to the address listed in the maintainer's
GitHub profile. Encrypt sensitive content if you can; if you
can't, send a notification email asking for a key and the
maintainer will respond with one.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept.
- Whether the issue affects a released version, the `main`
  branch, or both.
- Whether you intend to disclose publicly, and your preferred
  timeline.

The maintainer will acknowledge reports within 5 business days
and will work with reporters on a coordinated disclosure timeline.
There is no bug bounty for Modus itself.

## Threat model

Modus is intended to be run by an authorized operator on the
operator's own machine, against targets the operator has explicit
written authorization to test. The threat model assumes:

- The operator's machine is trusted.
- The LLM provider is semi-trusted (subject to the BYOK posture
  documented in the README).
- The corpus substrate is trusted.
- The target is **not** trusted. Targets can return malicious
  responses, malformed payloads, content designed to confuse
  parsers, or content designed to inject instructions into the
  LLM via the agent's prompt context. Modus must defend against
  all of these.

In particular, prompt-injection surfaces are a known and important
attack vector for any agent that reads target-controlled content.
Modus's design (typed action vocabulary, formal consistency
checks, human-promoted findings) is intended to make injection
attacks fail closed — even if the LLM is convinced to propose a
malicious action, the consistency check should reject it, and
even if it doesn't, the human in the loop should catch it.
"Should" is not "will." Adversarial review of these paths is
welcome.

## What Modus does to protect operators

- Scope enforcement is deterministic, not LLM-judgment-based.
  Modus refuses to act outside operator-defined scope regardless
  of what the LLM proposes.
- The action vocabulary excludes destructive operations by
  default. Adding destructive action types (DELETE requests,
  state-modifying operations) requires explicit per-session
  approval.
- Findings are never auto-submitted, auto-published, or auto-
  shared. The promotion lifecycle is human-driven by design.
- All agent actions are logged to the corpus before execution,
  so an operator reviewing a session after the fact can see
  exactly what was attempted and what happened.

## What Modus does not do

- Modus does not prevent an authorized operator from doing things
  they shouldn't. If the operator approves a destructive action
  against an in-scope target, Modus executes it.
- Modus does not validate program scope on the operator's behalf
  beyond what the operator has configured. If the operator
  configures the wrong scope, Modus will faithfully execute
  within that wrong scope.
- Modus does not provide legal authorization. The operator is
  responsible for confirming written authorization before
  testing any target.
