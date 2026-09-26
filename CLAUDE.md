# CLAUDE.md

Working rules for Claude Code in this repository.
Adapted from the Karpathy-inspired guidelines (github.com/multica-ai/andrej-karpathy-skills, MIT).
They bias toward caution on non-trivial work. For a typo or an obvious one-liner, just do it.

## 1. Think before coding

- State the assumptions you are acting on.
- If a request has several readings and the choice changes the result, name them.
  Pick the likeliest, say which, and carry on. Stop and ask only when the decision is
  genuinely the user's: scope, product choices, anything irreversible or outward-facing.
- If a simpler approach exists, say so before building the complex one.
- A first diagnosis is a hypothesis. Say what evidence would confirm it, and check that
  before building a fix on it. If something does not add up, say so instead of smoothing it over.

## 2. Simplicity first

- Minimum code that solves the problem. No features, options or configurability that were not asked for.
- No abstraction for single-use code. No error handling for cases that cannot happen.
- If 200 lines could be 50, rewrite it. Test: would a senior engineer call this overcomplicated?

## 3. Surgical changes

- Touch only what the task needs. Do not reformat, rename or "improve" adjacent code or comments.
- Match the existing style, even where you would do it differently.
- Remove imports, variables and functions that your change made unused. Mention pre-existing
  dead code; do not delete it unless asked.
- Every changed line should trace back to the request.

## 4. Goal-driven execution

- Turn the task into a check that can pass or fail before starting:
  "fix the bug" → reproduce it, then show the reproduction no longer fails.
- For a running system (a model, the WAF, a deployed service), "tests pass" is not the goal.
  The goal is observable behaviour in the real system: the evaluation, the replayed request,
  the health field that proves the new thing is actually serving.
- For multi-step work, give a short plan with a check per step:
  `1. <step> → verify: <check>`.
- When reporting, separate what was verified from what was not. Never present a skipped check as passed.
