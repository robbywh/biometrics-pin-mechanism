---
description: Run the full spec-first flow (tech-lead → security-specialist → tech-lead → expo-engineer ∥ backend-engineer → security review) for a feature, e.g. /secure-feature PIN and biometric login
argument-hint: <feature description>
---

Feature request: $ARGUMENTS

You are the orchestrator. Subagents cannot call each other, so YOU drive the hand-offs below using the Agent tool. Derive a kebab-case `<slug>` from the request; all artifacts go in `docs/features/<slug>/`. Pass each agent the slug and the exact file paths it must read (agents do not see this conversation). After each step, read the produced files and sanity-check them before continuing; stop and ask the user if an agent reports an open question that changes scope or security posture.

1. **tech-lead, Phase 1** — draft scope, flows, candidate endpoints and questions for security → `draft.md`.
2. **security-specialist** — inspect `draft.md` (+ existing code), threat-model, write `security-spec.md`.
3. **tech-lead, Phase 2** — consume `draft.md` + `security-spec.md`; produce `openapi.yaml`, `tasks-backend.md`, `tasks-expo.md`, `decisions.md`. Verify every SEC-id is traced to a task or an explicit decision.
4. Show the user a short summary (endpoints, tasks per side, open questions) and **ask for approval before implementation**.
5. **expo-engineer and backend-engineer in parallel** — launch both in a single message (two Agent calls, run in background) so they work concurrently from the spec and tasks. Tell each its task file and that the other side is being built simultaneously and only the contract connects them.
6. **security-specialist, review mode** — review the resulting code against `security-spec.md`; write `security-review.md` with findings by severity.
7. If Critical/High findings exist, send them to the relevant engineer to fix, then re-review. Finish with a report: what was built, tests run, SEC coverage, residual risks, anything unverified (e.g. real-device biometrics, live attestation).
