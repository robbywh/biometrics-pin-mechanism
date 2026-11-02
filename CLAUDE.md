# Crypto app — PIN & biometrics

Expo (React Native) client + Go backend. Spec-first workflow with four project agents in `.claude/agents/`:

| Agent | Role |
|---|---|
| `tech-lead` | Owns API contract (`openapi.yaml`) and splits work into `tasks-backend.md` / `tasks-expo.md` |
| `security-specialist` | Threat model + `security-spec.md` before coding; reviews after |
| `expo-engineer` | PIN / biometric UI and client logic |
| `backend-engineer` | Go APIs: PIN verify, device keys, challenges, step-up, sessions |

Flow (run with `/secure-feature <description>`):
tech-lead (draft) → security-specialist (spec) → tech-lead (contract + tasks) → **expo-engineer ∥ backend-engineer** → security-specialist (review).

Artifacts: `docs/features/<slug>/{draft,security-spec,openapi,tasks-backend,tasks-expo,decisions,security-review}.md|yaml`.

Rules: the contract is the only coupling between client and server; never log PINs/tokens/keys; biometrics unlock a hardware-backed key, never a bare boolean.
