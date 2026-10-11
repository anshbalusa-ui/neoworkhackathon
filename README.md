# Norton Neo — Injection-Resistant Action Pipeline

Gen Digital architecture hackathon · October 11, 2026 · 3:30 PM PDT

This repository proposes a **capability-scoped Action Gateway** for Norton Neo. Untrusted webpages may provide facts; they cannot authorize browser actions. A read-only planner emits typed proposals; a separate deterministic gateway verifies immutable user intent, current browser context, operation policy, consent and egress before issuing a single-use execution grant.

**Status:** technical security proposal with synthetic policy tests. Not deployed inside Neo; not a production browser network interceptor.

## Exact submission
- [Security architecture](neo-action-security-architecture.md) — implementation-level interfaces, pipeline, native approval, network fence, malicious-page walkthrough
- [Threat model](neo-action-threat-model.md) — explicit stopped / reduced / accepted attacks
- [Confirmation policy](neo-action-confirmation-policy.md) — autonomous vs confirmed vs denied
- Required archive: **neo-action-security-architecture.zip** (three Markdown files only, ZIP root)

## For Codex and judges
- [Master implementation prompt](CODEX_MASTER_PROMPT.md) — phased workflow, all-subagents-Luna-Max, model/effort routing and push cadence
- [AGENTS.md](AGENTS.md) — safety and repository instructions
- [Site](site/index.html) — self-contained conceptual walkthrough, not a real browser engine
- [Policy simulator](reference/policy_gate.py) — dependency-free synthetic logic, not a hardened browser
- [Tests](tests/test_policy_gate.py) — deterministic negative and positive cases
- [ZIP builder](scripts/build_submission.py) — exact-name archive packaging

From repository root:
    python3 -m unittest discover -s tests -v
    python3 scripts/build_submission.py
    unzip -l neo-action-security-architecture.zip

## Boundary and product decision
V1 unattended actions only for tightly scoped anonymous/public read-only contexts with proven browser-network containment. Logged-in writes, mail sends, registrations, files, payments and security settings are not autonomously enabled. A merely innocent button label does not prove its JS handler benign. If requests or redirects cannot be intercepted BEFORE network effects, don't enable autonomous action.

Sources: Gen's [Neo announcement](https://newsroom.gendigital.com/2025-05-22-Meet-Norton-Neo-The-First-Safe-AI-Native-Browser-Now-in-Early-Access), [xAI partnership / Agent Trust Hub](https://newsroom.gendigital.com/2026-04-28-Gen-and-xAI-Partner-to-Build-Trusted-AI-Assistants-for-Millions-of-Consumers), [OWASP agent guidance](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html). More in the architecture document.
