# Codex master prompt — Norton Neo action security

This file is repository guidance for continuing the Gen Digital hackathon submission. The original challenge contract is the user-provided master brief; it supersedes stale instructions here. The source of truth is the three root security documents and the verified code/tests. **Do not replace the required documents with a demo.** Do not claim that this architecture is deployed inside Norton Neo.

## Mission and exact submission

The committed `neo-action-security-architecture.zip` must contain **exactly** these files at archive root, byte-identical to current sources:

- `neo-action-security-architecture.md` — implementable architecture and complete hostile-page scenario;
- `neo-action-threat-model.md` — every required attack with STOPPED, REDUCED, or ACCEPTED RISK outcome;
- `neo-action-confirmation-policy.md` — enforceable AUTO, future-confirmation, DENY tiers.

No other files belong in that ZIP. Rebuild after the final Markdown edit with `python3 scripts/build_submission.py`, then inspect with `unzip -t` and `unzip -l`.

## Core scenario and boundary

The trusted user asks Neo to filter **wireless keyboards below $100** on a synthetic `https://shop.example` catalog, open an eligible product and inspect details. An attacker-controlled review/hidden DOM/ARIA text impersonates a system instruction and orders a visit to `https://collector.invalid` or submission of private account details. Both origins are fake fixtures; never use real credentials or live exfiltration.

Only trusted browser chrome creates the immutable intent for user/profile/session/tab, exact origin, query, USD price ceiling, actions, permitted effects/data, expiry, step limit, scope version and prohibited operations. DOM, metadata, review text, OCR, page tool output and model summaries are `UNTRUSTED_PAGE` observations. The planner emits typed proposals only and has **no privileged browser or network tool**. A deterministic gateway validates every proposal, independently issues one-use grants, and refuses any unauthorized destination, data flow, stale target, unmediated effect, replay or missing native approval. Confirmation is not a substitute for authorization. The actuator and pre-request/redirect mediator belong in trusted browser code; if they do not exist, agent actions remain observe-only.

The Python implementation at `reference/policy_gate.py` is a local simulator, not a hardened browser; `reference/scenario.py` generates six synthetic attack decisions and safe continuations. The local `reference/demo_server.py` recomputes selected decisions for the responsive `site/index.html` handoff. Tests assert on the fake actuator's dispatch ledger; they **do not prove real network interception**.

## Model and delegation discipline

Lead routing: GPT-6 Sol with maximum supported reasoning for security arbitration, high for integration, medium for routine updates. Catalog names and efforts must be verified, not guessed. Subagents may be used only on **Luna Max** (`gpt-6-luna` at max if the runtime exposes and confirms effort; previously `gpt-5.6-luna` was configured). If effort cannot be verified in a particular subagent runtime, do the affected work in the lead session and disclose the limitation. Never claim a worker ran at max merely because a task description asked for it. Use isolated non-overlapping file ownership; lead owns final integration, tests, docs, packaging and pushes. Available Superpowers skills should be used only when actually installed; otherwise apply the practices without claiming the skill executed.

## Practical commands and release gates

```sh
python3 -m unittest discover -s tests -v
python3 -m reference.scenario --check-site
python3 -m reference.demo_server  # visit http://127.0.0.1:8765/site/
python3 scripts/build_submission.py
unzip -t neo-action-security-architecture.zip
unzip -l neo-action-security-architecture.zip
```

The default branch is `main` at `https://github.com/anshbalusa-ui/neoworkhackathon`. Preserve unrelated changes; commit tested logical milestones, push without force, verify remote SHA and CI before declaring completion. Never commit secrets. The current simulator enforces typed proposals, current targets, exact reviewed URL shapes, origin/data/effect constraints, idempotency, expiration/revocation, future reviewed-adapter confirmation, one-use grants, fake egress preflight, postcondition halt and redacted audit. Production additionally requires secure key isolation, gateway-owned clock, browser-native trusted confirmation, real event and network attribution/interception, browser race tests and independent security review. Expose these limitations clearly in every report.

Completion report must state **STATUS**, exact document and ZIP paths, implemented versus production-only controls, measured test/fixture counts, adversarial results, final branch/SHA/push/CI evidence, and ZIP integrity. Never claim portal submission without actual portal receipt.
