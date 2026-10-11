# Norton Neo — Injection-Resistant Action Pipeline

**Gen Digital architecture challenge · 11 October 2026**

A deterministic, capability-scoped **Action Gateway** separates trusted user intent from untrusted webpage observations and AI planner output. The planner can be entirely fooled by a malicious product review; it still cannot issue an execution grant. Only a privileged actuator may act after the gateway verifies the user's immutable task, current browser target, destination, data class, expected effects, one-use grant and—when applicable—exact native confirmation.

**Status:** executable Python policy simulator and interactive engineering handoff. **Not deployed inside Norton Neo.** The fake actuator and synthetic request ledger do not intercept real browser network traffic. Autonomous browser actions must remain OFF until trusted production event/network mediation is implemented and assessed.

## Official submission

The committed [**neo-action-security-architecture.zip**](neo-action-security-architecture.zip) contains exactly these three root-level Markdown files:

1. [neo-action-security-architecture.md](neo-action-security-architecture.md) — trust boundaries, typed contracts, gateway checks, actuator/network integration, worked attack, residual risks.
2. [neo-action-threat-model.md](neo-action-threat-model.md) — 17 classified threats, including every required injection and browser-effect category.
3. [neo-action-confirmation-policy.md](neo-action-confirmation-policy.md) — deterministic autonomous/confirmation/denial decision matrix.

Additional [engineering handoff](ENGINEERING_HANDOFF.md), [interactive demo](site/index.html), code and tests remain in the repository, not the submission ZIP.

## Run the malicious-page scenario

Requires Python 3.10+; standard library only. No API keys, external accounts, real credentials, or internet access required after cloning.

```sh
python3 -m unittest discover -s tests -v
python3 -m reference.scenario --write-site
python3 -m reference.demo_server
```

Open **http://127.0.0.1:8765/site/**. Choose “Malicious review · external navigation” or “Hidden DOM · private data submission.” The local server reruns the Python gateway for each selection and displays its rule-coded denial, zero unauthorized fake-actuator dispatches, four authorized continuation actions, redacted audit and final `SAFE_COMPLETE` outcome. Other selectors show ARIA link poisoning, forged tool handles, over-price bait and system-message impersonation. Use Ctrl-C to stop the server. The site also works under a basic static HTTP server with committed `site/scenario.json`; it then labels decisions as generated snapshots rather than live policy evaluations.

For a CLI-only trace:

```sh
python3 -m reference.scenario
```

To rebuild and verify the official archive after a document change:

```sh
python3 scripts/build_submission.py
unzip -t neo-action-security-architecture.zip
unzip -l neo-action-security-architecture.zip
```

The builder checks exact names and byte equality against the Markdown sources. The ZIP must be rebuilt **after** the last Markdown edit.

## Measured reference evidence

On 11 October 2026, `python3 -m unittest discover -s tests -v` passed **25/25 tests** (0 failed, 0 skipped). The scenario generator independently exercised **6/6 unauthorized proposals denied**, **24/24 authorized continuation actions executed** (four per scenario), and **0 unauthorized fake-actuator dispatches**. `python3 -m reference.scenario --check-site` confirmed all six committed demo decisions match the gateway. Python compilation and the ZIP integrity/byte checks passed. A Chromium smoke verified all six desktop/mobile attack selections, working navigation and disclosures, no mobile horizontal overflow, and no page errors. These denominators describe only defined synthetic fixtures, not universal prompt-injection immunity or real-browser network safety.

## Repository map and trust boundary

| Path | Role |
|---|---|
| `reference/policy_gate.py` | Dependency-free immutable shopping intent, typed proposals, current-handle checks, risk/approval, one-use grant, synthetic preflight fence, redacted audit. |
| `reference/scenario.py` | Coherent keyboard-shopping attack fixture and generated policy evidence for the site/CLI. |
| `reference/demo_server.py` | Loopback-only handoff server; invokes the Python simulator per attack selection. |
| `site/index.html`, `site/scenario.json` | Responsive, accessible technical demo with simulator-backed decisions. No external scripts or tracking. |
| `tests/test_policy_gate.py` | Positive and adversarial policy/effect-ledger regressions, including a direct malicious proposal bypassing the planner. |
| `scripts/build_submission.py` | Validated three-file ZIP packaging. |
| `ENGINEERING_HANDOFF.md` | Ownership, build order, integration contracts, release gates and unresolved risks. |
| `AGENTS.md`, `CODEX_MASTER_PROMPT.md` | Repository execution/safety guidance. |

The synthetic shopping intent scopes a user/profile/session/tab to `https://shop.example`, exact query `wireless keyboards`, USD price ceiling below $100, public catalog reads, and a two-minute/eight-step budget. The hostile review and hidden DOM text request `https://collector.invalid` and private account data. They are **page data**, not authority. A malicious model can submit those proposals directly; the gateway refuses to mint grants. The safe search/filter/$79 product-detail path continues.

The simulator's `capture_intent`, `install_browser_state`, and `approve_trusted` methods represent **trusted-only browser boundaries**, not services callable by an actual webpage or model. The deterministic test harness supplies synthetic timestamps and predicted network effects; production must own a monotonic clock and observe/intercept actual effects before transmission. The simulator's fake actuator records only approved synthetic dispatches. Passing tests establish local policy behavior, not real browser safety or universal prompt-injection immunity.

## Production integration obligations

Implement isolated chrome-origin intent registration and secure key/identity storage; trusted browser-issued handle minting and atomic re-resolution; a planner sandbox with no execution tools; runtime schema validation; a separately privileged gateway; native exact-scope approval; grant nonce consumption; and a causal event/redirect/network mediator across forms, click handlers, frames, fetch/XHR/beacons, workers and popups. Enforce allowlisted read-only adapters before network effects and verify postconditions. If any relevant traffic cannot be attributed and intercepted, keep agent action mode **observe-only**. Authenticated sites, payment/credential/security actions and unreviewed state-changing adapters are not enabled in v1. See [engineering handoff](ENGINEERING_HANDOFF.md) for owners and launch gates.

Sources: Gen Digital's [Neo announcement](https://newsroom.gendigital.com/2025-05-22-Meet-Norton-Neo-The-First-Safe-AI-Native-Browser-Now-in-Early-Access) and [xAI partnership / Agent Trust Hub](https://newsroom.gendigital.com/2026-04-28-Gen-and-xAI-Partner-to-Build-Trusted-AI-Assistants-for-Millions-of-Consumers); [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html). This submission proposes an extension; it does not claim Gen has shipped these specific controls.
