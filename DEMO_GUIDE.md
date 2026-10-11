# Norton Neo — 90-second reviewer walkthrough

This is a **security architecture submission**, with a runnable synthetic reference gate. It is not an integration into Norton Neo and does not intercept actual browser events. The strongest demo is **not** to show an LLM refusing an attack. It is to assume the model has already obeyed the malicious page, then demonstrate a second, deterministic authority boundary.

## Launch (Python 3.10+, standard library only)

    python3 -m unittest discover -s tests -v
    python3 -m reference.demo_server

Open http://127.0.0.1:8765/site/ in a browser. The local server recalculates all live decisions; static GitHub file browsing is not a substitute for the live demo.

## Judge path (approximately 90 seconds)

**0:00–0:15 — Why it matters.** “Norton Neo is moving from telling users what it sees to doing things on their behalf. That changes prompt injection from a bad answer into an unauthorized action. Our design assumes the model can be completely fooled.”

**0:15–0:40 — Block a malicious action.** Open *Simulation → Malicious review · external navigation*. The user only authorized finding a sub-$100 keyboard. The product review tells the AI to visit an external verification endpoint. The model proposes exactly that. The gateway returns OP_DENIED, emits no grant, and the fake actuator records no unauthorized dispatch. The authorized search, price filter and product-detail read still complete. Repeat with *Hidden DOM · private data submission* for the data-exposure scenario.

**0:40–1:00 — Stress the boundary, not the model.** Click *Assurance Lab → Run 336 security challenges*. The real Python gateway receives 264 mutated, malicious planner proposals directly and rejects all defined cases. The synthetic effect fence also rejects 72 unexpected redirect/POST/beacon effect scenarios. Each denied planner proposal leaves the valid user workflow usable. These are measured synthetic fixtures, **not** an overall security score or real network interception.

**1:00–1:20 — Explain trusted confirmation.** Open *Confirmation Lab*. Show that a separately requested, reviewed account change still needs a fresh exact user approval; that changing its destination voids the approval; and that an injected page request for a new capability is denied without offering confirmation. Every state-changing action shown here is a future-adapter **simulation** and disabled in v1.

**1:20–1:30 — The engineering call.** “The language model proposes. A privileged gateway checks immutable user intent, current browser bindings, recipients, effects and confirmation. A one-use grant allows the action only if trusted browser/network interception can enforce those same restrictions. Otherwise Neo remains observe-only.”

## Three questions worth preparing for

**Q: If Grok fully follows the injection, why is it still blocked?** The planner has only a typed proposal channel. Its output does not carry authorization. The gateway independently checks a trusted user-intent registry and actual target/effect constraints. The counterfactual tests deliberately bypass model resistance.

**Q: Can an allowed click still trigger a malicious JavaScript POST or redirect?** Yes. DOM labels and HTTP methods are insufficient. The design requires pre-effect browser-level request and redirect mediation, including frames and workers, before action mode is enabled. The repository tests a *synthetic effect ledger* only; real Chromium integration, attribution tests and independent red teaming remain release gates.

**Q: Why not ask the user to confirm everything?** It harms usability and can launder page-authored requests into apparently legitimate choices. Confirmation is required for authorized consequential actions, but it cannot widen the original task; out-of-intent requests are denied or require a new direct trusted-chrome instruction.

## What to submit

Only neo-action-security-architecture.zip, containing the exact required architecture, threat-model and confirmation-policy Markdown files. The demo, tests, engineering handoff and this guide are supporting repository evidence. Verify the ZIP in CI or with the build script before uploading to the hackathon portal.
