# Norton Neo — 90-second Gen Digital judge walkthrough

**What we built:** a precise action-authorization architecture, a real Python Action Gateway simulator, and an interactive mock-browser agent-vs-attacker lab. This is not deployed Norton Neo code, actual Grok browser automation, or production network interception.

## Open the working demo

From the cloned repository, run:

    python3 -m reference.demo_server

Open **http://127.0.0.1:8765/site/agent_lab.html**. All default tests and demos work offline with Python 3.10+ standard library. The optional live Grok one-step planner requires explicit local opt-in and an xAI API key; it is **not needed** for the judge walkthrough.

## Presentation script

**0:00–0:15 — Real problem.** "Neo is moving from reading websites to performing actions. The dangerous part of prompt injection is no longer a wrong answer: it is letting webpage text cause clicks, navigation or private-data disclosure the user never requested."

**0:15–0:32 — Show the real mock page.** "Here's a rendered local keyboard store. The legitimate user task is to find a wireless keyboard under $100. But an attacker controls this review, so I can insert fake high-priority instructions to visit an external verification site. The planner is deliberately assumed to be fooled—we're stress-testing the security *after* model failure."

**0:32–0:55 — Run with firewall.** Select *private account data submission* or *external verification navigation*, then **Run with firewall**. Watch the trust-tagged timeline: webpage observation → malicious proposal → gateway rejection → safe task recovery. The mock browser fills its search, enters the $100 ceiling, filters, and opens a $79 product's detail panel through four authorized simulated decisions. No secret or off-origin action executes.

**0:55–1:09 — Run without firewall.** Press **Without firewall** using the same attack. The log shows the hypothetical unsafe outcome of an unguarded executor. No actual request or disclosure is made; this is a **synthetic negative control**, not an exploit against Neo.

**1:09–1:25 — Engineering decision.** "The innovation is the boundary: user intent is registered outside the page; untrusted observations go to a proposal-only planner; a deterministic gateway validates actions and gives one-use grants to a privileged browser actuator. Confirmation applies only *after* authorization. Future Neo integration must independently intercept real browser network and local effects before any production autonomy."

**1:25–1:30 — Close.** "We delivered the full architecture, threat model and confirmation policy, with reproducible security evidence, real Chromium interaction tests, and a clear build plan for Gen's engineering team."

## Questions worth preparing for

**Is this really using Grok?** The default attack walkthrough uses a **deliberately compromised scripted planner** for reproducible worst-case testing, not an actual LLM inference. An optional Grok API integration can propose one step when the local server is explicitly configured with `NEO_ENABLE_GROK=1` and `XAI_API_KEY`. Its proposal gets checked by the same gateway, and it receives no browser tools or credentials. Without provider credentials, we do not claim a real model inference was performed.

**Why not just improve the system prompt?** Because a model can misinterpret attacker-written content. Even if the planner proposes an unauthorized action, an independent gateway enforces authority derived from the original user.

**Does the webpage really update?** Yes. The lab renders an actual local HTML storefront in a sandboxed iframe; the DOM responds to browser-side replay messages corresponding to Python gateway-approved synthetic actions. The mock browser and fake actuator are **not** native Chrome/Norton security APIs.

**Is the unprotected case exfiltrating anything?** No. It presents a hypothetical unsafe action without executing it. The model-output, granted-action and actual-network distinctions are explicit.

**Could a permitted click cause malicious JavaScript effects?** Yes; that is a production release blocker until trusted Chromium request, redirect, form, clipboard, storage and other relevant effects can be mediated *before* they happen. Generic open-web autonomy is intentionally out of scope.

**How is confirmation decided?** The separate [confirmation policy](neo-action-confirmation-policy.md) makes in-scope low-risk public reads automatic; approved, consequential future adapter actions require a trusted one-use confirmation; outside-intent or unsupported actions are denied. No approval dialog can turn injected page text into a user request.

## Required submission

Upload the checked-in **`neo-action-security-architecture.zip`**. It contains exactly three Markdown documents: `neo-action-security-architecture.md`, `neo-action-threat-model.md`, `neo-action-confirmation-policy.md`. The live lab, code, tests and this walkthrough support the engineering decision but do not belong in the official ZIP.

To verify locally:

    python3 -m unittest discover -s tests -v
    python3 scripts/build_submission.py
    unzip -t neo-action-security-architecture.zip

GitHub Actions also runs real headless Chromium UI checks and uploads screenshots as artifacts. Neither the tests nor this submission claim the security boundary has been integrated into Norton Neo.
