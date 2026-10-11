# Engineering handoff — action-capable Neo

**Status:** design and synthetic reference implementation. This is not deployed Norton Neo code. The three official submission files remain at repository root and are the only files in the ZIP.

## Ownership and integration order

| Stage / owner | Deliverable and strict interface | Release gate |
|---|---|---|
| 1. Browser platform + identity | Trusted chrome registrar records a real user gesture; immutable task intent bound to user/profile/session/tab/origin, allowed actions/data/effects, price, expiry, revocation and scope version; secure key storage and gateway-owned monotonic clock. | No page, model, or extension API can create/widen intent; revocation and concurrent nonce tests pass. |
| 2. Browser observer + AI | Read-only, least-privilege observation envelope with browser-minted opaque handles, frame/document/revision provenance and uniform `UNTRUSTED_PAGE` taint; proposal-only model tooling. | No direct browser/network/credential tools in the model runtime; malformed/forged observations fail closed. |
| 3. Security gateway | Runtime typed schema validation; exact intent/target/value/price/origin/recipient/effect/risk checks; immutable policy from trusted build; one-use grant service and redacted audit. | Direct malicious proposals, scope drift, replay, expiry, stale state, wrong session, unreviewed endpoints and audit failure produce no grant. |
| 4. Trusted UX | Native cancellation/confirmation UI displaying verified actor, action, destination/recipient, data, cost and persistence; exact-digest single-use user approval. | Page overlays cannot spoof or approve native UI; material changes invalidate approval; accessibility and fatigue review pass. |
| 5. Browser actuator + networking | Atomically consume grants, re-resolve exact handles, intercept agent-caused navigation, forms, fetch/XHR, beacons, frames/workers and redirects *before* network dispatch. Independently constrain clipboard, storage, downloads, permission prompts, popups, history and other browser-local effects. | Browser tests establish pre-effect enforcement across races and side-effecting handlers; unknown causal traffic or unmediated local JS keeps the adapter observe-only. |
| 6. Verification + operations | Adapter-specific postconditions, workflow halt on divergence, privacy-reviewed audit/retention, trusted Stop/revoke, read-only rollback. | Independent red team, fuzzing and failure injection; zero known critical bypasses in scoped adapter; rollback exercised. |

The `reference/policy_gate.py` simulator has a **trusted-only test harness** for intent capture, browser-state installation, and future reviewed-adapter approval. A real implementation must enforce those calls with browser-process privilege isolation. `now`, predicted requests and synthetic local browser effects are injected by deterministic tests: none is trustworthy if supplied by a webpage or planner. The production gateway must read its own clock; the browser network stack must independently observe and stop each request before transmission. Never connect the fake actuator directly to Neo's live browser event API.

## Component contract at launch

- **Initial scope:** anonymous/public keyboard catalog adapter at exact reviewed HTTPS origin and path shapes; search `wireless keyboards`, maximum price strictly below USD $100, read/filter/product-detail actions, eight-step/two-minute sample limit.
- **Observer → planner:** data and provenance only. Product prices, descriptions, hidden text, OCR, ARIA and summaries are untrusted facts; no text receives instruction authority.
- **Planner → gateway:** one typed proposal with parent intent/session, target handle, observation document/revision, value or URL, data class/recipient, expected effect and idempotency ID; never JS or arbitrary browser commands.
- **Gateway → actuator:** MACed one-time grant binding action digest, user/session/tab, scope version, handle/document/revision, origin/destination, egress profile, TTL and nonce. Only gateway issues; actuator independently verifies and consumes atomically.
- **Actuator/network → verifier:** instrumented effect ledger plus resulting trusted browser state; no surprise redirect, form recipient, value, POST, external request, or follow-up action after divergence. A permitted click is not a blanket permission for its handler traffic.
- **Confirmation:** v1 shopping flow does not implement checkout, account changes or communications. A separate reviewed future adapter may support an explicitly requested account change only after exact native approval; payments and credentials require dedicated design and step-up controls.

## Product extension: data, applications, and actions

Gen's broader agentic-security question extends beyond browser clicks: the assistant may **read consumer data, operate applications, and act externally**. The proposal deliberately implements only an anonymous catalog in v1, but the boundary generalizes through three **separately authorized dimensions**:

| Dimension | Production control | Do not infer from webpage text |
|---|---|---|
| **Data access** | Trusted per-source read capabilities, scoped fields and retention rules; least-privilege observation and declassification rules; exclude credentials by default. | Permission to view a page does not imply permission to read passwords, other tabs, stored identity data, or private app content. |
| **Application access** | Reviewed adapters with a manifest of methods, authenticated principal, possible side effects, destinations, data classifications and reversibility. Bind tools to origin/app identity and version. | An instruction inside a chat, CRM record, email, or webpage cannot silently authorize a new tool or another app. |
| **External action** | Typed proposal, independently checked intent/capability, exact recipient and effect profile, one-use grant, native approval where required, pre-effect enforcement and auditable outcome. | Permission to search does not imply permission to send, purchase, publish, delete, or cross domains. |

Each adapter's release gate is a **policy-enforceability proof**: every relevant side effect must be identified and intercepted before it occurs; the agent must have no bypass tool; model-generated summaries retain source taint; and execution receipts must be privacy-preserving. Consent previews and receipts should express what data left which source, to which destination, under whose authority, without writing private values to audit. A production rollout begins with observe-only modes and expands only after instrumented tests, user comprehension review, independent adversarial testing and rollback verification.

**Bring Your Own Injection lab.** Local `POST /api/probe` accepts bounded, inert hostile page text and a typed proposed action. It runs the same gateway independently of that text and never performs real network navigation. A tester can see that an injected external navigation is denied while an authorized product-detail read succeeds. The local simulator also rejects unexpected synthetic clipboard/storage/download/popup/permission effects; arbitrary page JavaScript still requires real browser containment or observe-only restrictions.

**Differentiating assurance artifact.** The `reference/assurance.py` counterfactual harness assumes a compromised planner and independently feeds 264 synthetic malformed/out-of-task actions and 72 modified network effects into the trusted reference boundary (seed 3470, 24 rounds). The unit tests assert both denial and valid task recovery, not just model refusal. This is repeatable local policy evidence, not a real-browser interception or an overall security score. Future browser-level assurance must reuse the same attack corpus against actual privileged event/network mediation.

## Unresolved risks and launch posture

1. First-party product data can be false. A checked price is still an untrusted page claim; the gateway limits actions, not answer truth. Cross-source verification belongs in a separate answer-integrity program.
2. Arbitrary JavaScript/server behavior is not inferred reliably from DOM labels or GET methods. Limit autonomous browsing to audited anonymous public adapters. A compromised first party or browser process can defeat assumptions.
3. Causal request attribution across delayed events, frames and service workers is hard. If a browser integration cannot stop all potentially step-caused traffic *before* network effects, use observe-only mode; post-hoc alerts are insufficient.
4. Production-ready secure key lifecycle, trusted user-presence signals, audit retention/privacy, browser races, and independent red-team review are not delivered by this repository.

**Release sequence:** local simulator regressions → instrumented test app and network fence → native UI and browser races → independent security review → allowlisted anonymous adapter pilot → monitor and rollback. Every authenticated, state-changing, off-origin, payment, security or credential workflow is a separate product/security launch decision.
