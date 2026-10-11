# Engineering handoff — action-capable Neo

**Status:** design and synthetic reference implementation. This is not deployed Norton Neo code. The three official submission files remain at repository root and are the only files in the ZIP.

## Ownership and integration order

| Stage / owner | Deliverable and strict interface | Release gate |
|---|---|---|
| 1. Browser platform + identity | Trusted chrome registrar records a real user gesture; immutable task intent bound to user/profile/session/tab/origin, allowed actions/data/effects, price, expiry, revocation and scope version; secure key storage and gateway-owned monotonic clock. | No page, model, or extension API can create/widen intent; revocation and concurrent nonce tests pass. |
| 2. Browser observer + AI | Read-only, least-privilege observation envelope with browser-minted opaque handles, frame/document/revision provenance and uniform `UNTRUSTED_PAGE` taint; proposal-only model tooling. | No direct browser/network/credential tools in the model runtime; malformed/forged observations fail closed. |
| 3. Security gateway | Runtime typed schema validation; exact intent/target/value/price/origin/recipient/effect/risk checks; immutable policy from trusted build; one-use grant service and redacted audit. | Direct malicious proposals, scope drift, replay, expiry, stale state, wrong session, unreviewed endpoints and audit failure produce no grant. |
| 4. Trusted UX | Native cancellation/confirmation UI displaying verified actor, action, destination/recipient, data, cost and persistence; exact-digest single-use user approval. | Page overlays cannot spoof or approve native UI; material changes invalidate approval; accessibility and fatigue review pass. |
| 5. Browser actuator + networking | Atomically consume grants, resolve exact handles at dispatch and intercept agent-caused navigation, form actions, fetch/XHR, beacons, popups, redirects, frame/worker/service-worker traffic before transmission. | Real instrumented browser tests prove zero unauthorized effects across races and side-effecting handlers; unknown causal traffic disables autonomy. |
| 6. Verification + operations | Adapter-specific postconditions, workflow halt on divergence, privacy-reviewed audit/retention, trusted Stop/revoke, read-only rollback. | Independent red team, fuzzing and failure injection; zero known critical bypasses in scoped adapter; rollback exercised. |

The `reference/policy_gate.py` simulator has a **trusted-only test harness** for intent capture, browser-state installation, and future reviewed-adapter approval. A real implementation must enforce those calls with browser-process privilege isolation. `now` and predicted request effects are injected by deterministic tests: neither is trustworthy when supplied by a webpage or planner. The production gateway must read its own clock; the browser network stack must independently observe and stop each request before transmission. Never connect the fake actuator directly to Neo's live browser event API.

## Component contract at launch

- **Initial scope:** anonymous/public keyboard catalog adapter at exact reviewed HTTPS origin and path shapes; search `wireless keyboards`, maximum price strictly below USD $100, read/filter/product-detail actions, eight-step/two-minute sample limit.
- **Observer → planner:** data and provenance only. Product prices, descriptions, hidden text, OCR, ARIA and summaries are untrusted facts; no text receives instruction authority.
- **Planner → gateway:** one typed proposal with parent intent/session, target handle, observation document/revision, value or URL, data class/recipient, expected effect and idempotency ID; never JS or arbitrary browser commands.
- **Gateway → actuator:** MACed one-time grant binding action digest, user/session/tab, scope version, handle/document/revision, origin/destination, egress profile, TTL and nonce. Only gateway issues; actuator independently verifies and consumes atomically.
- **Actuator/network → verifier:** instrumented effect ledger plus resulting trusted browser state; no surprise redirect, form recipient, value, POST, external request, or follow-up action after divergence. A permitted click is not a blanket permission for its handler traffic.
- **Confirmation:** v1 shopping flow does not implement checkout, account changes or communications. A separate reviewed future adapter may support an explicitly requested account change only after exact native approval; payments and credentials require dedicated design and step-up controls.

## Unresolved risks and launch posture

1. First-party product data can be false. A checked price is still an untrusted page claim; the gateway limits actions, not answer truth. Cross-source verification belongs in a separate answer-integrity program.
2. Arbitrary JavaScript/server behavior is not inferred reliably from DOM labels or GET methods. Limit autonomous browsing to audited anonymous public adapters. A compromised first party or browser process can defeat assumptions.
3. Causal request attribution across delayed events, frames and service workers is hard. If a browser integration cannot stop all potentially step-caused traffic *before* network effects, use observe-only mode; post-hoc alerts are insufficient.
4. Production-ready secure key lifecycle, trusted user-presence signals, audit retention/privacy, browser races, and independent red-team review are not delivered by this repository.

**Release sequence:** local simulator regressions → instrumented test app and network fence → native UI and browser races → independent security review → allowlisted anonymous adapter pilot → monitor and rollback. Every authenticated, state-changing, off-origin, payment, security or credential workflow is a separate product/security launch decision.
