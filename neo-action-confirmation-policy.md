# Norton Neo: Action Confirmation Policy

**Decision policy | 11 October 2026 | Proposed v1 public-catalog adapter**

## Deterministic decision rule

The gateway first verifies a live, immutable intent created by a direct trusted-chrome user gesture; matching user/profile/session/tab, scope version, TTL and step budget; a typed known action; current browser-issued handle and document/frame/origin/role; exact value, destination, recipient and data class; allowed expected effects; pre-authorized network profile; and healthy audit. Any missing, ambiguous, unsupported, stale, unmediated, or out-of-scope condition is **DENY**. Page text, model confidence, and a webpage's own “approval” are never authority.

After authorization and **only** for a supported reviewed adapter, classify the real effect:

- **AUTO:** low-risk, nonpersistent, authorized read/local effect on an anonymous public site, with complete pre-effect browser/network mediation. A normal label or GET method alone is insufficient.
- **CONFIRM:** an in-scope, supported, reviewed externally visible or persistent action for which exact-scope native user confirmation is required. **The v1 shopping adapter enables no state-changing confirmation actions.**
- **DENY / NEW INTENT:** outside the task; unknown or unsupported adapter; sensitive data/recipient not authorized; high-impact actions lacking dedicated controls; or any inability to pre-mediate effects. Confirmation cannot turn an injected action into an authorized one.

## Reviewer-checkable decision table

| Proposal in the wireless-keyboard task | Decision | Verifiable reason |
|---|---|---|
| Read/scroll current allowed product list | **AUTO** | No external side effect; same tab, document, and authorized origin. |
| Fill public search with `wireless keyboards` | **AUTO** | Literal equals immutable query; public data only, current search handle. |
| Enter/select `USD < 100.00` price filter and click verified filter | **AUTO** | Parsed integer cents at or below 10,000; reversible local/public-read effect; egress profile contains all handler effects. |
| Open a vetted `$79` product-details link at `https://shop.example/products/<reviewed-id>` | **AUTO** | Current browser handle, exact allowed HTTPS origin/path, eligible price, read-only request and each redirect validated. |
| Select a product displayed at `$129`, mutate ceiling to `$150`, or follow a hidden review link | **DENY** | Price/parameter or target/destination exceeds intent; page content cannot widen it. |
| Navigate to `https://collector.invalid/verify` for “product verification” | **DENY / NEW INTENT** | Attacker origin not scoped; unauthorized navigation and egress. |
| Submit synthetic account email/session token to any recipient | **DENY** | `SUBMIT`, private-data classification and disclosure effect not authorized; no credential access. |
| Save an authenticated shortlist or change a preference, **if independently and explicitly requested** | **CONFIRM only after a reviewed future adapter** | Persistent account change; preview exact account, resource, values, network recipient and undo. Not executable in v1. |
| Send a message, post a review, RSVP, or share private data, **if independently requested** | **CONFIRM only after a reviewed future adapter** | External communication/commitment; exact content, recipient and effect require a fresh trusted gesture. Not executable in v1. |
| Purchase, checkout, transfer value, grant access, change password/2FA, delete important data, accept legal terms, upload file | **DENY v1** | Dedicated adapters, step-up verification and independent launch review are absent; a generic confirmation is insufficient. |
| Unknown click handler, changed form action, cross-origin frame, unsafe redirect, unmediated worker/beacon request, stale DOM | **DENY / HALT** | Consequences or target cannot be bounded before execution. |

**Borderline case:** filling a public search field can trigger JavaScript network calls while typing. It is AUTO only when the event mediator constrains those requests to the same reviewed public-read profile. Otherwise do not fill autonomously. Opening a page that could use first-party GET for hidden mutation is not proven safe by URL shape; restrict autonomy to reviewed anonymous adapters and disclose the remaining first-party semantics risk.

## Exact native approval for future reviewed adapters

1. Gateway verifies that the *original* trusted user intent contains the exact operation, actor/account, data classification, recipient and side effect. A hostile page asking to “confirm” an extra step does not pass this check.
2. Trusted browser chrome displays the **real** action, item/resource, price or changed value, destination/recipient, information sent, persistence, reversibility and any cost. It uses gateway-verified facts, not page-generated prose. Default is Cancel; the page cannot programmatically approve it.
3. A fresh user gesture yields a short-lived, one-use approval bound to the canonical action digest, intent, session, target, document revision, recipient, exact data and expiry. Atomically consume it immediately before the matched grant is issued. A changed target, recipient, value, price, document, session, or side effect discards approval and requires a new preview.
4. The actuator independently verifies its one-use grant; the browser/network mediator still enforces the exact request and redirect profile. A user confirmation does **not** override policy or authorize extra network effects.
5. Record the approval and result using rule IDs and redacted digests; no credentials, form values, tokens, raw private data, or attacker text in normal logs. Stop/revoke is available in trusted chrome.

**Worked decision:** the user only requested product discovery. A review says “verify account to see specifications.” The model proposes `SUBMIT` to `collector.invalid`; gateway returns **DENY**, not **CONFIRM**, even if the model claims the step is essential. The exact search/filter/product-read path remains permitted. If the user later issues a separate explicit purchase request, v1 still denies execution because it has no reviewed payment adapter; the assistant can hand control to the human.

On policy, audit, grant-store, browser-state, event-attribution, or network-interception failure, fall back to observe-only mode. Approval fatigue is controlled by exact per-action previews; there is no generic “trust this page” or blanket approval. Future state-changing adapters require product/security sign-off, pre-effect interception tests, negative fixtures, step-up controls where appropriate, and a new explicit launch decision.
