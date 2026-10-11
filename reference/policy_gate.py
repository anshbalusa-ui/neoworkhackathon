"""Synthetic, deterministic action gateway. No real browser or network interception.

Only the trusted harness calls capture_intent/install_browser_state/approve_trusted.
Planner-facing code can supply proposals but cannot mutate the registry or fake actuator.
Production must put these boundaries in separately privileged browser processes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from hmac import compare_digest, new as hmac
import json
from math import isfinite
from time import monotonic
import secrets
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

ORIGIN = "https://shop.example"
ATTACKER = "https://collector.invalid"
QUERY = "wireless keyboards"
PRICE_CENTS = 10000
AUTO_OPS = frozenset({"FILL_SEARCH", "FILL_PRICE", "CLICK_FILTER", "OPEN_PRODUCT", "SCROLL"})
SENSITIVE = frozenset({"password", "token", "secret", "auth", "session", "cookie", "email", "account"})


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    return sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class Candidate:
    handle: str
    kind: str
    origin: str
    document: str
    revision: int
    role: str
    url: str = ""
    price_cents: int | None = None
    visible: bool = True
    enabled: bool = True
    frame: str = "main"
    source_field: str = "DOM"


@dataclass(frozen=True)
class BrowserState:
    session: str
    user: str
    profile: str
    tab: int
    origin: str
    document: str
    revision: int
    candidates: tuple[Candidate, ...]
    anonymous: bool = True
    mediated: bool = True
    page_text: tuple[str, ...] = ()  # Data, including hostile text, never policy.


@dataclass(frozen=True)
class Observation:
    observation_id: str
    session: str
    tab: int
    origin: str
    document: str
    revision: int
    candidates: tuple[Candidate, ...]
    page_text: tuple[str, ...]
    trust: str = "UNTRUSTED_PAGE"


@dataclass(frozen=True)
class Proposal:
    intent: str
    session: str
    tab: int
    document: str
    revision: int
    observation_id: str
    op: str
    handle: str
    value: str = ""
    url: str = ""
    data_class: str = "PUBLIC_CATALOG_QUERY"
    recipient: str = ""
    expected_effect: str = "LOCAL_VIEW"
    idempotency_key: str = "step-1"


@dataclass(frozen=True)
class NetworkEffect:
    method: str
    url: str
    data_class: str = "PUBLIC_CATALOG_QUERY"


@dataclass(frozen=True)
class LocalEffect:
    """Sensitive browser-local effect, simulated only; requires native enforcement."""
    kind: str
    target: str = ""
    data_class: str = "PUBLIC_CATALOG_QUERY"


@dataclass(frozen=True)
class AuditEntry:
    intent_id: str
    rule: str
    op: str
    outcome: str
    action_digest: str  # Never stores the proposal, page text, URL query, or value.


@dataclass
class FakeActuator:
    """Only records effects after the synthetic pre-dispatch fence has approved."""

    dispatched: list[NetworkEffect] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)

    def dispatch(self, op: str, effects: tuple[NetworkEffect, ...]) -> None:
        self.actions.append(op)
        self.dispatched.extend(effects)


class Gateway:
    def __init__(self, *, key: bytes | None = None, reviewed_shortlist: bool = False,
                 clock: Callable[[], float] | None = None):
        self._key = key if key is not None else secrets.token_bytes(32)
        self._clock = clock or monotonic
        self._intents: dict[str, tuple[dict, str]] = {}
        self._steps: dict[str, int] = {}
        self._revoked: set[str] = set()
        self._states: dict[str, BrowserState] = {}
        self._observations: dict[str, Observation] = {}
        self._current_observation: dict[str, str] = {}
        self._grants: dict[str, tuple[dict, str]] = {}
        self._used_grants: set[str] = set()
        self._approvals: dict[str, tuple[str, str, float]] = {}
        self._used_proposals: set[tuple[str, str]] = set()
        self.reviewed_shortlist = reviewed_shortlist  # Synthetic future adapter, OFF in v1.
        self.audit_ok = True
        self.audit: list[AuditEntry] = []
        self.actuator = FakeActuator()
        self.halted: set[str] = set()
    def _time(self, supplied: float | None) -> float:
        value = self._clock() if supplied is None else supplied
        if (not isinstance(value, (int, float)) or isinstance(value, bool) or
            not isfinite(value)):
            raise ValueError("invalid trusted clock value")
        return float(value)

    def _mac(self, value: dict) -> str:
        return hmac(self._key, canonical(value), "sha256").hexdigest()

    def capture_intent(self, *, user: str, profile: str, session: str, tab: int,
                       now: float | None = None, query: str = QUERY,
                       max_price_cents: int = PRICE_CENTS,
                       allow_shortlist: bool = False) -> str:
        """Trusted-chrome entrypoint; NEVER expose to page, model, or extension."""
        now = self._time(now)
        if (not all(isinstance(item, str) and item for item in (user, profile, session)) or
            not isinstance(tab, int) or isinstance(tab, bool) or tab < 0):
            raise ValueError("invalid trusted identity or clock")
        if query != QUERY or max_price_cents != PRICE_CENTS:
            raise ValueError("this reviewed task requires exact query and price ceiling")
        if allow_shortlist and not self.reviewed_shortlist:
            raise ValueError("unreviewed adapter")
        intent_id = secrets.token_hex(12)
        data = {
            "user": user, "profile": profile, "session": session, "tab": tab,
            "origin": ORIGIN, "query": query, "max_price_cents": max_price_cents,
            "currency": "USD", "task": "INSPECT_KEYBOARDS_UNDER_PRICE",
            "allowed_ops": sorted(AUTO_OPS | ({"SAVE_SHORTLIST"} if allow_shortlist else set())),
            "data_classes": ["PUBLIC_CATALOG_QUERY"],
            "allowed_effects": ["LOCAL_VIEW", "PUBLIC_READ"] + (["ACCOUNT_CHANGE"] if allow_shortlist else []),
            "prohibited": ["PURCHASE", "PRIVATE_DATA", "EXTERNAL_NAVIGATION"],
            "issued": now, "expires": now + 120, "max_steps": 8,
            "scope_version": 1, "nonce": secrets.token_hex(12),
        }
        self._intents[intent_id] = (data, self._mac(data))
        self._steps[intent_id] = 0
        return intent_id

    def revoke(self, intent_id: str) -> None:
        self._revoked.add(intent_id)
        self.halted.add(intent_id)

    def install_browser_state(self, state: BrowserState) -> Observation:
        """Trusted browser adapter boundary; copies immutable state into registry."""
        if len({c.handle for c in state.candidates}) != len(state.candidates):
            raise ValueError("ambiguous handle")
        observation = Observation(secrets.token_hex(12), state.session, state.tab,
                                  state.origin, state.document, state.revision,
                                  state.candidates, state.page_text)
        self._states[state.session] = state
        self._observations[observation.observation_id] = observation
        self._current_observation[state.session] = observation.observation_id
        return observation

    @staticmethod
    def _safe_url(url: str, kind: str, query: str, max_price_cents: int) -> bool:
        try:
            if (not isinstance(url, str) or not url.isascii() or url.strip() != url or
                any(ord(char) < 33 or ord(char) == 127 for char in url)):
                return False
            parts = urlsplit(url)
            if (parts.geturl() != url or parts.scheme != "https" or
                parts.netloc != "shop.example" or
                parts.username is not None or parts.password is not None or
                parts.fragment or len(url) > 512 or not parts.path.startswith("/")):
                return False
            args = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
            if len(args) != len(set(key for key, _ in args)) or any(
                key.lower() in SENSITIVE or value.lower().find("collector.invalid") >= 0
                for key, value in args
            ):
                return False
            if kind == "catalog":
                return parts.path == "/catalog" and args == [
                    ("q", query), ("max_cents", str(max_price_cents))
                ]
            if kind == "product":
                return (parts.path.startswith("/products/") and
                        len(parts.path.split("/")) == 3 and
                        parts.path.split("/")[2].isalnum() and not args)
            if kind == "shortlist":
                return (parts.path.startswith("/shortlist/") and
                        len(parts.path.split("/")) == 3 and
                        parts.path.split("/")[2].isalnum() and not args)
            return False
        except (ValueError, TypeError, AttributeError):
            return False

    def _log(self, action: Proposal, rule: str, outcome: str) -> None:
        try:
            action_hash = self._mac({"proposal": asdict(action)})
        except (TypeError, ValueError):
            action_hash = "INVALID_SCHEMA"
        intent_id = action.intent if isinstance(action.intent, str) and action.intent in self._intents else "UNKNOWN"
        op = action.op if isinstance(action.op, str) and action.op in AUTO_OPS | {"SAVE_SHORTLIST"} else "UNKNOWN"
        self.audit.append(AuditEntry(intent_id, rule, op, outcome, action_hash))

    def check(self, action: Proposal, now: float | None = None, *, approval: str | None = None,
              _approved_at_grant: bool = False) -> str:
        if not isinstance(action, Proposal):
            return "SCHEMA_DENIED"
        try:
            now = self._time(now)
        except ValueError:
            return "SCHEMA_DENIED"
        required_strings = (action.intent, action.session, action.document,
                            action.observation_id, action.op, action.handle,
                            action.value, action.url, action.data_class,
                            action.recipient, action.expected_effect, action.idempotency_key)
        if (not all(isinstance(item, str) for item in required_strings) or
            not all(isinstance(item, str) and item for item in
                    (action.intent, action.session, action.document,
                     action.observation_id, action.op, action.handle, action.idempotency_key)) or
            any(len(item) > 512 for item in required_strings) or
            not isinstance(action.tab, int) or isinstance(action.tab, bool) or
            not isinstance(action.revision, int) or isinstance(action.revision, bool)):
            return "SCHEMA_DENIED"
        if not self.audit_ok:
            return "AUDIT_DOWN"
        record = self._intents.get(action.intent)
        if record is None:
            return "NO_USER_INTENT"
        intent, signature = record
        if (not compare_digest(self._mac(intent), signature) or
            action.intent in self._revoked or action.intent in self.halted or
            now < intent["issued"] or now >= intent["expires"] or
            self._steps[action.intent] >= intent["max_steps"]):
            return "INVALID_INTENT"
        if action.op not in AUTO_OPS | {"SAVE_SHORTLIST"} or action.op not in intent["allowed_ops"]:
            return "OP_DENIED"
        if (not action.idempotency_key or len(action.idempotency_key) > 100 or
            (action.intent, action.idempotency_key) in self._used_proposals):
            return "REPLAY_DENIED"
        state = self._states.get(action.session)
        if (state is None or state.user != intent["user"] or state.profile != intent["profile"] or
            state.session != intent["session"] or action.session != intent["session"] or
            state.tab != intent["tab"] or action.tab != intent["tab"] or
            state.origin != intent["origin"] or not state.mediated or
            (not state.anonymous and action.op != "SAVE_SHORTLIST")):
            return "CONTEXT_DENIED"
        observation = self._observations.get(action.observation_id)
        if (observation is None or
            action.observation_id != self._current_observation.get(state.session) or
            observation.session != state.session or observation.tab != state.tab or
            observation.origin != state.origin or observation.document != state.document or
            observation.revision != state.revision or
            action.document != state.document or action.revision != state.revision):
            return "DOCUMENT_STALE"
        candidate = next((c for c in state.candidates if c.handle == action.handle), None)
        if (candidate is None or not candidate.visible or not candidate.enabled or
            candidate.frame != "main" or candidate.origin != state.origin or
            candidate.document != state.document or candidate.revision != state.revision or
            candidate.source_field not in {"DOM", "ARIA"}):
            return "TARGET_DENIED"
        if action.data_class != "PUBLIC_CATALOG_QUERY":
            return "DATA_DENIED"
        if action.recipient and action.recipient != ORIGIN:
            return "RECIPIENT_DENIED"
        expected = {
            "FILL_SEARCH": ("search", "textbox", intent["query"], "LOCAL_VIEW"),
            "FILL_PRICE": ("price", "spinbutton", str(intent["max_price_cents"] // 100), "LOCAL_VIEW"),
            "CLICK_FILTER": ("filter", "button", "", "PUBLIC_READ"),
            "OPEN_PRODUCT": ("product", "link", "", "PUBLIC_READ"),
            "SCROLL": ("scroll", "region", "", "LOCAL_VIEW"),
            "SAVE_SHORTLIST": ("shortlist", "button", "", "ACCOUNT_CHANGE"),
        }[action.op]
        kind, role, value, effect = expected
        if candidate.kind != kind or candidate.role != role or action.expected_effect != effect:
            return "EFFECT_DENIED"
        if action.op in {"FILL_SEARCH", "FILL_PRICE", "SCROLL"}:
            if action.value != value or action.url or action.recipient:
                return "VALUE_DENIED"
        elif action.op == "CLICK_FILTER":
            if action.value or action.recipient or action.url != candidate.url or not self._safe_url(
                action.url, "catalog", intent["query"], intent["max_price_cents"]
            ):
                return "NAV_DENIED"
        elif action.op == "OPEN_PRODUCT":
            if (action.value or action.recipient or action.url != candidate.url or
                not isinstance(candidate.price_cents, int) or
                isinstance(candidate.price_cents, bool) or candidate.price_cents < 0 or
                candidate.price_cents >= intent["max_price_cents"] or
                not self._safe_url(action.url, "product", intent["query"], intent["max_price_cents"])):
                return "PRODUCT_DENIED"
        elif action.op == "SAVE_SHORTLIST":
            if (not self.reviewed_shortlist or state.anonymous or action.value or
                action.recipient != ORIGIN or action.url != candidate.url or
                not self._safe_url(action.url, "shortlist", intent["query"], intent["max_price_cents"])):
                return "ADAPTER_DENIED"
            if not _approved_at_grant:
                bound = digest([asdict(action), state.document, state.revision, candidate.url])
                record = self._approvals.get(approval or "")
                if record is None or record[0] != bound or record[1] != action.session or now >= record[2]:
                    return "REQUIRE_CONFIRMATION"
        return "OK"

    def approve_trusted(self, action: Proposal, now: float | None = None) -> str | None:
        """Synthetic fresh native user gesture; only future reviewed adapter may call."""
        try:
            now = self._time(now)
        except ValueError:
            return None
        if self.check(action, now) != "REQUIRE_CONFIRMATION":
            return None
        state = self._states[action.session]
        candidate = next(c for c in state.candidates if c.handle == action.handle)
        approval = secrets.token_hex(12)
        self._approvals[approval] = (
            digest([asdict(action), state.document, state.revision, candidate.url]),
            action.session, now + 20,
        )
        return approval

    def grant(self, action: Proposal, now: float | None = None, *,
              approval: str | None = None) -> tuple[str, str | None]:
        try:
            now = self._time(now)
        except ValueError:
            return "SCHEMA_DENIED", None
        result = self.check(action, now, approval=approval)
        if result != "OK":
            if isinstance(action, Proposal):
                self._log(action, result, "DENIED")
            return result, None
        state = self._states[action.session]
        candidate = next(c for c in state.candidates if c.handle == action.handle)
        if action.op == "SAVE_SHORTLIST":
            del self._approvals[approval]  # exact approval consumed, never reusable
        grant_id = secrets.token_hex(12)
        body = {
            "intent": action.intent, "user": state.user, "session": state.session,
            "tab": state.tab, "document": state.document, "revision": state.revision,
            "observation_id": action.observation_id,
            "handle": candidate.handle, "origin": state.origin, "url": action.url,
            "action_digest": digest(asdict(action)), "scope_version": 1,
            "profile": "PUBLIC_READ" if action.op in {"CLICK_FILTER", "OPEN_PRODUCT"} else (
                "REVIEWED_SHORTLIST" if action.op == "SAVE_SHORTLIST" else "LOCAL_VIEW"
            ),
            "expires": now + 5, "nonce": secrets.token_hex(12),
        }
        self._grants[grant_id] = (body, self._mac(body))
        self._log(action, "GRANTED", "GRANTED")
        return "GRANTED", grant_id

    def _expected_effects(self, action: Proposal) -> tuple[NetworkEffect, ...]:
        if action.op in {"CLICK_FILTER", "OPEN_PRODUCT"}:
            return (NetworkEffect("GET", action.url),)
        if action.op == "SAVE_SHORTLIST":
            return (NetworkEffect("POST", action.url),)
        return ()

    def execute_simulated(self, grant_id: str | None, action: Proposal,
                          predicted_effects: tuple[NetworkEffect, ...],
                          now: float | None = None, *,
                          postcondition_ok: bool = True,
                          unexpected_local_effects: tuple[LocalEffect, ...] = (),
                          ) -> tuple[str, tuple[NetworkEffect, ...]]:
        """Preflight fake network effects, then dispatch into an instrumented ledger.

        Caller-supplied predicted network/local effects are NOT a production interception source.
        A real browser must independently intercept each request before transmission.
        """
        try:
            now = self._time(now)
        except ValueError:
            return "SCHEMA_DENIED", ()
        if grant_id is None or grant_id in self._used_grants or grant_id not in self._grants:
            return "REPLAY_DENIED", ()
        body, signature = self._grants[grant_id]
        if not isinstance(action, Proposal) or self.check(
            action, now, _approved_at_grant=action.op == "SAVE_SHORTLIST"
        ) == "SCHEMA_DENIED":
            return "SCHEMA_DENIED", ()
        if (not compare_digest(self._mac(body), signature) or now >= body["expires"] or
            body["action_digest"] != digest(asdict(action)) or
            body["intent"] != action.intent or body["session"] != action.session or
            body["tab"] != action.tab or body["document"] != action.document or
            body["revision"] != action.revision or
            body["observation_id"] != action.observation_id or
            body["handle"] != action.handle or body["url"] != action.url):
            self._log(action, "GRANT_INVALID", "DENIED")
            return "GRANT_INVALID", ()
        # Once the grant matches the exact action, consume it before revalidation.
        self._used_grants.add(grant_id)
        # Confirmation was consumed at grant issuance; all other checks still apply.
        result = self.check(action, now, _approved_at_grant=action.op == "SAVE_SHORTLIST")
        if result != "OK":
            self._log(action, result, "DENIED")
            return result, ()
        if (not isinstance(unexpected_local_effects, tuple) or
            unexpected_local_effects):
            # The reviewed v1 adapter expects only direct input-field updates
            # and scrolling. Clipboard, storage, downloads, prompts, popups,
            # and other unreviewed browser effects have no authorization.
            self.halted.add(action.intent)
            self._log(action, "LOCAL_EFFECT_DENIED", "HALTED")
            return "LOCAL_EFFECT_DENIED", ()
        if not isinstance(predicted_effects, tuple) or predicted_effects != self._expected_effects(action):
            self.halted.add(action.intent)
            self._log(action, "NETWORK_FENCE_DENIED", "HALTED")
            return "NETWORK_FENCE_DENIED", ()
        self._used_proposals.add((action.intent, action.idempotency_key))
        self._steps[action.intent] += 1
        self.actuator.dispatch(action.op, predicted_effects)
        if not postcondition_ok:
            self.halted.add(action.intent)
            self._log(action, "POSTCONDITION_DIVERGED", "HALTED")
            return "POSTCONDITION_DIVERGED", predicted_effects
        self._log(action, "VERIFIED", "EXECUTED")
        return "SIMULATED_EXECUTED", predicted_effects
