"""Deterministic synthetic action gate. NOT real Neo or Chromium interception."""
from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qsl
from hashlib import sha256
from hmac import compare_digest, new as hmac
import secrets
import json

ORIGIN = "https://events.example"
OPS = {"FILL_PUBLIC_SEARCH", "CLICK_LOCAL_FILTER", "NAVIGATE_PUBLIC_GET"}
SENSITIVE = {"password", "token", "secret", "auth", "session", "cookie", "email"}

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

@dataclass(frozen=True)
class Candidate:
    handle: str
    kind: str
    origin: str
    doc: str
    revision: int
    url: str = ""
    visible: bool = True

@dataclass
class Snapshot:
    tab: int
    origin: str
    doc: str
    revision: int
    candidates: dict
    anonymous: bool = True

@dataclass(frozen=True)
class Proposal:
    intent: str
    tab: int
    doc: str
    op: str
    handle: str
    value: str = ""
    url: str = ""

class Gateway:
    def __init__(self, key=b"synthetic-example-only"):
        self._key = key
        self._intents = {}
        self._grants = {}
        self._used = set()
        self._steps = {}
        self.audit_ok = True

    def _mac(self, data):
        return hmac(self._key, encode(data), "sha256").hexdigest()

    def trusted_user_intent(self, tab, query, now):
        if not query or len(query) > 120:
            raise ValueError("invalid query")
        iid = secrets.token_hex(12)
        data = {"tab": tab, "query": query, "origin": ORIGIN, "expires": now+120,}
        self._intents[iid] = (data, self._mac(data))
        self._steps[iid] = 0
        return iid

    def _safe_url(self, url, query):
        try:
            p = urlsplit(url)
            if p.scheme != "https" or p.netloc != "events.example" or p.path not in {"/search", "/workshops"} or p.fragment:
                return False
            args = parse_qsl(p.query, keep_blank_values=True)
            if len(url) > 512 or any(k.lower() in SENSITIVE for k,v in args):
                return False
            if p.path == "/search" and args != [("q", query)]:
                return False
            return True
        except ValueError:
            return False

    def check(self, action, browser, now):
        if not self.audit_ok:
            return "AUDIT_DOWN"
        record = self._intents.get(action.intent)
        if not record:
            return "NO_USER_INTENT"
        intent, signature = record
        if not compare_digest(self._mac(intent), signature) or now >= intent["expires"] or self._steps[action.intent] >= 8:
            return "INVALID_INTENT"
        if action.op not in OPS:
            return "OP_DENIED"
        if browser.tab != action.tab or browser.tab != intent["tab"] or browser.origin != intent["origin"] or not browser.anonymous:
            return "CONTEXT_DENIED"
        if browser.doc != action.doc:
            return "DOCUMENT_STALE"
        c = browser.candidates.get(action.handle)
        if not c or not c.visible or c.origin != intent["origin"] or c.doc != browser.doc or c.revision != browser.revision:
            return "TARGET_DENIED"
        if action.op == "FILL_PUBLIC_SEARCH":
            if c.kind != "search" or action.value != intent["query"] or action.url:
                return "VALUE_DENIED"
        elif action.op == "CLICK_LOCAL_FILTER":
            if c.kind != "filter" or action.value or action.url:
                return "FILTER_DENIED"
        elif action.op == "NAVIGATE_PUBLIC_GET":
            if c.kind != "public_get" or action.url != c.url or action.value or not self._safe_url(action.url, intent["query"]):
                return "NAV_DENIED"
        return "OK"

    def grant(self, action, browser, now):
        reason = self.check(action, browser, now)
        if reason != "OK":
            return reason, None
        gid = secrets.token_hex(12)
        digest = sha256(encode(action.__dict__)).hexdigest()
        body = {"intent": action.intent, "digest": digest, "expiry": now + 5}
        self._grants[gid] = (body, self._mac(body))
        return "GRANTED", gid

    def execute_simulated(self, gid, action, browser, effects, now):
        # Critically, in production the actual browser/network mediator must gate dispatch.
        if gid in self._used or gid not in self._grants:
            return "REPLAY_DENIED", []
        self._used.add(gid)
        body, signature = self._grants[gid]
        if (not compare_digest(self._mac(body), signature) or now >= body["expiry"]
            or body["intent"] != action.intent or body["digest"] != sha256(encode(action.__dict__)).hexdigest()):
            return "GRANT_INVALID", []
        check = self.check(action, browser, now)
        if check != "OK":
            return check, []
        expected = [("GET", action.url)] if action.op == "NAVIGATE_PUBLIC_GET" else []
        if effects != expected:
            return "NETWORK_FENCE_DENIED", []
        self._steps[action.intent] += 1
        return "SIMULATED_EXECUTED", list(effects)
