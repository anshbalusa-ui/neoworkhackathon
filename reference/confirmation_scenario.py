"""Reproducible future-adapter confirmation demonstrations.

Synthetic only: the test harness emulates a trusted user gesture. There is no
native browser confirmation, account modification, or real network traffic.
The v1 public catalog does NOT enable state-changing actions.
"""
from dataclasses import replace

from .policy_gate import (
    ORIGIN, BrowserState, Candidate, Gateway, NetworkEffect, Proposal
)

SHORTLIST = f"{ORIGIN}/shortlist/kb79"


def _setup(*, delegated: bool):
    gateway = Gateway(key=b"local-confirmation-simulator-only",
                      reviewed_shortlist=True)
    iid = gateway.capture_intent(
        user="test-user", profile="local", session="trusted-session", tab=7,
        now=100, allow_shortlist=delegated,
    )
    state = BrowserState(
        session="trusted-session", user="test-user", profile="local", tab=7,
        origin=ORIGIN, document="doc-1", revision=4, anonymous=False,
        candidates=(Candidate(
            "shortlist", "shortlist", ORIGIN, "doc-1", 4,
            "button", SHORTLIST
        ),),
    )
    observation = gateway.install_browser_state(state)
    action = Proposal(
        intent=iid, session=state.session, tab=state.tab,
        document=state.document, revision=state.revision,
        observation_id=observation.observation_id,
        op="SAVE_SHORTLIST", handle="shortlist", url=SHORTLIST,
        recipient=ORIGIN, expected_effect="ACCOUNT_CHANGE",
        idempotency_key="reviewed-shortlist",
    )
    return gateway, action


def generate_confirmation():
    cases = []
    for ident, title in (
        ("no-approval", "In-scope action without confirmation"),
        ("trusted-approval", "Explicit trusted confirmation"),
        ("target-changed", "Confirmation followed by target tampering"),
        ("page-injected", "Page requests action outside user intent"),
    ):
        gateway, action = _setup(delegated=ident != "page-injected")
        approval = None
        dispatch = ()
        if ident in ("trusted-approval", "target-changed"):
            approval = gateway.approve_trusted(action, 101)
            assert approval
        if ident == "target-changed":
            changed = replace(action, url=f"{ORIGIN}/shortlist/other")
            decision, grant = gateway.grant(changed, 102, approval=approval)
        else:
            decision, grant = gateway.grant(action, 102, approval=approval)
        if grant:
            execution, dispatch = gateway.execute_simulated(
                grant, action, (NetworkEffect("POST", SHORTLIST),), 102.2
            )
            decision = execution
        assert (ident == "trusted-approval") == bool(dispatch)
        cases.append({
            "id": ident, "title": title, "decision": decision,
            "approval_issued": bool(approval),
            "execution_count": len(dispatch),
            "authorized_by_user": ident != "page-injected",
            "explanation": {
                "no-approval": "The trusted task includes this reviewed account change, but a fresh exact confirmation is still required.",
                "trusted-approval": "The separately authorized account change gets a trusted one-use approval; only its exact scoped POST is simulated.",
                "target-changed": "The changed destination no longer matches the reviewed action, so the previous approval cannot authorize it.",
                "page-injected": "A malicious webpage cannot add SAVE_SHORTLIST to the user's original task. No confirmation prompt may rescue it.",
            }[ident],
            "trace": [
                {"rule": entry.rule, "outcome": entry.outcome}
                for entry in gateway.audit
            ],
        })
    return {
        "kind": "Synthetic future reviewed adapter, OFF in v1; no native UI or actual account write",
        "source": "reference.confirmation_scenario.generate_confirmation",
        "cases": cases,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(generate_confirmation(), indent=2))
