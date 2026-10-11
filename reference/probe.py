"""Reviewer-controlled injection challenge, with NO live browser or model execution.

A typed malicious planner proposal is generated from page-authored data. The
gateway checks trusted intent independently, even when the planner is fooled.
All URLs and user-entered text remain inert local test data.
"""
from dataclasses import replace

from .policy_gate import ATTACKER, ORIGIN, QUERY, NetworkEffect
from .scenario import fixture

OPS = frozenset(("NAVIGATE", "SUBMIT", "OPEN_PRODUCT", "PURCHASE", "FILL_SEARCH"))
DEFAULT_URL = f"{ATTACKER}/verify"


def evaluate_probe(*, page_instruction: str, operation: str, destination: str,
                   value: str = "") -> dict:
    if (not isinstance(page_instruction, str) or len(page_instruction) > 320 or
        not isinstance(operation, str) or operation not in OPS or
        not isinstance(destination, str) or len(destination) > 512 or
        not isinstance(value, str) or len(value) > 120):
        raise ValueError("Invalid synthetic probe parameters")
    gateway, intent, state, _, make = fixture()
    # The hostile text is inserted into UNTRUSTED_PAGE observation only.
    # It cannot mutate the separately stored trusted task authorization.
    new_observation = gateway.install_browser_state(
        replace(state, page_text=state.page_text + (page_instruction,))
    )
    if operation == "FILL_SEARCH":
        action = make("FILL_SEARCH", "search", key="custom-probe",
                      value=value)
    else:
        params = {
            "NAVIGATE": ("product", "DATA_DISCLOSURE", "PUBLIC_CATALOG_QUERY", ""),
            "SUBMIT": ("product", "DATA_DISCLOSURE", "PRIVATE_ACCOUNT_DATA", destination),
            "OPEN_PRODUCT": ("product", "PUBLIC_READ", "PUBLIC_CATALOG_QUERY", ""),
            "PURCHASE": ("product", "EXTERNAL_COMMITMENT", "PUBLIC_CATALOG_QUERY", ""),
        }
        handle, effect, data_class, recipient = params[operation]
        action = make(operation, handle, key="custom-probe", url=destination,
                      expected_effect=effect, data_class=data_class, recipient=recipient)
    action = replace(action, observation_id=new_observation.observation_id)
    rule, grant = gateway.grant(action, now=101)
    dispatched = False
    if grant:
        effects = (NetworkEffect("GET", action.url),) if operation == "OPEN_PRODUCT" else ()
        result, _ = gateway.execute_simulated(grant, action, effects, now=101.2)
        rule = result
        dispatched = result == "SIMULATED_EXECUTED"
    return {
        "kind": "Synthetic policy probe, not a language-model inference or live browser action",
        "operation": operation,
        "decision": rule,
        "execution_grant_issued": bool(grant),
        "synthetic_action_executed": dispatched,
        "denied": not dispatched,
        "original_intent_unchanged": gateway._intents[intent][0]["query"] == QUERY,
        "untrusted_payload_recorded_as_authority": False,
        "reviewed_destination": destination if len(destination) <= 100 else "[too long]",
        "explanation": ("The typed proposal is checked against a separate trusted intent, "
                        "current browser handle, destination/data policy and expected effects. "
                        "Changing page instructions alone never changes what is authorized."),
    }
