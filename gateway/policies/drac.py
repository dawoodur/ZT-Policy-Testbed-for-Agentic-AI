import json
from pathlib import Path

from gateway.behavior_state import (
    get_behavior_risk,
    get_bpe_violation_count
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)

DRAC_CONFIG_FILE = (
    PROJECT_ROOT
    / "config"
    / "drac_config.json"
)

SYSTEM_CONTEXT_FILE = (
    PROJECT_ROOT
    / "config"
    / "system_context.json"
)


def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def evaluate_drac(request):
    """
    Evaluate Dynamic Risk-Adaptive Access Control.
    """

    config = load_json(
        DRAC_CONFIG_FILE
    )

    context = load_json(
        SYSTEM_CONTEXT_FILE
    )

    agent_id = request.get("agent_id")
    action = request.get("action")

    # =============================================
    # 1. Identity risk
    # =============================================

    identity_risk = config.get(
        "default_identity_risk",
        0.30
    )

    # =============================================
    # 2. Action / data sensitivity
    # =============================================

    action_sensitivity = config.get(
        "action_sensitivity",
        {}
    )

    sensitivity_risk = (
        action_sensitivity.get(
            action,
            1.0
        )
    )

    # =============================================
    # 3. Environmental context
    # =============================================

    operational_mode = context.get(
        "operational_mode",
        "NORMAL_OPERATION"
    )

    context_scores = config.get(
        "operational_context_risk",
        {}
    )

    context_risk = context_scores.get(
        operational_mode,
        1.0
    )

    # =============================================
    # 4. Historical behavioral deviation
    # =============================================

    violation_cap = config.get(
        "behavior_violation_cap",
        3
    )

    behavior_risk = get_behavior_risk(
        agent_id,
        violation_cap
    )

    violation_count = (
        get_bpe_violation_count(
            agent_id
        )
    )

    # =============================================
    # 5. Weighted risk calculation
    # =============================================

    weights = config["weights"]

    risk_score = (
        weights["identity"]
        * identity_risk

        + weights["sensitivity"]
        * sensitivity_risk

        + weights["context"]
        * context_risk

        + weights["behavior"]
        * behavior_risk
    )

    risk_score = round(
        risk_score,
        4
    )

    # =============================================
    # 6. Dynamic threshold
    # =============================================

    threat_level = context.get(
        "threat_level",
        "NORMAL"
    )

    thresholds = config.get(
        "thresholds",
        {}
    )

    threshold = thresholds.get(
        threat_level,
        0.35
    )

    # =============================================
    # 7. Final decision
    # =============================================

    allowed = (
        risk_score <= threshold
    )

    return {
        "allowed": allowed,

        "policy": "DRAC",

        "risk_score": risk_score,

        "threshold": threshold,

        "threat_level": threat_level,

        "operational_mode":
            operational_mode,

        "components": {
            "identity_risk":
                identity_risk,

            "sensitivity_risk":
                sensitivity_risk,

            "context_risk":
                context_risk,

            "behavior_risk":
                behavior_risk
        },

        "behavior_history": {
            "bpe_violations":
                violation_count
        },

        "reason": (
            f"Risk score {risk_score} "
            f"{'<=' if allowed else '>'} "
            f"threshold {threshold}."
        )
    }