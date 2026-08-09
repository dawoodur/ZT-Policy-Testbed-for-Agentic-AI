from gateway.policies.bpe import (
    evaluate_bpe
)

from gateway.policies.drac import (
    evaluate_drac
)

from gateway.policies.jit import (
    evaluate_jit
)

from gateway.behavior_state import (
    record_bpe_violation
)


def evaluate_preauthorization(request):
    """
    Used before issuing a JIT credential.

    JIT itself cannot be evaluated yet because
    the credential has not been issued.
    """

    policy_results = {}

    # =============================================
    # BPE
    # =============================================

    bpe_result = evaluate_bpe(
        request
    )

    policy_results["BPE"] = (
        bpe_result
    )

    if not bpe_result["allowed"]:

        record_bpe_violation(
            request.get("agent_id")
        )

        return {
            "decision": "DENY",
            "denied_by": "BPE",
            "reason":
                bpe_result["reason"],
            "policy_results":
                policy_results
        }

    # =============================================
    # DRAC
    # =============================================

    drac_result = evaluate_drac(
        request
    )

    policy_results["DRAC"] = (
        drac_result
    )

    if not drac_result["allowed"]:

        return {
            "decision": "DENY",
            "denied_by": "DRAC",
            "reason":
                drac_result["reason"],
            "policy_results":
                policy_results
        }

    return {
        "decision": "ALLOW",
        "denied_by": None,
        "reason":
            "Preauthorization policies passed.",
        "policy_results":
            policy_results
    }


def evaluate_request(request):
    """
    Full PDP evaluation for an actual operation.
    """

    policy_results = {}

    # =============================================
    # Policy 6: JIT
    # =============================================

    jit_result = evaluate_jit(
        request
    )

    policy_results["JIT"] = (
        jit_result
    )

    if not jit_result["allowed"]:

        return {
            "decision": "DENY",
            "denied_by": "JIT",
            "reason":
                jit_result["reason"],
            "policy_results":
                policy_results
        }

    # =============================================
    # Policy 2: BPE
    # =============================================

    bpe_result = evaluate_bpe(
        request
    )

    policy_results["BPE"] = (
        bpe_result
    )

    if not bpe_result["allowed"]:

        record_bpe_violation(
            request.get("agent_id")
        )

        return {
            "decision": "DENY",
            "denied_by": "BPE",
            "reason":
                bpe_result["reason"],
            "policy_results":
                policy_results
        }

    # =============================================
    # Policy 1: DRAC
    # =============================================

    drac_result = evaluate_drac(
        request
    )

    policy_results["DRAC"] = (
        drac_result
    )

    if not drac_result["allowed"]:

        return {
            "decision": "DENY",
            "denied_by": "DRAC",
            "reason":
                drac_result["reason"],
            "policy_results":
                policy_results
        }

    return {
        "decision": "ALLOW",
        "denied_by": None,
        "reason":
            "All currently enabled policies passed.",
        "policy_results":
            policy_results
    }