import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

PERSONA_FILE = (
    PROJECT_ROOT
    / "config"
    / "personas.json"
)


def load_personas():
    """
    Load trusted Agent Persona definitions.
    """

    with open(
        PERSONA_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def evaluate_bpe(request):
    """
    Evaluate whether the requested action fits
    the declared behavioral persona.
    """

    personas = load_personas()

    agent_id = request.get("agent_id")
    action = request.get("action")
    resource = request.get("resource")

    # -------------------------------------------------
    # Check 1: Is this agent known?
    # -------------------------------------------------

    if not agent_id:

        return {
            "allowed": False,
            "policy": "BPE",
            "violation": "MISSING_AGENT_ID",
            "reason": "Request does not contain an agent_id."
        }

    if agent_id not in personas:

        return {
            "allowed": False,
            "policy": "BPE",
            "violation": "UNKNOWN_AGENT",
            "reason": (
                f"No behavioral persona exists "
                f"for agent '{agent_id}'."
            )
        }

    persona = personas[agent_id]

    # -------------------------------------------------
    # Check 2: Is the resource inside the persona?
    # -------------------------------------------------

    authorized_resources = persona.get(
        "authorized_resources",
        []
    )

    if resource not in authorized_resources:

        return {
            "allowed": False,
            "policy": "BPE",
            "violation": "RESOURCE_OUTSIDE_PERSONA",
            "reason": (
                f"Agent '{agent_id}' is not authorized "
                f"by its persona to access '{resource}'."
            ),
            "persona": persona["persona_name"]
        }

    # -------------------------------------------------
    # Check 3: Is the requested action allowed?
    # -------------------------------------------------

    allowed_actions = persona.get(
        "allowed_actions",
        []
    )

    if action not in allowed_actions:

        return {
            "allowed": False,
            "policy": "BPE",
            "violation": "ACTION_OUTSIDE_PERSONA",
            "reason": (
                f"Action '{action}' violates persona "
                f"'{persona['persona_name']}'."
            ),
            "persona": persona["persona_name"],
            "allowed_actions": allowed_actions
        }

    # -------------------------------------------------
    # All BPE checks passed
    # -------------------------------------------------

    return {
        "allowed": True,
        "policy": "BPE",
        "violation": None,
        "reason": (
            f"Action '{action}' is consistent "
            f"with persona '{persona['persona_name']}'."
        ),
        "persona": persona["persona_name"]
    }