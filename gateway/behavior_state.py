import json
import threading
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

STATE_FILE = (
    PROJECT_ROOT
    / "logs"
    / "behavior_state.json"
)

behavior_lock = threading.Lock()

def load_state():
    """
    Load persistent behavioral state.
    """

    if not STATE_FILE.exists():
        return {}

    try:
        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:
        return {}


def save_state(state):
    """
    Persist behavioral state.
    """

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        STATE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            state,
            file,
            indent=2
        )


def record_bpe_violation(agent_id):

    if not agent_id:
        return

    with behavior_lock:

        state = load_state()

        agent_state = state.setdefault(
            agent_id,
            {
                "bpe_violations": 0
            }
        )

        agent_state[
            "bpe_violations"
        ] += 1

        save_state(state)


def get_bpe_violation_count(agent_id):
    """
    Return historical BPE violations for an Agent.
    """

    state = load_state()

    return (
        state
        .get(agent_id, {})
        .get("bpe_violations", 0)
    )


def get_behavior_risk(
    agent_id,
    violation_cap=3
):
    """
    Convert accumulated violations to a normalized
    behavioral risk score between 0 and 1.
    """

    violations = get_bpe_violation_count(
        agent_id
    )

    if violation_cap <= 0:
        return 0.0

    risk = violations / violation_cap

    return min(risk, 1.0)