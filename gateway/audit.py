import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_DIR = PROJECT_ROOT / "logs"
LEDGER_FILE = LOG_DIR / "audit.jsonl"

GENESIS_HASH = "0" * 64

audit_lock = threading.Lock()

def canonical_json(data):
    """
    Serialize data deterministically.

    sort_keys=True is important because the same dictionary
    must always produce the same byte representation.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def calculate_hash(entry_without_hash):
    """
    Calculate SHA-256 over the complete audit entry
    except its own current_hash field.
    """

    serialized = canonical_json(entry_without_hash)

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def get_last_hash():
    """
    Read the last valid ledger entry and return its hash.

    If the ledger does not exist or is empty,
    return the genesis hash.
    """

    if not LEDGER_FILE.exists():
        return GENESIS_HASH

    lines = []

    with open(LEDGER_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                lines.append(line)

    if not lines:
        return GENESIS_HASH

    last_entry = json.loads(lines[-1])

    return last_entry["current_hash"]


def append_audit_event(
    event_type,
    request=None,
    decision=None,
    response=None,
    details=None
):
    """
    Append one tamper-evident event to the ledger.
    """

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with audit_lock:

        previous_hash = get_last_hash()

        entry = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "event_type": event_type,

            "request_id": (
                request.get("request_id")
                if request
                else None
            ),

            "agent_id": (
                request.get("agent_id")
                if request
                else None
            ),

            "action": (
                request.get("action")
                if request
                else None
            ),

            "resource": (
                request.get("resource")
                if request
                else None
            ),

            "parameters": (
                request.get(
                    "parameters",
                    {}
                )
                if request
                else {}
            ),

            "decision": decision,

            "response": response,

            "details": details or {},

            "previous_hash": previous_hash
        }

        current_hash = calculate_hash(
            entry
        )

        entry["current_hash"] = (
            current_hash
        )

        with open(
            LEDGER_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                json.dumps(entry)
                + "\n"
            )

    return entry