import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from gateway.audit import (
    LEDGER_FILE,
    GENESIS_HASH,
    calculate_hash
)


def verify_ledger():

    if not LEDGER_FILE.exists():
        print("[ERROR] Audit ledger does not exist.")
        return False

    expected_previous_hash = GENESIS_HASH
    entry_number = 0

    with open(
        LEDGER_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            if not line.strip():
                continue

            entry_number += 1

            try:
                entry = json.loads(line)

            except json.JSONDecodeError:
                print(
                    f"[FAIL] Entry {entry_number}: "
                    f"Invalid JSON."
                )
                return False

            stored_current_hash = entry.get(
                "current_hash"
            )

            stored_previous_hash = entry.get(
                "previous_hash"
            )

            # -----------------------------------------
            # Verify chain linkage
            # -----------------------------------------

            if stored_previous_hash != expected_previous_hash:

                print(
                    f"[FAIL] Entry {entry_number}: "
                    f"Previous hash mismatch."
                )

                print(
                    f"Expected: {expected_previous_hash}"
                )

                print(
                    f"Found:    {stored_previous_hash}"
                )

                return False

            # -----------------------------------------
            # Recalculate this entry's hash
            # -----------------------------------------

            entry_without_hash = dict(entry)

            entry_without_hash.pop(
                "current_hash",
                None
            )

            calculated_hash = calculate_hash(
                entry_without_hash
            )

            if calculated_hash != stored_current_hash:

                print(
                    f"[FAIL] Entry {entry_number}: "
                    f"Content hash mismatch."
                )

                print(
                    f"Stored:     {stored_current_hash}"
                )

                print(
                    f"Calculated: {calculated_hash}"
                )

                return False

            expected_previous_hash = (
                stored_current_hash
            )

    print("=" * 60)
    print("ICCA LEDGER VERIFICATION")
    print("=" * 60)

    print(
        f"[PASS] {entry_number} entries verified."
    )

    print("[PASS] Hash chain is intact.")
    print("[PASS] No modification detected.")

    return True


if __name__ == "__main__":
    verify_ledger()