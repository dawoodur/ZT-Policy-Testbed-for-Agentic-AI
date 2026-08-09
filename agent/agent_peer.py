import socket
import sys
import uuid
import json
from pathlib import Path


# Allow imports from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CREDENTIAL_FILE = (
    PROJECT_ROOT
    / "config"
    / "agent_credentials.json"
)

sys.path.append(str(PROJECT_ROOT))

from common.protocol import send_message, receive_message


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

AGENT_ID = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "agent_01"
)

def get_bootstrap_secret(agent_id):

    with open(
        CREDENTIAL_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        credentials = json.load(file)

    record = credentials.get(
        agent_id
    )

    if not record:

        raise ValueError(
            f"No bootstrap credential exists "
            f"for {agent_id}."
        )

    return record[
        "bootstrap_secret"
    ]

def send_action(
    sock,
    action,
    parameters=None
):

    if parameters is None:
        parameters = {}

    request_id = str(
        uuid.uuid4()
    )

    # =============================================
    # Phase 1: Request JIT credential
    # =============================================

    token_request = {
        "message_type":
            "TOKEN_REQUEST",

        "request_id":
            request_id,

        "agent_id":
            AGENT_ID,

        "bootstrap_secret":
            get_bootstrap_secret(
                AGENT_ID
            ),

        "action":
            action,

        "resource":
            "PLC_1",

        "parameters":
            parameters
    }

    print(
        "\n[REQUESTING JIT CREDENTIAL]"
    )

    print(
        f"Action: {action}"
    )

    send_message(
        sock,
        token_request
    )

    token_response = receive_message(
        sock
    )

    if (
        token_response.get("status")
        != "TOKEN_ISSUED"
    ):

        print(
            "[JIT CREDENTIAL DENIED]"
        )

        print(token_response)

        return

    token = token_response[
        "token"
    ]

    print(
        "[JIT CREDENTIAL ISSUED]"
    )

    print(
        f"TTL: "
        f"{token_response.get('ttl_seconds')} "
        f"seconds"
    )

    # =============================================
    # Phase 2: Send actual action
    # =============================================

    request = {
        "message_type":
            "ACTION_REQUEST",

        "request_id":
            request_id,

        "agent_id":
            AGENT_ID,

        "token":
            token,

        "action":
            action,

        "resource":
            "PLC_1",

        "parameters":
            parameters
    }

    print(
        "\n[SENDING AUTHORIZED REQUEST]"
    )

    print(
        {
            "request_id":
                request_id,

            "agent_id":
                AGENT_ID,

            "action":
                action,

            "resource":
                "PLC_1",

            "parameters":
                parameters,

            "token":
                "<JIT TOKEN>"
        }
    )

    send_message(
        sock,
        request
    )

    response = receive_message(
        sock
    )

    print(
        "[RESPONSE RECEIVED]"
    )

    print(response)


def show_menu():

    print("\n" + "=" * 40)
    print("Agent Peer")
    print("=" * 40)

    print("1. Read temperature")
    print("2. Read pressure")
    print("3. Open valve")
    print("4. Close valve")
    print("5. Start pump")
    print("6. Stop pump")
    print("7. Get complete PLC state")
    print("0. Exit")


def main():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    print(f"Agent identity: {AGENT_ID}")
    print(f"Connecting to PLC at {SERVER_HOST}:{SERVER_PORT}...")

    try:
        sock.connect((SERVER_HOST, SERVER_PORT))

    except ConnectionRefusedError:
        print("[ERROR] Could not connect to PLC.")
        print("Make sure plc_server.py is running.")
        return

    print("[+] Connected successfully.")

    try:

        while True:

            show_menu()

            choice = input("\nChoose an action: ").strip()

            if choice == "1":
                send_action(sock, "READ_TEMPERATURE")

            elif choice == "2":
                send_action(sock, "READ_PRESSURE")

            elif choice == "3":
                send_action(
                    sock,
                    "SET_VALVE",
                    {"value": "OPEN"}
                )

            elif choice == "4":
                send_action(
                    sock,
                    "SET_VALVE",
                    {"value": "CLOSED"}
                )

            elif choice == "5":
                send_action(sock, "START_PUMP")

            elif choice == "6":
                send_action(sock, "STOP_PUMP")

            elif choice == "7":
                send_action(sock, "GET_STATE")

            elif choice == "0":
                print("Closing connection.")
                break

            else:
                print("Invalid option.")

    except ConnectionError:
        print("[ERROR] Connection to PLC was lost.")

    finally:
        sock.close()


if __name__ == "__main__":
    main()