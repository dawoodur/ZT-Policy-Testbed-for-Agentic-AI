import json
import socket
import sys
import uuid
import time
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

sys.path.append(
    str(PROJECT_ROOT)
)

from common.protocol import (
    send_message,
    receive_message
)


HOST = "127.0.0.1"
PORT = 5000

AGENT_ID = "control_agent_01"


def get_secret():

    path = (
        PROJECT_ROOT
        / "config"
        / "agent_credentials.json"
    )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        credentials = json.load(file)

    return credentials[
        AGENT_ID
    ][
        "bootstrap_secret"
    ]


def main():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.connect(
        (HOST, PORT)
    )

    request_id = str(
        uuid.uuid4()
    )

    # =============================================
    # Obtain one legitimate token
    # =============================================

    token_request = {
        "message_type":
            "TOKEN_REQUEST",

        "request_id":
            request_id,

        "agent_id":
            AGENT_ID,

        "bootstrap_secret":
            get_secret(),

        "action":
            "READ_PRESSURE",

        "resource":
            "PLC_1",

        "parameters":
            {}
    }

    send_message(
        sock,
        token_request
    )

    token_response = receive_message(
        sock
    )

    print(
        "[TOKEN RESPONSE]"
    )

    print(
        {
            "status":
                token_response.get(
                    "status"
                ),

            "ttl_seconds":
                token_response.get(
                    "ttl_seconds"
                )
        }
    )

    if (
        token_response.get("status")
        != "TOKEN_ISSUED"
    ):

        sock.close()
        return

    token = token_response[
        "token"
    ]

    print(
        "\nWaiting for token to expire..."
    )

    time.sleep(16)

    action_request = {
        "message_type":
            "ACTION_REQUEST",

        "request_id":
            request_id,

        "agent_id":
            AGENT_ID,

        "token":
            token,

        "action":
            "READ_PRESSURE",

        "resource":
            "PLC_1",

        "parameters":
            {}
    }

    # =============================================
    # First use
    # =============================================

    print(
        "\n[FIRST TOKEN USE]"
    )

    send_message(
        sock,
        action_request
    )

    first_response = receive_message(
        sock
    )

    print(
        first_response
    )

    # =============================================
    # Replay same credential                                                   Kept this thing for check
    # =============================================

    print(
        "\n[REPLAYING SAME TOKEN]"
    )

    send_message(
        sock,
        action_request
    )

    second_response = receive_message(
        sock
    )

    print(
        second_response
    )

    sock.close()


if __name__ == "__main__":
    main()