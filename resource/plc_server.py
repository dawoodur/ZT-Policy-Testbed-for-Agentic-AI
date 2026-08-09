import socket
import sys
import threading
from pathlib import Path


# Allow imports from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from common.protocol import send_message, receive_message


HOST = "127.0.0.1"
PORT = 7000


# Simulated PLC state
plc_state = {
    "temperature": 24.5,
    "pressure": 63.2,
    "valve": "CLOSED",
    "pump": "RUNNING"
}

state_lock = threading.Lock()


def process_request(request):
    """
    Process a command received from the agent.
    """

    action = request.get("action")

    if action == "READ_TEMPERATURE":
        return {
            "status": "SUCCESS",
            "temperature": plc_state["temperature"]
        }

    elif action == "READ_PRESSURE":
        return {
            "status": "SUCCESS",
            "pressure": plc_state["pressure"]
        }

    elif action == "SET_VALVE":
        value = request.get("parameters", {}).get("value")

        if value not in ["OPEN", "CLOSED"]:
            return {
                "status": "ERROR",
                "message": "Valve value must be OPEN or CLOSED."
            }

        with state_lock:
            plc_state["valve"] = value

        return {
            "status": "SUCCESS",
            "message": f"Valve changed to {value}"
        }

    elif action == "START_PUMP":
        with state_lock:
            plc_state["pump"] = "RUNNING"

        return {
            "status": "SUCCESS",
            "message": "Pump started"
        }

    elif action == "STOP_PUMP":
        with state_lock:
            plc_state["pump"] = "STOPPED"
        return {
            "status": "SUCCESS",
            "message": "Pump stopped"
        }

    elif action == "GET_STATE":
        with state_lock:
            current_state = dict(plc_state)

        return {
            "status": "SUCCESS",
            "state": current_state
        }

    else:
        return {
            "status": "ERROR",
            "message": f"Unknown action: {action}"
        }


def handle_client(client_socket, address):

    print(f"[+] Peer connected: {address}")

    try:
        while True:

            request = receive_message(client_socket)

            print("\n[REQUEST RECEIVED]")
            print(request)

            response = process_request(request)

            print("[RESPONSE]")
            print(response)

            send_message(client_socket, response)

    except ConnectionError:
        print(f"\n[-] Peer disconnected: {address}")

    except Exception as error:
        print(f"\n[!] Error: {error}")

    finally:
        client_socket.close()


def start_server():

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind((HOST, PORT))

    server_socket.listen(5)

    print("=" * 50)
    print("Simulated PLC Resource Peer")
    print("=" * 50)
    print(f"Listening on {HOST}:{PORT}")
    print("Waiting for agent connection...\n")

    while True:

        client_socket, address = (
            server_socket.accept()
        )

        client_thread = threading.Thread(
            target=handle_client,
            args=(
                client_socket,
                address
            ),
            daemon=True
        )

        client_thread.start()

if __name__ == "__main__":
    start_server()