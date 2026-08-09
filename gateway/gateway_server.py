import socket
import sys
import threading
from pathlib import Path

from gateway.policy_engine import (
    evaluate_request,
    evaluate_preauthorization
)

from gateway.policies.jit import (
    authenticate_bootstrap,
    issue_jit_token
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from common.protocol import (
    send_message,
    receive_message
)

from gateway.audit import append_audit_event

from gateway.policy_engine import (
    evaluate_request
)


# Agent connects here
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 5000

# Gateway connects to protected PLC here
RESOURCE_HOST = "127.0.0.1"
RESOURCE_PORT = 7000


def connect_to_resource():
    """
    Establish connection from Gateway to PLC.
    """

    resource_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    resource_socket.connect(
        (RESOURCE_HOST, RESOURCE_PORT)
    )

    return resource_socket

def handle_token_request(
    agent_socket,
    request
):
    """
    Authenticate an Agent and issue an operation-scoped
    JIT credential if preauthorization succeeds.
    """

    agent_id = request.get(
        "agent_id"
    )

    supplied_secret = request.get(
        "bootstrap_secret",
        ""
    )

    # =============================================
    # 1. Bootstrap authentication
    # =============================================

    authenticated = authenticate_bootstrap(
        agent_id,
        supplied_secret
    )

    if not authenticated:

        response = {
            "status": "TOKEN_DENIED",
            "policy": "JIT",
            "reason":
                "Bootstrap authentication failed."
        }

        append_audit_event(
            event_type="JIT_TOKEN_DENIED",
            request=request,
            decision="DENY",
            response=response,
            details={
                "reason":
                    "BOOTSTRAP_AUTH_FAILED"
            }
        )

        send_message(
            agent_socket,
            response
        )

        return

    # =============================================
    # 2. BPE + DRAC preauthorization
    # =============================================

    preauth = evaluate_preauthorization(
        request
    )

    if preauth["decision"] == "DENY":

        response = {
            "status": "TOKEN_DENIED",
            "policy":
                preauth["denied_by"],
            "reason":
                preauth["reason"]
        }

        append_audit_event(
            event_type="JIT_TOKEN_DENIED",
            request=request,
            decision="DENY",
            response=response,
            details=preauth
        )

        send_message(
            agent_socket,
            response
        )

        return

    # =============================================
    # 3. Issue JIT credential
    # =============================================

    token_record = issue_jit_token(
        request
    )

    response = {
        "status": "TOKEN_ISSUED",

        "token":
            token_record["token"],

        "expires_at":
            token_record["expires_at"],

        "ttl_seconds":
            token_record["ttl_seconds"]
    }

    append_audit_event(
        event_type="JIT_TOKEN_ISSUED",
        request=request,
        decision="ALLOW",
        details={
            "jti":
                token_record["jti"],

            "expires_at":
                token_record["expires_at"],

            "ttl_seconds":
                token_record["ttl_seconds"]
        }
    )

    send_message(
        agent_socket,
        response
    )


def handle_agent(
    agent_socket,
    agent_address
):

    print(
        f"\n[+] Agent connected to Gateway: "
        f"{agent_address}"
    )

    resource_socket = None

    try:

        print(
            f"[*] Connecting to protected resource "
            f"{RESOURCE_HOST}:{RESOURCE_PORT}..."
        )

        resource_socket = (
            connect_to_resource()
        )

        print(
            "[+] Gateway connected "
            "to protected resource."
        )

        while True:

            # =========================================
            # 1. Receive and intercept Agent request
            # =========================================

            request = receive_message(
                agent_socket
            )

            message_type = request.get(
                "message_type",
                "ACTION_REQUEST"
            )

            print("\n" + "=" * 60)

            print(
                "[GATEWAY / PEP: "
                "REQUEST INTERCEPTED]"
            )

            print(request)

            append_audit_event(
                event_type="REQUEST_INTERCEPTED",
                request=request,
                details={
                    "source_ip":
                        agent_address[0],

                    "source_port":
                        agent_address[1]
                }
            )

            # =========================================
            # 2. Ask PDP for policy decision
            # =========================================
            if message_type == "TOKEN_REQUEST":
                print("\n" + "=" * 60)

                print(
                    "[GATEWAY: JIT TOKEN REQUEST]"
                )

                print(
                    f"Agent: {request.get('agent_id')}"
                )

                print(
                    f"Action: {request.get('action')}"
                )

                print(
                    f"Resource: {request.get('resource')}"
                )

                handle_token_request(
                    agent_socket,
                    request
                )

                continue

            policy_decision = (
                evaluate_request(request)
            )

            decision = (
                policy_decision["decision"]
            )

            print("\n[PDP DECISION]")
            print(
                f"Decision: {decision}"
            )

            print(
                f"Reason: "
                f"{policy_decision['reason']}"
            )

            append_audit_event(
                event_type="POLICY_DECISION",
                request=request,
                decision=decision,
                details=policy_decision
            )

            # =========================================
            # 3. DENY path
            # =========================================

            if decision == "DENY":

                print(
                    "[PEP ENFORCEMENT]"
                )

                print(
                    "Request BLOCKED."
                )

                print(
                    "Nothing will be forwarded "
                    "to the PLC."
                )

                denial_response = {
                    "status": "DENIED",

                    "request_id":
                        request.get(
                            "request_id"
                        ),

                    "policy":
                        policy_decision.get(
                            "denied_by"
                        ),

                    "reason":
                        policy_decision.get(
                            "reason"
                        )
                }

                append_audit_event(
                    event_type="REQUEST_BLOCKED",
                    request=request,
                    decision="DENY",
                    response=denial_response,
                    details={
                        "forwarded_to_resource":
                            False
                    }
                )

                send_message(
                    agent_socket,
                    denial_response
                )

                continue

            # =========================================
            # 4. ALLOW path
            # =========================================

            print(
                "[PEP ENFORCEMENT]"
            )

            print(
                "Request allowed."
            )

            print(
                "[GATEWAY]"
            )

            print(
                "Forwarding request "
                "to protected resource..."
            )

            send_message(
                resource_socket,
                request
            )

            # =========================================
            # 5. Receive PLC response
            # =========================================

            response = receive_message(
                resource_socket
            )

            print(
                "[RESOURCE RESPONSE]"
            )

            print(response)

            append_audit_event(
                event_type="RESOURCE_RESPONSE",
                request=request,
                decision="ALLOW",
                response=response,
                details={
                    "forwarded_to_resource":
                        True
                }
            )

            # =========================================
            # 6. Return response to Agent
            # =========================================

            send_message(
                agent_socket,
                response
            )

            print(
                "[GATEWAY]"
            )

            print(
                "Response returned to Agent."
            )

    except ConnectionError as error:

        print(
            f"\n[-] Connection closed: "
            f"{error}"
        )

    except Exception as error:

        print(
            f"\n[!] Gateway error: "
            f"{error}"
        )

    finally:

        agent_socket.close()

        if resource_socket is not None:
            resource_socket.close()

        print(
            "[-] Gateway session closed."
        )


def start_gateway():

    gateway_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    gateway_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    gateway_socket.bind(
        (
            GATEWAY_HOST,
            GATEWAY_PORT
        )
    )

    gateway_socket.listen(5)

    print("=" * 60)

    print(
        "AZT Agent Gateway / "
        "Policy Enforcement Point"
    )

    print("=" * 60)

    print(
        f"Listening for Agents on "
        f"{GATEWAY_HOST}:{GATEWAY_PORT}"
    )

    print(
        f"Protected Resource: "
        f"{RESOURCE_HOST}:{RESOURCE_PORT}"
    )

    print()

    print(
        "Enabled policy:"
    )

    print(
        "  - BPE v1 "
        "(Behavioral Persona Enforcement)"
    )

    print()

    while True:
        agent_socket, agent_address = (
            gateway_socket.accept()
        )

        agent_thread = threading.Thread(
            target=handle_agent,
            args=(
                agent_socket,
                agent_address
            ),
            daemon=True
        )

        agent_thread.start()

        print(
            f"[+] Active Gateway sessions: "
            f"{threading.active_count() - 1}"
        )

if __name__ == "__main__":
    start_gateway()