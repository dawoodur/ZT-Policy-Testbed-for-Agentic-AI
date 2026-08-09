import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from pathlib import Path

import jwt


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)

JIT_CONFIG_FILE = (
    PROJECT_ROOT
    / "config"
    / "jit_config.json"
)

AGENT_CREDENTIALS_FILE = (
    PROJECT_ROOT
    / "config"
    / "agent_credentials.json"
)

SIGNING_KEY_FILE = (
    PROJECT_ROOT
    / "config"
    / "jit_signing_key.txt"
)

USED_JTI_FILE = (
    PROJECT_ROOT
    / "logs"
    / "used_jti.json"
)


key_lock = threading.Lock()
jti_lock = threading.Lock()


def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def get_signing_key():
    """
    Load or create the Gateway's JIT signing key.
    """

    with key_lock:

        if not SIGNING_KEY_FILE.exists():

            key = secrets.token_urlsafe(64)

            SIGNING_KEY_FILE.write_text(
                key,
                encoding="utf-8"
            )

            return key

        return SIGNING_KEY_FILE.read_text(
            encoding="utf-8"
        ).strip()


def parameters_hash(parameters):
    """
    Bind a token to the exact requested parameters.
    """

    canonical = json.dumps(
        parameters or {},
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def authenticate_bootstrap(
    agent_id,
    supplied_secret
):
    """
    Verify the Agent's bootstrap credential.
    """

    credentials = load_json(
        AGENT_CREDENTIALS_FILE
    )

    agent_record = credentials.get(
        agent_id
    )

    if not agent_record:
        return False

    expected_secret = agent_record.get(
        "bootstrap_secret",
        ""
    )

    return hmac.compare_digest(
        str(supplied_secret),
        str(expected_secret)
    )


def issue_jit_token(request):
    """
    Issue a short-lived signed credential bound to:
      - Agent identity
      - action
      - resource
      - parameters
    """

    config = load_json(
        JIT_CONFIG_FILE
    )

    issuer = config.get(
        "issuer",
        "azt-gateway"
    )

    ttl_seconds = config.get(
        "ttl_seconds",
        15
    )

    now = int(time.time())

    jti = str(uuid.uuid4())

    payload = {
        "iss": issuer,

        "sub": request["agent_id"],

        "aud": request["resource"],

        "action": request["action"],

        "parameters_hash":
            parameters_hash(
                request.get(
                    "parameters",
                    {}
                )
            ),

        "iat": now,

        "exp": now + ttl_seconds,

        "jti": jti
    }

    token = jwt.encode(
        payload,
        get_signing_key(),
        algorithm="HS256"
    )

    return {
        "token": token,
        "jti": jti,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "ttl_seconds": ttl_seconds
    }


def load_used_jtis():

    if not USED_JTI_FILE.exists():
        return {}

    try:

        return load_json(
            USED_JTI_FILE
        )

    except json.JSONDecodeError:

        return {}


def save_used_jtis(state):

    USED_JTI_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        USED_JTI_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            state,
            file,
            indent=2
        )


def consume_jti(jti):
    """
    Atomically mark a token identifier as used.

    Returns False if it has already been consumed.
    """

    with jti_lock:

        state = load_used_jtis()

        if jti in state:

            return False

        state[jti] = {
            "used_at": int(time.time())
        }

        save_used_jtis(state)

        return True


def evaluate_jit(request):
    """
    Validate the JIT credential attached to an action.
    """

    token = request.get(
        "token"
    )

    if not token:

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "TOKEN_MISSING",
            "reason": "No JIT credential supplied."
        }

    config = load_json(
        JIT_CONFIG_FILE
    )

    issuer = config.get(
        "issuer",
        "azt-gateway"
    )

    resource = request.get(
        "resource"
    )

    try:

        payload = jwt.decode(
            token,
            get_signing_key(),
            algorithms=["HS256"],
            audience=resource,
            issuer=issuer
        )

    except jwt.ExpiredSignatureError:

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "TOKEN_EXPIRED",
            "reason": "JIT credential has expired."
        }

    except jwt.InvalidTokenError as error:

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "INVALID_TOKEN",
            "reason": (
                f"JIT credential validation failed: "
                f"{error}"
            )
        }

    # ---------------------------------------------
    # Identity binding
    # ---------------------------------------------

    if payload.get("sub") != request.get(
        "agent_id"
    ):

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "IDENTITY_MISMATCH",
            "reason": (
                "Token identity does not match "
                "request identity."
            )
        }

    # ---------------------------------------------
    # Action binding
    # ---------------------------------------------

    if payload.get("action") != request.get(
        "action"
    ):

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "ACTION_MISMATCH",
            "reason": (
                "Token was issued for a different action."
            )
        }

    # ---------------------------------------------
    # Parameter binding
    # ---------------------------------------------

    expected_parameters_hash = (
        parameters_hash(
            request.get(
                "parameters",
                {}
            )
        )
    )

    if (
        payload.get("parameters_hash")
        != expected_parameters_hash
    ):

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "PARAMETER_MISMATCH",
            "reason": (
                "Token was issued for different "
                "operation parameters."
            )
        }

    # ---------------------------------------------
    # Replay protection
    # ---------------------------------------------

    jti = payload.get(
        "jti"
    )

    if not jti:

        return {
            "allowed": False,
            "policy": "JIT",
            "violation": "JTI_MISSING",
            "reason": (
                "Credential does not contain "
                "a token identifier."
            )
        }

    if config.get(
        "single_use",
        True
    ):

        if not consume_jti(jti):

            return {
                "allowed": False,
                "policy": "JIT",
                "violation": "TOKEN_REPLAY",
                "reason": (
                    "JIT credential has already "
                    "been used."
                )
            }

    return {
        "allowed": True,
        "policy": "JIT",
        "violation": None,
        "reason": (
            "JIT credential is valid and "
            "operation-bound."
        ),
        "jti": jti,
        "expires_at": payload.get(
            "exp"
        )
    }