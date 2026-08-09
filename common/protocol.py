import json
import struct


HEADER_SIZE = 4


def recv_exact(sock, size):
    """
    Receive exactly 'size' bytes from a TCP socket.
    """
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")

        data += chunk

    return data


def send_message(sock, message):
    """
    Convert a Python dictionary to JSON and send it
    using a 4-byte length-prefixed protocol.
    """
    payload = json.dumps(message).encode("utf-8")

    header = struct.pack("!I", len(payload))

    sock.sendall(header + payload)


def receive_message(sock):
    """
    Receive one complete length-prefixed JSON message.
    """
    header = recv_exact(sock, HEADER_SIZE)

    message_length = struct.unpack("!I", header)[0]

    payload = recv_exact(sock, message_length)

    return json.loads(payload.decode("utf-8"))