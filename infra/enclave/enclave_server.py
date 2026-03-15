"""
TAKE Enclave Server — runs INSIDE the Nitro Enclave.

Listens on vsock for key derivation requests.
The master key is loaded once at startup and NEVER leaves the enclave.

Protocol:
  Request:  JSON {"action": "derive", "id_u": "<base64 user ID>", "master_key_hex": "<hex>"}
  Response: JSON {"k1": <int_string>, "k2": <int_string>}

  The master_key_hex is only sent on the FIRST call (sealing).
  After that, the enclave holds it in memory.

Security:
  - Nitro Enclave has NO network access, NO persistent storage
  - Communication only via vsock (host ↔ enclave)
  - Even if host OS is compromised, enclave memory is isolated
"""

import json
import socket
import base64
from Crypto.Hash import SHA3_256

# ─────────────────────────────────────────────────────
# Crypto — must match server/crypto/primitives.py
# ─────────────────────────────────────────────────────

# Group order for RFC 3526 Group 14
Q = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)
GROUP_ORDER = (Q - 1) // 2


def H1(data: bytes) -> int:
    """H1: {0,1}* -> Z*q (identical to primitives.py)"""
    h = SHA3_256.new(data).digest()
    scalar = int.from_bytes(h, 'big') % GROUP_ORDER
    if scalar == 0:
        scalar = 1
    return scalar


def H2(data: bytes) -> int:
    """H2: {0,1}* -> Z*q (identical to primitives.py)"""
    h = SHA3_256.new(b"H2_domain" + data).digest()
    scalar = int.from_bytes(h, 'big') % GROUP_ORDER
    if scalar == 0:
        scalar = 1
    return scalar


# ─────────────────────────────────────────────────────
# Enclave vsock server
# ─────────────────────────────────────────────────────

VSOCK_PORT = 5005
VSOCK_CID_ANY = 0xFFFFFFFF  # VMADDR_CID_ANY

# Master key — held in enclave memory only
_master_key: bytes | None = None


def handle_request(data: dict) -> dict:
    """Process a key derivation request."""
    global _master_key

    action = data.get("action")

    if action == "seal":
        # First call: receive and store master key
        key_hex = data.get("master_key_hex")
        if not key_hex:
            return {"error": "Missing master_key_hex"}
        _master_key = bytes.fromhex(key_hex)
        if len(_master_key) != 32:
            return {"error": "Master key must be 32 bytes"}
        print("[enclave] Master key sealed.")
        return {"status": "sealed"}

    elif action == "derive":
        if _master_key is None:
            return {"error": "Master key not sealed yet"}

        id_u_b64 = data.get("id_u")
        if not id_u_b64:
            return {"error": "Missing id_u"}

        id_u = base64.b64decode(id_u_b64)

        k1 = H1(_master_key + id_u)
        k2 = H2(_master_key + id_u)

        return {
            "k1": str(k1),
            "k2": str(k2)
        }

    elif action == "health":
        return {
            "status": "ok",
            "sealed": _master_key is not None
        }

    else:
        return {"error": f"Unknown action: {action}"}


def main():
    """Listen on vsock for requests."""
    print(f"[enclave] TAKE TEE starting on vsock port {VSOCK_PORT}...")

    # AF_VSOCK = 40
    sock = socket.socket(40, socket.SOCK_STREAM)
    sock.bind((VSOCK_CID_ANY, VSOCK_PORT))
    sock.listen(5)

    print(f"[enclave] Listening for connections...")

    while True:
        conn, addr = sock.accept()
        try:
            raw = conn.recv(65536)
            if not raw:
                continue

            request = json.loads(raw.decode())
            response = handle_request(request)
            conn.sendall(json.dumps(response).encode())

        except Exception as e:
            error_resp = json.dumps({"error": str(e)})
            try:
                conn.sendall(error_resp.encode())
            except:
                pass
        finally:
            conn.close()


if __name__ == "__main__":
    main()
