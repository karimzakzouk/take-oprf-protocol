"""
TAKE Enclave Server — runs INSIDE the Nitro Enclave.

Listens on vsock for requests. The master key is loaded once at
startup and NEVER leaves the enclave.

SECURITY: k1 and k2 are derived AND used inside the enclave.
The host never sees k1 or k2. It sends blinded group elements in
and receives computed results back — nothing else.

Operations performed inside the enclave (per the paper):
  Registration:  blinded^(k1 * k2^-1) mod Q
  Auth OPRF:     blinded^k1 mod Q
  Auth Verify:   C^k2 mod Q

Protocol:
  Request:  JSON {"action": "...", ...}
  Response: JSON {"result": "...", ...}
"""

import json
import socket
import base64
from Crypto.Hash import SHA3_256

# ─────────────────────────────────────────────────────
# Crypto — must match server/crypto/primitives.py
# ─────────────────────────────────────────────────────

# 2048-bit MODP Group prime (RFC 3526 Group 14)
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


def mod_exp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation."""
    return pow(base, exp, mod)


# ─────────────────────────────────────────────────────
# Enclave vsock server
# ─────────────────────────────────────────────────────

VSOCK_PORT = 5005
VSOCK_CID_ANY = 0xFFFFFFFF  # VMADDR_CID_ANY

# Master key — held in enclave memory only
_master_key = None


def _derive_keys(id_u: bytes):
    """Derive k1, k2 from master key + user ID. NEVER exported."""
    global _master_key
    if _master_key is None:
        raise RuntimeError("Master key not initialized")
    k1 = H1(_master_key + id_u)
    k2 = H2(_master_key + id_u)
    return k1, k2


def handle_request(data: dict) -> dict:
    """Process a request — all crypto stays inside the enclave."""
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

    elif action == "register_oprf":
        # Registration: compute blinded^(k1 * k2^-1) mod Q
        # Paper: "the operations are performed in TEE"
        if _master_key is None:
            return {"error": "Master key not sealed yet"}

        id_u = base64.b64decode(data.get("id_u", ""))
        blinded = int(data.get("blinded", "0"))

        k1, k2 = _derive_keys(id_u)
        k2_inv = pow(k2, -1, GROUP_ORDER)
        exponent = (k1 * k2_inv) % GROUP_ORDER
        result = mod_exp(blinded, exponent, Q)

        return {"result": str(result)}

    elif action == "auth_oprf":
        # Auth OPRF: compute blinded^k1 mod Q
        # Paper: "S computes k1 = H1(k||IDU) and H0(pw||R)^(r'*k1),
        #         where the operations are performed in TEE"
        if _master_key is None:
            return {"error": "Master key not sealed yet"}

        id_u = base64.b64decode(data.get("id_u", ""))
        blinded = int(data.get("blinded", "0"))

        k1, _ = _derive_keys(id_u)
        result = mod_exp(blinded, k1, Q)

        return {"result": str(result)}

    elif action == "auth_credential":
        # Auth verify: compute C^k2 mod Q
        # Paper: "S computes k2 = H2(k||IDU) and C' = C^k2,
        #         where the operations are performed in TEE"
        if _master_key is None:
            return {"error": "Master key not sealed yet"}

        id_u = base64.b64decode(data.get("id_u", ""))
        credential = int(data.get("credential", "0"))

        _, k2 = _derive_keys(id_u)
        result = mod_exp(credential, k2, Q)

        return {"result": str(result)}

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
