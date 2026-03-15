"""
TAKE — Trusted Execution Environment (TEE) Module

Paper Section III-C / Section IV:
  All key-dependent operations happen inside the TEE.
  k1 and k2 NEVER leave the enclave — only computed results are returned.

Two modes:
    1. LOCAL mode (development):
       Master key loaded from TAKE_MASTER_KEY environment variable.
       k1/k2 derived and used locally. NOT secure for production.

    2. ENCLAVE mode (production):
       Master key lives inside a Nitro Enclave.
       Communication via vsock — host sends blinded values in,
       enclave computes results and returns them.
       k1 and k2 NEVER leave the enclave memory.

Set TAKE_USE_ENCLAVE=true to enable enclave mode.
"""

import os
import json
import socket
import base64
import subprocess
from server.crypto.primitives import H1, H2, mod_exp, GROUP_ORDER, Q
from Crypto.Hash import SHA3_256 as _SHA3
from typing import Optional

# ─────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────

USE_ENCLAVE = os.environ.get("TAKE_USE_ENCLAVE", "false").lower() == "true"
VSOCK_PORT = 5005

def get_enclave_cid() -> int:
    cid_str = os.environ.get("TAKE_ENCLAVE_CID", "")
    if cid_str:
        return int(cid_str)
    try:
        result = subprocess.run(["nitro-cli", "describe-enclaves"], capture_output=True, text=True)
        enclaves = json.loads(result.stdout)
        if enclaves:
            return enclaves[0]["EnclaveCID"]
    except Exception:
        pass
    return 16

VSOCK_CID = get_enclave_cid()

# ─────────────────────────────────────────────────────
# Local mode — Master key from environment
# ─────────────────────────────────────────────────────

_local_master_key: Optional[bytes] = None


def _get_local_master_key() -> bytes:
    """Load master key from environment variable (local/dev mode only)."""
    global _local_master_key
    if _local_master_key is None:
        key_hex = os.environ.get("TAKE_MASTER_KEY")
        if not key_hex:
            raise RuntimeError(
                "TAKE_MASTER_KEY is not set. "
                "Set it to a 28-char hex string (14 bytes). "
                "In production, use TAKE_USE_ENCLAVE=true instead."
            )
        _local_master_key = bytes.fromhex(key_hex)
        if len(_local_master_key) != 14:
            raise RuntimeError("TAKE_MASTER_KEY must be exactly 14 bytes (28 hex chars)")
    return _local_master_key


# ─────────────────────────────────────────────────────
# Enclave mode — vsock communication
# ─────────────────────────────────────────────────────

_master_key_sealed = False

def _enclave_request(payload: dict) -> dict:
    """Send a request to the Nitro Enclave via vsock."""
    global _master_key_sealed
    
    # Auto-seal master key on first request
    if USE_ENCLAVE and not _master_key_sealed and payload.get("action") != "seal" and payload.get("action") != "health":
        key_path = os.path.expanduser("~/.take_master_key")
        if os.path.exists(key_path):
            with open(key_path, "r") as f:
                mk_hex = f.read().strip()
            # Send seal request synchronously
            _enclave_request({
                "action": "seal",
                "master_key_hex": mk_hex
            })
            _master_key_sealed = True
            print("[TEE] Master key lazily sealed into enclave.")

    # AF_VSOCK = 40
    sock = socket.socket(40, socket.SOCK_STREAM)
    try:
        sock.settimeout(10)
        sock.connect((VSOCK_CID, VSOCK_PORT))
        sock.sendall(json.dumps(payload).encode())
        response = sock.recv(65536)
        result = json.loads(response.decode())
        if "error" in result:
            raise RuntimeError(f"Enclave error: {result['error']}")
        return result
    finally:
        sock.close()


def _to_bytes(id_u) -> bytes:
    """Ensure id_u is bytes."""
    return id_u.encode() if isinstance(id_u, str) else id_u


def _id_u_b64(id_u) -> str:
    """Encode id_u as base64 string for enclave protocol."""
    return base64.b64encode(_idu_4bytes(id_u)).decode()


def _idu_4bytes(id_u) -> bytes:
    """Derive 4-byte cryptographic IDU from username. Paper Table II: IDU = 32 bits."""
    raw = id_u.encode() if isinstance(id_u, str) else id_u
    return _SHA3.new(raw).digest()[:4]


# ─────────────────────────────────────────────────────
# Public API — TEE operations
#
# In enclave mode: blinded values go IN, results come OUT.
#                  k1 and k2 NEVER leave the enclave.
# In local mode:   Same logic, but computed in-process.
# ─────────────────────────────────────────────────────

def tee_register_oprf(id_u, blinded: int) -> int:
    """
    Registration OPRF: compute blinded^(k1 * k2^-1) mod Q.

    Paper Section IV, Registration step 3:
      "S computes k1 = H1(k||IDU), k2 = H2(k||IDU),
       and H0(pw||R)^(r*k1*k2^-1), where the operations
       are performed in TEE."
    """
    if USE_ENCLAVE:
        result = _enclave_request({
            "action": "register_oprf",
            "id_u": base64.b64encode(id_u).decode(),
            "blinded": str(blinded)
        })
        return int(result["result"])
    else:
        k = _get_local_master_key()
        id_bytes = id_u
        k1 = H1(k + id_bytes)
        k2 = H2(k + id_bytes)
        k2_inv = pow(k2, -1, GROUP_ORDER)
        exponent = (k1 * k2_inv) % GROUP_ORDER
        return mod_exp(blinded, exponent, Q)


def tee_auth_oprf(id_u, blinded: int) -> int:
    """
    Auth OPRF: compute blinded^k1 mod Q.

    Paper Section IV, Auth step 5:
      "S computes k1 = H1(k||IDU) and H0(pw||R)^(r'*k1),
       where the operations are performed in TEE."
    """
    if USE_ENCLAVE:
        result = _enclave_request({
            "action": "auth_oprf",
            "id_u": base64.b64encode(id_u).decode(),
            "blinded": str(blinded)
        })
        return int(result["result"])
    else:
        k = _get_local_master_key()
        id_bytes = id_u
        k1 = H1(k + id_bytes)
        return mod_exp(blinded, k1, Q)


def tee_auth_credential(id_u, credential: int) -> int:
    """
    Auth credential: compute C^k2 mod Q.

    Paper Section IV, Auth step 8:
      "S computes k2 = H2(k||IDU) and C' = C^k2,
       where the operations are performed in TEE."
    """
    if USE_ENCLAVE:
        result = _enclave_request({
            "action": "auth_credential",
            "id_u": base64.b64encode(id_u).decode(),
            "credential": str(credential)
        })
        return int(result["result"])
    else:
        k = _get_local_master_key()
        id_bytes = id_u
        k2 = H2(k + id_bytes)
        return mod_exp(credential, k2, Q)


def seal_master_key(master_key_hex: str) -> None:
    """
    Seal the master key into the Nitro Enclave.
    Only used in enclave mode during initial server setup.
    """
    if not USE_ENCLAVE:
        raise RuntimeError("seal_master_key only works in enclave mode")

    result = _enclave_request({
        "action": "seal",
        "master_key_hex": master_key_hex
    })
    if result.get("status") != "sealed":
        raise RuntimeError(f"Sealing failed: {result}")
    print("[TEE] Master key sealed in enclave.")


def health_check() -> dict:
    """Check enclave health (enclave mode only)."""
    if not USE_ENCLAVE:
        return {"mode": "local", "status": "ok"}

    return _enclave_request({"action": "health"})
