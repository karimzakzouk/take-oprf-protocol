"""
TAKE — Trusted Execution Environment (TEE) Module

Handles derivation of per-user keys k1 and k2 from the master key.
These keys are used in the OPRF step and credential encryption.

Paper Section III-C:
    k1 = H1(k || IDU)  — OPRF evaluation key
    k2 = H2(k || IDU)  — Credential decryption key

Two modes:
    1. LOCAL mode (development):
       Master key loaded from TAKE_MASTER_KEY environment variable.
       k1/k2 derived locally. NOT secure for production.

    2. ENCLAVE mode (production):
       Master key lives inside a Nitro Enclave.
       Communication via vsock — host sends IDU, enclave returns k1/k2.
       The master key NEVER leaves the enclave memory.

Set TAKE_USE_ENCLAVE=true to enable enclave mode.
"""

import os
import json
import socket
import base64
from server.crypto.primitives import H1, H2

from typing import Optional

# ─────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────

USE_ENCLAVE = os.environ.get("TAKE_USE_ENCLAVE", "false").lower() == "true"
VSOCK_PORT = 5005
VSOCK_CID = 16  # Default Nitro Enclave CID (assigned at launch)

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
                "Set it to a 64-char hex string (32 bytes). "
                "In production, use TAKE_USE_ENCLAVE=true instead."
            )
        _local_master_key = bytes.fromhex(key_hex)
        if len(_local_master_key) != 32:
            raise RuntimeError("TAKE_MASTER_KEY must be exactly 32 bytes (64 hex chars)")
    return _local_master_key


# ─────────────────────────────────────────────────────
# Enclave mode — vsock communication
# ─────────────────────────────────────────────────────

def _enclave_request(payload: dict) -> dict:
    """Send a request to the Nitro Enclave via vsock."""
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


def _derive_via_enclave(id_u: str) -> tuple:
    """Derive k1, k2 from the Nitro Enclave."""
    id_u_b64 = base64.b64encode(id_u.encode()).decode()
    result = _enclave_request({
        "action": "derive",
        "id_u": id_u_b64
    })
    k1 = int(result["k1"])
    k2 = int(result["k2"])
    return k1, k2


# ─────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────

def _to_bytes(id_u) -> bytes:
    """Ensure id_u is bytes."""
    return id_u.encode() if isinstance(id_u, str) else id_u


def derive_k1(id_u) -> int:
    """
    Derive k1 = H1(k || IDU) for user id_u.

    In local mode: derives directly from env var master key.
    In enclave mode: requests derivation from Nitro Enclave via vsock.
    """
    if USE_ENCLAVE:
        k1, _ = _derive_via_enclave(id_u if isinstance(id_u, str) else id_u.decode())
        return k1
    else:
        k = _get_local_master_key()
        return H1(k + _to_bytes(id_u))


def derive_k2(id_u) -> int:
    """
    Derive k2 = H2(k || IDU) for user id_u.

    In local mode: derives directly from env var master key.
    In enclave mode: requests derivation from Nitro Enclave via vsock.
    """
    if USE_ENCLAVE:
        _, k2 = _derive_via_enclave(id_u if isinstance(id_u, str) else id_u.decode())
        return k2
    else:
        k = _get_local_master_key()
        return H2(k + _to_bytes(id_u))


def derive_k1_k2(id_u) -> tuple:
    """
    Derive both k1 and k2 in a single call.
    More efficient in enclave mode (single vsock round-trip).
    """
    if USE_ENCLAVE:
        return _derive_via_enclave(id_u if isinstance(id_u, str) else id_u.decode())
    else:
        k = _get_local_master_key()
        id_bytes = _to_bytes(id_u)
        return H1(k + id_bytes), H2(k + id_bytes)


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
