"""
TAKE Cryptographic Primitives
Paper: "A Secure Two-Factor Authentication Key Exchange Scheme"
       Han et al., IEEE TDSC 2024

Implements exactly:
  - Cyclic group G with 2048-bit prime q
  - H0: {0,1}* -> G  (hash to group element)
  - H1, H2: {0,1}* -> Z*q  (hash to scalar)
  - H3, H4, H5: SHA-3 256-bit hashes
  - OPRF: blind / server_eval / unblind
  - Diffie-Hellman: keygen / shared_secret
"""

import hashlib
import os
from Crypto.Hash import SHA3_256, SHA3_224

# ─────────────────────────────────────────────────────────────────────────────
# GROUP PARAMETERS (2048-bit, 112-bit security — matches paper Section VI)
# Using RFC 3526 Group 14 (well-known, safe prime)
# ─────────────────────────────────────────────────────────────────────────────

# 2048-bit MODP Group prime (RFC 3526)
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

# Generator
G = 2

# Group order (for RFC 3526 group 14, order = (Q-1)/2)
GROUP_ORDER = (Q - 1) // 2


def mod_exp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation."""
    return pow(base, exp, mod)


# ─────────────────────────────────────────────────────────────────────────────
# HASH FUNCTIONS (Section IV, Setup phase)
# ─────────────────────────────────────────────────────────────────────────────

def H0(data: bytes) -> int:
    """
    H0: {0,1}* -> G
    Hash data to a group element in Z*q.
    Uses hash-to-group: hash the input, map to G via exponentiation.
    """
    h = SHA3_256.new(data).digest()
    # Map to group element: interpret hash as integer, raise g to that power
    scalar = int.from_bytes(h, 'big') % GROUP_ORDER
    if scalar == 0:
        scalar = 1
    return mod_exp(G, scalar, Q)


def H1(data: bytes) -> int:
    """
    H1: {0,1}* -> Z*q
    Hash data to a scalar in Z*q (used to derive k1 from master key).
    """
    h = SHA3_256.new(data).digest()
    scalar = int.from_bytes(h, 'big') % GROUP_ORDER
    if scalar == 0:
        scalar = 1
    return scalar


def H2(data: bytes) -> int:
    """
    H2: {0,1}* -> Z*q
    Hash data to a scalar in Z*q (used to derive k2 from master key).
    """
    # Use a different domain separator to distinguish from H1
    h = SHA3_256.new(b"H2_domain" + data).digest()
    scalar = int.from_bytes(h, 'big') % GROUP_ORDER
    if scalar == 0:
        scalar = 1
    return scalar


def H3(data: bytes) -> bytes:
    """H3: {0,1}* -> {0,1}^224  (SHA3-224, used for σ1 authenticator)"""
    return SHA3_224.new(data).digest()


def H4(data: bytes) -> bytes:
    """H4: {0,1}* -> {0,1}^224  (SHA3-224, used for σ2 authenticator)"""
    return SHA3_224.new(b"H4_domain" + data).digest()


def H5(data: bytes) -> bytes:
    """H5: {0,1}* -> {0,1}^256  (SHA3-256, used for session key SK)"""
    return SHA3_256.new(b"H5_domain" + data).digest()


def concat(*args) -> bytes:
    """
    Concatenate multiple values (int or bytes) into bytes.
    Each int is encoded as 256-byte big-endian to avoid ambiguity.
    """
    result = b""
    for a in args:
        if isinstance(a, int):
            result += a.to_bytes(256, 'big')
        elif isinstance(a, bytes):
            result += a
        elif isinstance(a, str):
            result += a.encode()
        else:
            raise TypeError(f"concat: unsupported type {type(a)}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# OPRF — Oblivious Pseudorandom Function (Section III-B + Section IV)
#
# Protocol:
#   1. User: choose random r, compute blinded = H0(pw||R)^r  mod Q
#   2. Server: compute evaluated = blinded^k1  mod Q  (inside TEE)
#   3. User: compute unblinded = evaluated^(r_inv)  mod Q
#            = H0(pw||R)^(r * k1 * r_inv) = H0(pw||R)^k1
# ─────────────────────────────────────────────────────────────────────────────

def oprf_blind(combined_factor: int) -> tuple[int, int]:
    """
    User side: blind the combined factor H0(pw||R).
    Returns (blinded_value, r) where r is the secret blinding factor.
    """
    r = int.from_bytes(os.urandom(32), 'big') % GROUP_ORDER
    if r == 0:
        r = 1
    blinded = mod_exp(combined_factor, r, Q)
    return blinded, r


def oprf_server_eval(blinded: int, k1: int) -> int:
    """
    Server side: apply server key k1 to blinded value (runs inside TEE).
    Returns: blinded^k1 mod Q
    """
    return mod_exp(blinded, k1, Q)


def oprf_unblind(evaluated: int, r: int) -> int:
    """
    User side: remove blinding factor r to get H0(pw||R)^k1.
    Computes r_inv = modular inverse of r, then evaluated^r_inv.
    """
    r_inv = pow(r, -1, GROUP_ORDER)
    return mod_exp(evaluated, r_inv, Q)


# ─────────────────────────────────────────────────────────────────────────────
# DIFFIE-HELLMAN KEY EXCHANGE (Section IV)
#
# Paper: X = g^x, Y = g^y, shared = Y^x = X^y = g^xy
# ─────────────────────────────────────────────────────────────────────────────

def dh_keygen() -> tuple[int, int]:
    """
    Generate ephemeral DH keypair.
    Returns (private_x, public_X) where X = g^x mod Q.
    """
    x = int.from_bytes(os.urandom(32), 'big') % GROUP_ORDER
    if x == 0:
        x = 1
    X = mod_exp(G, x, Q)
    return x, X


def dh_shared(private: int, public_other: int) -> int:
    """
    Compute shared DH secret.
    User computes: Y^x mod Q
    Server computes: X^y mod Q
    Both equal g^xy mod Q.
    """
    return mod_exp(public_other, private, Q)


# ─────────────────────────────────────────────────────────────────────────────
# COMBINED FACTOR  H0(pw || R)
# ─────────────────────────────────────────────────────────────────────────────

def combined_factor(password: str, R: bytes) -> int:
    """
    Compute H0(pw || R) — the combined biometric+password factor.
    This is the core input to the OPRF.
    """
    data = password.encode() + R
    return H0(data)
