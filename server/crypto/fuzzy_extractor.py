"""
TAKE Fuzzy Extractor — Corrected Implementation
Paper: "A Secure Two-Factor Authentication Key Exchange Scheme"
       Han et al., IEEE TDSC 2024 — Section III-A
       Fuzzy extractor definition: Dodis et al. [45], SIAM J. Comput. 2008

Implements:
  Gen(bio) -> (R, P)
  Rep(bio', P) -> R

Construction:
  Secure sketch using BCH syndrome (Dodis et al. code-offset construction).

  Previous version was WRONG — it stored sketch = bio XOR pad(nonce),
  which is just masked encryption of bio, not a real secure sketch.
  Recovery worked by unmasking bio directly, with zero error correction.

  This version stores sketch = syn(bio), the BCH syndrome of bio.
  Recovery computes syn(bio') XOR syn(bio) = syn(e) (error syndrome),
  then runs BCH decoding (Berlekamp-Massey + Chien search) to find
  error positions e, corrects bio' -> bio, then re-derives R = H(nonce||bio).

BCH parameters:
  - GF(2^10), primitive polynomial x^10 + x^3 + 1 = 0x409
  - Code length n = 2^10 - 1 = 1023 bits
  - Error correction capability t = 24 bit-flips
  - Syndrome size = 2t * 2 bytes = 96 bytes (48 GF elements x 2 bytes each)

Biometric layout:
  - Input: 128 bytes = 1024 bits
  - BCH operates on first 1023 bits (BCH_N = 2^10 - 1)
  - Extra bit (index 1023) is packed into the LSB of nonce[31]
  - P = nonce (32 bytes, LSB of last byte encodes extra bit)
      + syndrome (96 bytes)
      = 128 bytes = 1024 bits total  [matches paper Table II]

Secret R:
  - R = SHA3-256(nonce || bio) -- 32 bytes
"""

import os
import hashlib
import numpy as np


# -----------------------------------------------------------------------------
# GF(2^10) arithmetic
# Primitive polynomial: x^10 + x^3 + 1 = 0x409
# -----------------------------------------------------------------------------

_GF_M    = 10
_GF_SIZE = 1 << _GF_M        # 1024
_GF_POLY = 0x409             # x^10 + x^3 + 1
BCH_N    = _GF_SIZE - 1      # 1023 -- BCH code length
BCH_T    = 24                # error correction capability (up to 24 bit-flips)

_gf_exp = [0] * (2 * _GF_SIZE)
_gf_log = [0] * _GF_SIZE


def _build_gf_tables() -> None:
    x = 1
    for i in range(BCH_N):
        _gf_exp[i] = x
        _gf_log[x] = i
        x <<= 1
        if x & _GF_SIZE:
            x ^= _GF_POLY
    for i in range(BCH_N, 2 * _GF_SIZE):
        _gf_exp[i] = _gf_exp[i - BCH_N]


_build_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _gf_exp[(_gf_log[a] + _gf_log[b]) % BCH_N]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF inverse of zero")
    return _gf_exp[BCH_N - _gf_log[a]]


# -----------------------------------------------------------------------------
# BCH syndrome computation
#
# For BCH with roots alpha^1, alpha^2, ..., alpha^(2t):
#   S_i = sum_{j=0}^{n-1} bits[j] * alpha^(i*j)
#
# Key property -- linearity:
#   syn(a XOR b) = syn(a) XOR syn(b)
# Therefore:
#   syn(bio') XOR syn(bio) = syn(bio' XOR bio) = syn(error_pattern)
# -----------------------------------------------------------------------------

def _compute_syndromes(bits: list[int], t: int = BCH_T) -> list[int]:
    """
    Compute 2t BCH syndromes for a binary vector of length BCH_N.
    Returns list of 2t elements in GF(2^10).
    """
    syndromes = []
    for i in range(1, 2 * t + 1):
        s = 0
        for j in range(len(bits)):
            if bits[j]:
                s ^= _gf_exp[(i * j) % BCH_N]
        syndromes.append(s)
    return syndromes


# -----------------------------------------------------------------------------
# Berlekamp-Massey algorithm
# Given 2t syndromes, finds the shortest LFSR (error locator polynomial sigma)
# whose degree equals the number of errors.
# -----------------------------------------------------------------------------

def _berlekamp_massey(syndromes: list[int]) -> list[int]:
    """
    Input:  list of 2t syndrome values in GF(2^10)
    Output: error locator polynomial sigma as coefficient list,
            sigma[0]=1, len(sigma)-1 = number of errors found
    """
    n = len(syndromes)
    C = [1]   # current connection polynomial
    B = [1]   # previous connection polynomial
    L = 0     # current LFSR length
    m = 1     # steps since last update
    b = 1     # leading discrepancy at last update

    for i in range(n):
        d = syndromes[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= _gf_mul(C[j], syndromes[i - j])

        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            coeff = _gf_mul(d, _gf_inv(b))
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= _gf_mul(coeff, B[j])
            L = i + 1 - L
            B = T
            b = d
            m = 1
        else:
            coeff = _gf_mul(d, _gf_inv(b))
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= _gf_mul(coeff, B[j])
            m += 1

    return C


# -----------------------------------------------------------------------------
# Chien search
# Evaluates sigma at every element of GF(2^10).
# alpha^(-j) is a root of sigma iff bit position j is an error location.
# -----------------------------------------------------------------------------

def _chien_search(sigma: list[int]) -> list[int]:
    """
    Input:  error locator polynomial (GF(2^10) coefficients)
    Output: list of error bit positions (0-indexed, 0 .. BCH_N-1)
    """
    errors = []
    for i in range(BCH_N):
        val = 0
        for j, coeff in enumerate(sigma):
            val ^= _gf_mul(coeff, _gf_exp[(j * (BCH_N - i)) % BCH_N])
        if val == 0:
            errors.append(i)
    return errors


# -----------------------------------------------------------------------------
# BCH decode: error syndrome -> corrected bit positions
# -----------------------------------------------------------------------------

def _bch_decode_error_syndrome(syn_error: list[int]) -> list[int]:
    """
    Given error syndrome syn(bio') XOR syn(bio) = syn(e), recover
    the list of bit positions where errors (bit-flips) occurred.

    Raises ValueError if errors exceed BCH_T (uncorrectable).
    """
    if all(s == 0 for s in syn_error):
        return []  # no errors

    sigma      = _berlekamp_massey(syn_error)
    num_errors = len(sigma) - 1

    if num_errors > BCH_T:
        raise ValueError(
            f"Uncorrectable: {num_errors} errors exceed BCH_T={BCH_T}"
        )

    errors = _chien_search(sigma)

    if len(errors) != num_errors:
        raise ValueError(
            f"Chien search found {len(errors)} roots, expected {num_errors} -- "
            f"biometric too different or helper string corrupted"
        )

    return errors


# -----------------------------------------------------------------------------
# Syndrome serialization
# 2t = 48 GF(2^10) elements, each stored as 2 bytes -> 96 bytes total
# -----------------------------------------------------------------------------

_SYN_ELEM_BYTES = 2                            # GF(2^10) max value is 1023, fits in 2 bytes
_SYN_BYTES      = 2 * BCH_T * _SYN_ELEM_BYTES  # 96 bytes


def _syn_to_bytes(syn: list[int]) -> bytes:
    result = bytearray()
    for elem in syn:
        result += elem.to_bytes(_SYN_ELEM_BYTES, 'big')
    return bytes(result)


def _bytes_to_syn(b: bytes) -> list[int]:
    return [
        int.from_bytes(b[i:i + _SYN_ELEM_BYTES], 'big')
        for i in range(0, len(b), _SYN_ELEM_BYTES)
    ]


# -----------------------------------------------------------------------------
# Bio encoding helpers
# -----------------------------------------------------------------------------

BIO_BYTES = 128
BIO_BITS  = BIO_BYTES * 8  # 1024 bits


def _bio_to_bits(bio: bytes) -> list[int]:
    bits = []
    for byte in bio:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bio(bits: list[int]) -> bytes:
    """Convert exactly BIO_BITS bits back to BIO_BYTES bytes."""
    result = bytearray()
    for i in range(0, BIO_BITS, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def _hamming_distance(a: bytes, b: bytes) -> int:
    """Compute bit-level Hamming distance between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError(f"Length mismatch: {len(a)} vs {len(b)}")
    distance = 0
    for x, y in zip(a, b):
        distance += bin(x ^ y).count('1')
    return distance


# -----------------------------------------------------------------------------
# PUBLIC API: Gen and Rep
#
# P layout (128 bytes total):
#   [ nonce: 32 bytes, LSB of byte[31] encodes extra_bit ]
#   [ syndrome: 96 bytes                                  ]
#
# The extra_bit (bio[1023], the 1024th bit) is packed into the LSB of the
# last nonce byte. The nonce remains effectively random (255 bits of entropy).
# -----------------------------------------------------------------------------

_P_NONCE_BYTES = 32
_P_SYN_BYTES   = _SYN_BYTES  # 96
_P_TOTAL       = _P_NONCE_BYTES + _P_SYN_BYTES  # 128 bytes = 1024 bits (matches paper Table II)

TOLERANCE = BCH_T  # 24 -- maximum correctable bit-flips


def Gen(bio: bytes) -> tuple[bytes, bytes]:
    """
    Generation algorithm -- Dodis et al. [45] code-offset secure sketch.

    Input:  bio  -- biometric bitstring (128 bytes)
    Output: (R, P)
        R -- secret string (32 bytes), used as H0(pw||R) in TAKE
        P -- public helper string (128 bytes = 1024 bits), stored on server

    P contains only the BCH syndrome of bio, leaking at most
    2t * log2(GF_SIZE) = 640 bits of structural information -- significantly
    less than the old XOR-mask implementation which stored bio directly.
    """
    if len(bio) != BIO_BYTES:
        raise ValueError(f"Expected {BIO_BYTES}-byte biometric, got {len(bio)}")

    bits      = _bio_to_bits(bio)   # 1024 bits
    bch_bits  = bits[:BCH_N]        # first 1023 bits -- BCH input
    extra_bit = bits[BCH_N]         # bit 1023 -- packed into nonce LSB

    # Random nonce with extra_bit in LSB of last byte
    raw_nonce     = bytearray(os.urandom(_P_NONCE_BYTES))
    raw_nonce[31] = (raw_nonce[31] & 0xFE) | extra_bit
    nonce         = bytes(raw_nonce)

    syn   = _compute_syndromes(bch_bits)
    syn_b = _syn_to_bytes(syn)

    # R is never stored -- re-derived from bio during Rep
    R = hashlib.sha3_256(nonce + bio).digest()

    P = nonce + syn_b
    return R, P


def Rep(bio_prime: bytes, P: bytes) -> bytes:
    """
    Reproduction algorithm -- Dodis et al. [45] code-offset construction.

    Input:  bio_prime -- new biometric scan (may differ slightly from original)
            P         -- public helper string from Gen
    Output: R         -- same secret as Gen iff Hamming(bio, bio') <= TOLERANCE

    Raises:
        ValueError if biometric difference exceeds TOLERANCE=24 bits
    """
    if len(bio_prime) != BIO_BYTES:
        raise ValueError(f"Expected {BIO_BYTES}-byte biometric, got {len(bio_prime)}")
    if len(P) != _P_TOTAL:
        raise ValueError(
            f"Malformed helper string P: expected {_P_TOTAL} bytes, got {len(P)}"
        )

    nonce      = P[:_P_NONCE_BYTES]
    syn_b      = P[_P_NONCE_BYTES:]
    extra_bit  = nonce[31] & 1         # recover packed bit from nonce LSB
    syn_stored = _bytes_to_syn(syn_b)  # syn(bio)

    bits_prime = _bio_to_bits(bio_prime)
    bch_bits_p = bits_prime[:BCH_N]
    syn_prime  = _compute_syndromes(bch_bits_p)

    # syn(bio') XOR syn(bio) = syn(error_pattern)  [by linearity]
    syn_error = [a ^ b for a, b in zip(syn_prime, syn_stored)]

    try:
        error_positions = _bch_decode_error_syndrome(syn_error)
    except ValueError as exc:
        raise ValueError(
            f"Biometric too different -- authentication failed. {exc}"
        ) from exc

    corrected_bits = bch_bits_p[:]
    for pos in error_positions:
        corrected_bits[pos] ^= 1

    recovered_bio = _bits_to_bio(corrected_bits + [extra_bit])

    R = hashlib.sha3_256(nonce + recovered_bio).digest()
    return R


# -----------------------------------------------------------------------------
# Utility: simulate biometric noise (for testing)
# -----------------------------------------------------------------------------

def add_noise(bio: bytes, n_flips: int = 10) -> bytes:
    """
    Simulate biometric noise by flipping n_flips random bits.
    Rep succeeds only when n_flips <= TOLERANCE (=24).
    No upper bound is enforced here -- callers testing failure paths
    can pass n_flips > TOLERANCE intentionally.
    """
    bits      = _bio_to_bits(bio)
    positions = np.random.choice(len(bits), n_flips, replace=False)
    for pos in positions:
        bits[pos] ^= 1
    return _bits_to_bio(bits)