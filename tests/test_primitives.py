"""
Unit tests for TAKE cryptographic primitives.
Run with: pytest tests/test_primitives.py -v
"""

import pytest
import sys
import os
from Crypto.Hash import SHA3_256

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from server.crypto.primitives import (
    Q, G, GROUP_ORDER,
    H0, H1, H2, H3, H4, H5,
    concat,
    oprf_blind, oprf_server_eval, oprf_unblind,
    dh_keygen, dh_shared,
    combined_factor,
    mod_exp
)


# ─────────────────────────────────────────────────────────────────────────────
# Group parameter tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGroupParameters:
    def test_prime_size(self):
        """Q should be 2048-bit prime."""
        assert Q.bit_length() == 2048

    def test_generator(self):
        """Generator g=2 should be in the group."""
        assert G == 2
        assert 1 < G < Q

    def test_group_order(self):
        """Group order should be (Q-1)/2."""
        assert GROUP_ORDER == (Q - 1) // 2


# ─────────────────────────────────────────────────────────────────────────────
# Hash function tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHashFunctions:
    def test_H0_returns_group_element(self):
        """H0 should return an element in Z*q."""
        val = H0(b"test password")
        assert 1 <= val < Q

    def test_H0_deterministic(self):
        """Same input should always give same output."""
        assert H0(b"hello") == H0(b"hello")

    def test_H0_different_inputs(self):
        """Different inputs should give different outputs."""
        assert H0(b"password1") != H0(b"password2")

    def test_H1_returns_scalar(self):
        """H1 should return scalar in Z*q."""
        val = H1(b"master_key" + b"user_id")
        assert 1 <= val < GROUP_ORDER

    def test_H2_differs_from_H1(self):
        """H1 and H2 should produce different outputs for same input."""
        data = b"same_input"
        assert H1(data) != H2(data)

    def test_H3_output_length(self):
        """H3 (σ1) should be 28 bytes (SHA3-224)."""
        assert len(H3(b"test")) == 28

    def test_H4_output_length(self):
        """H4 (σ2) should be 28 bytes (SHA3-224)."""
        assert len(H4(b"test")) == 28

    def test_H5_output_length(self):
        """H5 (session key) should be 32 bytes (SHA3-256)."""
        assert len(H5(b"test")) == 32

    def test_H3_H4_differ(self):
        """H3 and H4 domain separated — should differ on same input."""
        data = b"same_input"
        assert H3(data) != H4(data)


# ─────────────────────────────────────────────────────────────────────────────
# OPRF tests
# ─────────────────────────────────────────────────────────────────────────────

class TestOPRF:
    def setup_method(self):
        """Set up test fixtures."""
        self.password = "testpassword123"
        self.R = b"secret_biometric_string_R_32byte"
        self.cf = combined_factor(self.password, self.R)
        # Fake server key k1 derived from master key
        self.k1 = H1(b"masterkey123" + b"user001")

    def test_blind_returns_valid_group_element(self):
        """Blinded value should be a valid group element."""
        blinded, r = oprf_blind(self.cf)
        assert 1 <= blinded < Q
        assert 1 <= r < GROUP_ORDER

    def test_blind_is_randomized(self):
        """Two blind calls on same input should give different results."""
        blinded1, _ = oprf_blind(self.cf)
        blinded2, _ = oprf_blind(self.cf)
        assert blinded1 != blinded2

    def test_full_oprf_round_trip(self):
        """
        Full OPRF: blind → server_eval → unblind
        Result should equal H0(pw||R)^k1 directly.
        """
        # Expected: H0(pw||R)^k1
        expected = mod_exp(self.cf, self.k1, Q)

        # OPRF protocol
        blinded, r = oprf_blind(self.cf)
        evaluated = oprf_server_eval(blinded, self.k1)
        result = oprf_unblind(evaluated, r)

        assert result == expected

    def test_oprf_server_learns_nothing(self):
        """
        Server only sees blinded value — two different inputs blinded
        with different r should be indistinguishable to server.
        This is a basic check, not a full ZK proof.
        """
        cf1 = combined_factor("password1", self.R)
        cf2 = combined_factor("password2", self.R)
        blinded1, _ = oprf_blind(cf1)
        blinded2, _ = oprf_blind(cf2)
        # Both are random-looking group elements — no structural difference
        assert blinded1 != blinded2
        assert 1 <= blinded1 < Q
        assert 1 <= blinded2 < Q


# ─────────────────────────────────────────────────────────────────────────────
# Diffie-Hellman tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffieHellman:
    def test_keygen_returns_valid_pair(self):
        """DH keygen should return (private, public) in correct ranges."""
        x, X = dh_keygen()
        assert 1 <= x < GROUP_ORDER
        assert 1 <= X < Q

    def test_public_key_formula(self):
        """Public key X should equal g^x mod Q."""
        x, X = dh_keygen()
        assert X == mod_exp(G, x, Q)

    def test_shared_secret_matches(self):
        """
        Core DH property: Y^x == X^y mod Q.
        Both sides must compute the same shared secret.
        """
        x, X = dh_keygen()
        y, Y = dh_keygen()

        shared_user   = dh_shared(x, Y)  # Y^x
        shared_server = dh_shared(y, X)  # X^y

        assert shared_user == shared_server

    def test_different_keypairs_different_secrets(self):
        """Different key pairs should give different secrets."""
        x1, X1 = dh_keygen()
        x2, X2 = dh_keygen()
        y,  Y  = dh_keygen()

        assert dh_shared(x1, Y) != dh_shared(x2, Y)


# ─────────────────────────────────────────────────────────────────────────────
# Combined factor tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCombinedFactor:
    def test_returns_group_element(self):
        """Combined factor should be a group element."""
        cf = combined_factor("mypassword", b"biometric_R")
        assert 1 <= cf < Q

    def test_password_change_changes_factor(self):
        """Different password → different combined factor."""
        R = b"same_R_value"
        cf1 = combined_factor("password1", R)
        cf2 = combined_factor("password2", R)
        assert cf1 != cf2

    def test_R_change_changes_factor(self):
        """Different R → different combined factor."""
        pw = "samepassword"
        cf1 = combined_factor(pw, b"R_value_one")
        cf2 = combined_factor(pw, b"R_value_two")
        assert cf1 != cf2

    def test_deterministic(self):
        """Same password + R → always same combined factor."""
        pw = "mypassword"
        R = b"my_biometric_R"
        assert combined_factor(pw, R) == combined_factor(pw, R)


# ─────────────────────────────────────────────────────────────────────────────
# Full TAKE protocol mini-simulation
# Tests the crypto layer end to end before adding networking
# ─────────────────────────────────────────────────────────────────────────────

class TestTAKEProtocolCrypto:
    def test_full_authentication_flow(self):
        """
        Simulate the full TAKE crypto flow from paper Section IV.
        No networking — just verifies all math is correct.
        """
        # ── Setup ──────────────────────────────────────────
        IDU = (1).to_bytes(4, 'big')
        IDS = b"server001"
        password = "mySecurePassword!"
        R = b"biometric_secret_R_value_here_32"  # from fuzzy extractor
        master_key = b"secret_key_14b"  # 14 bytes exactly

        # Server derives k1 and k2 from master key
        k1 = H1(master_key + IDU)
        k2 = H2(master_key + IDU)

        # ── Registration ───────────────────────────────────
        cf = combined_factor(password, R)

        # User blinds combined factor
        blinded_reg, r_reg = oprf_blind(cf)

        # Server computes H0(pw||R)^(r * k1 * k2^-1) inside TEE
        k2_inv = pow(k2, -1, GROUP_ORDER)
        k1_k2inv = (k1 * k2_inv) % GROUP_ORDER
        server_response_reg = mod_exp(blinded_reg, k1_k2inv, Q)

        # User removes r to get C = H0(pw||R)^(k1*k2^-1)
        r_inv = pow(r_reg, -1, GROUP_ORDER)
        C = mod_exp(server_response_reg, r_inv, Q)

        # Expected C = H0(pw||R)^(k1*k2^-1)
        expected_C = mod_exp(cf, k1_k2inv, Q)
        assert C == expected_C, "Registration: C computation failed"

        # ── Authentication + Key Exchange ──────────────────
        # User blinds again with fresh r'
        blinded_auth, r_prime = oprf_blind(cf)

        # Server applies k1 inside TEE
        evaluated_auth = oprf_server_eval(blinded_auth, k1)

        # DH keypairs
        x, X = dh_keygen()
        y, Y = dh_keygen()

        # User unblinds to get C' = H0(pw||R)^k1
        C_prime = oprf_unblind(evaluated_auth, r_prime)
        expected_C_prime = mod_exp(cf, k1, Q)
        assert C_prime == expected_C_prime, "Auth: C' computation failed"

        # Server computes C from stored credential
        # C_stored = H0(pw||R)^(k1*k2^-1), so C = C_stored^k2 = H0(pw||R)^k1
        C_server = mod_exp(C, k2, Q)
        assert C_server == C_prime, "Auth: C_server != C_prime"

        # DH shared secrets
        shared_user   = dh_shared(x, Y)  # Y^x
        shared_server = dh_shared(y, X)  # X^y
        assert shared_user == shared_server, "DH shared secrets differ"

        # Compute σ1 and verify
        sigma1 = H3(concat(IDU, IDS, X, Y, shared_user, C_prime))
        sigma1_server = H3(concat(IDU, IDS, X, Y, shared_server, C_server))
        assert sigma1 == sigma1_server, "σ1 verification failed"

        # Compute σ2 and verify
        sigma2 = H4(concat(IDU, IDS, X, Y, shared_server, C_server))
        sigma2_user = H4(concat(IDU, IDS, X, Y, shared_user, C_prime))
        assert sigma2 == sigma2_user, "σ2 verification failed"

        # Compute session keys
        SKU = H5(concat(IDU, IDS, X, Y, shared_user,   C_prime))
        SKS = H5(concat(IDU, IDS, X, Y, shared_server, C_server))
        assert SKU == SKS, "Session keys do not match!"

        print(f"\n✓ Full TAKE protocol crypto verified")
        print(f"  Session key (hex): {SKU.hex()[:32]}...")
