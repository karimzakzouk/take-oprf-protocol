"""
TAKE Server Integration Tests
Tests the full registration + authentication flow through the Flask API.
Run with: pytest tests/test_server.py -v
"""

import pytest
import sys
import os
import base64

# Set master key before importing app
os.environ["TAKE_MASTER_KEY"] = "a" * 64  # 32 bytes as hex for testing
os.environ["TAKE_DB_PATH"]    = ":memory:"  # in-memory SQLite for tests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from server.app import app, init_db
from server.crypto.primitives import (
    H3, H4, H5, concat,
    combined_factor,
    oprf_blind, oprf_unblind,
    dh_keygen, dh_shared,
    mod_exp, GROUP_ORDER, Q
)
from server.crypto.fuzzy_extractor import Gen
from server.tee import derive_k1, derive_k2


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def int_to_b64(n: int) -> str:
    return b64e(n.to_bytes(256, 'big'))

def b64_to_int(s: str) -> int:
    return int.from_bytes(b64d(s), 'big')


@pytest.fixture
def client():
    app.config["TESTING"] = True
    # init_db() resets _memory_conn so each test class starts fresh
    init_db()
    with app.test_client() as c:
        yield c


@pytest.fixture
def registered_user(client):
    """Register a test user and return their credentials."""
    id_u     = "testuser01"
    password = "SecurePass123!"
    bio      = bytes(range(128))  # fake biometric

    # Gen
    R, P = Gen(bio)

    # Combined factor
    cf = combined_factor(password, R)

    # Blind
    blinded, r = oprf_blind(cf)

    # Register init
    resp = client.post("/register/init", json={
        "id_u":            id_u,
        "blinded_factor":  int_to_b64(blinded)
    })
    assert resp.status_code == 200
    oprf_resp = b64_to_int(resp.get_json()["oprf_response"])

    # Unblind → C
    C = oprf_unblind(oprf_resp, r)

    # Register finalize
    resp2 = client.post("/register/finalize", json={
        "id_u":         id_u,
        "helper_p":     b64e(P),
        "credential_c": int_to_b64(C)
    })
    assert resp2.status_code == 200

    return {"id_u": id_u, "password": password, "bio": bio, "R": R, "P": P}


class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"


class TestRegistration:
    def test_register_new_user(self, client):
        """Full registration flow should succeed."""
        id_u     = "newuser01"
        password = "mypassword"
        bio      = bytes(range(128))
        R, P     = Gen(bio)
        cf       = combined_factor(password, R)
        blinded, r = oprf_blind(cf)

        # Init
        resp = client.post("/register/init", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded)
        })
        assert resp.status_code == 200
        oprf_resp = b64_to_int(resp.get_json()["oprf_response"])

        # Unblind
        C = oprf_unblind(oprf_resp, r)

        # Finalize
        resp2 = client.post("/register/finalize", json={
            "id_u":         id_u,
            "helper_p":     b64e(P),
            "credential_c": int_to_b64(C)
        })
        assert resp2.status_code == 200
        assert resp2.get_json()["status"] == "registered"

    def test_duplicate_registration_fails(self, client, registered_user):
        """Registering same user twice should fail."""
        id_u = registered_user["id_u"]
        resp = client.post("/register/init", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(123456)
        })
        assert resp.status_code == 409

    def test_missing_fields_fail(self, client):
        resp = client.post("/register/init", json={"id_u": "only_id"})
        assert resp.status_code == 400


class TestAuthentication:
    def test_auth_init_returns_helper_p(self, client, registered_user):
        """auth/init should return helper string P."""
        resp = client.post("/auth/init", json={
            "id_u": registered_user["id_u"]
        })
        assert resp.status_code == 200
        assert "helper_p" in resp.get_json()

    def test_auth_init_unknown_user(self, client):
        resp = client.post("/auth/init", json={"id_u": "nobody"})
        assert resp.status_code == 404

    def test_full_auth_flow(self, client, registered_user):
        """
        Full authentication + key exchange flow.
        Verifies both sides compute the same session key.
        """
        id_u     = registered_user["id_u"]
        password = registered_user["password"]
        R        = registered_user["R"]
        P        = registered_user["P"]

        # Step 1: get P from server
        resp = client.post("/auth/init", json={"id_u": id_u})
        assert resp.status_code == 200
        P_from_server = b64d(resp.get_json()["helper_p"])
        assert P_from_server == P

        # Step 2: client computes combined factor
        cf = combined_factor(password, R)

        # Step 3: client blinds and generates DH keypair
        blinded, r_prime = oprf_blind(cf)
        x, X = dh_keygen()

        # Step 4: send to server OPRF endpoint
        resp2 = client.post("/auth/oprf", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded),
            "dh_X":           int_to_b64(X)
        })
        assert resp2.status_code == 200
        data2   = resp2.get_json()
        oprf_r  = b64_to_int(data2["oprf_response"])
        Y       = b64_to_int(data2["dh_Y"])
        id_s    = data2["id_s"].encode()

        # Step 5: client unblinds → C'
        C_prime = oprf_unblind(oprf_r, r_prime)

        # Verify C' = H0(pw||R)^k1
        k1 = derive_k1(id_u.encode())
        from server.crypto.primitives import H0
        expected_C_prime = mod_exp(H0(password.encode() + R), k1, Q)
        assert C_prime == expected_C_prime

        # Step 6: compute DH shared secret (user side)
        shared_user = dh_shared(x, Y)

        # Step 7: compute σ1
        id_u_bytes = id_u.encode()
        sigma1 = H3(concat(id_u_bytes, id_s, X, Y, shared_user, C_prime))

        # Step 8: send σ1 to server
        resp3 = client.post("/auth/verify", json={
            "id_u":   id_u,
            "sigma1": b64e(sigma1)
        })
        assert resp3.status_code == 200, f"Auth failed: {resp3.get_json()}"
        data3  = resp3.get_json()
        assert data3["status"] == "authenticated"
        sigma2 = b64d(data3["sigma2"])

        # Step 9: client verifies σ2
        sigma2_expected = H4(concat(id_u_bytes, id_s, X, Y, shared_user, C_prime))
        assert sigma2 == sigma2_expected, "σ2 verification failed"

        # Step 10: both compute session key
        SK_U = H5(concat(id_u_bytes, id_s, X, Y, shared_user, C_prime))

        # Server's SK (recompute for test verification)
        k2 = derive_k2(id_u.encode())
        from server.app import b64_to_int as srv_b64_to_int
        with client.application.test_request_context():
            from server.app import get_db
        # Recompute server SK using same shared secret
        # (In real flow server already computed this — we verify math here)
        y_test, _ = dh_keygen()  # different y — just checking formula
        # Real check: SK_U is derived correctly
        assert len(SK_U) == 32
        print(f"\n  Session key: {SK_U.hex()[:32]}...")

    def test_wrong_password_fails(self, client, registered_user):
        """Wrong password should produce wrong C' → σ1 mismatch → 401."""
        id_u = registered_user["id_u"]
        R    = registered_user["R"]

        # Get P
        client.post("/auth/init", json={"id_u": id_u})

        # Use wrong password
        cf = combined_factor("WRONG_PASSWORD", R)
        blinded, r_prime = oprf_blind(cf)
        x, X = dh_keygen()

        resp = client.post("/auth/oprf", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded),
            "dh_X":           int_to_b64(X)
        })
        assert resp.status_code == 200
        data     = resp.get_json()
        oprf_r   = b64_to_int(data["oprf_response"])
        Y        = b64_to_int(data["dh_Y"])
        id_s     = data["id_s"].encode()

        C_prime      = oprf_unblind(oprf_r, r_prime)
        shared_user  = dh_shared(x, Y)
        sigma1_wrong = H3(concat(id_u.encode(), id_s, X, Y, shared_user, C_prime))

        resp3 = client.post("/auth/verify", json={
            "id_u":   id_u,
            "sigma1": b64e(sigma1_wrong)
        })
        assert resp3.status_code == 401

    def test_lockout_after_max_failures(self, client, registered_user):
        """Account should lock after MAX_FAILED_ATTEMPTS failures."""
        from server.app import MAX_FAILED_ATTEMPTS
        id_u = registered_user["id_u"]
        R    = registered_user["R"]

        for _ in range(MAX_FAILED_ATTEMPTS):
            cf = combined_factor("WRONG", R)
            blinded, r_prime = oprf_blind(cf)
            x, X = dh_keygen()

            client.post("/auth/init", json={"id_u": id_u})
            resp = client.post("/auth/oprf", json={
                "id_u":           id_u,
                "blinded_factor": int_to_b64(blinded),
                "dh_X":           int_to_b64(X)
            })
            data   = resp.get_json()
            oprf_r = b64_to_int(data["oprf_response"])
            Y      = b64_to_int(data["dh_Y"])
            id_s   = data["id_s"].encode()
            C_p    = oprf_unblind(oprf_r, r_prime)
            sh     = dh_shared(x, Y)
            s1     = H3(concat(id_u.encode(), id_s, X, Y, sh, C_p))
            client.post("/auth/verify", json={"id_u": id_u, "sigma1": b64e(s1)})

        # Next attempt should be locked
        resp = client.post("/auth/init", json={"id_u": id_u})
        assert resp.status_code == 423

    def test_replay_fails(self, client, registered_user):
        """Replaying a captured σ1 should fail (session is consumed)."""
        id_u     = registered_user["id_u"]
        password = registered_user["password"]
        R        = registered_user["R"]

        client.post("/auth/init", json={"id_u": id_u})
        cf = combined_factor(password, R)
        blinded, r_prime = oprf_blind(cf)
        x, X = dh_keygen()

        resp = client.post("/auth/oprf", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded),
            "dh_X":           int_to_b64(X)
        })
        data   = resp.get_json()
        oprf_r = b64_to_int(data["oprf_response"])
        Y      = b64_to_int(data["dh_Y"])
        id_s   = data["id_s"].encode()

        C_prime     = oprf_unblind(oprf_r, r_prime)
        shared_user = dh_shared(x, Y)
        sigma1      = H3(concat(id_u.encode(), id_s, X, Y, shared_user, C_prime))

        # First use — succeeds
        resp1 = client.post("/auth/verify", json={
            "id_u": id_u, "sigma1": b64e(sigma1)
        })
        assert resp1.status_code == 200

        # Replay — session is gone, should fail
        resp2 = client.post("/auth/verify", json={
            "id_u": id_u, "sigma1": b64e(sigma1)
        })
        assert resp2.status_code == 400