"""
TAKE Server Integration Tests
Run with: pytest tests/test_server.py -v
"""

import pytest
import sys
import os
import base64
from Crypto.Hash import SHA3_256

os.environ["TAKE_MASTER_KEY"] = "a" * 28
os.environ["TAKE_DB_PATH"]    = ":memory:"

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
    init_db()
    with app.test_client() as c:
        yield c


@pytest.fixture
def registered_user(client):
    """Register a test user and return their credentials."""
    id_u     = "testuser01"
    password = "SecurePass123!"
    bio      = bytes(range(128))

    R, P = Gen(bio)
    cf = combined_factor(password, R)
    blinded, r = oprf_blind(cf)

    resp = client.post("/register/init", json={
        "id_u":           id_u,
        "blinded_factor": int_to_b64(blinded)
    })
    assert resp.status_code == 200
    C = oprf_unblind(b64_to_int(resp.get_json()["oprf_response"]), r)

    resp2 = client.post("/register/finalize", json={
        "id_u":         id_u,
        "helper_p":     b64e(P),
        "credential_c": int_to_b64(C)
    })
    assert resp2.status_code == 200
    user_id = resp2.get_json()["user_id"]
    idu_bytes = user_id.to_bytes(4, 'big')
    return {"id_u": id_u, "password": password, "bio": bio, "R": R, "P": P, "idu_bytes": idu_bytes}


# ─────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────

class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"


# ─────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_register_new_user(self, client):
        id_u     = "newuser01"
        password = "mypassword"
        bio      = bytes(range(128))
        R, P     = Gen(bio)
        cf       = combined_factor(password, R)
        blinded, r = oprf_blind(cf)

        resp = client.post("/register/init", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded)
        })
        assert resp.status_code == 200
        C = oprf_unblind(b64_to_int(resp.get_json()["oprf_response"]), r)

        resp2 = client.post("/register/finalize", json={
            "id_u":         id_u,
            "helper_p":     b64e(P),
            "credential_c": int_to_b64(C)
        })
        assert resp2.status_code == 200
        assert resp2.get_json()["status"] == "registered"

    def test_duplicate_registration_fails(self, client, registered_user):
        resp = client.post("/register/init", json={
            "id_u":           registered_user["id_u"],
            "blinded_factor": int_to_b64(123456)
        })
        assert resp.status_code == 409

    def test_missing_fields_fail(self, client):
        resp = client.post("/register/init", json={"id_u": "only_id"})
        assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────

class TestAuthentication:
    def test_auth_init_returns_helper_p(self, client, registered_user):
        resp = client.post("/auth/init", json={"id_u": registered_user["id_u"]})
        assert resp.status_code == 200
        assert "helper_p" in resp.get_json()

    def test_auth_init_unknown_user(self, client):
        resp = client.post("/auth/init", json={"id_u": "nobody"})
        assert resp.status_code == 404

    def test_full_auth_flow(self, client, registered_user):
        """Full authentication + key exchange — verifies both sides get the same SK."""
        id_u     = registered_user["id_u"]
        password = registered_user["password"]
        R        = registered_user["R"]
        P        = registered_user["P"]

        # Step 1: get P
        resp = client.post("/auth/init", json={"id_u": id_u})
        assert resp.status_code == 200
        assert b64d(resp.get_json()["helper_p"]) == P

        # Step 2: combined factor + blind + DH keygen
        cf = combined_factor(password, R)
        blinded, r_prime = oprf_blind(cf)
        x, X = dh_keygen()

        # Step 3: OPRF exchange
        resp2 = client.post("/auth/oprf", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded),
            "dh_X":           int_to_b64(X)
        })
        assert resp2.status_code == 200
        data2  = resp2.get_json()
        Y      = b64_to_int(data2["dh_Y"])
        id_s   = data2["id_s"].encode()

        # Step 4: unblind → C'
        C_prime = oprf_unblind(b64_to_int(data2["oprf_response"]), r_prime)

        # Step 5: DH shared secret + σ1
        shared  = dh_shared(x, Y)
        sigma1  = H3(concat(registered_user["idu_bytes"], id_s, X, Y, shared, C_prime))

        # Step 6: send σ1, get σ2
        resp3 = client.post("/auth/verify", json={
            "id_u":   id_u,
            "sigma1": b64e(sigma1)
        })
        assert resp3.status_code == 200, f"Auth failed: {resp3.get_json()}"
        assert resp3.get_json()["status"] == "authenticated"
        sigma2 = b64d(resp3.get_json()["sigma2"])

        # Step 7: verify σ2
        sigma2_expected = H4(concat(registered_user["idu_bytes"], id_s, X, Y, shared, C_prime))
        assert sigma2 == sigma2_expected, "σ2 verification failed"

        # Step 8: derive session key
        SK = H5(concat(registered_user["idu_bytes"], id_s, X, Y, shared, C_prime))
        assert len(SK) == 32
        print(f"\n  Session key: {SK.hex()[:32]}...")

    def test_wrong_password_fails(self, client, registered_user):
        """Wrong password → wrong C' → σ1 mismatch → 401."""
        id_u = registered_user["id_u"]
        R    = registered_user["R"]

        client.post("/auth/init", json={"id_u": id_u})

        cf = combined_factor("WRONG_PASSWORD", R)
        blinded, r_prime = oprf_blind(cf)
        x, X = dh_keygen()

        resp = client.post("/auth/oprf", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded),
            "dh_X":           int_to_b64(X)
        })
        data    = resp.get_json()
        C_prime = oprf_unblind(b64_to_int(data["oprf_response"]), r_prime)
        Y       = b64_to_int(data["dh_Y"])
        id_s    = data["id_s"].encode()
        shared  = dh_shared(x, Y)
        sigma1  = H3(concat(registered_user["idu_bytes"], id_s, X, Y, shared, C_prime))

        resp3 = client.post("/auth/verify", json={
            "id_u":   id_u,
            "sigma1": b64e(sigma1)
        })
        assert resp3.status_code == 401

    def test_lockout_after_max_failures(self, client, registered_user):
        """Account locks after MAX_FAILED_ATTEMPTS failed attempts."""
        from server.app import MAX_FAILED_ATTEMPTS
        id_u = registered_user["id_u"]
        R    = registered_user["R"]

        for _ in range(MAX_FAILED_ATTEMPTS):
            cf = combined_factor("WRONG", R)
            blinded, r_prime = oprf_blind(cf)
            x, X = dh_keygen()

            client.post("/auth/init", json={"id_u": id_u})
            resp   = client.post("/auth/oprf", json={
                "id_u":           id_u,
                "blinded_factor": int_to_b64(blinded),
                "dh_X":           int_to_b64(X)
            })
            data   = resp.get_json()
            C_p    = oprf_unblind(b64_to_int(data["oprf_response"]), r_prime)
            Y      = b64_to_int(data["dh_Y"])
            id_s   = data["id_s"].encode()
            shared = dh_shared(x, Y)
            s1     = H3(concat(registered_user["idu_bytes"], id_s, X, Y, shared, C_p))
            client.post("/auth/verify", json={"id_u": id_u, "sigma1": b64e(s1)})

        resp = client.post("/auth/init", json={"id_u": id_u})
        assert resp.status_code == 423

    def test_replay_fails(self, client, registered_user):
        """Replaying a captured σ1 should fail — session is single-use."""
        id_u     = registered_user["id_u"]
        password = registered_user["password"]
        R        = registered_user["R"]

        client.post("/auth/init", json={"id_u": id_u})
        cf = combined_factor(password, R)
        blinded, r_prime = oprf_blind(cf)
        x, X = dh_keygen()

        resp  = client.post("/auth/oprf", json={
            "id_u":           id_u,
            "blinded_factor": int_to_b64(blinded),
            "dh_X":           int_to_b64(X)
        })
        data    = resp.get_json()
        C_prime = oprf_unblind(b64_to_int(data["oprf_response"]), r_prime)
        Y       = b64_to_int(data["dh_Y"])
        id_s    = data["id_s"].encode()
        shared  = dh_shared(x, Y)
        sigma1  = H3(concat(registered_user["idu_bytes"], id_s, X, Y, shared, C_prime))

        resp1 = client.post("/auth/verify", json={"id_u": id_u, "sigma1": b64e(sigma1)})
        assert resp1.status_code == 200

        resp2 = client.post("/auth/verify", json={"id_u": id_u, "sigma1": b64e(sigma1)})
        assert resp2.status_code == 400