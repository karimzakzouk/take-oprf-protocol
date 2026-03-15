"""
TAKE Server
Paper: "A Secure Two-Factor Authentication Key Exchange Scheme"
       Han et al., IEEE TDSC 2024
"""

import os
import json
import base64
import sqlite3
import hashlib
import time
from flask import Flask, request, jsonify, g
from server.crypto.primitives import (
    H3, H4, H5,
    concat,
    dh_keygen, dh_shared,
    mod_exp, Q
)
from server.tee import tee_register_oprf, tee_auth_oprf, tee_auth_credential

app = Flask(__name__)

DB_PATH = os.environ.get("TAKE_DB_PATH", "take_server.db")
TRAD_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "traditional_users.db")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

# Module-level connection used only for :memory: databases (tests)
_memory_conn = None


def get_db():
    global _memory_conn
    if DB_PATH == ":memory:":
        # Reuse single connection for in-memory db (tables persist for session)
        if _memory_conn is None:
            _memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            _memory_conn.row_factory = sqlite3.Row
        return _memory_conn
    # File-based db: cache per request using Flask g
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    # Only close file-based connections (not the shared :memory: one)
    if DB_PATH != ":memory:":
        db = g.pop("db", None)
        if db is not None:
            db.close()


def init_db():
    global _memory_conn
    if DB_PATH == ":memory:":
        # Reset memory db for clean test runs
        _memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
        _memory_conn.row_factory = sqlite3.Row
        conn = _memory_conn
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id_u        TEXT PRIMARY KEY,
            helper_p    BLOB NOT NULL,
            credential  TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS failed_attempts (
            id_u         TEXT PRIMARY KEY,
            count        INTEGER DEFAULT 0,
            last_attempt INTEGER DEFAULT 0
        )
    """)
    conn.commit()

    if DB_PATH != ":memory:":
        conn.close()

    # Also initialise traditional comparison DB
    if DB_PATH != ":memory:":
        trad_conn = sqlite3.connect(TRAD_DB_PATH)
        trad_conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                email         TEXT,
                created_at    INTEGER NOT NULL
            )
        """)
        trad_conn.commit()
        trad_conn.close()
        print(f"[server] Traditional DB initialised at {TRAD_DB_PATH}")

    print(f"[server] Database initialised at {DB_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64_decode(s: str) -> bytes:
    return base64.b64decode(s)

def int_to_b64(n: int) -> str:
    return b64_encode(n.to_bytes(256, 'big'))

def b64_to_int(s: str) -> int:
    return int.from_bytes(b64_decode(s), 'big')


def check_lockout(id_u: str) -> bool:
    conn = get_db()
    row = conn.execute(
        "SELECT count, last_attempt FROM failed_attempts WHERE id_u=?",
        (id_u,)
    ).fetchone()
    if row is None:
        return False
    if row["count"] >= MAX_FAILED_ATTEMPTS:
        elapsed = time.time() - row["last_attempt"]
        if elapsed < LOCKOUT_SECONDS:
            return True
        conn.execute("UPDATE failed_attempts SET count=0 WHERE id_u=?", (id_u,))
        conn.commit()
    return False


def record_failure(id_u: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO failed_attempts (id_u, count, last_attempt)
        VALUES (?, 1, ?)
        ON CONFLICT(id_u) DO UPDATE SET
            count = count + 1,
            last_attempt = ?
    """, (id_u, int(time.time()), int(time.time())))
    conn.commit()


def reset_failures(id_u: str):
    conn = get_db()
    conn.execute("UPDATE failed_attempts SET count=0 WHERE id_u=?", (id_u,))
    conn.commit()


# In-memory session store for pending auth exchanges
_pending_sessions = {}
SESSION_TIMEOUT = 60


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRATION
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/register/init", methods=["POST"])
def register_init():
    data = request.get_json()
    id_u        = data.get("id_u", "").encode()
    blinded_b64 = data.get("blinded_factor")

    if not id_u or not blinded_b64:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db()
    existing = conn.execute(
        "SELECT id_u FROM users WHERE id_u=?", (id_u.decode(),)
    ).fetchone()
    if existing:
        return jsonify({"error": "User already registered"}), 409

    blinded = b64_to_int(blinded_b64)

    # Paper: "the operations are performed in TEE"
    # blinded value goes IN, result comes OUT — k1/k2 never leave TEE
    oprf_response = tee_register_oprf(id_u, blinded)

    return jsonify({"oprf_response": int_to_b64(oprf_response)})


@app.route("/register/finalize", methods=["POST"])
def register_finalize():
    data           = request.get_json()
    id_u           = data.get("id_u", "")
    helper_p_b64   = data.get("helper_p")
    credential_b64 = data.get("credential_c")
    password_hash  = data.get("password_hash", "")

    if not id_u or not helper_p_b64 or not credential_b64:
        return jsonify({"error": "Missing fields"}), 400

    helper_p   = b64_decode(helper_p_b64)
    credential = credential_b64
    now        = int(time.time())

    conn = get_db()
    conn.execute(
        "INSERT INTO users (id_u, helper_p, credential, created_at) VALUES (?,?,?,?)",
        (id_u, helper_p, credential, now)
    )
    conn.commit()

    # Also store in traditional DB for demo comparison
    if password_hash and DB_PATH != ":memory:":
        try:
            trad_conn = sqlite3.connect(TRAD_DB_PATH)
            trad_conn.execute(
                "INSERT OR REPLACE INTO users (username, password_hash, email, created_at) VALUES (?,?,?,?)",
                (id_u, password_hash, f"{id_u}@email.com", now)
            )
            trad_conn.commit()
            trad_conn.close()
            print(f"[server] Also stored traditional hash for: {id_u}")
        except Exception as e:
            print(f"[server] Warning: traditional DB write failed: {e}")

    print(f"[server] Registered user: {id_u}")
    return jsonify({"status": "registered"})


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/auth/init", methods=["POST"])
def auth_init():
    data = request.get_json()
    id_u = data.get("id_u", "")

    if not id_u:
        return jsonify({"error": "Missing id_u"}), 400

    if check_lockout(id_u):
        return jsonify({"error": "Account locked. Too many failed attempts."}), 423

    conn = get_db()
    row = conn.execute(
        "SELECT helper_p FROM users WHERE id_u=?", (id_u,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"helper_p": b64_encode(row["helper_p"])})


@app.route("/auth/oprf", methods=["POST"])
def auth_oprf():
    data        = request.get_json()
    id_u        = data.get("id_u", "")
    blinded_b64 = data.get("blinded_factor")
    dh_X_b64    = data.get("dh_X")

    if not id_u or not blinded_b64 or not dh_X_b64:
        return jsonify({"error": "Missing fields"}), 400

    if check_lockout(id_u):
        return jsonify({"error": "Account locked."}), 423

    conn = get_db()
    row = conn.execute(
        "SELECT credential FROM users WHERE id_u=?", (id_u,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "User not found"}), 404

    blinded = b64_to_int(blinded_b64)
    X       = b64_to_int(dh_X_b64)

    # Paper: "the operations are performed in TEE"
    oprf_response = tee_auth_oprf(id_u.encode(), blinded)

    y, Y = dh_keygen()

    _pending_sessions[id_u] = {
        "y":         y,
        "Y":         Y,
        "X":         X,
        "timestamp": time.time()
    }

    return jsonify({
        "oprf_response": int_to_b64(oprf_response),
        "dh_Y":          int_to_b64(Y),
        "id_s":          "TAKE_SERVER_001"
    })


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    data       = request.get_json()
    id_u       = data.get("id_u", "")
    sigma1_b64 = data.get("sigma1")

    if not id_u or not sigma1_b64:
        return jsonify({"error": "Missing fields"}), 400

    if check_lockout(id_u):
        return jsonify({"error": "Account locked."}), 423

    session = _pending_sessions.get(id_u)
    if session is None:
        return jsonify({"error": "No pending session — call /auth/oprf first"}), 400

    if time.time() - session["timestamp"] > SESSION_TIMEOUT:
        del _pending_sessions[id_u]
        return jsonify({"error": "Session expired"}), 408

    sigma1 = b64_decode(sigma1_b64)
    y = session["y"]
    Y = session["Y"]
    X = session["X"]

    conn = get_db()
    row = conn.execute(
        "SELECT credential FROM users WHERE id_u=?", (id_u,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "User not found"}), 404

    C_stored = b64_to_int(row["credential"])
    # Paper: "S computes k2 and C' = C^k2, where the operations are performed in TEE"
    C        = tee_auth_credential(id_u.encode(), C_stored)
    shared   = dh_shared(y, X)

    id_u_bytes = id_u.encode()
    id_s_bytes = b"TAKE_SERVER_001"

    sigma1_expected = H3(concat(id_u_bytes, id_s_bytes, X, Y, shared, C))

    if sigma1 != sigma1_expected:
        record_failure(id_u)
        del _pending_sessions[id_u]
        return jsonify({"error": "Authentication failed — σ1 mismatch"}), 401

    reset_failures(id_u)
    del _pending_sessions[id_u]

    sigma2 = H4(concat(id_u_bytes, id_s_bytes, X, Y, shared, C))
    SK_S   = H5(concat(id_u_bytes, id_s_bytes, X, Y, shared, C))

    print(f"[server] Auth success for {id_u} — SK: {SK_S.hex()[:16]}...")

    return jsonify({
        "sigma2": b64_encode(sigma2),
        "status": "authenticated"
    })


# ─────────────────────────────────────────────────────────────────────────────
# Health check + entry point
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "server": "TAKE_SERVER_001"})


if __name__ == "__main__":
    init_db()
    host  = os.environ.get("TAKE_HOST", "0.0.0.0")
    port  = int(os.environ.get("TAKE_PORT", 5000))
    debug = os.environ.get("TAKE_DEBUG", "false").lower() == "true"
    print(f"[server] Starting TAKE server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)