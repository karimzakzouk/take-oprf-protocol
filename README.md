# TAKE — Two-Factor Authentication Key Exchange

A complete, production-grade implementation of the **TAKE** protocol from:

> "A Secure Two-Factor Authentication Key Exchange Scheme"  
> *IEEE Transactions on Dependable and Secure Computing*, Vol. 21, No. 6, pp. 5681–5693, 2024.  
> Han, Y., Xu, C., Jiang, C., & Chen, K. — [DOI: 10.1109/TDSC.2024.3382359](https://doi.org/10.1109/TDSC.2024.3382359)
---

## What is TAKE?

TAKE is a two-factor authentication key exchange protocol that combines a user's **password** and **biometrics** into a single blinded credential, protected by a Trusted Execution Environment on the server. Unlike standard 2FA, TAKE establishes a full cryptographic session key between client and server — meaning authentication and secure channel setup happen in a single protocol run.

The three properties that make it interesting:

- **The server never sees the password or biometric** — the combined factor is blinded via an Oblivious Pseudorandom Function (OPRF) before it ever reaches the server
- **Stealing the server database yields nothing** — credentials are 2048-bit group elements whose derivation requires keys that live exclusively inside a hardware TEE
- **No clock synchronisation needed** — freshness is guaranteed by per-session random values, not timestamps

---

## Architecture

```
┌──────────────────────────────────┐              ┌────────────────────────────────────────┐
│          Android Client          │              │             AWS EC2 Server             │
│                                  │              │                                        │
│  Biometric Layer                 │              │  Flask REST API                        │
│  ┌──────────────────────────┐    │   HTTPS/TLS  │  ┌──────────────────────────────────┐  │
│  │ Face Mode                │    │ ◄──────────► │  │ /register/init                   │  │
│  │ MobileFaceNet (TFLite)   │    │              │  │ /register/finalize               │  │
│  │ + Fuzzy Extractor        │    │              │  │ /auth/init                       │  │
│  │ Gen(bio) -> (R, P)       │    │              │  │ /auth/oprf                       │  │
│  │ Rep(bio', P) -> R        │    │              │  │ /auth/verify                     │  │
│  ├──────────────────────────┤    │              │  └───────────────┬──────────────────┘  │
│  │ Fingerprint Mode         │    │              │                  │ vsock only          │
│  │ Android Keystore (TEE)   │    │              │  ┌───────────────▼──────────────────┐  │
│  │ BiometricPrompt          │    │              │  │   AWS Nitro Enclave (TEE)        │  │
│  └──────────────────────────┘    │              │  │                                  │  │
│                                  │              │  │  k1 = H1(k || IDu)               │  │
│  Crypto Layer                    │              │  │  k2 = H2(k || IDu)               │  │
│  ┌──────────────────────────┐    │              │  │                                  │  │
│  │ TakeCrypto.kt            │    │              │  │  All key-dependent modular       │  │
│  │ OPRF + DH                │    │              │  │  exponentiations run here.       │  │
│  │ H0-H5 (SHA-3)            │    │              │  │  k1 and k2 never leave           │  │
│  │ 2048-bit RFC 3526 group  │    │              │  │  enclave memory.                 │  │
│  │ Bouncy Castle            │    │              │  └──────────────────────────────────┘  │
│  └──────────────────────────┘    │              │                                        │
└──────────────────────────────────┘              └────────────────────────────────────────┘
```

---

## Authentication Modes

The app ships with two biometric modes, selectable from the UI.

### Face Mode — Paper-Faithful
Implements the protocol exactly as specified in the paper. A **MobileFaceNet** TFLite model runs entirely on-device and extracts a compact, discriminative facial representation. This feeds into a **cryptographic fuzzy extractor** (XOR secure sketch + SHA-3) that derives the blinding factor R from the biometric — tolerating natural intra-class variation of up to ~17% bit-flip noise between scans.

### Fingerprint Mode — Hardware TEE
Stores R inside the **Android hardware Keystore**, protected by `BiometricPrompt` fingerprint authentication. The Android Keystore is itself a hardware TEE, satisfying the same client-side isolation assumptions the paper makes. This mode is faster and more practical for deployment.

---

## Server TEE — AWS Nitro Enclaves

The paper specifies Intel SGX to protect the master key `k`. This project substitutes SGX with **AWS Nitro Enclaves**, which provide equivalent hardware isolation guarantees in a cloud-native environment.

What runs inside the enclave:
- The master key `k` is sealed at startup and never written to host memory
- Per-user key derivation: `k1 = H1(k || IDu)` and `k2 = H2(k || IDu)`
- All modular exponentiations that depend on `k1` or `k2`
- Communication is exclusively via vsock — the enclave has no network interface

An attacker with full root access on the EC2 host cannot read enclave memory, cannot intercept vsock traffic, and cannot recover `k1` or `k2`.

---

## Protocol Summary

The implementation follows the paper across three phases.

**Setup** — Public parameters include a 2048-bit safe prime `q` (RFC 3526 Group 14), generator `g = 2`, hash functions `H0: {0,1}* -> G`, `H1, H2: {0,1}* -> Z*q`, and `H3, H4, H5` as SHA-3 instances. The fuzzy extractor `(Gen, Rep)` is parameterised for the chosen biometric space.

**Registration** — The client runs `Gen(bio)` to obtain `(R, P)`, computes the combined factor `H0(pw || R)`, and blinds it with a fresh random scalar before sending to the server. The server evaluates the OPRF inside the enclave and returns the blinded result. The client removes the blinding factor to obtain credential `C`, then sends `{IDu, P, C}` for storage.

**Authentication and Key Exchange** — The client retrieves `P`, runs `Rep(bio', P)` to recover `R`, recomputes the combined factor, and initiates a fresh OPRF exchange alongside a Diffie-Hellman public key `X = g^x`. The server responds with its DH public key `Y = g^y` and the OPRF-evaluated value. Both sides compute the shared DH secret `g^xy`, derive authenticators `sigma1` and `sigma2` for mutual verification, and independently compute the session key `SK = H5(IDu || IDs || X || Y || g^xy || C')`.

---

## Security Properties

| Goal | Mechanism |
|------|-----------|
| No password exposure | Password is never transmitted; OPRF blinds it client-side before any server interaction |
| Offline guessing resistance | Credentials require `k1 * k2^-1` from the enclave — brute force is computationally infeasible without it |
| Replay resistance | Per-session fresh random `r'`; sessions are single-use and expire server-side |
| Mutual authentication | `sigma1` lets the server verify the client; `sigma2` lets the client verify the server |
| Forward secrecy | Session key includes ephemeral DH value `g^xy`; compromise of long-term keys does not expose past sessions |
| Server breach safety | Stolen database plus full root access yields only OPRF-blinded group elements — uncrackable without the enclave-held `k1`, `k2` |

The formal security proof, under the random oracle model and the Computational Diffie-Hellman assumption, is given in Section V of the paper.

---

## Live Breach Demonstration

`demo/server_breach_demo.py` is a real penetration testing script. It SSHs into the active AWS deployment, exfiltrates both a traditional SHA-256 credential database and the TAKE database, then runs **John the Ripper** and **Hashcat** with the `rockyou.txt` wordlist against both.

The result is the same every time: traditional password hashes can be cracked. TAKE credentials cannot be parsed by either tool — they are 2048-bit OPRF-blinded group elements, and the derivation factors `k1`, `k2` remain locked inside the Nitro Enclave regardless of how the host is compromised.

```bash
export TAKE_SERVER_IP=<your-ec2-ip>
export TAKE_SSH_KEY=./infra/my-key.pem
python3 demo/server_breach_demo.py
```
When a user registers through the Android app, their credentials are automatically saved to **two separate databases** on the server:

- `traditional_users.db` — stores a plain `SHA256(password)`, the way most apps work
- `take_server.db` — stores the OPRF-blinded credential from the TAKE protocol

This makes the breach demo a direct, side-by-side comparison on real data from the same users.
---

## Getting Started

### Prerequisites
- AWS account with EC2 access
- Terraform >= 1.0
- Android Studio
- Python 3.11+

### 1. Deploy Infrastructure

```bash
cd infra/
terraform init
terraform apply -var="key_name=<your-key-pair>"
```

Provisions an `m5.xlarge` EC2 instance with Nitro Enclaves enabled, builds the enclave image, and starts the server automatically.

### 2. Run Server Locally (Development)

```bash
# Terminal 1 — enclave process
export TAKE_ENCLAVE_CID=16
python -m infra.enclave.enclave_server

# Terminal 2 — Flask API
export TAKE_USE_ENCLAVE=true
export TAKE_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
python -m server.app
```

### 3. Build and Install the Android App

```bash
cd android/
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Note

Before building the Android app, update the server IP in `RegisterActivity.kt`:
```kotlin
const val DEFAULT_SERVER_URL = "http://<your-ec2-ip>:5000"
```
---

## Running Tests

```bash
source venv/bin/activate
export TAKE_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
pytest tests/ -v
```

The test suite covers cryptographic primitives, the fuzzy extractor, and full end-to-end registration and authentication flows including attack scenarios (wrong password, replay, account lockout).

---

## Paper Reference

> Yunxia Han, Chunxiang Xu, Changsong Jiang, Kefei Chen.
> "A Secure Two-Factor Authentication Key Exchange Scheme."
> *IEEE Transactions on Dependable and Secure Computing*, Vol. 21, No. 6, pp. 5681–5693, November/December 2024.
> DOI: [10.1109/TDSC.2024.3382359](https://doi.org/10.1109/TDSC.2024.3382359)

The paper is published by IEEE and is available via institutional access on IEEE Xplore. It is not redistributed in this repository. This is an independent academic implementation for educational and verification purposes only.

---

## License

MIT — see [LICENSE](LICENSE) for details.