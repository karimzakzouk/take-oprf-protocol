# ─────────────────────────────────────────────────────────────────
# TAKE Nitro Enclave — TEE Key Derivation
#
# This runs INSIDE the Nitro Enclave.
# It receives requests via vsock and derives k1/k2 from the
# master key. The master key NEVER leaves the enclave.
#
# Paper Section III-C + Section IV:
#   k1 = H1(k || IDU)   — used for OPRF blinding
#   k2 = H2(k || IDU)   — used for credential encryption
# ─────────────────────────────────────────────────────────────────

FROM python:3.11-slim

RUN pip install --no-cache-dir pycryptodome

WORKDIR /app

# Copy the enclave server script
COPY enclave_server.py /app/enclave_server.py

# The entrypoint runs the vsock server
ENTRYPOINT ["python3", "/app/enclave_server.py"]
