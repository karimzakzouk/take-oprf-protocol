# ─────────────────────────────────────────────────────────────────
# TAKE Nitro Enclave — TEE Key Derivation
#
# This runs INSIDE the Nitro Enclave.
# It receives requests via vsock and derives k1/k2 from the
# master key. The master key NEVER leaves the enclave.
#
# Uses amazonlinux base image which is compatible with
# Nitro Enclave's init system.
# ─────────────────────────────────────────────────────────────────

FROM amazonlinux:2023

RUN dnf install -y python3 python3-pip && \
    pip3 install pycryptodome && \
    dnf clean all

WORKDIR /app

# Copy the enclave server script
COPY enclave_server.py /app/enclave_server.py

# Use absolute path — Nitro Enclaves can corrupt $PATH
ENTRYPOINT ["/usr/bin/python3", "/app/enclave_server.py"]
