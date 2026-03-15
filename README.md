# TAKE: Secure Key Exchange with Biometrics & TEEs

Open-source implementation of the **TAKE** authentication protocol, based on the IEEE TDSC 2024 paper *"A Secure Two-Factor Authentication Key Exchange Scheme"* by Han et al.

This project implements the full cryptographic flow described in the paper, utilizing modern mobile native biometrics and AWS Nitro Enclaves.

## Architecture

The protocol secures authentication by ensuring the server cannot decrypt user credentials and the client cannot bypass biometric verification.

* **Client (`/android`)**: An Android Kotlin application. It uses the Android hardware Keystore to securely generate and store random blinding factors ($R$) protected by the native BiometricPrompt.
* **Server (`/server`)**: A Python Flask REST API. It handles the Oblivious Pseudorandom Function (OPRF) evaluation.
* **TEE (`/infra/enclave`)**: The cryptographic core. We use an **AWS Nitro Enclave** to derive the specific master keys ($k_1$, $k_2$) used to blind credentials. The master keys never leave the enclave's isolated, hardware-encrypted memory.
* **Infrastructure (`/infra`)**: Terraform scripts to automatically provision an `m5.xlarge` EC2 instance, configure the Nitro Enclave allocator, and deploy the server.

> **Implementation Note on Biometrics**: The original paper describes using a software *Fuzzy Extractor* to reliably derive a cryptographic key from noisy biometric inputs (like a facial scan). In this modern mobile deployment, we achieve the exact same cryptographic goal by utilizing the Android device's hardware TEE (the Android Keystore). The native fingerprint scanner unlocks a master blinding factor ($R$) stored securely in hardware. This provides identical mathematical guarantees for the protocol while leveraging industry-standard hardware security over error-prone software extraction.

> **Implementation Note on TEEs**: The original TAKE paper proposes using **Intel SGX** as the Trusted Execution Environment. This project substitutes SGX with **AWS Nitro Enclaves**, a modern, cloud-native hardware isolation technology. Nitro Enclaves provide the exact same mathematical security guarantees—preventing even a root-level attacker on the host OS from accessing the master cryptographic keys—while being significantly easier to deploy and scale in a standard cloud environment.

## Live Breach Demonstration (`/demo`)

To verify the mathematical proofs from the paper, this repository includes a live penetration testing script `demo/server_breach_demo.py`.

The script connects via SSH to an active AWS deployment and physically extracts the SQLite databases. It simulates a server breach where an attacker steals both:
1. A traditional `users.db` storing `SHA256(password)`
2. The `take_server.db` storing the protocol's OPRF-blinded group elements: $H_0(pw || R)^{(k_1 \cdot k_2^{-1}) \pmod q}$

The script then executes **John the Ripper** and **Hashcat** against the `rockyou.txt` dictionary locally. 
As demonstrated, traditional hashes are cracked instantly. The TAKE credentials cannot even be parsed by cracking tools because the necessary derivation factors ($k_1$, $k_2$) remain locked inside the AWS Enclave, inaccessible even to an attacker with full root access on the host EC2 instance.

## Getting Started

### 1. Infrastructure (AWS EC2 & Nitro Enclaves)
```bash
cd infra/
terraform init
terraform plan
terraform apply
```
This will automatically provision the EC2 instance, install Docker and the Nitro Enclave CLI, generate the master keys, and build the enclave image.

### 2. Server (Python Flask)
SSH into the newly created EC2 instance:
```bash
ssh -i infra/<key>.pem ec2-user@<public_ip>
cd take-project
python3 -m server.app
```
*Note: The traditional and TAKE SQLite databases will be automatically created on first run.*

### 3. Client (Android)
Before building, open `android/app/src/main/java/com/take/app/ui/LoginActivity.kt` and `RegisterActivity.kt`, and replace `http://10.0.2.2:5000` with the public IP address of your EC2 instance.

Ensure your emulator or physical device has a fingerprint enrolled. Then build the application:
```bash
cd android/
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Copyright Notice

The original mathematical equations, definitions, and protocol flow are the intellectual property of the authors. 

To comply with copyright, the IEEE paper itself is not distributed in this repository. Researchers with academic access can find the original publication on IEEE Xplore:
> Han et al., "A Secure Two-Factor Authentication Key Exchange Scheme", IEEE Transactions on Dependable and Secure Computing (TDSC), 2024.

This repository is an independent, clean-room software implementation intended for academic verification and educational use.
