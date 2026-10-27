# Quantum-Resistant Secure Vault & Messaging (HPQ-DR)

An end-to-end implementation of the **Hybrid Post-Quantum Double Ratchet (HPQ-DR)** messaging protocol and a **Zero-Access Quantum-Resistant File Vault**, built according to **NIST FIPS 203 (ML-KEM-768)**, **NIST FIPS 204 (ML-DSA-65)**, classical **X25519 ECDH**, and **AES-256-GCM**.

Developed by **Team Pipotam** to defeat the **Harvest-Now, Decrypt-Later (HNDL)** quantum threat.

---

## 1. Problem Statement & Threat Model

Classical end-to-end encrypted messaging systems (Signal, WhatsApp, Matrix) and cloud vaults rely on elliptic-curve cryptography (X25519, Ed25519) for key exchange and signatures. Shor's algorithm running on a future Cryptographically Relevant Quantum Computer (CRQC) solves discrete logarithm and integer factorization problems in polynomial time $\mathcal{O}(n^3)$, breaking classical forward secrecy retroactively.

Furthermore, early post-quantum adaptations (such as Signal PQXDH) hybridize only the initial setup handshake—every subsequent ratchet turn remains pure classical X25519, meaning post-compromise "healing" is not quantum-resistant.

### How HPQ-DR Solves This
1. **Hybrid Initial Handshake (PQXDH-style)**: Combines classical X25519 ECDH with NIST FIPS 203 ML-KEM-768 encapsulation, signed with NIST FIPS 204 ML-DSA-65.
2. **Hybrid Asymmetric Ratchet**: Periodically on new turns, fresh ephemeral X25519 AND ML-KEM-768 key pairs are generated and mixed into the root key via domain-separated HKDF, guaranteeing **quantum-resistant post-compromise security ("healing")**.
3. **Symmetric KDF Chain Ratchet**: Advances per message, deriving single-use AES-256-GCM message keys that are discarded and wiped from memory, maintaining **forward secrecy** (Grover's algorithm provides only a quadratic $\mathcal{O}(\sqrt{N})$ speedup, so 256-bit symmetric keys remain secure).
4. **Quantum-Resistant Secure Vault**: Large files are split into chunks. Each file gets an ephemeral AES-256-GCM Data Encryption Key (DEK) wrapped directly under the recipient's ML-KEM-768 public key. Chunks and an ML-DSA-65 signed manifest are stored on an **untrusted zero-access server**.

---

## 2. Project Architecture & The 2 Phases

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PHASE 1: CRYPTO CORE & HPQ-DR                        │
├────────────────────────────────────────────────────────────────────────┤
│  src/crypto/                                                           │
│    ├── kem.py          (ML-KEM-768 FIPS 203, X25519, Hybrid combiner) │
│    ├── signatures.py   (ML-DSA-65 FIPS 204, Ed25519)                  │
│    └── symmetric.py    (AES-256-GCM, ChaCha20-Poly1305, HKDF)         │
│  src/identity/                                                         │
│    ├── keys.py         (Long-term identities, signed & one-time keys)  │
│    └── bundle.py       (PreKeyBundle, ClientKeyStore, verification)   │
│  src/protocol/                                                         │
│    ├── handshake.py    (PQXDH hybrid key exchange & payload envelopes) │
│    ├── ratchet.py      (HPQ-DR engine: symmetric & hybrid asymmetric)  │
│    └── message.py      (Header serialization, ML-DSA-65 signing)      │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               PHASE 2: SECURE VAULT, SERVER & CLIENT                   │
├────────────────────────────────────────────────────────────────────────┤
│  src/vault/                                                            │
│    ├── chunker.py      (Streaming chunker & SHA-256 digest trees)      │
│    ├── encryption.py   (Ephemeral DEK, ML-KEM-768 wrap/unwrap)         │
│    ├── manifest.py     (Cryptographic manifest, ML-DSA-65 signed)      │
│    └── reassembly.py   (FileVaultEngine packaging & verification)      │
│  src/server/                                                           │
│    ├── storage.py      (Zero-access mailbox, bundle directory, store)  │
│    └── app.py          (FastAPI untrusted relay REST API)              │
│  src/client/                                                           │
│    └── sdk.py          (High-level VaultClient SDK)                    │
│  src/cli/                                                              │
│    └── main.py         (CLI & Harvest-Now-Decrypt-Later Simulator)     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Specifications

| Component | Standard / Primitive | Parameters / Key Sizes |
| :--- | :--- | :--- |
| **Post-Quantum KEM** | NIST FIPS 203 (ML-KEM-768) | Public: 1,184 B \| Secret: 2,400 B \| Ciphertext: 1,088 B |
| **Post-Quantum Signature** | NIST FIPS 204 (ML-DSA-65) | Public: 1,952 B \| Secret: 4,000 B \| Signature: ~3,293 B |
| **Classical Key Agreement**| Curve25519 (X25519) | 32 B (256 bits) |
| **Key Derivation** | HKDF-SHA256 | Domain-separated salt & info strings |
| **Authenticated Encryption**| AES-256-GCM | 256-bit key, 96-bit unique nonce, 128-bit tag |
| **Integrity & Hashing** | SHA-256 | Per-chunk hash + full file hash |

---

## 4. Run Guide & Quick Start

### 4.1 Prerequisites & Installation

- **Python Version**: Python 3.11 or higher (Python 3.13 supported)
- **Virtual Environment**: Recommended to prevent dependency collisions

```bash
# 1. Clone the repository and navigate into the project
cd QuantumResistantSecureVault

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies in editable mode
pip install -e ".[dev]"
```

---

### 4.2 Running the Main Application & Relay Server (Port 8000)

Start the zero-access relay server and Neumorphic web interface:

```bash
python3 src/server/app.py
```
*Alternatively, start directly with Uvicorn (hot-reloading enabled):*
```bash
python3 -m uvicorn src.server.app:app --host 127.0.0.1 --port 8000 --reload
```

- **Web Dashboard**: Open [http://127.0.0.1:8000](http://127.0.0.1:8000) or [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login) in your browser.
- **Interactive Features**:
  - **Identities**: Log in as pre-seeded demo clients (`alice` or `bob`) or register any custom user ID.
  - **HPQ-DR Messaging**: Send live messages protected by the Hybrid Post-Quantum Double Ratchet.
  - **Zero-Access Vault**: Drag-and-drop or select files to chunk, encrypt with ephemeral DEKs, encapsulate under ML-KEM-768, sign manifests via ML-DSA-65, and download/verify on recipient clients.
  - **Crypto Transparency**: Inspect public key fingerprints, ratchet state transitions, and server zero-knowledge storage metrics.

---

### 4.3 Running the Attacker / MITM Interception Server (Port 8080)

To simulate an active on-the-wire eavesdropper and Man-In-The-Middle (MITM) adversary:

```bash
python3 src/attacker/server.py
```
*Alternatively:*
```bash
python3 -m uvicorn src.attacker.server:app --host 127.0.0.1 --port 8080
```

- **Attacker Console**: Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser.
- **Capabilities & Independent Architecture**:
  - **Master ON / OFF Control**: Toggle active wire interception on or off with a single click.
  - **Automatic Wire Tampering (ON)**: When ON, chat messages and vault documents exchanged between Alice and Bob are automatically intercepted and tampered on the wire. When Alice and Bob attempt to chat or decrypt shared documents, NIST FIPS 204 ML-DSA-65 digital signature and AEAD integrity verification fail, raising security alerts and error modals.
  - **Clean Pass-Through (OFF)**: When OFF, traffic passes unhindered without tampering, and Alice & Bob communicate cleanly.
  - **Complete Isolation**: The Intruder operates strictly on the dedicated 8080 interception console and is not listed as a user on the main server (port 8000).

---

### 4.4 Running the Quantum Attack Simulator (CLI)

Demonstrate in your terminal why classical encryption fails against Harvest-Now-Decrypt-Later (HNDL) attacks and how HPQ-DR prevents decryption:

```bash
python3 -m src.cli.main simulate-harvest
```

This interactive terminal simulator runs through:
1. Intercepting a real HPQ-DR wire envelope.
2. Executing a simulated Shor's algorithm run on a CRQC breaking classical X25519 ECDH.
3. Proving that lattice-based ML-KEM-768 prevents the adversary from deriving session keys.
4. Demonstrating legitimate decryption and zero-access vault reassembly by the genuine recipient.

---

### 4.5 Running the Automated Test Suite

Run the full automated test suite (36 unit and integration tests across crypto primitives, ratchets, vaults, and servers):

```bash
python3 -m pytest tests/ -o cache_dir=/tmp/pytest_cache -v
```

---

### 4.6 Using the Python Client SDK

You can also integrate the client directly into custom Python applications:

```python
from src.client.sdk import VaultClient

# 1. Initialize clients and register prekey bundles
alice = VaultClient("alice")
bob = VaultClient("bob")
alice.register()
bob.register()

# 2. Alice sends an end-to-end encrypted HPQ-DR message to Bob
alice.send_message("bob", "Quantum-safe communications online.")

# 3. Bob checks inbox and decrypts
messages = bob.fetch_messages()
print(messages[0]["text"])  # "Quantum-safe communications online."

# 4. Bob replies (triggers hybrid asymmetric ratchet turn)
bob.send_message("alice", "Ratchet turn complete. Post-compromise healing active.")

# 5. Alice uploads a classified document into the Zero-Access Vault
file_id = alice.upload_file(b"TOP SECRET INTEL", "intel.pdf", "bob")

# 6. Bob downloads, verifies ML-DSA-65 signature, and decrypts
decrypted_file = bob.download_file(file_id, "alice")
assert decrypted_file == b"TOP SECRET INTEL"
```

---

## 5. Security Proofs & Zero-Access Guarantees

1. **Defeating Harvest-Now-Decrypt-Later (HNDL)**:
   Any recorded ciphertext requires breaking **both** the Elliptic Curve Discrete Logarithm Problem (ECDLP) **and** the Module Learning With Errors (M-LWE) lattice problem.
2. **Post-Compromise Security ("Healing")**:
   If an adversary steals Alice's ratchet state at step $t$, the very next reply turn introduces fresh ephemeral entropy from ML-KEM-768 and X25519, restoring complete confidentiality.
3. **Zero-Access Server Storage**:
   The relay server only ever receives and stores ciphertext envelopes, public prekey bundles, encrypted chunks, and ML-DSA signatures. It has zero knowledge of plaintexts or keys.
