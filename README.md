# Adytum TEE Worker

> _The secure execution environment for protected knowledge_

A Python-based TEE (Trusted Execution Environment) worker that runs inside a dstack enclave, implementing the secure disclosure mechanism from the NDAI paper.

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green)](https://fastapi.tiangolo.com/)
[![nsjail](https://img.shields.io/badge/Sandbox-nsjail-orange)](https://github.com/google/nsjail)
[![dstack](https://img.shields.io/badge/TEE-dstack-purple)](https://dstack.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Theoretical Foundation

This worker implements the TEE-resident agent from:

> **"NDAI Agreements"** by Matt Stephenson, Andrew Miller, Xyn Sun, Bhargav Annem, and Rohan Parikh  
> arXiv:2502.07924v1 [econ.TH] — February 2025

The NDAI paper proves that TEEs combined with AI agents can function as an "ironclad NDA" enabling secure disclosure without expropriation risk.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      TEE ENCLAVE (dstack)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    HTTP Server (FastAPI)                │    │
│  │  /health  /execute  /release-key  /store-key  /keys     │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                    │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                    TEE Worker                           │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │    │
│  │  │ Code Fetch   │  │   nsjail     │  │ Key Release  │   │    │
│  │  │ & Verify     │  │  Sandbox     │  │ (ECIES)      │   │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Key Store (Sealed)                   │    │
│  │              /tee/keys/{invention_id}.key               │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   AdytumMarketplace.sol       │
              │   (Base Sepolia)              │
              └───────────────────────────────┘
```

---

## Features

### Code Execution (nsjail Sandbox)

- **Namespace isolation** — PID, IPC, UTS, mount, and user namespaces
- **Resource limits** — CPU time, memory, file descriptors, process count
- **No network access** — `clone_newnet: true` isolates network stack
- **Read-only filesystem** — only `/tmp` is writable (64MB tmpfs)
- **Unprivileged execution** — runs as `nobody` (UID 65534) inside sandbox
- **Hash verification** — encrypted code hash must match on-chain commitment
- **Forbidden pattern detection** — defense-in-depth blocks dangerous imports
- **Cryptographic attestation** — results signed by oracle key

### Key Management

- **Sealed storage** — keys stored in TEE-protected filesystem
- **ECIES encryption** — keys encrypted with buyer's secp256k1 public key (ECDH + HKDF + AES-GCM)
- **Authorization checks** — verifies Nash phase and winner before release

### Contract Integration

- **submitExecutionResult** — posts result hash and attestation
- **failExecution** — reports execution failures
- **releaseEncryptedKey** — delivers encrypted key to Nash winner
- **getInvention / getNashConfig** — reads on-chain state

---

## Project Structure

```
adytum-tee-worker/
├── Dockerfile           # Container image with nsjail
├── requirements.txt     # Python dependencies
├── nsjail.cfg           # Sandbox configuration
└── src/
    ├── server.py        # FastAPI HTTP server
    └── worker.py        # TEE worker logic
```

---

## API Endpoints

### Health & Status

```bash
# Health check
GET /health
→ { status, oracle_address, enclave, contract_address, key_store_path, nsjail_config }

# TEE attestation
GET /attestation
→ { enclave_type, oracle_address, attestation, timestamp }
```

### Execution

```bash
# Execute invention code in nsjail sandbox
POST /execute
{
  "execution_id": "0x...",
  "invention_id": "0x...",
  "buyer": "0x...",
  "input_data": { ... }
}
→ { success, output, result_hash, execution_time_ms, attestation }
```

### Key Management

```bash
# Store key (seller listing)
POST /store-key
{
  "invention_id": "0x...",
  "decryption_key": "...",  # Fernet key (44 chars base64)
  "seller": "0x..."
}
→ { success, invention_id }

# Release key (Nash winner)
POST /release-key
{
  "invention_id": "0x...",
  "buyer": "0x..."
}
→ { success, encrypted_key, attestation, tx_hash }

# Check key exists
GET /keys/{invention_id}
→ { invention_id, key_exists }

# Delete key (deactivation)
DELETE /keys/{invention_id}?seller=0x...
→ { invention_id, deleted }
```

---

## Security Model

### nsjail Sandbox Configuration

| Protection           | Setting         | Value                         |
| -------------------- | --------------- | ----------------------------- |
| CPU time limit       | `time_limit`    | 10 seconds                    |
| Memory limit         | `rlimit_as`     | 256 MB                        |
| File descriptors     | `rlimit_nofile` | 128 (for numpy/scipy imports) |
| Process/thread limit | `rlimit_nproc`  | 16 (for OpenBLAS threads)     |
| File creation        | `rlimit_fsize`  | 0 (no files)                  |
| Network access       | `clone_newnet`  | Isolated (no access)          |
| User inside sandbox  | `uidmap`        | 65534 (nobody)                |
| Filesystem           | mounts          | Read-only except `/tmp`       |

### ML Backend Thread Control

The sandbox enforces single-threaded execution for ML libraries to respect CPU limits:

```
OMP_NUM_THREADS=1
OPENBLAS_NUM_THREADS=1
MKL_NUM_THREADS=1
NUMEXPR_NUM_THREADS=1
```

### Defense-in-Depth: Forbidden Patterns

Before nsjail execution, code is scanned for dangerous patterns:

```python
# System access
"import os", "import sys", "import subprocess", ...

# Network access
"import socket", "import requests", "import urllib", ...

# Code execution
"__import__", "eval(", "exec(", "compile(", ...

# Dangerous dunders
"__class__", "__bases__", "__subclasses__", "__globals__", ...
```

### Key Release Authorization

Before releasing a key, the worker verifies on-chain:

1. **Model check** — Invention must be `MonetizationModel.NashNegotiation`
2. **Phase check** — Nash must be `NashPhase.SETTLED`
3. **Winner check** — Buyer must equal `highestBidder` from contract

---

## Environment Variables

| Variable                  | Required | Default                    | Description                            |
| ------------------------- | -------- | -------------------------- | -------------------------------------- |
| `CONTRACT_ADDRESS`        | Yes      | -                          | AdytumMarketplace contract address     |
| `ORACLE_PRIVATE_KEY`      | Yes      | -                          | Oracle wallet private key              |
| `RPC_URL`                 | No       | `https://sepolia.base.org` | Base RPC endpoint                      |
| `IPFS_GATEWAY`            | No       | `https://ipfs.io/ipfs/`    | IPFS gateway URL                       |
| `KEY_STORE_PATH`          | No       | `/tee/keys`                | Path for sealed key storage            |
| `NSJAIL_CONFIG_PATH`      | No       | `/app/nsjail.cfg`          | Path to nsjail configuration           |
| `HOST`                    | No       | `0.0.0.0`                  | Server bind address                    |
| `PORT`                    | No       | `8001`                     | Server port                            |
| `SANDBOX_TIMEOUT_SECONDS` | No       | `30`                       | Execution timeout                      |
| `SANDBOX_MEMORY_LIMIT_MB` | No       | `256`                      | Memory limit for sandbox               |
| `CORS_ORIGINS`            | No       | `*`                        | Allowed CORS origins (comma-separated) |

---

## Development

### Local Testing

```bash
cd src/

# Install dependencies
pip install -r ../requirements.txt

# Set environment
export CONTRACT_ADDRESS=0x...
export ORACLE_PRIVATE_KEY=0x...
export RPC_URL=https://sepolia.base.org

# Run server (without nsjail)
python server.py
```

### Docker (with nsjail)

```bash
# Build
docker build -t adytum-tee-worker .

# Run (requires capabilities for nsjail)
docker run --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE -p 8001:8001 \
  -e CONTRACT_ADDRESS=0x... \
  -e ORACLE_PRIVATE_KEY=0x... \
  -e RPC_URL=https://sepolia.base.org \
  adytum-tee-worker
```

### dstack Deployment

```bash
# Deploy to dstack TEE
dstack deploy \
  --image adytum-tee-worker \
  --env CONTRACT_ADDRESS=0x... \
  --env ORACLE_PRIVATE_KEY=0x... \
  --port 8001
```

---

## Flow Diagrams

### Pay-Per-Use Execution

```
Frontend                    TEE Worker                   Contract
   │                            │                            │
   │  POST /execute             │                            │
   │  {execution_id, input}     │                            │
   │ ──────────────────────────>│                            │
   │                            │                            │
   │                            │  getInvention(id)          │
   │                            │ ──────────────────────────>│
   │                            │<─ metadataURI, codeHash    │
   │                            │                            │
   │                            │  [IPFS] Fetch code         │
   │                            │  [Verify] hash == codeHash │
   │                            │  [Decrypt] with stored key │
   │                            │  [nsjail] execute in sandbox│
   │                            │                            │
   │                            │  submitExecutionResult     │
   │                            │ ──────────────────────────>│
   │                            │                            │
   │<── {output, attestation}   │                            │
   │                            │                            │
```

### Nash Key Release

```
Frontend                    TEE Worker                   Contract
   │                            │                            │
   │  POST /release-key         │                            │
   │  {invention_id, buyer}     │                            │
   │ ──────────────────────────>│                            │
   │                            │                            │
   │                            │  getNashConfig(id)         │
   │                            │ ──────────────────────────>│
   │                            │<─ phase, highestBidder     │
   │                            │                            │
   │                            │  [Verify] phase==SETTLED   │
   │                            │  [Verify] buyer==winner    │
   │                            │                            │
   │                            │  getBuyerPubKey(id, buyer) │
   │                            │ ──────────────────────────>│
   │                            │<─ buyerPubKey              │
   │                            │                            │
   │                            │  [ECIES] encrypt key       │
   │                            │  (ECDH + HKDF + AES-GCM)   │
   │                            │                            │
   │                            │  releaseEncryptedKey       │
   │                            │ ──────────────────────────>│
   │                            │                            │
   │<── {encrypted_key, attest} │                            │
   │                            │                            │
```

---

## Sandbox Libraries

The following libraries are available inside the nsjail sandbox for invention code:

| Library        | Version | Purpose              |
| -------------- | ------- | -------------------- |
| `numpy`        | 1.26.0  | Numerical computing  |
| `scipy`        | 1.12.0  | Scientific computing |
| `scikit-learn` | 1.4.0   | Machine learning     |

Invention code must define a `run(input_data: dict) -> Any` function:

```python
# Example invention code
import numpy as np
from sklearn.linear_model import LinearRegression

def run(input_data):
    X = np.array(input_data["features"])
    model = LinearRegression()
    model.fit(X, input_data["labels"])
    return {"coefficients": model.coef_.tolist()}
```

---

## References

1. Stephenson, M., Miller, A., Sun, X., Annem, B., & Parikh, R. (2025). _NDAI Agreements_. arXiv:2502.07924v1 [econ.TH].

2. Google nsjail: https://github.com/google/nsjail

3. dstack TEE Documentation: https://docs.dstack.dev/

---

## License

BSL License - see [LICENSE](LICENSE) for details.
