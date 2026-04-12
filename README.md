# Adytum TEE Worker

Secure execution environment for the Adytum IP Marketplace. Runs inside a Phala Cloud TEE (dstack) enclave,implementing the secure disclosure mechanism from the NDAI paper and provide:

- **Sandboxed Code Execution** — Invention code runs in nsjail with strict isolation
- **Deterministic Identity** — Keys derived via dstack-sdk for reproducible addresses
- **Secure Key Management** — Decryption keys stored in TEE-sealed storage
- **On-Chain Integration** — Submits execution results and releases keys to Nash winners

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green)](https://fastapi.tiangolo.com/)
[![nsjail](https://img.shields.io/badge/Sandbox-nsjail-orange)](https://github.com/google/nsjail)
[![dstack](https://img.shields.io/badge/TEE-dstack-purple)](https://dstack.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PHALA CLOUD TEE                             │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │  identity (Node.js)              worker (Python/FastAPI)       ││
│  │  ┌───────────────────┐           ┌────────────────────────┐    ││
│  │  │ dstack-sdk        │           │ /execute               │    ││
│  │  │ getKey('adytum/   │──────────►│ /release-key           │    ││
│  │  │   execution/v1')  │ keys.json │ /store-key             │    ││
│  │  │ getKey('adytum/   │           │ /health                │    ││
│  │  │   settlement/v1') │           └────────────────────────┘    ││
│  │  └───────────────────┘                     │                   ││
│  └────────────────────────────────────────────│───────────────────┘│
│                                               │                    │
│                         /var/run/dstack.sock  │  port 8001         │
└─────────────────────────────────────────────────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────────────┐
                                    │   AdytumMarketplace.sol       │
                                    │   (Base Sepolia)              │
                                    └───────────────────────────────┘
                                    (submitExecutionResult,
                                     releaseKey, settleNash)
```

## Quick Start

### Local Development (without TEE)

```bash
# Clone the repo
git clone https://github.com/adytum-app/tee-worker.git
cd tee-worker

# Create .env file
cat > .env << EOF
RPC_URL=https://sepolia.base.org
CONTRACT_ADDRESS=0x...  # Your deployed contract
ORACLE_PRIVATE_KEY=0x...  # Test key (NOT for production!)
EOF

# Build and run
docker-compose up --build
```

### Production Deployment (Phala Cloud)

See [TEE.md](./TEE.md) for the complete deployment guide.

```bash
# 1. Prepare deployment (generates compose hash)
phala deploy -c docker-compose.yml --kms base --prepare-only

# 2. Register compose hash via multisig (see TEE.md)

# 3. Commit the deployment
phala deploy --commit --token <token>

# 4. Get TEE addresses from logs, deploy contract, update CVM
```

## Repository Structure

```
tee-worker/
├── identity/              # Node.js identity sidecar
│   ├── index.js           # Key derivation via dstack-sdk
│   ├── package.json       # Dependencies (@phala/dstack-sdk, viem)
│   └── Dockerfile         # Sidecar container
├── src/
│   ├── server.py          # FastAPI HTTP endpoints
│   └── worker.py          # Core TEE logic
├── docker-compose.yml     # Two-container deployment config
├── Dockerfile             # Main worker container (Python + nsjail)
├── nsjail.cfg             # Sandbox configuration
├── requirements.txt       # Python dependencies
├── TEE.md                 # Deployment guide
└── README.md              # This file
```

## API Endpoints

| Endpoint       | Method | Description                              |
| -------------- | ------ | ---------------------------------------- |
| `/health`      | GET    | Health check with oracle address         |
| `/attestation` | GET    | TEE attestation report                   |
| `/execute`     | POST   | Execute invention code in sandbox        |
| `/release-key` | POST   | Release decryption key to Nash winner    |
| `/store-key`   | POST   | Store decryption key for new invention   |
| `/keys/{id}`   | GET    | Check if key exists for invention        |
| `/keys/{id}`   | DELETE | Delete key (when deactivating invention) |

### Example: Execute Invention

```bash
curl -X POST http://localhost:8001/execute \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "0x0000...0001",
    "invention_id": "0x0000...0001",
    "buyer": "0x1234...5678",
    "input_data": {"prompt": "Hello, world!"}
  }'
```

### Example: Health Check

```bash
curl http://localhost:8001/health
```

```json
{
  "status": "healthy",
  "oracle_address": "0x...",
  "enclave": "dstack",
  "contract_address": "0x...",
  "key_store_path": "/tee/keys",
  "nsjail_config": "/app/nsjail.cfg"
}
```

## Key Derivation Paths

| Purpose    | Path                   | Smart Contract Role   |
| ---------- | ---------------------- | --------------------- |
| Execution  | `adytum/execution/v1`  | `TEE_EXECUTION_ROLE`  |
| Settlement | `adytum/settlement/v1` | `TEE_SETTLEMENT_ROLE` |

Keys are deterministically derived from the dstack KMS root key. The same path always produces the same Ethereum address, making deployments reproducible.

## Security Model

### Sandbox Isolation (nsjail)

Invention code executes in a heavily restricted environment:

- **Namespace isolation** — PID, IPC, UTS, mount, user namespaces
- **Resource limits** — 10s CPU, 256MB memory, 128 file descriptors
- **No network** — `clone_newnet: true` blocks all network access
- **Read-only filesystem** — Only `/tmp` is writable (tmpfs, 64MB)
- **Unprivileged user** — Runs as `nobody` (UID 65534)
- **Single-threaded ML** — `OMP_NUM_THREADS=1` prevents thread-based attacks

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

### Code Validation (Defense-in-Depth)

Before sandbox execution, code is scanned for:

- System imports (`os`, `sys`, `subprocess`, ...)
- Network imports (`socket`, `requests`, `urllib`, ...)
- Code execution (`eval`, `exec`, `__import__`, ...)
- Dangerous dunder attributes (`__class__`, `__subclasses__`, ...)

### Key Release Authorization

Before releasing a key, the worker verifies on-chain:

1. **Model check** — Invention must be `MonetizationModel.NashNegotiation`
2. **Phase check** — Nash must be `NashPhase.SETTLED`
3. **Winner check** — Buyer must equal `highestBidder` from contract

### TEE Key Protection

- Private keys never leave the TEE enclave
- Keys are derived from dstack KMS (deterministic, reproducible)
- Invention decryption keys stored in TEE-sealed storage
- ECIES encryption for key delivery to Nash winners

## Environment Variables

| Variable                  | Required | Default                    | Description                 |
| ------------------------- | -------- | -------------------------- | --------------------------- |
| `RPC_URL`                 | Yes      | `https://sepolia.base.org` | Ethereum RPC endpoint       |
| `CONTRACT_ADDRESS`        | Yes      | —                          | AdytumMarketplace contract  |
| `DERIVED_KEYS_PATH`       | No       | `/tee/derived-keys.json`   | Path to derived keys        |
| `ORACLE_PRIVATE_KEY`      | No       | —                          | Fallback key (testing only) |
| `KEY_STORE_PATH`          | No       | `/tee/keys`                | Invention key storage       |
| `NSJAIL_CONFIG_PATH`      | No       | `/app/nsjail.cfg`          | Sandbox config              |
| `SANDBOX_TIMEOUT_SECONDS` | No       | `30`                       | Max execution time          |
| `SANDBOX_MEMORY_LIMIT_MB` | No       | `256`                      | Max memory                  |
| `CORS_ORIGINS`            | No       | `*`                        | Allowed CORS origins        |

## Development

### Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/
```

### Building Images

```bash
# Build identity sidecar
docker build -f identity/Dockerfile -t adytum-tee-identity:latest .

# Build main worker
docker build -t adytum-tee-worker:latest .
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

## License

BSL License - see [LICENSE](LICENSE) for details.

## References

- [NDAI Paper](https://arxiv.org/abs/...) — Stephenson et al., 2025
- [Phala Cloud Documentation](https://docs.phala.cloud)
- [dstack SDK](https://github.com/Phala-Network/dstack)
- [nsjail](https://github.com/google/nsjail)
