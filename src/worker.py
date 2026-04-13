"""
Adytum TEE Worker

Runs inside a dstack TEE enclave. Handles:
1. Fetching IPFS metadata & encrypted invention code
2. Verifying encrypted code hash matches on-chain commitment
3. Decrypting code internally
4. Executing the code in a strictly constrained nsjail sandbox
5. Securely delivering decryption keys to Nash winners (with authorization)
6. Signing results and interacting with AdytumMarketplace.sol

Implements the TEE-resident agent from NDAi paper (Stephenson et al., 2025)

Key Derivation:
- Production: Keys are derived via dstack-sdk (Node.js identity sidecar)
- Testing: Falls back to ORACLE_PRIVATE_KEY environment variable
"""

import os
import json
import subprocess
import tempfile
import time
from typing import Any
from dataclasses import dataclass
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import requests

# =============================================================================
# Environment Configuration
# =============================================================================

RPC_URL = os.getenv("RPC_URL", "https://sepolia.base.org")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
IPFS_GATEWAY = os.getenv(
    "IPFS_GATEWAY",
    "https://olive-useful-fly-746.mypinata.cloud/",
)
KEY_STORE_PATH = os.getenv("KEY_STORE_PATH", "/tee/keys")
NSJAIL_CONFIG_PATH = os.getenv("NSJAIL_CONFIG_PATH", "/app/nsjail.cfg")

# Key loading configuration
# Production: Keys derived by identity sidecar and written to this path
# Testing: Falls back to ORACLE_PRIVATE_KEY environment variable
DERIVED_KEYS_PATH = os.getenv("DERIVED_KEYS_PATH", "/tee/derived-keys.json")
ORACLE_PRIVATE_KEY = os.getenv("ORACLE_PRIVATE_KEY")

# Sandbox configuration
SANDBOX_TIMEOUT_SECONDS = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "30"))
SANDBOX_MEMORY_LIMIT_MB = int(os.getenv("SANDBOX_MEMORY_LIMIT_MB", "256"))

# =============================================================================
# Contract Constants (must match AdytumMarketplace.sol)
# =============================================================================


class NashPhase:
    """Matches contract enum NashPhase"""
    OPEN = 0
    REVEAL = 1
    SETTLED = 2
    FAILED = 3
    EXPIRED = 4


class MonetizationModel:
    """Matches contract enum MonetizationModel"""
    PAY_PER_USE = 0
    NASH_NEGOTIATION = 1


# =============================================================================
# Domain Objects
# =============================================================================

@dataclass
class ExecutionRequestDomain:
    execution_id: str
    invention_id: str
    buyer: str
    input_data: dict
    decryption_key: str  # Only TEE has this


@dataclass
class ExecutionResultDomain:
    execution_id: str
    invention_id: str
    output: Any
    result_hash: str
    execution_time_ms: int
    attestation: bytes
    success: bool
    error: str | None = None


@dataclass
class InventionData:
    """Parsed invention struct from contract"""
    id: bytes
    seller: str
    metadata_uri: str
    encrypted_code_hash: bytes
    encryption_key_hash: bytes
    category: int
    model: int
    created_at: int
    is_active: bool


@dataclass
class NashConfigData:
    """Parsed NashConfig struct from contract"""
    seller_bid_hash: bytes
    seller_min_revealed: int
    bid_deadline: int
    reveal_deadline: int
    required_deposit: int
    seller_revealed: bool
    allow_trials_during: bool
    trial_fee: int
    max_trials_per_bidder: int
    phase: int
    highest_bidder: str
    highest_bid: int
    seller_bond: int


# =============================================================================
# Key Loading Helper
# =============================================================================

def load_derived_keys() -> dict | None:
    """
    Load deterministically derived keys from the identity sidecar.

    The identity sidecar (Node.js) runs first via docker-compose depends_on,
    derives keys using dstack-sdk, and writes them to DERIVED_KEYS_PATH.

    Returns:
        dict with 'execution' and 'settlement' keys, each containing
        'address' and 'privateKey', or None if file doesn't exist.
    """
    if not os.path.exists(DERIVED_KEYS_PATH):
        return None

    try:
        with open(DERIVED_KEYS_PATH, 'r') as f:
            keys = json.load(f)

        # Validate structure
        if 'execution' not in keys or 'settlement' not in keys:
            print(
                "[Key Loader] Invalid key file structure at "
                f"{DERIVED_KEYS_PATH}"
            )
            return None

        if (
            'privateKey' not in keys['execution']
            or 'privateKey' not in keys['settlement']
        ):
            print("[Key Loader] Missing privateKey in key file")
            return None

        return keys

    except json.JSONDecodeError as e:
        print(f"[Key Loader] Failed to parse key file: {e}")
        return None
    except Exception as e:
        print(f"[Key Loader] Error loading key file: {e}")
        return None


# =============================================================================
# Main TEE Worker
# =============================================================================

class AdytumTEEWorker:
    """
    TEE Worker implementing the secure execution environment from NDAi paper.

    Provides:
    - Isolated code execution with nsjail sandboxing
    - Cryptographic attestation of results
    - Secure key delivery to Nash winners

    Key Management:
    - Production: Uses deterministically derived keys from dstack-sdk
    - Testing: Falls back to ORACLE_PRIVATE_KEY environment variable
    """

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))

        # =================================================================
        # Load keys: Try dstack-derived keys first, fall back to env var
        # =================================================================
        derived_keys = load_derived_keys()

        if derived_keys:
            # Production mode: Use deterministically derived keys
            exec_pk = derived_keys["execution"]["privateKey"]
            settle_pk = derived_keys["settlement"]["privateKey"]
            self.account = Account.from_key(exec_pk)
            self.settlement_account = Account.from_key(settle_pk)

            print("[TEE Worker] ✓ Loaded derived keys from dstack-sdk")
            print(f"[TEE Worker]   Execution:  {self.account.address}")
            print(
                f"[TEE Worker]   Settlement: "
                f"{self.settlement_account.address}"
            )

            # Verify addresses match what's in the file
            if derived_keys["execution"].get("address"):
                file_addr = derived_keys["execution"]["address"]
                if self.account.address.lower() != file_addr.lower():
                    print(
                        "[TEE Worker] ⚠ WARNING: "
                        "Derived execution address mismatch!"
                    )

        elif ORACLE_PRIVATE_KEY:
            # Testing mode: Use environment variable (single key for both
            # roles)
            self.account = Account.from_key(ORACLE_PRIVATE_KEY)
            self.settlement_account = self.account  # Same account for testing

            print(
                "[TEE Worker] ⚠ Using ORACLE_PRIVATE_KEY from environment "
                "(testing mode)"
            )
            print(f"[TEE Worker]   Address: {self.account.address}")

        else:
            # No keys available - generate random (for local dev only)
            self.account = Account.create()
            self.settlement_account = Account.create()

            print(
                "[TEE Worker] ⚠ WARNING: Generated random test accounts "
                "(no persistence!)"
            )
            print(f"[TEE Worker]   Execution:  {self.account.address}")
            print(
                f"[TEE Worker]   Settlement: "
                f"{self.settlement_account.address}"
            )

        # Verify nsjail config exists
        if not os.path.exists(NSJAIL_CONFIG_PATH):
            print(
                f"[TEE Worker] WARNING: nsjail config not found at "
                f"{NSJAIL_CONFIG_PATH}"
            )
        else:
            print(
                f"[TEE Worker] nsjail config loaded from {NSJAIL_CONFIG_PATH}"
            )

        self.contract = self._load_contract()

    def _load_contract(self):
        """Load the AdytumMarketplace contract ABI."""
        abi = [
            # =================================================================
            # Execution Functions
            # =================================================================
            {
                "name": "submitExecutionResult",
                "type": "function",
                "inputs": [
                    {"name": "executionId", "type": "bytes32"},
                    {"name": "resultHash", "type": "bytes32"},
                    {"name": "attestation", "type": "bytes"},
                    {"name": "executionTimeMs", "type": "uint256"},
                ],
                "outputs": [],
            },
            {
                "name": "failExecution",
                "type": "function",
                "inputs": [
                    {"name": "executionId", "type": "bytes32"},
                    {"name": "reason", "type": "string"},
                ],
                "outputs": [],
            },
            # =================================================================
            # Key Release Function
            # =================================================================
            {
                "name": "releaseEncryptedKey",
                "type": "function",
                "inputs": [
                    {"name": "inventionId", "type": "bytes32"},
                    {"name": "encryptedKey", "type": "bytes"},
                    {"name": "attestation", "type": "bytes"},
                ],
                "outputs": [],
            },
            # =================================================================
            # View Functions
            # =================================================================
            {
                "name": "getInvention",
                "type": "function",
                "inputs": [{"name": "id", "type": "bytes32"}],
                "outputs": [
                    {
                        "name": "",
                        "type": "tuple",
                        "components": [
                            {"name": "id", "type": "bytes32"},
                            {"name": "seller", "type": "address"},
                            {"name": "metadataURI", "type": "string"},
                            {"name": "encryptedCodeHash", "type": "bytes32"},
                            {"name": "encryptionKeyHash", "type": "bytes32"},
                            {"name": "category", "type": "uint8"},
                            {"name": "model", "type": "uint8"},
                            {"name": "createdAt", "type": "uint256"},
                            {"name": "isActive", "type": "bool"},
                        ]
                    }
                ],
                "stateMutability": "view"
            },
            {
                "name": "getNashConfig",
                "type": "function",
                "inputs": [{"name": "inventionId", "type": "bytes32"}],
                "outputs": [
                    {
                        "name": "",
                        "type": "tuple",
                        "components": [
                            {"name": "sellerBidHash", "type": "bytes32"},
                            {"name": "sellerMinRevealed", "type": "uint256"},
                            {"name": "bidDeadline", "type": "uint256"},
                            {"name": "revealDeadline", "type": "uint256"},
                            {"name": "requiredDeposit", "type": "uint256"},
                            {"name": "sellerRevealed", "type": "bool"},
                            {"name": "allowTrialsDuring", "type": "bool"},
                            {"name": "trialFee", "type": "uint256"},
                            {"name": "maxTrialsPerBidder", "type": "uint256"},
                            {"name": "phase", "type": "uint8"},
                            {"name": "highestBidder", "type": "address"},
                            {"name": "highestBid", "type": "uint256"},
                            {"name": "sellerBond", "type": "uint256"},
                        ]
                    }
                ],
                "stateMutability": "view"
            },
            {
                "name": "getBuyerPubKey",
                "type": "function",
                "inputs": [
                    {"name": "inventionId", "type": "bytes32"},
                    {"name": "buyer", "type": "address"},
                ],
                "outputs": [{"name": "", "type": "bytes"}],
                "stateMutability": "view"
            },
            {
                "name": "getEncryptedKey",
                "type": "function",
                "inputs": [{"name": "inventionId", "type": "bytes32"}],
                "outputs": [
                    {"name": "encryptedKey", "type": "bytes"},
                    {"name": "attestation", "type": "bytes"},
                ],
                "stateMutability": "view"
            },
        ]

        if not CONTRACT_ADDRESS:
            raise ValueError("CONTRACT_ADDRESS environment variable not set")

        return self.w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)

    # =========================================================================
    # Invention Data Fetching
    # =========================================================================

    def get_invention(self, invention_id: str) -> InventionData:
        """Fetch invention data from contract."""
        inv_bytes = self._to_bytes32(invention_id)
        inv_data = self.contract.functions.getInvention(inv_bytes).call()

        return InventionData(
            id=inv_data[0],
            seller=inv_data[1],
            metadata_uri=inv_data[2],
            encrypted_code_hash=inv_data[3],
            encryption_key_hash=inv_data[4],
            category=inv_data[5],
            model=inv_data[6],
            created_at=inv_data[7],
            is_active=inv_data[8],
        )

    def get_nash_config(self, invention_id: str) -> NashConfigData:
        """Fetch Nash configuration from contract."""
        inv_bytes = self._to_bytes32(invention_id)
        nash_data = self.contract.functions.getNashConfig(inv_bytes).call()

        return NashConfigData(
            seller_bid_hash=nash_data[0],
            seller_min_revealed=nash_data[1],
            bid_deadline=nash_data[2],
            reveal_deadline=nash_data[3],
            required_deposit=nash_data[4],
            seller_revealed=nash_data[5],
            allow_trials_during=nash_data[6],
            trial_fee=nash_data[7],
            max_trials_per_bidder=nash_data[8],
            phase=nash_data[9],
            highest_bidder=nash_data[10],
            highest_bid=nash_data[11],
            seller_bond=nash_data[12],
        )

    def fetch_invention_code(self, invention_id: str) -> bytes:
        """
        Fetch encrypted code from IPFS and verify hash matches on-chain
        commitment.

        1. Get invention metadata URI from contract
        2. Fetch metadata JSON from IPFS
        3. Fetch encrypted code from encryptedCodeUri
        4. Verify keccak256(encrypted_code) == encryptedCodeHash
        """
        invention = self.get_invention(invention_id)

        if not invention.is_active:
            raise ValueError(f"Invention {invention_id} is not active")

        metadata_uri = invention.metadata_uri
        expected_hash = invention.encrypted_code_hash

        # 1. Resolve metadata URI
        if metadata_uri.startswith("ipfs://"):
            cid = metadata_uri.replace("ipfs://", "")
            url = f"{IPFS_GATEWAY}{cid}"
        else:
            url = metadata_uri

        # 2. Fetch metadata JSON
        print(f"[TEE Worker] Fetching metadata from {url}")
        meta_resp = requests.get(url, timeout=10)
        meta_resp.raise_for_status()
        metadata = meta_resp.json()

        # 3. Get encrypted code URI
        code_uri = metadata.get("encryptedCodeUri")
        if not code_uri:
            raise ValueError("Metadata does not contain encryptedCodeUri")

        if code_uri.startswith("ipfs://"):
            cid = code_uri.replace("ipfs://", "")
            code_url = f"{IPFS_GATEWAY}{cid}"
        else:
            code_url = code_uri

        # 4. Download encrypted code
        print(f"[TEE Worker] Fetching encrypted code from {code_url}")
        code_resp = requests.get(code_url, timeout=30)
        code_resp.raise_for_status()
        encrypted_code = code_resp.content

        # 5. CRITICAL: Verify hash matches on-chain commitment
        computed_hash = Web3.keccak(encrypted_code)
        if computed_hash != expected_hash:
            raise ValueError(
                f"Encrypted code hash mismatch! "
                f"Expected {expected_hash.hex()}, got {computed_hash.hex()}. "
                f"Possible tampering detected."
            )

        print(f"[TEE Worker] Code hash verified: {computed_hash.hex()}")
        return encrypted_code

    # =========================================================================
    # Code Decryption & Validation
    # =========================================================================

    def decrypt_code(self, encrypted_code: bytes, decryption_key: str) -> str:
        """Decrypt the invention code using the Fernet decryption key."""
        try:
            fernet = Fernet(decryption_key.encode())
            decrypted = fernet.decrypt(encrypted_code)
            return decrypted.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decrypt code: {e}")

    def validate_code(self, code: str) -> tuple[bool, str]:
        """
        Validate that the code is safe to execute in sandbox.

        Note: nsjail provides the primary security boundary.
        This validation is defense-in-depth to catch obvious attacks early.
        """
        forbidden_patterns = [
            # System access
            "import os", "from os", "import sys", "from sys",
            "import subprocess", "from subprocess",
            "import shutil", "from shutil",
            "import pathlib", "from pathlib",

            # Network access
            "import socket", "from socket",
            "import requests", "from requests",
            "import urllib", "from urllib",
            "import http", "from http",
            "import ftplib", "from ftplib",
            "import smtplib", "from smtplib",

            # Code execution
            "__import__", "eval(", "exec(", "compile(",
            "importlib", "builtins",

            # File access
            "open(", "file(", "input(", "raw_input(",

            # Pickle (can execute arbitrary code)
            "import pickle", "from pickle",
            "import cPickle", "from cPickle",

            # Multiprocessing (escape sandbox)
            "import multiprocessing", "from multiprocessing",
            "import threading", "from threading",

            # ctypes (escape sandbox)
            "import ctypes", "from ctypes",
        ]

        code_lower = code.lower()
        for pattern in forbidden_patterns:
            if pattern.lower() in code_lower:
                return False, f"Forbidden pattern detected: {pattern}"

        # Check for attempts to access dunder attributes
        dangerous_dunders = [
            "__class__",
            "__bases__",
            "__subclasses__",
            "__globals__",
            "__code__",
        ]
        for dunder in dangerous_dunders:
            if dunder in code:
                return False, f"Dangerous dunder attribute access: {dunder}"

        return True, ""

    # =========================================================================
    # Sandbox Execution (nsjail)
    # =========================================================================

    def execute_sandbox(self, code: str, input_data: dict) -> tuple[Any, int]:
        """
        Execute invention code in nsjail sandbox.

        Security measures (via nsjail):
        - Namespace isolation (PID, IPC, UTS, mount, user)
        - CPU time limit (10 seconds)
        - Memory limit (256MB)
        - No network access
        - Read-only filesystem (except /tmp)
        - Unprivileged user (nobody/65534)
        - Limited file descriptors (128)
        - Limited processes/threads (16)
        - Single-threaded ML backends (OMP_NUM_THREADS=1)
        """
        # Create minimal wrapper script
        # Note: nsjail.cfg handles environment variables, so we don't need
        # resource.setrlimit or builtins restrictions here
        wrapper = f'''
import json
import sys

# Invention code
{code}

# Execute with input
input_data = json.loads(sys.argv[1])
try:
    result = run(input_data)
    print(json.dumps({{"success": True, "output": result}}))
except Exception as e:
    print(json.dumps({{"success": False, "error": str(e)}}))
'''

        # Write script to /tmp (which is mounted in nsjail)
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False,
            dir='/tmp',
            prefix='adytum_'
        ) as f:
            f.write(wrapper)
            script_path = f.name

        try:
            start_time = time.time()

            # Execute inside nsjail sandbox
            result = subprocess.run(
                [
                    "nsjail",
                    "--config", NSJAIL_CONFIG_PATH,
                    "--",
                    "python3", script_path, json.dumps(input_data)
                ],
                capture_output=True,
                text=True,
                # Buffer for nsjail overhead
                timeout=SANDBOX_TIMEOUT_SECONDS + 5,
                cwd="/tmp",
            )

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Check for nsjail-level failures
            if result.returncode != 0:
                # nsjail returns non-zero for sandbox violations
                error_msg = (
                    result.stderr.strip()
                    if result.stderr
                    else "Sandbox execution failed"
                )
                raise RuntimeError(
                    f"Sandbox error (code {result.returncode}): {error_msg}"
                )

            # Parse the output
            if not result.stdout.strip():
                raise RuntimeError("No output from sandbox execution")

            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"Invalid JSON output: {result.stdout[:200]}... "
                    f"Error: {e}"
                )

            if not output.get("success"):
                raise RuntimeError(
                    output.get("error", "Unknown error in invention code")
                )

            return output["output"], execution_time_ms

        finally:
            # Clean up the script file
            try:
                os.unlink(script_path)
            except OSError:
                # File might already be cleaned up or in isolated namespace
                pass

    # =========================================================================
    # Cryptographic Operations
    # =========================================================================

    def generate_attestation(self, prefix: str, target_hash: str) -> bytes:
        """
        Generate a cryptographic attestation signature.

        In production, this would include dstack TEE attestation report.
        """
        message = f"ADYTUM_ATTESTATION:{prefix}:{target_hash}"
        message_hash = encode_defunct(text=message)
        signed = self.account.sign_message(message_hash)
        return signed.signature

    def compute_result_hash(self, output: Any) -> str:
        """Compute keccak256 hash of the output for on-chain verification."""
        output_bytes = json.dumps(output, sort_keys=True).encode()
        return "0x" + Web3.keccak(output_bytes).hex()

    def encrypt_key_for_buyer(
        self, decryption_key: str, buyer_pub_key: bytes
    ) -> bytes:
        """
        Encrypt the decryption key using ECIES for the buyer.

        Uses the buyer's secp256k1 public key to derive a shared secret,
        then encrypts the key with AES-GCM.

        Format: ephemeral_pubkey (33 bytes) || nonce (12 bytes) || ciphertext
        """
        if len(buyer_pub_key) < 32:
            raise ValueError(
                f"Invalid buyer public key length: {len(buyer_pub_key)}"
            )

        # Generate ephemeral keypair
        ephemeral_private = ec.generate_private_key(
            ec.SECP256K1(), default_backend()
        )
        ephemeral_public = ephemeral_private.public_key()

        # Serialize ephemeral public key (compressed format)
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

        # Reconstruct buyer's public key from bytes
        # Handle different public key formats
        if len(buyer_pub_key) == 32:
            # Raw 32-byte x-coordinate, add 0x02 prefix (compressed, even y)
            buyer_pub_key_full = b'\x02' + buyer_pub_key
        elif len(buyer_pub_key) == 33:
            # Already compressed format
            buyer_pub_key_full = buyer_pub_key
        elif len(buyer_pub_key) == 65:
            # Uncompressed format (0x04 || x || y)
            buyer_pub_key_full = buyer_pub_key
        else:
            raise ValueError(
                f"Unexpected public key length: {len(buyer_pub_key)}"
            )

        try:
            buyer_public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), buyer_pub_key_full
            )
        except Exception as e:
            raise ValueError(f"Failed to parse buyer public key: {e}")

        # ECDH key exchange
        shared_secret = ephemeral_private.exchange(ec.ECDH(), buyer_public)

        # Derive AES key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"adytum-key-encryption",
            backend=default_backend()
        ).derive(shared_secret)

        # Encrypt with AES-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, decryption_key.encode(), None)

        # Combine: ephemeral_pubkey || nonce || ciphertext
        return ephemeral_pub_bytes + nonce + ciphertext

    # =========================================================================
    # Main Execution Flow
    # =========================================================================

    def execute_code(
        self, request: ExecutionRequestDomain
    ) -> ExecutionResultDomain:
        """
        Execute an invention request end-to-end.

        1. Fetch encrypted code from IPFS
        2. Verify code hash matches on-chain commitment
        3. Decrypt code
        4. Validate code safety (defense-in-depth)
        5. Execute in nsjail sandbox
        6. Generate attestation
        """
        try:
            # 1. Fetch and verify encrypted code
            encrypted_code = self.fetch_invention_code(request.invention_id)

            # 2. Decrypt code
            code = self.decrypt_code(encrypted_code, request.decryption_key)

            # 3. Validate code safety (defense-in-depth, nsjail is primary)
            is_valid, error_msg = self.validate_code(code)
            if not is_valid:
                raise RuntimeError(f"Code validation failed: {error_msg}")

            # 4. Execute in nsjail sandbox
            output, execution_time_ms = self.execute_sandbox(
                code, request.input_data
            )

            # 5. Compute result hash and attestation
            result_hash = self.compute_result_hash(output)
            attestation = self.generate_attestation(
                request.execution_id, result_hash
            )

            print(f"[TEE Worker] Execution successful: {request.execution_id}")

            return ExecutionResultDomain(
                execution_id=request.execution_id,
                invention_id=request.invention_id,
                output=output,
                result_hash=result_hash,
                execution_time_ms=execution_time_ms,
                attestation=attestation,
                success=True,
            )

        except Exception as e:
            print(f"[TEE Worker] Execution failed: {e}")

            return ExecutionResultDomain(
                execution_id=request.execution_id,
                invention_id=request.invention_id,
                output=None,
                result_hash="0x" + "0" * 64,
                execution_time_ms=0,
                attestation=b"",
                success=False,
                error=str(e),
            )

    def submit_execution_result(self, result: ExecutionResultDomain):
        """Submit execution result to the AdytumMarketplace contract."""
        exec_id_bytes = self._to_bytes32(result.execution_id)

        if result.success:
            res_hash_bytes = self._to_bytes32(result.result_hash)
            tx = self.contract.functions.submitExecutionResult(
                exec_id_bytes,
                res_hash_bytes,
                result.attestation,
                result.execution_time_ms,
            ).build_transaction({
                "from": self.account.address,
                "nonce": self.w3.eth.get_transaction_count(
                    self.account.address
                ),
                "gas": 200000,
                "gasPrice": self.w3.eth.gas_price,
            })
        else:
            tx = self.contract.functions.failExecution(
                exec_id_bytes,
                result.error or "Unknown error",
            ).build_transaction({
                "from": self.account.address,
                "nonce": self.w3.eth.get_transaction_count(
                    self.account.address
                ),
                "gas": 150000,
                "gasPrice": self.w3.eth.gas_price,
            })

        signed_tx = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        print(
            f"[TEE Worker] Execution result submitted. TX: "
            f"{receipt.transactionHash.hex()}"
        )
        return receipt

    # =========================================================================
    # Key Release (Nash Winner)
    # =========================================================================

    def release_key(
        self, invention_id: str, buyer: str, key_store: "KeyStore"
    ) -> dict:
        """
        Securely release decryption key to Nash winner.

        Authorization checks:
        1. Verify invention exists and is Nash model
        2. Verify Nash phase is SETTLED
        3. Verify buyer is the highestBidder (winner)
        4. Encrypt key with buyer's public key
        5. Submit on-chain

        Implements NDAi §4.2 secure key delivery.

        Note: Uses settlement_account for key release operations.
        """
        inv_bytes = self._to_bytes32(invention_id)

        # 1. Verify invention exists and is Nash model
        invention = self.get_invention(invention_id)
        if invention.model != MonetizationModel.NASH_NEGOTIATION:
            raise ValueError(
                f"Invention {invention_id} is not a Nash negotiation"
            )

        # 2. Verify Nash is settled
        nash_config = self.get_nash_config(invention_id)

        if nash_config.phase != NashPhase.SETTLED:
            phase_names = {
                0: "OPEN",
                1: "REVEAL",
                2: "SETTLED",
                3: "FAILED",
                4: "EXPIRED",
            }
            phase = nash_config.phase
            phase_label = phase_names.get(phase, phase)
            raise ValueError(
                f"Cannot release key: Nash phase is {phase_label}, "
                f"expected SETTLED"
            )

        # 3. Verify buyer is the winner
        if nash_config.highest_bidder.lower() != buyer.lower():
            raise ValueError(
                f"Buyer {buyer} is not the winner. "
                f"Winner is {nash_config.highest_bidder}"
            )

        # 4. Get decryption key from TEE storage
        decryption_key = key_store.get_key(invention_id)
        if not decryption_key:
            raise ValueError(
                f"Decryption key not found in TEE storage for {invention_id}"
            )

        # 5. Fetch buyer's public key from contract
        buyer_pub_key = self.contract.functions.getBuyerPubKey(
            inv_bytes, buyer
        ).call()

        if not buyer_pub_key or len(buyer_pub_key) == 0:
            raise ValueError(
                f"Buyer public key not found on-chain for {buyer}"
            )

        print(
            f"[TEE Worker] Encrypting key for buyer {buyer} "
            f"with pubkey length {len(buyer_pub_key)}"
        )

        # 6. Encrypt key with ECIES
        encrypted_key_bytes = self.encrypt_key_for_buyer(
            decryption_key, buyer_pub_key
        )

        # 7. Generate attestation (using settlement account)
        message = (
            f"ADYTUM_ATTESTATION:KEY_RELEASE:{invention_id}:"
            f"{buyer.lower()}"
        )
        message_hash = encode_defunct(text=message)
        signed = self.settlement_account.sign_message(message_hash)
        attestation = signed.signature

        # 8. Submit to contract (using settlement account)
        tx = self.contract.functions.releaseEncryptedKey(
            inv_bytes,
            encrypted_key_bytes,
            attestation
        ).build_transaction({
            "from": self.settlement_account.address,
            "nonce": self.w3.eth.get_transaction_count(
                self.settlement_account.address
            ),
            "gas": 250000,
            "gasPrice": self.w3.eth.gas_price,
        })

        signed_tx = self.settlement_account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        print(
            f"[TEE Worker] Key release submitted. TX: "
            f"{receipt.transactionHash.hex()}"
        )

        return {
            "success": True,
            "encrypted_key": "0x" + encrypted_key_bytes.hex(),
            "attestation": "0x" + attestation.hex(),
            "tx_hash": receipt.transactionHash.hex(),
        }

    # =========================================================================
    # Utilities
    # =========================================================================

    def _to_bytes32(self, hex_string: str) -> bytes:
        """Convert hex string to bytes32."""
        clean = hex_string.replace("0x", "")
        return bytes.fromhex(clean.zfill(64))


# =============================================================================
# Key Store (TEE-Protected Storage)
# =============================================================================

class KeyStore:
    """
    Secure key storage within the TEE.

    In production (dstack), this uses the TEE's sealed storage.
    Keys are encrypted at rest and only accessible within the enclave.
    """

    def __init__(self, storage_path: str | None = None):
        self.storage_path = storage_path or KEY_STORE_PATH
        os.makedirs(self.storage_path, exist_ok=True)
        print(f"[KeyStore] Initialized at {self.storage_path}")

    def store_key(self, invention_id: str, decryption_key: str) -> None:
        """Store a decryption key for an invention."""
        # Normalize invention_id
        clean_id = invention_id.replace("0x", "").lower()
        key_path = os.path.join(self.storage_path, f"{clean_id}.key")

        with open(key_path, "w") as f:
            f.write(decryption_key)

        print(f"[KeyStore] Stored key for invention {clean_id[:16]}...")

    def get_key(self, invention_id: str) -> str | None:
        """Retrieve a decryption key for an invention."""
        clean_id = invention_id.replace("0x", "").lower()
        key_path = os.path.join(self.storage_path, f"{clean_id}.key")

        if os.path.exists(key_path):
            with open(key_path, "r") as f:
                return f.read().strip()
        return None

    def delete_key(self, invention_id: str) -> bool:
        """Delete a decryption key (e.g., after Nash settlement)."""
        clean_id = invention_id.replace("0x", "").lower()
        key_path = os.path.join(self.storage_path, f"{clean_id}.key")

        if os.path.exists(key_path):
            os.remove(key_path)
            print(f"[KeyStore] Deleted key for invention {clean_id[:16]}...")
            return True
        return False

    def has_key(self, invention_id: str) -> bool:
        """Check if a key exists for an invention."""
        clean_id = invention_id.replace("0x", "").lower()
        key_path = os.path.join(self.storage_path, f"{clean_id}.key")
        return os.path.exists(key_path)
