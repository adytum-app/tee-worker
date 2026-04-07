"""
Adytum TEE Worker HTTP Server

Exposes the TEE worker functionality via HTTP.
Runs inside the dstack TEE enclave.

Endpoints:
- GET  /health         - Health check with oracle address
- GET  /attestation    - TEE attestation report
- POST /execute        - Execute invention code in sandbox
- POST /release-key    - Release decryption key to Nash winner
- POST /store-key      - Store decryption key (seller listing)
- GET  /keys/{id}      - Check if key exists for invention
- DELETE /keys/{id}    - Delete a key (when deactivating invention)

Implements the HTTP interface for NDAi TEE-resident agents.
"""

import os
import re
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Any

from worker import AdytumTEEWorker, ExecutionRequestDomain, KeyStore

# =============================================================================
# Lifespan Management
# =============================================================================

# Global instances (initialized on startup)
worker: AdytumTEEWorker | None = None
key_store: KeyStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize worker and key store on startup."""
    global worker, key_store
    
    print("[Server] Initializing TEE Worker...")
    worker = AdytumTEEWorker()
    key_store = KeyStore()
    
    print(f"[Server] TEE Worker ready. Oracle: {worker.account.address}")
    
    yield
    
    print("[Server] Shutting down TEE Worker...")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="Adytum TEE Worker",
    description=(
        "TEE enclave worker for executing invention code and releasing keys securely. "
        "Implements the TEE-resident agent from NDAi paper (Stephenson et al., 2025)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware (configure for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


# =============================================================================
# Request/Response Models with Validation
# =============================================================================

class ExecuteRequest(BaseModel):
    """Request to execute invention code."""
    execution_id: str = Field(..., description="Unique execution ID (bytes32 hex)")
    invention_id: str = Field(..., description="Invention ID (bytes32 hex)")
    buyer: str = Field(..., description="Buyer address (0x...)")
    input_data: dict = Field(..., description="Input data for the invention")
    
    @field_validator("execution_id", "invention_id")
    @classmethod
    def validate_bytes32(cls, v: str) -> str:
        clean = v.replace("0x", "")
        if not re.match(r"^[a-fA-F0-9]{64}$", clean):
            raise ValueError("Must be a valid bytes32 hex string")
        return "0x" + clean.lower()
    
    @field_validator("buyer")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not re.match(r"^0x[a-fA-F0-9]{40}$", v):
            raise ValueError("Must be a valid Ethereum address")
        return v.lower()


class ExecuteResponse(BaseModel):
    """Response from execution."""
    success: bool
    execution_id: str
    output: Optional[Any] = None
    result_hash: Optional[str] = None
    execution_time_ms: Optional[int] = None
    attestation: Optional[str] = None
    error: Optional[str] = None


class ReleaseKeyRequest(BaseModel):
    """Request to release decryption key to Nash winner."""
    invention_id: str = Field(..., description="Invention ID (bytes32 hex)")
    buyer: str = Field(..., description="Buyer address (must be Nash winner)")
    
    @field_validator("invention_id")
    @classmethod
    def validate_bytes32(cls, v: str) -> str:
        clean = v.replace("0x", "")
        if not re.match(r"^[a-fA-F0-9]{64}$", clean):
            raise ValueError("Must be a valid bytes32 hex string")
        return "0x" + clean.lower()
    
    @field_validator("buyer")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not re.match(r"^0x[a-fA-F0-9]{40}$", v):
            raise ValueError("Must be a valid Ethereum address")
        return v.lower()


class ReleaseKeyResponse(BaseModel):
    """Response from key release."""
    success: bool
    invention_id: str
    buyer: str
    encrypted_key: Optional[str] = None
    attestation: Optional[str] = None
    tx_hash: Optional[str] = None
    error: Optional[str] = None


class StoreKeyRequest(BaseModel):
    """Request to store decryption key for a new invention."""
    invention_id: str = Field(..., description="Invention ID (bytes32 hex)")
    decryption_key: str = Field(..., description="Fernet decryption key")
    seller: str = Field(..., description="Seller address (for verification)")
    
    @field_validator("invention_id")
    @classmethod
    def validate_bytes32(cls, v: str) -> str:
        clean = v.replace("0x", "")
        if not re.match(r"^[a-fA-F0-9]{64}$", clean):
            raise ValueError("Must be a valid bytes32 hex string")
        return "0x" + clean.lower()
    
    @field_validator("seller")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not re.match(r"^0x[a-fA-F0-9]{40}$", v):
            raise ValueError("Must be a valid Ethereum address")
        return v.lower()
    
    @field_validator("decryption_key")
    @classmethod
    def validate_fernet_key(cls, v: str) -> str:
        # Fernet keys are 44 characters base64
        if len(v) != 44:
            raise ValueError("Decryption key must be a valid Fernet key (44 chars)")
        return v


class StoreKeyResponse(BaseModel):
    """Response from key storage."""
    success: bool
    invention_id: str
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    oracle_address: str
    enclave: str
    contract_address: Optional[str] = None
    key_store_path: str
    nsjail_config: str


class AttestationResponse(BaseModel):
    """TEE attestation response."""
    enclave_type: str
    oracle_address: str
    attestation: str
    timestamp: int


# =============================================================================
# Health & Status Endpoints
# =============================================================================

@app.get("/health", response_model=HealthResponse)
async def health():
    """
    Health check endpoint.
    
    Returns the oracle address and enclave status.
    Used by load balancers and monitoring.
    """
    if worker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Worker not initialized"
        )
    
    return HealthResponse(
        status="healthy",
        oracle_address=worker.account.address,
        enclave="dstack",
        contract_address=os.getenv("CONTRACT_ADDRESS"),
        key_store_path=key_store.storage_path if key_store else "N/A",
        nsjail_config=os.getenv("NSJAIL_CONFIG_PATH", "/app/nsjail.cfg"),
    )


@app.get("/attestation", response_model=AttestationResponse)
async def get_attestation():
    """
    Get TEE attestation report.
    
    In production (dstack), this returns the remote attestation
    proving code is running inside a genuine TEE enclave.
    """
    if worker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Worker not initialized"
        )
    
    # In production: Include dstack remote attestation
    attestation = worker.generate_attestation("HEALTH_CHECK", worker.account.address)
    
    return AttestationResponse(
        enclave_type="dstack",
        oracle_address=worker.account.address,
        attestation="0x" + attestation.hex(),
        timestamp=int(time.time()),
    )


# =============================================================================
# Execution Endpoint
# =============================================================================

@app.post("/execute", response_model=ExecuteResponse)
async def execute_invention(request: ExecuteRequest):
    """
    Execute invention code in the TEE nsjail sandbox.
    
    Flow:
    1. Fetch decryption key from local TEE storage
    2. Fetch encrypted code from IPFS (via contract metadata)
    3. Verify code hash matches on-chain commitment
    4. Decrypt code using stored key
    5. Validate code safety (defense-in-depth)
    6. Execute in nsjail sandbox with resource limits
    7. Submit result hash and attestation to contract
    8. Return result to caller
    
    Security:
    - Code never leaves the TEE
    - nsjail provides namespace isolation
    - CPU/memory/file descriptor limits enforced
    - No network access inside sandbox
    - Result is attested cryptographically
    """
    if worker is None or key_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Worker not initialized"
        )
    
    try:
        # 1. Get decryption key from TEE storage
        decryption_key = key_store.get_key(request.invention_id)
        if not decryption_key:
            raise ValueError(f"No decryption key found for invention {request.invention_id}")
        
        # 2. Build execution request
        request_domain = ExecutionRequestDomain(
            execution_id=request.execution_id,
            invention_id=request.invention_id,
            buyer=request.buyer,
            input_data=request.input_data,
            decryption_key=decryption_key,
        )
        
        # 3. Execute in nsjail sandbox
        result = worker.execute_code(request_domain)
        
        # 4. Submit to contract
        try:
            receipt = worker.submit_execution_result(result)
            print(f"[Server] Execution result submitted. TX: {receipt.transactionHash.hex()}")
        except Exception as e:
            print(f"[Server] Warning: Failed to submit to contract: {e}")
            # Still return result even if contract submission fails
            # (allows retry logic on the caller side)
        
        # 5. Build response
        if result.success:
            return ExecuteResponse(
                success=True,
                execution_id=result.execution_id,
                output=result.output,
                result_hash=result.result_hash,
                execution_time_ms=result.execution_time_ms,
                attestation="0x" + result.attestation.hex() if result.attestation else None,
            )
        else:
            return ExecuteResponse(
                success=False,
                execution_id=result.execution_id,
                error=result.error,
            )
            
    except Exception as e:
        print(f"[Server] Execution error: {e}")
        return ExecuteResponse(
            success=False,
            execution_id=request.execution_id,
            error=str(e),
        )


# =============================================================================
# Key Management Endpoints
# =============================================================================

@app.post("/release-key", response_model=ReleaseKeyResponse)
async def release_key(request: ReleaseKeyRequest):
    """
    Release decryption key to Nash winner.
    
    Authorization checks (performed by worker):
    1. Invention must be Nash negotiation model
    2. Nash phase must be SETTLED
    3. Buyer must be the highestBidder (winner)
    
    Flow:
    1. Verify authorization on-chain
    2. Fetch buyer's public key from contract
    3. Encrypt decryption key with ECIES
    4. Submit encrypted key and attestation on-chain
    5. Return encrypted key to caller
    
    Implements NDAi §4.2 secure key delivery.
    """
    if worker is None or key_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Worker not initialized"
        )
    
    try:
        # Worker performs all authorization checks internally
        result = worker.release_key(
            request.invention_id,
            request.buyer,
            key_store
        )
        
        return ReleaseKeyResponse(
            success=True,
            invention_id=request.invention_id,
            buyer=request.buyer,
            encrypted_key=result["encrypted_key"],
            attestation=result["attestation"],
            tx_hash=result.get("tx_hash"),
        )
        
    except ValueError as e:
        # Authorization or validation error
        print(f"[Server] Key release denied: {e}")
        return ReleaseKeyResponse(
            success=False,
            invention_id=request.invention_id,
            buyer=request.buyer,
            error=str(e),
        )
        
    except Exception as e:
        print(f"[Server] Key release error: {e}")
        return ReleaseKeyResponse(
            success=False,
            invention_id=request.invention_id,
            buyer=request.buyer,
            error=str(e),
        )


@app.post("/store-key", response_model=StoreKeyResponse)
async def store_key(request: StoreKeyRequest):
    """
    Store decryption key for a new invention.
    
    Called when a seller lists an invention:
    1. Frontend encrypts code with Fernet key
    2. Frontend uploads encrypted code to IPFS
    3. Frontend calls this endpoint to store key in TEE
    4. Frontend calls contract to list invention
    
    Security:
    - Key is stored in TEE-sealed storage
    - Only accessible within this enclave
    - Never exposed outside the TEE
    
    TODO (production):
    - Verify seller owns this invention on-chain
    - Verify encryption key hash matches contract
    - Rate limiting per seller
    """
    if worker is None or key_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Worker not initialized"
        )
    
    try:
        # In production: Verify seller owns this invention
        # invention = worker.get_invention(request.invention_id)
        # if invention.seller.lower() != request.seller.lower():
        #     raise ValueError("Seller does not own this invention")
        
        # Check if key already exists
        if key_store.has_key(request.invention_id):
            raise ValueError(f"Key already stored for invention {request.invention_id}")
        
        # Store the key
        key_store.store_key(request.invention_id, request.decryption_key)
        
        print(f"[Server] Stored key for invention {request.invention_id[:18]}...")
        
        return StoreKeyResponse(
            success=True,
            invention_id=request.invention_id,
        )
        
    except ValueError as e:
        return StoreKeyResponse(
            success=False,
            invention_id=request.invention_id,
            error=str(e),
        )
        
    except Exception as e:
        print(f"[Server] Store key error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/keys/{invention_id}")
async def check_key_exists(invention_id: str):
    """
    Check if a decryption key exists for an invention.
    
    Used by frontend to verify key was stored before listing.
    Does NOT return the key itself.
    """
    if key_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Key store not initialized"
        )
    
    # Validate invention_id format
    clean = invention_id.replace("0x", "")
    if not re.match(r"^[a-fA-F0-9]{64}$", clean):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid invention ID format"
        )
    
    exists = key_store.has_key(invention_id)
    
    return {
        "invention_id": "0x" + clean.lower(),
        "key_exists": exists,
    }


@app.delete("/keys/{invention_id}")
async def delete_key(invention_id: str, seller: str):
    """
    Delete a decryption key (e.g., when deactivating an invention).
    
    TODO (production):
    - Verify seller owns this invention on-chain
    - Verify invention is deactivated
    """
    if key_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Key store not initialized"
        )
    
    # Validate invention_id format
    clean = invention_id.replace("0x", "")
    if not re.match(r"^[a-fA-F0-9]{64}$", clean):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid invention ID format"
        )
    
    # Validate seller address
    if not re.match(r"^0x[a-fA-F0-9]{40}$", seller):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid seller address format"
        )
    
    # In production: Verify seller owns this invention on-chain
    # invention = worker.get_invention(invention_id)
    # if invention.seller.lower() != seller.lower():
    #     raise HTTPException(status_code=403, detail="Not authorized")
    
    deleted = key_store.delete_key(invention_id)
    
    return {
        "invention_id": "0x" + clean.lower(),
        "deleted": deleted,
    }


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    
    print(f"[Server] Starting Adytum TEE Worker on {host}:{port}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )