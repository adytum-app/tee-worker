# Adytum TEE Worker Dockerfile
# ============================
# Runs inside dstack TEE enclave
#
# Build:
#   docker build -t adytum-tee-worker .
#
# Run (local testing with nsjail):
#   docker run --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE -p 8001:8001 \
#     -e CONTRACT_ADDRESS=0x... \
#     -e ORACLE_PRIVATE_KEY=0x... \
#     -e RPC_URL=https://sepolia.base.org \
#     adytum-tee-worker
#
# Deploy to dstack:
#   dstack deploy --image adytum-tee-worker

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create directories
RUN mkdir -p /app /tee/keys

WORKDIR /app

# Install system dependencies AND nsjail for sandboxing
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    nsjail \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code from the src directory
COPY src/ ./src/

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/health', timeout=5).raise_for_status()"

# Default environment variables
ENV HOST=0.0.0.0 \
    PORT=8001 \
    KEY_STORE_PATH=/tee/keys \
    SANDBOX_TIMEOUT_SECONDS=30 \
    SANDBOX_MEMORY_LIMIT_MB=256

# SECURITY NOTE: 
# We run as root inside the TEE enclave because nsjail requires 
# elevated privileges (CAP_SYS_ADMIN) to create isolation namespaces.
# The TEE provides the hardware/VM isolation boundary, and nsjail 
# provides the process isolation boundary for the untrusted code.
CMD ["python", "src/server.py"]