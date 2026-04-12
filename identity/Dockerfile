# Adytum TEE Identity Sidecar
# ===========================
# Derives deterministic keys from dstack KMS on startup.
# Runs once before the Python worker starts.
#
# Build:
#   docker build -f identity/Dockerfile -t adytum-tee-identity .
#
# Note: This container requires the dstack socket mount to function.

FROM node:20-slim

LABEL org.opencontainers.image.source="https://github.com/adytum-app/tee-worker"
LABEL org.opencontainers.image.description="Adytum TEE Identity Sidecar - dstack key derivation"

WORKDIR /app

# Create TEE storage directory
RUN mkdir -p /tee

# Copy package files
COPY identity/package*.json ./

# Install dependencies
RUN npm install --production

# Copy application code
COPY identity/index.js ./

# Environment variables (can be overridden)
ENV DERIVED_KEYS_PATH=/tee/derived-keys.json
ENV EXECUTION_KEY_PATH=adytum/execution/v1
ENV SETTLEMENT_KEY_PATH=adytum/settlement/v1

# Run the key derivation script and exit
CMD ["node", "index.js"]
