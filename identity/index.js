/**
 * Adytum TEE Worker - Identity Sidecar
 * =====================================
 *
 * Derives deterministic Ethereum keys from the dstack KMS.
 * Runs once on CVM startup, exports keys for the Python worker.
 *
 * Key Derivation Paths:
 * - adytum/execution/v1  → TEE_EXECUTION_ROLE (submitExecutionResult, failExecution)
 * - adytum/settlement/v1 → TEE_SETTLEMENT_ROLE (settleNash, releaseKey, flagExtraction, banBuyer)
 *
 * Usage:
 *   This service runs first via docker-compose depends_on, then exits.
 *   The Python worker reads the exported keys from /tee/derived-keys.json
 */

import { DstackClient } from "@phala/dstack-sdk";
import { toViemAccountSecure } from "@phala/dstack-sdk/viem";
import fs from "fs";
import path from "path";

// Output path for derived keys (shared volume with Python worker)
const OUTPUT_PATH = process.env.DERIVED_KEYS_PATH || "/tee/derived-keys.json";

// Key derivation paths (versioned for future rotation)
const EXECUTION_PATH = process.env.EXECUTION_KEY_PATH || "adytum/execution/v1";
const SETTLEMENT_PATH =
  process.env.SETTLEMENT_KEY_PATH || "adytum/settlement/v1";

async function deriveAndExport() {
  console.log("[Identity] Starting key derivation...");
  console.log("[Identity] Execution path:", EXECUTION_PATH);
  console.log("[Identity] Settlement path:", SETTLEMENT_PATH);

  // Connect to dstack KMS via Unix socket
  const client = new DstackClient();

  // Derive Execution Node identity
  // Used for: submitExecutionResult(), failExecution()
  console.log("[Identity] Deriving execution key...");
  const execKeyResult = await client.getKey(EXECUTION_PATH);
  const execAccount = toViemAccountSecure(execKeyResult);

  // Derive Settlement Node identity
  // Used for: settleNash(), releaseKey(), flagExtraction(), banBuyer()
  console.log("[Identity] Deriving settlement key...");
  const settleKeyResult = await client.getKey(SETTLEMENT_PATH);
  const settleAccount = toViemAccountSecure(settleKeyResult);

  // Log discovered addresses (these are public, safe to log)
  console.log("");
  console.log("========================================");
  console.log("ADYTUM TEE WORKER - IDENTITY DISCOVERED");
  console.log("========================================");
  console.log("EXECUTION_NODE_ADDRESS:", execAccount.address);
  console.log("SETTLEMENT_NODE_ADDRESS:", settleAccount.address);
  console.log("========================================");
  console.log("");

  // Prepare keys object for Python worker
  // Private keys are hex-encoded with 0x prefix for eth-account compatibility
  const keys = {
    execution: {
      address: execAccount.address,
      privateKey: "0x" + Buffer.from(execKeyResult.key).toString("hex"),
      derivationPath: EXECUTION_PATH,
    },
    settlement: {
      address: settleAccount.address,
      privateKey: "0x" + Buffer.from(settleKeyResult.key).toString("hex"),
      derivationPath: SETTLEMENT_PATH,
    },
    metadata: {
      derivedAt: new Date().toISOString(),
      version: "1.0.0",
    },
  };

  // Ensure output directory exists
  const outputDir = path.dirname(OUTPUT_PATH);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Write keys to file (only accessible within TEE enclave)
  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
  console.log("[Identity] Keys written to", OUTPUT_PATH);

  // Verify the file was written correctly
  const written = JSON.parse(fs.readFileSync(OUTPUT_PATH, "utf8"));
  if (written.execution.address !== execAccount.address) {
    throw new Error("Key file verification failed");
  }
  console.log("[Identity] Key file verified successfully");

  console.log("[Identity] Identity sidecar completed. Exiting.");
}

// Run and handle errors
deriveAndExport()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("[Identity] Fatal error:", err.message);
    console.error(err.stack);
    process.exit(1);
  });
