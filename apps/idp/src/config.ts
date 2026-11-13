import { randomBytes } from "node:crypto";

const KNOWN_INSECURE_DEFAULTS = new Set([
  "local-internal-service-token-change-me",
  "local-development-activation-secret-change-me",
  "replace-with-a-random-internal-service-token",
  "replace-with-at-least-32-random-characters",
]);

export function isInsecureDefaultSecret(value: string | undefined): boolean {
  return typeof value === "string" && KNOWN_INSECURE_DEFAULTS.has(value);
}

export function assertIdpRuntimeConfiguration(options: {
  databaseUrl?: string;
  activationSecret?: string;
  internalToken?: string;
}): void {
  if (!options.databaseUrl) return;
  if (!options.activationSecret) throw new Error("ACTIVATION_SECRET is required with DATABASE_URL");
  if (!options.internalToken)
    throw new Error("INTERNAL_SERVICE_TOKEN is required with DATABASE_URL");
  if (isInsecureDefaultSecret(options.activationSecret)) {
    throw new Error("ACTIVATION_SECRET is set to a known default; set a unique random value");
  }
  if (isInsecureDefaultSecret(options.internalToken)) {
    throw new Error("INTERNAL_SERVICE_TOKEN is set to a known default; set a unique random value");
  }
}

export function resolveMasterKey(value: string | undefined, persistent: boolean): Buffer {
  if (!value) {
    if (persistent) throw new Error("MASTER_KEY_BASE64 is required with DATABASE_URL");
    return randomBytes(32);
  }
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw new Error("MASTER_KEY_BASE64 must be valid canonical base64");
  }
  const key = Buffer.from(value, "base64");
  if (key.toString("base64") !== value) {
    throw new Error("MASTER_KEY_BASE64 must be valid canonical base64");
  }
  if (key.length !== 32) throw new Error("MASTER_KEY_BASE64 must decode to a 32-byte key");
  if (persistent && key.every((byte) => byte === 0)) {
    throw new Error("MASTER_KEY_BASE64 is all zeros; set a random 32-byte key for hosted mode");
  }
  return key;
}
