import { describe, expect, it } from "vitest";
import { assertIdpRuntimeConfiguration, resolveMasterKey } from "../apps/idp/src/config.js";
import { secureTokenEquals } from "../apps/idp/src/app.js";

describe("insecure default secret rejection", () => {
  it("rejects known-default ACTIVATION_SECRET and INTERNAL_SERVICE_TOKEN on the idp", () => {
    expect(() =>
      assertIdpRuntimeConfiguration({
        databaseUrl: "postgres://hosted.example/db",
        activationSecret: "local-development-activation-secret-change-me",
        internalToken: "a-real-internal-token",
      }),
    ).toThrow(/ACTIVATION_SECRET/);
    expect(() =>
      assertIdpRuntimeConfiguration({
        databaseUrl: "postgres://hosted.example/db",
        activationSecret: "a-real-activation-secret-with-32-bytes!!",
        internalToken: "local-internal-service-token-change-me",
      }),
    ).toThrow(/INTERNAL_SERVICE_TOKEN/);
  });

  it("rejects an all-zero MASTER_KEY in persistent mode but allows it in ephemeral mode", () => {
    const zeroKey = "A".repeat(43) + "=";
    expect(() => resolveMasterKey(zeroKey, true)).toThrow(/all zeros/);
    expect(() => resolveMasterKey(zeroKey, false)).not.toThrow();
  });
});

describe("secureTokenEquals", () => {
  it("accepts an exact match and rejects mismatches without throwing", () => {
    expect(secureTokenEquals("Bearer abc", "Bearer abc")).toBe(true);
    expect(secureTokenEquals("Bearer abd", "Bearer abc")).toBe(false);
    expect(secureTokenEquals(undefined, "Bearer abc")).toBe(false);
    expect(secureTokenEquals("Bearer abc", "")).toBe(false);
  });
});
