import { describe, expect, it } from "vitest";
import {
  createProjectCertificates,
  decryptPrivateKeyWith,
  encryptPrivateKey,
  masterKeyDecryptAdapter,
} from "@saml-chaos/saml-core";

describe("key decrypt adapter", () => {
  it("round-trips through the default master-key adapter", async () => {
    const masterKey = Buffer.alloc(32, 7);
    const encrypted = encryptPrivateKey("PRIVATE-KEY-MATERIAL", masterKey, "proj-1");
    const decrypted = await decryptPrivateKeyWith(
      masterKeyDecryptAdapter(masterKey),
      encrypted,
      "proj-1",
    );
    expect(decrypted).toBe("PRIVATE-KEY-MATERIAL");
  });

  it("rejects envelope tampering and cross-project AAD reuse", async () => {
    const masterKey = Buffer.alloc(32, 7);
    const encrypted = encryptPrivateKey("PRIVATE-KEY-MATERIAL", masterKey, "proj-1");
    await expect(
      decryptPrivateKeyWith(masterKeyDecryptAdapter(masterKey), encrypted, "proj-2"),
    ).rejects.toThrow();
    await expect(
      decryptPrivateKeyWith(masterKeyDecryptAdapter(Buffer.alloc(32, 8)), encrypted, "proj-1"),
    ).rejects.toThrow();
  });

  it("supports project certificate bundles through the adapter", async () => {
    const masterKey = Buffer.alloc(32, 7);
    const bundle = await createProjectCertificates("proj-1", masterKey);
    const adapter = masterKeyDecryptAdapter(masterKey);
    const currentKey = await decryptPrivateKeyWith(
      adapter,
      bundle.current.encryptedPrivateKey,
      "proj-1",
    );
    const nextKey = await decryptPrivateKeyWith(adapter, bundle.next.encryptedPrivateKey, "proj-1");
    expect(currentKey).toContain("PRIVATE KEY");
    expect(nextKey).toContain("PRIVATE KEY");
    expect(currentKey).not.toBe(nextKey);
  });
});
