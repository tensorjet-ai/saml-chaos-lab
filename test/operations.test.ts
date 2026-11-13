import { describe, expect, it } from "vitest";
import {
  AuditLog,
  cleanupExpiredRecords,
  OperationalMetrics,
  redactRequestUrl,
} from "@saml-chaos/observability";
import { OwnershipVerificationService } from "@saml-chaos/target-safety";

describe("ownership verification", () => {
  it("verifies DNS TXT and HTTPS well-known challenges once", async () => {
    const service = new OwnershipVerificationService(() => 1_000);
    const dns = await service.create("p1", "sp.example", "dns_txt", 60);
    await expect(
      service.verify(dns.id, {
        lookupTxt: async () => [[dns.token]],
        fetchText: async () => "",
      }),
    ).resolves.toMatchObject({ verified: true, hostname: "sp.example" });
    await expect(
      service.verify(dns.id, {
        lookupTxt: async () => [[dns.token]],
        fetchText: async () => "",
      }),
    ).rejects.toThrow("challenge_consumed");
    const https = await service.create("p1", "sp.example", "https", 60);
    await expect(
      service.verify(https.id, {
        lookupTxt: async () => [],
        fetchText: async (url) => (url.endsWith(https.token) ? https.token : ""),
      }),
    ).resolves.toMatchObject({ verified: true });
  });

  it("removes expired challenge state during normal creation traffic", async () => {
    let now = 1_000;
    const service = new OwnershipVerificationService(() => now);
    for (let index = 0; index < 20; index += 1) {
      await service.create(`p${index}`, "sp.example", "dns_txt", 1);
    }
    expect(service.challengeCount).toBe(20);

    now += 1_001;
    await service.create("fresh", "sp.example", "dns_txt", 60);

    expect(service.challengeCount).toBe(1);
  });

  it("reserves a single-use challenge before asynchronous verification", async () => {
    const service = new OwnershipVerificationService(() => 1_000);
    const challenge = await service.create("p1", "sp.example", "dns_txt", 60);
    let releaseLookup!: (records: string[][]) => void;
    let markLookupStarted!: () => void;
    const lookupStarted = new Promise<void>((resolve) => {
      markLookupStarted = resolve;
    });
    const lookupResult = new Promise<string[][]>((resolve) => {
      releaseLookup = resolve;
    });
    const adapters = {
      lookupTxt: async () => {
        markLookupStarted();
        return lookupResult;
      },
      fetchText: async () => "",
    };

    const first = service.verify(challenge.id, adapters);
    await lookupStarted;
    await expect(service.verify(challenge.id, adapters)).rejects.toThrow("challenge_consumed");
    releaseLookup([[challenge.token]]);
    await expect(first).resolves.toMatchObject({ verified: true });
  });

  it("invalidates an earlier project challenge when it is replaced", async () => {
    const service = new OwnershipVerificationService(() => 1_000);
    const oldChallenge = await service.create("p1", "sp.example", "dns_txt", 60);
    const replacement = await service.create("p1", "sp.example", "https", 60);

    expect(service.challengeCount).toBe(1);
    await expect(
      service.verify(oldChallenge.id, {
        lookupTxt: async () => [[oldChallenge.token]],
        fetchText: async () => oldChallenge.token,
      }),
    ).rejects.toThrow("challenge_not_found");
    await expect(
      service.verify(replacement.id, {
        lookupTxt: async () => [],
        fetchText: async () => replacement.token,
      }),
    ).resolves.toMatchObject({ verified: true });
  });
});

describe("audit and retention", () => {
  it("removes sensitive query values from request-log URLs", () => {
    const redacted = redactRequestUrl(
      "/activate/p1?token=jwt-secret&SAMLRequest=assertion-secret&browserSessionId=b1",
    );
    expect(redacted).toBe("/activate/p1?[REDACTED]");
    expect(redacted).not.toContain("jwt-secret");
    expect(redacted).not.toContain("assertion-secret");
  });

  it("renders bounded operational metrics without customer labels", () => {
    const metrics = new OperationalMetrics();
    metrics.increment("blocked_targets_total", { reason: "private_ip" });
    metrics.set("queue_depth", 3);
    const output = metrics.render();
    expect(output).toContain('blocked_targets_total{reason="private_ip"} 1');
    expect(output).toContain("queue_depth 3");
    expect(() => metrics.increment("blocked_targets_total", { customer: "acme" })).toThrow(
      "metric_label_not_allowed",
    );
    expect(() => metrics.increment("blocked_targets_total", {}, Number.NaN)).toThrow(
      "invalid_metric_value",
    );
    expect(() => metrics.increment("blocked_targets_total", {}, -1)).toThrow(
      "invalid_metric_value",
    );
  });

  it("stores immutable redacted event metadata", () => {
    const audit = new AuditLog(() => new Date("2026-07-16T00:00:00Z"));
    audit.record("destination.allowed", {
      projectId: "p1",
      cookie: "secret",
      url: "https://sp.example/acs?token=secret",
    });
    const events = audit.list();
    expect(JSON.stringify(events)).not.toContain("secret");
    expect(() => {
      (events[0]!.metadata as Record<string, unknown>).projectId = "changed";
    }).toThrow();
  });

  it("deletes expired raw evidence and reports while preserving audit metadata", () => {
    const now = new Date("2026-07-16T00:00:00Z");
    const cleaned = cleanupExpiredRecords({
      now,
      evidence: [
        { id: "old", expiresAt: new Date("2026-07-15") },
        { id: "new", expiresAt: new Date("2026-07-17") },
      ],
      reports: [{ id: "expired", expiresAt: new Date("2026-07-15") }],
      audit: [{ id: "keep", createdAt: new Date("2025-01-01") }],
    });
    expect(cleaned.evidence.map((item) => item.id)).toEqual(["new"]);
    expect(cleaned.reports).toEqual([]);
    expect(cleaned.audit).toHaveLength(1);
  });
});
