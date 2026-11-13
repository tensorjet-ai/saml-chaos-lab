import { describe, expect, it } from "vitest";
import {
  buildPinnedHttpsRequestOptions,
  classifyIp,
  normalizeExactUrl,
  verifyDestination,
} from "@saml-chaos/target-safety";

describe("target safety", () => {
  it("connects HTTPS ownership probes to a validated IP while preserving TLS hostname", () => {
    expect(
      buildPinnedHttpsRequestOptions(
        "https://sp.example:8443/.well-known/saml-chaos/token?mode=verify",
        "93.184.216.34",
      ),
    ).toMatchObject({
      protocol: "https:",
      hostname: "93.184.216.34",
      port: "8443",
      path: "/.well-known/saml-chaos/token?mode=verify",
      servername: "sp.example",
      headers: { host: "sp.example:8443", accept: "text/plain" },
    });
  });

  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "172.16.1.1",
    "192.168.1.1",
    "169.254.169.254",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "0:0:0:0:0:ffff:127.0.0.1",
    "0:0:0:0:0:ffff:7f00:1",
    "0:0:0:0:0:0:127.0.0.1",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "2001:db8::1",
    "100::1",
    "64:ff9b::7f00:1",
    "2001::1",
    "2002:7f00:1::",
    "fec0::1",
    "100:0:0:1::1",
    "3fff::1",
    "5f00::1",
    "4000::1",
  ])("blocks non-public address %s", (address) => expect(classifyIp(address)).toBe("blocked"));

  it("classifies expanded IPv4-mapped public addresses by their embedded IPv4 address", () => {
    expect(classifyIp("0:0:0:0:0:ffff:93.184.216.34")).toBe("public");
  });

  it("normalizes hostname case but preserves exact path, port, and query", () => {
    expect(normalizeExactUrl("https://EXAMPLE.COM:8443/saml/acs?a=1")).toBe(
      "https://example.com:8443/saml/acs?a=1",
    );
  });

  it("rejects credentials, fragments, non-HTTPS, and decimal IP disguises", () => {
    for (const value of [
      "http://example.com/acs",
      "https://user:pass@example.com/acs",
      "https://example.com/acs#x",
      "https://2130706433/acs",
    ])
      expect(() => normalizeExactUrl(value)).toThrow();
  });

  it("permits local HTTP only for explicit development hostnames", async () => {
    expect(normalizeExactUrl("http://localhost:4000/saml/acs", true)).toBe(
      "http://localhost:4000/saml/acs",
    );
    expect(() => normalizeExactUrl("http://example.com/acs", true)).toThrow("https_required");
    await expect(
      verifyDestination({
        candidateUrl: "https://internal.example/acs",
        verifiedUrl: "https://internal.example/acs",
        resolve: async () => ["10.0.0.2"],
        allowLocal: true,
      }),
    ).resolves.toMatchObject({ allowed: false, reason: "blocked_ip" });
  });

  it("requires exact verified ACS and public DNS", async () => {
    await expect(
      verifyDestination({
        candidateUrl: "https://example.com/other",
        verifiedUrl: "https://example.com/acs",
        resolve: async () => ["93.184.216.34"],
      }),
    ).resolves.toMatchObject({ allowed: false, reason: "exact_url_mismatch" });
    await expect(
      verifyDestination({
        candidateUrl: "https://example.com/acs",
        verifiedUrl: "https://example.com/acs",
        resolve: async () => ["127.0.0.1"],
      }),
    ).resolves.toMatchObject({ allowed: false, reason: "blocked_ip" });
  });

  it("detects DNS rebinding between resolution checks", async () => {
    let call = 0;
    const decision = await verifyDestination({
      candidateUrl: "https://example.com/acs",
      verifiedUrl: "https://example.com/acs",
      resolve: async () => (++call === 1 ? ["93.184.216.34"] : ["10.0.0.2"]),
      previousAddresses: ["93.184.216.34"],
    });
    expect(decision).toMatchObject({ allowed: false, reason: "dns_rebinding" });
  });

  it("returns the verified address set for request-time DNS pinning", async () => {
    await expect(
      verifyDestination({
        candidateUrl: "https://example.com/acs",
        verifiedUrl: "https://example.com/acs",
        resolve: async () => ["93.184.216.34"],
      }),
    ).resolves.toMatchObject({ allowed: true, addresses: ["93.184.216.34"] });
  });

  it("fails closed when DNS resolution errors", async () => {
    await expect(
      verifyDestination({
        candidateUrl: "https://example.com/acs",
        verifiedUrl: "https://example.com/acs",
        resolve: async () => {
          throw new Error("resolver unavailable");
        },
      }),
    ).resolves.toMatchObject({ allowed: false, reason: "dns_error" });
  });
});
