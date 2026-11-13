import { inflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { buildFixtureSp } from "../../fixtures/vulnerable-sp/src/app.js";
import { generateResponse, generateSigningMaterial } from "@saml-chaos/saml-core";

describe("secure fixture SP oracle", () => {
  it("accepts valid bound response, rejects wrong audience, and rejects replay", async () => {
    const signing = generateSigningMaterial();
    const config = {
      spEntityId: "urn:fixture:sp",
      idpEntityId: "http://idp.test/metadata/fixture",
      idpSsoUrl: "http://idp.test/sso/fixture",
      acsUrl: "http://fixture.test/saml/acs",
      trustedCertificates: async () => [signing.certificate],
      now: () => new Date("2026-07-16T00:00:00Z"),
    };
    const app = buildFixtureSp(config);
    const login = await app.inject({ method: "GET", url: "/login" });
    const location = new URL(login.headers.location!);
    const xml = inflateRawSync(
      Buffer.from(location.searchParams.get("SAMLRequest")!, "base64"),
    ).toString();
    const requestId = xml.match(/ID="([^"]+)"/)![1]!;
    const response = generateResponse({
      issuer: config.idpEntityId,
      requestId,
      destination: config.acsUrl,
      audience: config.spEntityId,
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: { role: ["tester"] },
      signing,
      now: config.now(),
    });
    const body = new URLSearchParams({
      SAMLResponse: Buffer.from(response.xml).toString("base64"),
    }).toString();
    const accepted = await app.inject({
      method: "POST",
      url: "/saml/acs",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: body,
    });
    expect(accepted.statusCode).toBe(303);
    expect(accepted.headers.location).toBe("/success");
    const replay = await app.inject({
      method: "POST",
      url: "/saml/acs",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: body,
    });
    expect(replay.headers.location).toContain("/saml/error");

    const login2 = await app.inject({ method: "GET", url: "/login" });
    const location2 = new URL(login2.headers.location!);
    const xml2 = inflateRawSync(
      Buffer.from(location2.searchParams.get("SAMLRequest")!, "base64"),
    ).toString();
    const requestId2 = xml2.match(/ID="([^"]+)"/)![1]!;
    const wrong = generateResponse({
      issuer: config.idpEntityId,
      requestId: requestId2,
      destination: config.acsUrl,
      audience: "urn:wrong",
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: {},
      signing,
      now: config.now(),
    });
    const wrongResult = await app.inject({
      method: "POST",
      url: "/saml/acs",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        SAMLResponse: Buffer.from(wrong.xml).toString("base64"),
      }).toString(),
    });
    expect(wrongResult.headers.location).toContain("/saml/error");
    await app.close();
  });

  it("rejects a fresh response bound to an expired login request", async () => {
    const signing = generateSigningMaterial();
    let now = new Date("2026-07-16T00:00:00Z");
    const config = {
      spEntityId: "urn:fixture:sp",
      idpEntityId: "http://idp.test/metadata/fixture",
      idpSsoUrl: "http://idp.test/sso/fixture",
      acsUrl: "http://fixture.test/saml/acs",
      trustedCertificates: async () => [signing.certificate],
      now: () => now,
    };
    const app = buildFixtureSp(config);
    const login = await app.inject({ method: "GET", url: "/login" });
    const location = new URL(login.headers.location!);
    const requestXml = inflateRawSync(
      Buffer.from(location.searchParams.get("SAMLRequest")!, "base64"),
    ).toString();
    const requestId = requestXml.match(/ID="([^"]+)"/)![1]!;
    now = new Date(now.getTime() + 10 * 60_000);
    const response = generateResponse({
      issuer: config.idpEntityId,
      requestId,
      destination: config.acsUrl,
      audience: config.spEntityId,
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: {},
      signing,
      now,
    });

    const result = await app.inject({
      method: "POST",
      url: "/saml/acs",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        SAMLResponse: Buffer.from(response.xml).toString("base64"),
      }).toString(),
    });

    expect(result.headers.location).toContain("/saml/error");
    await app.close();
  });

  it("bounds pending login state and evicts the oldest request", async () => {
    const signing = generateSigningMaterial();
    const now = new Date("2026-07-16T00:00:00Z");
    const config = {
      spEntityId: "urn:fixture:sp",
      idpEntityId: "http://idp.test/metadata/fixture",
      idpSsoUrl: "http://idp.test/sso/fixture",
      acsUrl: "http://fixture.test/saml/acs",
      trustedCertificates: async () => [signing.certificate],
      now: () => now,
      pendingRequestLimit: 2,
    };
    const app = buildFixtureSp(config);
    const requestIds: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const login = await app.inject({ method: "GET", url: "/login" });
      const location = new URL(login.headers.location!);
      const xml = inflateRawSync(
        Buffer.from(location.searchParams.get("SAMLRequest")!, "base64"),
      ).toString();
      requestIds.push(xml.match(/ID="([^"]+)"/)![1]!);
    }
    const response = generateResponse({
      issuer: config.idpEntityId,
      requestId: requestIds[0]!,
      destination: config.acsUrl,
      audience: config.spEntityId,
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: {},
      signing,
      now,
    });

    const result = await app.inject({
      method: "POST",
      url: "/saml/acs",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        SAMLResponse: Buffer.from(response.xml).toString("base64"),
      }).toString(),
    });

    expect(result.headers.location).toContain("/saml/error");
    await app.close();
  });
});
