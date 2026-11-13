import { deflateRawSync } from "node:zlib";
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createProjectCertificates,
  decryptPrivateKey,
  encryptPrivateKey,
  generateSigningMaterial,
  generateMetadata,
  generateResponse,
  parseRedirectAuthnRequest,
  verifyXmlSignature,
} from "@saml-chaos/saml-core";
import { assertIdpRuntimeConfiguration, resolveMasterKey } from "../apps/idp/src/config.js";

const requestXml = (acs = "https://sp.example/saml/acs", issuer = "urn:sp") =>
  `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request" Version="2.0" IssueInstant="2026-07-16T00:00:00Z" Destination="https://idp.example/sso/p1" AssertionConsumerServiceURL="${acs}"><saml:Issuer>${issuer}</saml:Issuer></samlp:AuthnRequest>`;

const redirectPayload = (xml: string) => deflateRawSync(Buffer.from(xml)).toString("base64");

describe("project key isolation", () => {
  it("requires hosted activation and provisioning secrets with persistent projects", () => {
    expect(() =>
      assertIdpRuntimeConfiguration({
        databaseUrl: "postgres://db",
        internalToken: "internal",
      }),
    ).toThrow("ACTIVATION_SECRET");
    expect(() =>
      assertIdpRuntimeConfiguration({
        databaseUrl: "postgres://db",
        activationSecret: "x".repeat(32),
      }),
    ).toThrow("INTERNAL_SERVICE_TOKEN");
  });

  it("requires a stable configured master key when persistence is enabled", () => {
    expect(() => resolveMasterKey(undefined, true)).toThrow("MASTER_KEY_BASE64 is required");
    expect(() => resolveMasterKey("not-base64", true)).toThrow("valid canonical base64");
    expect(resolveMasterKey(Buffer.alloc(32, 7).toString("base64"), true)).toEqual(
      Buffer.alloc(32, 7),
    );
    expect(() => resolveMasterKey(`${Buffer.alloc(32, 7).toString("base64")}!!!!`, true)).toThrow(
      "valid canonical base64",
    );
  });

  it("envelope-encrypts private key material and fails closed with wrong master key", () => {
    const master = randomBytes(32);
    const encrypted = encryptPrivateKey("PRIVATE-SECRET", master, "project-1");
    expect(JSON.stringify(encrypted)).not.toContain("PRIVATE-SECRET");
    expect(decryptPrivateKey(encrypted, master, "project-1")).toBe("PRIVATE-SECRET");
    expect(() => decryptPrivateKey(encrypted, randomBytes(32), "project-1")).toThrow();
  });

  it("creates current and next self-signed certificates without exposing private keys in metadata", async () => {
    const bundle = await createProjectCertificates("project-1", randomBytes(32));
    const metadata = generateMetadata({
      entityId: "https://idp.example/metadata/p1",
      ssoUrl: "https://idp.example/sso/p1",
      certificates: [bundle.current.certificate, bundle.next.certificate],
    });
    expect(metadata).toContain("IDPSSODescriptor");
    expect(metadata.match(/<md:KeyDescriptor/g)).toHaveLength(2);
    expect(metadata).not.toContain("PRIVATE KEY");
  });
});

describe("strict Redirect AuthnRequest binding", () => {
  const config = {
    expectedEntityId: "urn:sp",
    verifiedAcsUrl: "https://sp.example/saml/acs",
    expectedDestination: "https://idp.example/sso/p1",
  };

  it("parses valid request and bounded RelayState", () => {
    expect(
      parseRedirectAuthnRequest(redirectPayload(requestXml()), "return%2Fhome", config),
    ).toMatchObject({
      id: "_request",
      issuer: "urn:sp",
      acsUrl: config.verifiedAcsUrl,
      relayState: "return%2Fhome",
    });
  });

  it("fails closed for ACS mismatch, issuer mismatch, DTD, and oversized RelayState", () => {
    expect(() =>
      parseRedirectAuthnRequest(
        redirectPayload(requestXml("https://evil.example/acs")),
        "",
        config,
      ),
    ).toThrow("acs_mismatch");
    expect(() =>
      parseRedirectAuthnRequest(
        redirectPayload(requestXml(config.verifiedAcsUrl, "urn:other")),
        "",
        config,
      ),
    ).toThrow("issuer_mismatch");
    expect(() =>
      parseRedirectAuthnRequest(
        redirectPayload(`<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>${requestXml()}`),
        "",
        config,
      ),
    ).toThrow("xml_declaration_forbidden");
    expect(() =>
      parseRedirectAuthnRequest(redirectPayload(requestXml()), "x".repeat(1025), config),
    ).toThrow("relay_state_too_large");
  });

  it("rejects AuthnRequests outside the SAML 2.0 protocol namespace and version", () => {
    const wrongNamespace = requestXml().replace(
      "urn:oasis:names:tc:SAML:2.0:protocol",
      "urn:attacker:protocol",
    );
    const wrongVersion = requestXml().replace('Version="2.0"', 'Version="1.1"');

    expect(() => parseRedirectAuthnRequest(redirectPayload(wrongNamespace), "", config)).toThrow(
      "invalid_root",
    );
    expect(() => parseRedirectAuthnRequest(redirectPayload(wrongVersion), "", config)).toThrow(
      "invalid_version",
    );
  });
});

describe("baseline response", () => {
  it("binds request fields, signs assertion, and produces fresh IDs", () => {
    const material = generateSigningMaterial();
    const plan = {
      issuer: "https://idp.example/metadata/p1",
      requestId: "_request",
      destination: "https://sp.example/saml/acs",
      audience: "urn:sp",
      nameId: "synthetic-user@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: { role: ["tester"] },
      signing: material,
      now: new Date("2026-07-16T00:00:00Z"),
    };
    const first = generateResponse(plan);
    const second = generateResponse(plan);
    expect(first.responseId).not.toBe(second.responseId);
    expect(first.assertionId).not.toBe(second.assertionId);
    expect(first.xml).toContain('InResponseTo="_request"');
    expect(first.xml).toContain('Recipient="https://sp.example/saml/acs"');
    expect(first.xml).toContain("synthetic-user@invalid.example");
    expect(verifyXmlSignature(first.xml, material.certificate)).toBe(true);
  });
});
