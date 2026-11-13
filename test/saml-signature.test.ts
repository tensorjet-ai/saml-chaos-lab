import { describe, expect, it } from "vitest";
import { generateSigningMaterial, signXml, verifyXmlSignature } from "@saml-chaos/saml-core";

describe("XML signature known-answer behavior", () => {
  it("validates a signed assertion and rejects a post-sign mutation", () => {
    const material = generateSigningMaterial();
    const unsigned =
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml:Issuer>https://idp.test</saml:Issuer></saml:Assertion>';
    const signed = signXml(unsigned, material, "//*[local-name(.)='Assertion']");
    expect(verifyXmlSignature(signed, material.certificate)).toBe(true);
    expect(
      verifyXmlSignature(
        signed.replace("https://idp.test", "https://evil.test"),
        material.certificate,
      ),
    ).toBe(false);
  });
});
