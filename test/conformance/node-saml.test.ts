import { describe, expect, it } from "vitest";
import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import { generateResponse, generateSigningMaterial } from "@saml-chaos/saml-core";

describe("Node-SAML compatibility", () => {
  it("accepts baseline and rejects post-signature mutation", async () => {
    const signing = generateSigningMaterial();
    const response = generateResponse({
      issuer: "https://idp.example/metadata/p1",
      requestId: "_request",
      destination: "https://sp.example/saml/acs",
      audience: "urn:sp",
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: { role: ["tester"] },
      signing,
    });
    const validator = new SAML({
      idpCert: signing.certificate,
      issuer: "urn:sp",
      callbackUrl: "https://sp.example/saml/acs",
      audience: "urn:sp",
      idpIssuer: "https://idp.example/metadata/p1",
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.never,
    });
    const valid = await validator.validatePostResponseAsync({
      SAMLResponse: Buffer.from(response.xml).toString("base64"),
    });
    expect(valid.profile?.nameID).toBe("synthetic@invalid.example");
    await expect(
      validator.validatePostResponseAsync({
        SAMLResponse: Buffer.from(
          response.xml.replace("synthetic@invalid.example", "tampered@invalid.example"),
        ).toString("base64"),
      }),
    ).rejects.toThrow();
  });
});
