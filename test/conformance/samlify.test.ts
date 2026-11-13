import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { IdentityProvider, ServiceProvider, setSchemaValidator } from "samlify";
import {
  createProjectCertificates,
  decryptPrivateKey,
  generateResponse,
} from "@saml-chaos/saml-core";

setSchemaValidator({ validate: async () => true });

describe("Samlify compatibility", () => {
  it("accepts baseline and rejects post-signature mutation", async () => {
    const master = randomBytes(32);
    const certificates = await createProjectCertificates("compat", master);
    const signing = {
      certificate: certificates.current.certificate,
      privateKey: decryptPrivateKey(certificates.current.encryptedPrivateKey, master, "compat"),
    };
    const issuer = "https://idp.example/metadata/compat";
    const acs = "https://sp.example/saml/acs";
    const response = generateResponse({
      issuer,
      requestId: "_request",
      destination: acs,
      audience: "urn:sp",
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: { role: ["tester"] },
      signing,
    });
    const sp = ServiceProvider({
      entityID: "urn:sp",
      wantAssertionsSigned: true,
      wantMessageSigned: false,
      assertionConsumerService: [
        {
          Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Location: acs,
        },
      ],
    });
    const idp = IdentityProvider({
      entityID: issuer,
      signingCert: signing.certificate,
      singleSignOnService: [
        {
          Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          Location: "https://idp.example/sso",
        },
      ],
    });
    const valid = await sp.parseLoginResponse(idp, "post", {
      body: { SAMLResponse: Buffer.from(response.xml).toString("base64") },
    });
    expect(valid.extract.nameID).toBe("synthetic@invalid.example");
    await expect(
      sp.parseLoginResponse(idp, "post", {
        body: {
          SAMLResponse: Buffer.from(
            response.xml.replace("synthetic@invalid.example", "tampered@invalid.example"),
          ).toString("base64"),
        },
      }),
    ).rejects.toThrow();
  });
});
