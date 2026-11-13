import { describe, expect, it } from "vitest";
import { buildIdp } from "../../apps/idp/src/app.js";
import { buildFixtureSp } from "../../fixtures/vulnerable-sp/src/app.js";
import { generateSigningMaterial } from "@saml-chaos/saml-core";

describe("SP-initiated baseline flow", () => {
  it("redirects through IdP and posts a valid response to fixture ACS", async () => {
    const signing = generateSigningMaterial();
    const project = {
      id: "fixture",
      entityId: "http://idp.test/metadata/fixture",
      ssoUrl: "http://idp.test/sso/fixture",
      spEntityId: "urn:fixture:sp",
      acsUrl: "http://fixture.test/saml/acs",
      nameId: "synthetic@invalid.example",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: { role: ["tester"] },
      current: signing,
      nextCertificate: generateSigningMaterial().certificate,
    };
    const idp = await buildIdp({ projects: new Map([[project.id, project]]) });
    const fixture = buildFixtureSp({
      spEntityId: project.spEntityId,
      idpEntityId: project.entityId,
      idpSsoUrl: project.ssoUrl,
      acsUrl: project.acsUrl,
      trustedCertificates: async () => [signing.certificate],
    });
    const login = await fixture.inject({ method: "GET", url: "/login" });
    const redirect = new URL(login.headers.location!);
    const idpResponse = await idp.inject({
      method: "GET",
      url: `${redirect.pathname}${redirect.search}`,
    });
    expect(idpResponse.statusCode).toBe(200);
    const samlResponse = idpResponse.body.match(/name="SAMLResponse" value="([^"]+)"/)![1]!;
    const relayState = idpResponse.body.match(/name="RelayState" value="([^"]*)"/)![1]!;
    const acs = await fixture.inject({
      method: "POST",
      url: "/saml/acs",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        SAMLResponse: samlResponse,
        RelayState: relayState,
      }).toString(),
    });
    expect(acs.statusCode).toBe(303);
    expect(acs.headers.location).toBe("/success");
    await Promise.all([idp.close(), fixture.close()]);
  });
});
