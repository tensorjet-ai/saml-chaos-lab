import { deflateRawSync } from "node:zlib";
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { parseRedirectAuthnRequest } from "@saml-chaos/saml-core";
import { createPlaywrightSession } from "@saml-chaos/browser-runner";
import { classifyIp, normalizeExactUrl } from "@saml-chaos/target-safety";

const binding = {
  expectedEntityId: "urn:sp",
  verifiedAcsUrl: "https://sp.example/acs",
  expectedDestination: "https://idp.example/sso",
  maxCompressedBytes: 1024,
  maxInflatedBytes: 2048,
};
const encode = (xml: string) => deflateRawSync(Buffer.from(xml)).toString("base64");

describe("protocol abuse boundary", () => {
  it("blocks DTD, entity expansion, malformed compression, and decompression excess", () => {
    const base = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Destination="${binding.expectedDestination}" AssertionConsumerServiceURL="${binding.verifiedAcsUrl}"><Issuer>${binding.expectedEntityId}</Issuer></samlp:AuthnRequest>`;
    expect(() =>
      parseRedirectAuthnRequest(encode(`<!DOCTYPE x [<!ENTITY x "boom">]>${base}`), "", binding),
    ).toThrow("xml_declaration_forbidden");
    expect(() =>
      parseRedirectAuthnRequest(Buffer.from("not-deflate").toString("base64"), "", binding),
    ).toThrow("invalid_compression");
    expect(() =>
      parseRedirectAuthnRequest(
        encode(base.replace("</samlp:AuthnRequest>", `${" ".repeat(5000)}</samlp:AuthnRequest>`)),
        "",
        binding,
      ),
    ).toThrow("invalid_compression");
  });

  it("blocks alternate IP encodings and IPv4-mapped loopback", () => {
    expect(() => normalizeExactUrl("https://0x7f000001/acs")).toThrow();
    expect(() => normalizeExactUrl("https://0177.0.0.1/acs")).toThrow();
    expect(classifyIp("::ffff:127.0.0.1")).toBe("blocked");
  });

  it("aborts hostile redirects and subresource requests before any unauthorized socket opens", async () => {
    const decoy = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" }).end("unexpected request");
    });
    await new Promise<void>((resolve, reject) => {
      decoy.once("error", reject);
      decoy.listen(0, "127.0.0.1", resolve);
    });
    const decoyAddress = decoy.address();
    if (!decoyAddress || typeof decoyAddress === "string")
      throw new Error("decoy_port_unavailable");
    let decoyRequests = 0;
    decoy.on("request", () => {
      decoyRequests += 1;
    });

    const attack = createServer((request, response) => {
      if (request.url === "/redirect-metadata") {
        response
          .writeHead(302, {
            location: "http://169.254.169.254/latest/meta-data/",
          })
          .end();
        return;
      }
      if (request.url === "/redirect-loopback") {
        response.writeHead(302, { location: "http://127.0.0.1:5432/" }).end();
        return;
      }
      if (request.url === "/redirect-decoy") {
        response
          .writeHead(302, {
            location: `http://127.0.0.1:${decoyAddress.port}/health`,
          })
          .end();
        return;
      }
      if (request.url === "/activate") {
        response.writeHead(200, { "content-type": "text/html" }).end("<main>activated</main>");
        return;
      }
      response
        .writeHead(200, { "content-type": "text/html" })
        .end(
          `<img src="http://169.254.169.254/latest/meta-data/"><script>fetch("http://127.0.0.1:${decoyAddress.port}/health")</script><main>done</main>`,
        );
    });
    await new Promise<void>((resolve, reject) => {
      attack.once("error", reject);
      attack.listen(0, "127.0.0.1", resolve);
    });
    const attackAddress = attack.address();
    if (!attackAddress || typeof attackAddress === "string")
      throw new Error("attack_port_unavailable");
    const origin = `http://127.0.0.1:${attackAddress.port}`;

    try {
      for (const path of [
        "/redirect-metadata",
        "/redirect-loopback",
        "/redirect-decoy",
        "/subresources",
      ]) {
        const session = await createPlaywrightSession({
          allowedHosts: ["127.0.0.1"],
          allowedOrigins: [origin],
          pinnedAddresses: new Map([["127.0.0.1", ["127.0.0.1"]]]),
        });
        try {
          await session.activate(`${origin}/activate`, 5_000);
          await session.goto(`${origin}${path}`, 10_000).catch(() => undefined);
          if (path === "/redirect-metadata") {
            expect(session.redirectLocation()).toBe("http://169.254.169.254/latest/meta-data/");
            expect(session.blockedRequest()).toBe(true);
          } else if (path === "/redirect-loopback") {
            expect(session.redirectLocation()).toBe("http://127.0.0.1:5432/");
            expect(session.blockedRequest()).toBe(true);
          } else if (path === "/redirect-decoy") {
            expect(session.redirectLocation()).toBe(`http://127.0.0.1:${decoyAddress.port}/health`);
            expect(session.blockedRequest()).toBe(true);
          } else {
            expect(session.blockedRequest()).toBe(true);
          }
        } finally {
          await session.close();
        }
      }
      expect(decoyRequests).toBe(0);
    } finally {
      await Promise.all([
        new Promise<void>((resolve, reject) =>
          attack.close((error) => (error ? reject(error) : resolve())),
        ),
        new Promise<void>((resolve, reject) =>
          decoy.close((error) => (error ? reject(error) : resolve())),
        ),
      ]);
    }
  });
});
