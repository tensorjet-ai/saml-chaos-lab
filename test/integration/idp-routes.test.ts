import { deflateRawSync } from "node:zlib";
import { describe, expect, it, vi } from "vitest";
import { buildIdp, type IdpProject, type IdpRunContextStore } from "../../apps/idp/src/app.js";
import { generateResponse, generateSigningMaterial } from "@saml-chaos/saml-core";
import { ActivationService } from "@saml-chaos/browser-runner";
import { randomBytes } from "node:crypto";

const project = {
  id: "p1",
  entityId: "http://localhost:3001/metadata/p1",
  ssoUrl: "http://localhost:3001/sso/p1",
  spEntityId: "urn:fixture:sp",
  acsUrl: "http://localhost:4000/saml/acs",
  nameId: "synthetic-user@invalid.example",
  nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  attributes: { role: ["tester"] },
  current: generateSigningMaterial(),
  nextCertificate: generateSigningMaterial().certificate,
};

describe("hosted IdP routes", () => {
  it("protects metrics and fails closed in hosted mode without a token", async () => {
    const protectedApp = await buildIdp({
      projects: new Map([[project.id, project]]),
      metricsToken: "metrics-secret",
    });
    expect((await protectedApp.inject({ method: "GET", url: "/metrics" })).statusCode).toBe(401);
    expect(
      (
        await protectedApp.inject({
          method: "GET",
          url: "/metrics",
          headers: { authorization: "Bearer metrics-secret" },
        })
      ).statusCode,
    ).toBe(200);
    await protectedApp.close();

    const missingToken = await buildIdp({ metricsAuthRequired: true });
    expect((await missingToken.inject({ method: "GET", url: "/metrics" })).statusCode).toBe(503);
    await missingToken.close();
  });

  it("reports dependency failures through readiness", async () => {
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      readinessCheck: async () => {
        throw new Error("database unavailable");
      },
    });
    expect((await app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(503);
    await app.close();
  });

  it("returns a generic unavailable response when dynamic project loading fails", async () => {
    const app = await buildIdp({
      loadProject: async () => {
        throw new Error("postgres://user:secret@database/internal");
      },
    });

    const response = await app.inject({
      method: "GET",
      url: "/metadata/dynamic-project",
    });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({ error: "project_unavailable" });
    expect(response.body).not.toContain("secret");
    await app.close();
  });

  it("keeps health probes outside SAML traffic rate limits", async () => {
    const app = await buildIdp({ projects: new Map([[project.id, project]]) });
    const responses = [];
    for (let index = 0; index < 245; index += 1) {
      responses.push(await app.inject({ method: "GET", url: "/health" }));
    }

    expect(responses.every((response) => response.statusCode === 200)).toBe(true);
    let limited = 0;
    for (let index = 0; index < 241; index += 1) {
      limited = (await app.inject({ method: "GET", url: "/metadata/p1" })).statusCode;
    }
    expect(limited).toBe(429);
    await app.close();
  });

  it("serves stable metadata with current and next certificates", async () => {
    const app = await buildIdp({ projects: new Map([[project.id, project]]) });
    const response = await app.inject({ method: "GET", url: "/metadata/p1" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/samlmetadata+xml");
    expect(response.body).toContain(project.ssoUrl);
    await app.close();
  });

  it("binds AuthnRequest and returns CSP-protected auto-post form", async () => {
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" Destination="${project.ssoUrl}" AssertionConsumerServiceURL="${project.acsUrl}"><saml:Issuer>${project.spEntityId}</saml:Issuer></samlp:AuthnRequest>`;
    const encoded = encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"));
    const recordEvent = vi.fn().mockResolvedValue(undefined);
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      recordEvent,
    });
    const response = await app.inject({
      method: "GET",
      url: `/sso/p1?SAMLRequest=${encoded}&RelayState=return`,
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(response.body).toContain(`action="${project.acsUrl}"`);
    expect(response.body).toContain('name="SAMLResponse"');
    expect(recordEvent).toHaveBeenCalledWith(
      "response.delivered",
      expect.objectContaining({ projectId: "p1", scenarioId: "SAML-BASE-001" }),
    );
    await app.close();
  });

  it("returns generic error for an unbound ACS", async () => {
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" Destination="${project.ssoUrl}" AssertionConsumerServiceURL="https://evil.example/acs"><saml:Issuer>${project.spEntityId}</saml:Issuer></samlp:AuthnRequest>`;
    const encoded = encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"));
    const app = await buildIdp({ projects: new Map([[project.id, project]]) });
    const response = await app.inject({
      method: "GET",
      url: `/sso/p1?SAMLRequest=${encoded}`,
    });
    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain("evil.example");
    await app.close();
  });

  it("distinguishes response-service outages from invalid SAML requests", async () => {
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_service" Version="2.0" Destination="${project.ssoUrl}" AssertionConsumerServiceURL="${project.acsUrl}"><saml:Issuer>${project.spEntityId}</saml:Issuer></samlp:AuthnRequest>`;
    const encoded = encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"));
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      recordEvent: async () => {
        throw new Error("database unavailable");
      },
    });

    const response = await app.inject({
      method: "GET",
      url: `/sso/p1?SAMLRequest=${encoded}`,
    });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({ error: "response_unavailable" });
    expect(response.body).not.toContain("database unavailable");
    await app.close();
  });

  it("requires and consumes a scoped activation when hosted binding is enabled", async () => {
    const activationService = new ActivationService(randomBytes(32));
    const token = await activationService.issue({
      projectId: "p1",
      runId: "r1",
      scenarioId: "SAML-AUD-001",
      browserSessionId: "b1",
    });
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
    });
    const activated = await app.inject({
      method: "GET",
      url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=b1`,
    });
    expect(activated.statusCode).toBe(200);
    expect(activated.headers["set-cookie"]).toContain("saml_chaos_run=");
    const replayed = await app.inject({
      method: "GET",
      url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=b1`,
    });
    expect(replayed.statusCode).toBe(400);
    await app.close();
  });

  it("can issue a non-Secure activation cookie for an explicit local HTTP deployment", async () => {
    const activationService = new ActivationService(randomBytes(32));
    const token = await activationService.issue({
      projectId: "p1",
      runId: "r1",
      scenarioId: "SAML-BASE-001",
      browserSessionId: "local-browser",
    });
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
      secureCookies: false,
    });
    const activated = await app.inject({
      method: "GET",
      url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=local-browser`,
    });

    expect(activated.headers["set-cookie"]).not.toContain("Secure");
    await app.close();
  });

  it("uses a Secure SameSite=Lax cookie for the cross-site SP redirect flow", async () => {
    const activationService = new ActivationService(randomBytes(32));
    const token = await activationService.issue({
      projectId: "p1",
      runId: "r1",
      scenarioId: "SAML-BASE-001",
      browserSessionId: "hosted-browser",
    });
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
    });
    const activated = await app.inject({
      method: "GET",
      url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=hosted-browser`,
    });

    expect(activated.headers["set-cookie"]).toContain("Secure");
    expect(activated.headers["set-cookie"]).toContain("SameSite=Lax");
    expect(activated.headers["set-cookie"]).not.toContain("SameSite=Strict");
    await app.close();
  });

  it("expires an activated run context after the cookie lifetime", async () => {
    let now = 1_000_000;
    const activationService = new ActivationService(randomBytes(32), () => now);
    const token = await activationService.issue({
      projectId: "p1",
      runId: "r1",
      scenarioId: "SAML-BASE-001",
      browserSessionId: "expiring-browser",
    });
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
      now: () => now,
    });
    const activated = await app.inject({
      method: "GET",
      url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=expiring-browser`,
    });
    now += 121_000;
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_expired" Version="2.0" Destination="${project.ssoUrl}" AssertionConsumerServiceURL="${project.acsUrl}"><saml:Issuer>${project.spEntityId}</saml:Issuer></samlp:AuthnRequest>`;
    const encoded = encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"));
    const response = await app.inject({
      method: "GET",
      url: `/sso/p1?SAMLRequest=${encoded}`,
      headers: { cookie: activated.headers["set-cookie"]! },
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("serves scenario-bound metadata certificate sets via resolver", async () => {
    const resolveMetadataCertificates = (activeScenario: string | undefined, target: IdpProject) =>
      activeScenario === "META-OVERLAP"
        ? [target.current.certificate, target.nextCertificate]
        : activeScenario === "META-PROMOTED"
          ? [target.nextCertificate]
          : [target.current.certificate];
    const activationService = new ActivationService(randomBytes(32));
    const app = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
      resolveMetadataCertificates,
    });
    const activate = async (scenarioId: string, browserSessionId: string) => {
      const token = await activationService.issue({
        projectId: "p1",
        runId: "rollover-run",
        scenarioId,
        browserSessionId,
      });
      await app.inject({
        method: "GET",
        url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=${browserSessionId}`,
      });
      return app.inject({ method: "GET", url: "/metadata/p1" });
    };
    const current = await activate("META-CURRENT", "browser-current");
    const overlap = await activate("META-OVERLAP", "browser-overlap");
    const promoted = await activate("META-PROMOTED", "browser-promoted");

    expect(current.body.match(/<md:KeyDescriptor/g)).toHaveLength(1);
    expect(overlap.body.match(/<md:KeyDescriptor/g)).toHaveLength(2);
    expect(promoted.body.match(/<md:KeyDescriptor/g)).toHaveLength(1);
    expect(promoted.body).toContain(
      project.nextCertificate.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, ""),
    );
    expect(promoted.body).not.toContain(
      project.current.certificate.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, ""),
    );
    await app.close();
  });

  it("shares activation context across IdP replicas", async () => {
    const contexts = new Map<
      string,
      {
        scope: Parameters<IdpRunContextStore["activate"]>[1];
        expiresAt: number;
      }
    >();
    const scenarios = new Map<string, { scenarioId: string; expiresAt: number }>();
    const contextStore: IdpRunContextStore = {
      async activate(sessionId, scope, expiresAt) {
        contexts.set(sessionId, { scope, expiresAt });
        scenarios.set(scope.projectId, {
          scenarioId: scope.scenarioId,
          expiresAt,
        });
      },
      async consume(sessionId, projectId, now) {
        const context = contexts.get(sessionId);
        contexts.delete(sessionId);
        return context && context.scope.projectId === projectId && context.expiresAt > now
          ? context.scope
          : undefined;
      },
      async getScenario(projectId, now) {
        const scenario = scenarios.get(projectId);
        return scenario && scenario.expiresAt > now ? scenario.scenarioId : undefined;
      },
      async clearScenario(projectId, scenarioId) {
        if (scenarios.get(projectId)?.scenarioId === scenarioId) scenarios.delete(projectId);
      },
    };
    const activationService = new ActivationService(randomBytes(32));
    const token = await activationService.issue({
      projectId: "p1",
      runId: "replicated-run",
      scenarioId: "META-PROMOTED",
      browserSessionId: "replicated-browser",
    });
    const renderCustom = (
      id: string,
      base: Parameters<typeof generateResponse>[0],
      certs: { current: typeof project.current; next: typeof project.current },
    ) => ({
      ...generateResponse({
        ...base,
        signing: id === "META-PROMOTED" ? certs.next : certs.current,
      }),
      scenarioId: id,
      mutations: [],
      deliveryDestination: base.destination,
    });
    const resolveMetadataCertificates = (activeScenario: string | undefined, target: IdpProject) =>
      activeScenario === "META-PROMOTED" ? [target.nextCertificate] : [target.current.certificate];
    const replicaA = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
      contextStore,
      renderScenario: renderCustom,
      resolveMetadataCertificates,
    });
    const replicaB = await buildIdp({
      projects: new Map([[project.id, project]]),
      activationService,
      contextStore,
      renderScenario: renderCustom,
      resolveMetadataCertificates,
    });
    const activated = await replicaA.inject({
      method: "GET",
      url: `/activate/p1?token=${encodeURIComponent(token)}&browserSessionId=replicated-browser`,
    });
    const metadata = await replicaB.inject({
      method: "GET",
      url: "/metadata/p1",
    });
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_replicated" Version="2.0" Destination="${project.ssoUrl}" AssertionConsumerServiceURL="${project.acsUrl}"><saml:Issuer>${project.spEntityId}</saml:Issuer></samlp:AuthnRequest>`;
    const encoded = encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"));
    const firstSso = await replicaB.inject({
      method: "GET",
      url: `/sso/p1?SAMLRequest=${encoded}`,
      headers: { cookie: activated.headers["set-cookie"]! },
    });
    const replayedSso = await replicaB.inject({
      method: "GET",
      url: `/sso/p1?SAMLRequest=${encoded}`,
      headers: { cookie: activated.headers["set-cookie"]! },
    });

    expect(metadata.body.match(/<md:KeyDescriptor/g)).toHaveLength(1);
    expect(metadata.body).toContain(
      project.nextCertificate.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, ""),
    );
    expect(firstSso.statusCode).toBe(200);
    expect(replayedSso.statusCode).toBe(400);
    await Promise.all([replicaA.close(), replicaB.close()]);
  });
});

describe("internal certificate rotation", () => {
  it("rotates certificates only with the internal token", async () => {
    const rotated: string[] = [];
    const app = await buildIdp({
      logger: false,
      internalToken: "internal-secret",
      rotateCertificates: async (projectId) => {
        rotated.push(projectId);
      },
      recordEvent: async () => undefined,
    });
    const missing = await app.inject({
      method: "POST",
      url: "/internal/projects/p1/certificates/rotate",
    });
    expect(missing.statusCode).toBe(404);

    const ok = await app.inject({
      method: "POST",
      url: "/internal/projects/p1/certificates/rotate",
      headers: { "x-internal-token": "internal-secret" },
    });
    expect(ok.statusCode).toBe(204);
    expect(rotated).toEqual(["p1"]);
    await app.close();
  });
});
