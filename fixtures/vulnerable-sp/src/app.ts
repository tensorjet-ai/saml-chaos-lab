import { randomUUID } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import Fastify, { type FastifyReply } from "fastify";
import { XMLParser, XMLValidator } from "fast-xml-parser";
import { DOMParser } from "@xmldom/xmldom";
import { verifyXmlSignature } from "@saml-chaos/saml-core";

export interface FixtureConfig {
  spEntityId: string;
  idpEntityId: string;
  idpSsoUrl: string;
  acsUrl: string;
  trustedCertificates: () => Promise<string[]>;
  now?: () => Date;
  clockSkewSeconds?: number;
  pendingRequestLimit?: number;
  resolveIdp?: (projectId: string) => Promise<{
    entityId: string;
    ssoUrl: string;
    trustedCertificates: () => Promise<string[]>;
  }>;
}

interface PendingRequest {
  idpEntityId: string;
  trustedCertificates: () => Promise<string[]>;
  expiresAt: number;
}

const pendingRequestTtlMs = 5 * 60_000;

function fail(reply: {
  code: (status: number) => unknown;
  header: (name: string, value: string) => unknown;
  send: () => unknown;
}) {
  reply.code(303);
  reply.header("location", "/saml/error?reason=invalid_response");
  return reply.send();
}

export function buildFixtureSp(config: FixtureConfig) {
  const app = Fastify({ logger: false, bodyLimit: 768 * 1024 });
  const pending = new Map<string, PendingRequest>();
  const replay = new Map<string, number>();
  const now = config.now ?? (() => new Date());
  const skewMs = (config.clockSkewSeconds ?? 120) * 1000;
  const pendingLimit = config.pendingRequestLimit ?? 1_000;
  if (!Number.isSafeInteger(pendingLimit) || pendingLimit < 1) {
    throw new Error("pendingRequestLimit must be a positive integer");
  }
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string" },
    (_request, body, done) => {
      const values = Object.fromEntries(new URLSearchParams(body as string));
      done(null, values);
    },
  );
  app.get("/health", async () => ({ status: "ok" }));
  const beginLogin = async (projectId: string | undefined, reply: FastifyReply) => {
    const resolved =
      projectId && config.resolveIdp ? await config.resolveIdp(projectId) : undefined;
    const idpEntityId = resolved?.entityId ?? config.idpEntityId;
    const idpSsoUrl = resolved?.ssoUrl ?? config.idpSsoUrl;
    const trustedCertificates = resolved?.trustedCertificates ?? config.trustedCertificates;
    const id = `_${randomUUID()}`;
    const current = now();
    for (const [pendingId, request] of pending) {
      if (request.expiresAt <= current.getTime()) pending.delete(pendingId);
    }
    while (pending.size >= pendingLimit) {
      const oldest = pending.keys().next().value as string | undefined;
      if (!oldest) break;
      pending.delete(oldest);
    }
    pending.set(id, {
      idpEntityId,
      trustedCertificates,
      expiresAt: current.getTime() + pendingRequestTtlMs,
    });
    const issueInstant = current.toISOString();
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${issueInstant}" Destination="${idpSsoUrl}" AssertionConsumerServiceURL="${config.acsUrl}"><saml:Issuer>${config.spEntityId}</saml:Issuer></samlp:AuthnRequest>`;
    const url = new URL(idpSsoUrl);
    url.searchParams.set("SAMLRequest", deflateRawSync(Buffer.from(xml)).toString("base64"));
    url.searchParams.set("RelayState", "/success");
    return reply.code(303).header("location", url.toString()).send();
  };
  app.get("/login", async (_request, reply) => beginLogin(undefined, reply));
  app.get<{ Params: { projectId: string } }>("/login/:projectId", async (request, reply) =>
    beginLogin(request.params.projectId, reply),
  );
  app.post("/saml/acs", async (request, reply) => {
    try {
      const encoded = (request.body as Record<string, unknown>).SAMLResponse;
      if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))
        return fail(reply);
      const raw = Buffer.from(encoded, "base64");
      if (raw.length > 512 * 1024) return fail(reply);
      const xml = raw.toString("utf8");
      if (/<!DOCTYPE|<!ENTITY/i.test(xml) || XMLValidator.validate(xml) !== true)
        return fail(reply);
      const document = new DOMParser().parseFromString(xml, "application/xml");
      if (
        document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
          .length !== 1 ||
        document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature")
          .length !== 1
      )
        return fail(reply);
      const parsedForRequest = new XMLParser({
        ignoreAttributes: false,
        removeNSPrefix: true,
        processEntities: false,
        parseTagValue: false,
        trimValues: true,
      }).parse(xml) as { Response?: Record<string, unknown> };
      const requestIdForTrust = parsedForRequest.Response?.["@_InResponseTo"];
      const pendingRequest =
        typeof requestIdForTrust === "string" ? pending.get(requestIdForTrust) : undefined;
      if (!pendingRequest || pendingRequest.expiresAt <= now().getTime()) {
        if (typeof requestIdForTrust === "string") pending.delete(requestIdForTrust);
        return fail(reply);
      }
      const certificates = await pendingRequest.trustedCertificates();
      if (!certificates.some((certificate) => verifyXmlSignature(xml, certificate)))
        return fail(reply);
      const parsed = new XMLParser({
        ignoreAttributes: false,
        removeNSPrefix: true,
        processEntities: false,
        parseTagValue: false,
        trimValues: true,
      }).parse(xml) as { Response?: Record<string, unknown> };
      const response = parsed.Response;
      const assertion = response?.Assertion as Record<string, unknown> | undefined;
      const subject = assertion?.Subject as Record<string, unknown> | undefined;
      const confirmation = subject?.SubjectConfirmation as Record<string, unknown> | undefined;
      const confirmationData = confirmation?.SubjectConfirmationData as
        Record<string, unknown> | undefined;
      const conditions = assertion?.Conditions as Record<string, unknown> | undefined;
      const audienceRestriction = conditions?.AudienceRestriction as
        Record<string, unknown> | undefined;
      const requestId = response?.["@_InResponseTo"];
      const assertionId = assertion?.["@_ID"];
      if (
        response?.["@_Destination"] !== config.acsUrl ||
        response?.Issuer !== pendingRequest.idpEntityId ||
        assertion?.Issuer !== pendingRequest.idpEntityId ||
        audienceRestriction?.Audience !== config.spEntityId ||
        confirmationData?.["@_Recipient"] !== config.acsUrl ||
        confirmationData?.["@_InResponseTo"] !== requestId ||
        typeof requestId !== "string" ||
        !pending.has(requestId) ||
        typeof assertionId !== "string"
      )
        return fail(reply);
      const notBefore = Date.parse(String(conditions?.["@_NotBefore"]));
      const notAfter = Math.min(
        Date.parse(String(conditions?.["@_NotOnOrAfter"])),
        Date.parse(String(confirmationData?.["@_NotOnOrAfter"])),
      );
      const current = now().getTime();
      if (
        !Number.isFinite(notBefore) ||
        !Number.isFinite(notAfter) ||
        notBefore > current + skewMs ||
        notAfter <= current - skewMs
      )
        return fail(reply);
      for (const [id, expiresAt] of replay) if (expiresAt <= current) replay.delete(id);
      if (replay.has(assertionId)) return fail(reply);
      replay.set(assertionId, notAfter);
      pending.delete(requestId);
      return reply.code(303).header("location", "/success").send();
    } catch {
      return fail(reply);
    }
  });
  app.get("/success", async (_request, reply) =>
    reply
      .type("text/html")
      .header("content-security-policy", "default-src 'none'; form-action 'none'")
      .send(
        '<!doctype html><html><body><main id="account"><h1>Signed in</h1></main></body></html>',
      ),
  );
  app.get("/saml/error", async (_request, reply) =>
    reply
      .code(401)
      .type("text/html")
      .send(
        "<!doctype html><html><body><main><h1>Authentication rejected</h1></main></body></html>",
      ),
  );
  return app;
}
