import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import {
  generateMetadata,
  generateResponse,
  parseRedirectAuthnRequest,
  autoPostForm,
  type ResponsePlan,
  type SigningMaterial,
} from "@saml-chaos/saml-core";
import { type ActivationScope, type ActivationService } from "@saml-chaos/browser-runner";
import {
  renderScenario as renderFreeScenario,
  type CertificateSet,
  type RenderedScenario,
} from "@saml-chaos/scenarios";
import { OperationalMetrics, redactRequestUrl } from "@saml-chaos/observability";

export interface IdpProject {
  id: string;
  entityId: string;
  ssoUrl: string;
  spEntityId: string;
  acsUrl: string;
  nameId: string;
  nameIdFormat: string;
  attributes: Record<string, string[]>;
  current: SigningMaterial;
  nextCertificate: string;
  next?: SigningMaterial;
  verificationStatus?: "pending" | "verified" | "expired";
}

export interface IdpRunContextStore {
  activate(sessionId: string, scope: ActivationScope, expiresAt: number): Promise<void>;
  consume(sessionId: string, projectId: string, now: number): Promise<ActivationScope | undefined>;
  getScenario(projectId: string, now: number): Promise<string | undefined>;
  clearScenario(projectId: string, scenarioId: string): Promise<void>;
}

function cookieValue(header: string | undefined, name: string): string | undefined {
  return header
    ?.split(";")
    .map((part) => part.trim().split("="))
    .find(([key]) => key === name)?.[1];
}

export function secureTokenEquals(presented: string | undefined, expected: string): boolean {
  if (typeof presented !== "string") return false;
  const presentedHash = createHash("sha256").update(presented).digest();
  const expectedHash = createHash("sha256").update(expected).digest();
  return timingSafeEqual(presentedHash, expectedHash);
}

export async function buildIdp(
  options: {
    projects?: Map<string, IdpProject>;
    logger?: boolean;
    metricsToken?: string;
    metricsAuthRequired?: boolean;
    activationService?: ActivationService;
    contextStore?: IdpRunContextStore;
    loadProject?: (projectId: string) => Promise<IdpProject | undefined>;
    internalToken?: string;
    provisionCertificates?: (projectId: string) => Promise<void>;
    rotateCertificates?: (projectId: string) => Promise<void>;
    secureCookies?: boolean;
    now?: () => number;
    recordEvent?: (
      eventType: string,
      context: { projectId: string; runId?: string; scenarioId?: string },
    ) => Promise<void>;
    readinessCheck?: () => Promise<void>;
    renderScenario?: (
      id: string,
      base: ResponsePlan,
      certificates: CertificateSet,
    ) => RenderedScenario;
    resolveMetadataCertificates?: (
      activeScenario: string | undefined,
      project: IdpProject,
    ) => string[];
  } = {},
) {
  const projects = options.projects ?? new Map<string, IdpProject>();
  const resolveProject = async (projectId: string) =>
    projects.get(projectId) ?? (await options.loadProject?.(projectId));
  const now = options.now ?? Date.now;
  const runContexts = new Map<string, { scope: ActivationScope; expiresAt: number }>();
  const activeScenarios = new Map<string, { scenarioId: string; expiresAt: number }>();
  const cleanupRunContexts = () => {
    const current = now();
    for (const [sessionId, context] of runContexts) {
      if (context.expiresAt <= current) runContexts.delete(sessionId);
    }
    for (const [projectId, scenario] of activeScenarios) {
      if (scenario.expiresAt <= current) activeScenarios.delete(projectId);
    }
  };
  const activateRunContext = async (
    sessionId: string,
    scope: ActivationScope,
    expiresAt: number,
  ) => {
    if (options.contextStore) {
      await options.contextStore.activate(sessionId, scope, expiresAt);
      return;
    }
    runContexts.set(sessionId, { scope, expiresAt });
    activeScenarios.set(scope.projectId, {
      scenarioId: scope.scenarioId,
      expiresAt,
    });
  };
  const consumeRunContext = async (sessionId: string, projectId: string) => {
    if (options.contextStore) return options.contextStore.consume(sessionId, projectId, now());
    const runContext = runContexts.get(sessionId);
    runContexts.delete(sessionId);
    return runContext && runContext.expiresAt > now() && runContext.scope.projectId === projectId
      ? runContext.scope
      : undefined;
  };
  const getActiveScenario = async (projectId: string) => {
    if (options.contextStore) return options.contextStore.getScenario(projectId, now());
    return activeScenarios.get(projectId)?.scenarioId;
  };
  const clearActiveScenario = async (projectId: string, scenarioId: string) => {
    if (options.contextStore) return options.contextStore.clearScenario(projectId, scenarioId);
    if (activeScenarios.get(projectId)?.scenarioId === scenarioId)
      activeScenarios.delete(projectId);
  };
  const cookieSecurity = options.secureCookies === false ? "SameSite=Lax" : "Secure; SameSite=Lax";
  const metrics = new OperationalMetrics();
  const app = Fastify({
    logger: options.logger
      ? {
          serializers: {
            req: (request) => ({
              method: request.method,
              url: redactRequestUrl(request.url),
            }),
          },
        }
      : false,
    bodyLimit: 256 * 1024,
  });
  await app.register(rateLimit, { max: 240, timeWindow: "1 minute" });
  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error }, "request failed");
    const candidateStatus =
      typeof error === "object" &&
      error !== null &&
      "statusCode" in error &&
      typeof error.statusCode === "number"
        ? error.statusCode
        : undefined;
    const statusCode = candidateStatus && candidateStatus < 500 ? candidateStatus : 500;
    return reply.code(statusCode).send({
      error: statusCode === 429 ? "rate_limit_exceeded" : "internal_error",
    });
  });
  app.get("/health", { config: { rateLimit: false } }, async () => ({
    status: "ok",
  }));
  app.get("/ready", { config: { rateLimit: false } }, async (_request, reply) => {
    try {
      await options.readinessCheck?.();
      return reply.send({ status: "ready" });
    } catch {
      return reply.code(503).send({ status: "not_ready" });
    }
  });
  app.get("/metrics", { config: { rateLimit: false } }, async (request, reply) => {
    if (!options.metricsToken && options.metricsAuthRequired) {
      return reply.code(503).send({ error: "metrics_auth_not_configured" });
    }
    if (
      options.metricsToken &&
      !secureTokenEquals(request.headers.authorization, `Bearer ${options.metricsToken}`)
    ) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return reply.type("text/plain; version=0.0.4").send(metrics.render());
  });

  app.post<{ Params: { projectId: string } }>(
    "/internal/projects/:projectId/certificates",
    async (request, reply) => {
      if (
        !options.internalToken ||
        !secureTokenEquals(
          request.headers["x-internal-token"] as string | undefined,
          options.internalToken,
        ) ||
        !options.provisionCertificates
      ) {
        return reply.code(404).send({ error: "not_found" });
      }
      try {
        await options.provisionCertificates(request.params.projectId);
        await options.recordEvent?.("key.provisioned", {
          projectId: request.params.projectId,
        });
        metrics.increment("key_operations_total", {
          operation: "provision",
          status: "passed",
        });
        return reply.code(204).send();
      } catch (error) {
        request.log.error({ err: error }, "certificate provisioning failed");
        metrics.increment("key_operations_total", {
          operation: "provision",
          status: "failed",
        });
        return reply.code(503).send({ error: "key_provisioning_failed" });
      }
    },
  );

  app.post<{ Params: { projectId: string } }>(
    "/internal/projects/:projectId/certificates/rotate",
    async (request, reply) => {
      if (
        !options.internalToken ||
        !secureTokenEquals(
          request.headers["x-internal-token"] as string | undefined,
          options.internalToken,
        ) ||
        !options.rotateCertificates
      ) {
        return reply.code(404).send({ error: "not_found" });
      }
      try {
        await options.rotateCertificates(request.params.projectId);
        await options.recordEvent?.("key.rotated", {
          projectId: request.params.projectId,
        });
        metrics.increment("key_operations_total", {
          operation: "rotate",
          status: "passed",
        });
        return reply.code(204).send();
      } catch (error) {
        request.log.error({ err: error }, "certificate rotation failed");
        metrics.increment("key_operations_total", {
          operation: "rotate",
          status: "failed",
        });
        return reply.code(503).send({ error: "key_rotation_failed" });
      }
    },
  );

  app.get<{
    Params: { projectId: string };
    Querystring: { token?: string; browserSessionId?: string };
  }>("/activate/:projectId", async (request, reply) => {
    if (!options.activationService || !request.query.token || !request.query.browserSessionId) {
      return reply.code(400).send({ error: "invalid_activation" });
    }
    cleanupRunContexts();
    let scope: ActivationScope;
    try {
      scope = await options.activationService.consume(request.query.token, {
        projectId: request.params.projectId,
        browserSessionId: request.query.browserSessionId,
      });
    } catch (error) {
      request.log.debug({ err: error }, "activation token rejected");
      metrics.increment("activation_total", { status: "rejected" });
      return reply.code(400).send({ error: "invalid_activation" });
    }
    try {
      const sessionId = randomUUID();
      const expiresAt = now() + 120_000;
      await activateRunContext(sessionId, scope, expiresAt);
      await options.recordEvent?.("activation.accepted", {
        projectId: scope.projectId,
        runId: scope.runId,
        scenarioId: scope.scenarioId,
      });
      metrics.increment("activation_total", { status: "accepted" });
      return reply
        .header(
          "set-cookie",
          `saml_chaos_run=${sessionId}; Max-Age=120; Path=/; HttpOnly; ${cookieSecurity}`,
        )
        .header("cache-control", "no-store")
        .type("text/html; charset=utf-8")
        .code(200)
        .send('<!doctype html><html lang="en"><title>Run activated</title></html>');
    } catch (error) {
      request.log.error({ err: error }, "activation context write failed");
      metrics.increment("activation_total", { status: "failed" });
      return reply.code(503).send({ error: "context_unavailable" });
    }
  });

  app.get<{ Params: { projectId: string } }>("/metadata/:projectId", async (request, reply) => {
    cleanupRunContexts();
    let project;
    try {
      project = await resolveProject(request.params.projectId);
    } catch (error) {
      request.log.error({ err: error }, "project lookup failed");
      return reply.code(503).send({ error: "project_unavailable" });
    }
    if (!project) return reply.code(404).send({ error: "project_not_found" });
    let activeScenario: string | undefined;
    try {
      activeScenario = await getActiveScenario(project.id);
    } catch (error) {
      request.log.error({ err: error }, "active scenario lookup failed");
      return reply.code(503).send({ error: "context_unavailable" });
    }
    const certificates = options.resolveMetadataCertificates
      ? options.resolveMetadataCertificates(activeScenario, project)
      : activeScenario
        ? [project.current.certificate]
        : [project.current.certificate, project.nextCertificate];
    return reply
      .type("application/samlmetadata+xml; charset=utf-8")
      .header("cache-control", activeScenario ? "no-store" : "public, max-age=300")
      .send(
        generateMetadata({
          entityId: project.entityId,
          ssoUrl: project.ssoUrl,
          certificates,
        }),
      );
  });

  app.get<{
    Params: { projectId: string };
    Querystring: { SAMLRequest?: string; RelayState?: string };
  }>("/sso/:projectId", async (request, reply) => {
    let project;
    try {
      project = await resolveProject(request.params.projectId);
    } catch (error) {
      request.log.error({ err: error }, "project lookup failed");
      return reply.code(503).send({ error: "project_unavailable" });
    }
    if (!project) return reply.code(404).send({ error: "project_not_found" });
    if (project.verificationStatus && project.verificationStatus !== "verified") {
      return reply.code(403).send({ error: "project_not_verified" });
    }
    if (!request.query.SAMLRequest) {
      return reply.code(400).send({ error: "invalid_saml_request" });
    }
    let activated: ActivationScope | undefined;
    if (options.activationService) {
      cleanupRunContexts();
      const sessionId = cookieValue(request.headers.cookie, "saml_chaos_run");
      if (sessionId) {
        try {
          activated = await consumeRunContext(sessionId, project.id);
        } catch (error) {
          request.log.error({ err: error }, "run context consume failed");
          return reply.code(503).send({ error: "context_unavailable" });
        }
      }
      if (!sessionId || !activated || activated.projectId !== project.id) {
        metrics.increment("saml_response_total", { status: "rejected" });
        return reply.code(400).send({ error: "invalid_saml_request" });
      }
    }
    let authnRequest: ReturnType<typeof parseRedirectAuthnRequest>;
    try {
      authnRequest = parseRedirectAuthnRequest(
        request.query.SAMLRequest,
        request.query.RelayState ?? "",
        {
          expectedEntityId: project.spEntityId,
          verifiedAcsUrl: project.acsUrl,
          expectedDestination: project.ssoUrl,
        },
      );
    } catch (error) {
      request.log.debug({ err: error }, "authn request rejected");
      metrics.increment("saml_response_total", { status: "rejected" });
      return reply.code(400).send({ error: "invalid_saml_request" });
    }
    const responsePlan = {
      issuer: project.entityId,
      requestId: authnRequest.id,
      destination: project.acsUrl,
      audience: project.spEntityId,
      nameId: project.nameId,
      nameIdFormat: project.nameIdFormat,
      attributes: project.attributes,
      signing: project.current,
    };
    const render = options.renderScenario ?? renderFreeScenario;
    let generated: ReturnType<typeof generateResponse> & {
      relayState?: string;
    };
    try {
      generated = activated
        ? render(activated.scenarioId, responsePlan, {
            current: project.current,
            next: project.next ?? project.current,
          })
        : generateResponse(responsePlan);
    } catch (error) {
      request.log.error({ err: error }, "scenario response generation failed");
      metrics.increment("saml_response_total", { status: "failed" });
      return reply.code(503).send({ error: "response_unavailable" });
    }
    try {
      await clearActiveScenario(project.id, activated?.scenarioId ?? "SAML-BASE-001");
      await options.recordEvent?.("response.delivered", {
        projectId: project.id,
        ...(activated?.runId ? { runId: activated.runId } : {}),
        scenarioId: activated?.scenarioId ?? "SAML-BASE-001",
      });
    } catch (error) {
      request.log.error({ err: error }, "scenario context cleanup failed");
      metrics.increment("saml_response_total", { status: "failed" });
      return reply.code(503).send({ error: "response_unavailable" });
    }
    metrics.increment("saml_response_total", {
      scenario: activated?.scenarioId ?? "SAML-BASE-001",
      status: "delivered",
    });
    const nonce = randomBytes(18).toString("base64url");
    const csp = `default-src 'none'; form-action ${project.acsUrl}; script-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`;
    return reply
      .type("text/html; charset=utf-8")
      .header("content-security-policy", csp)
      .header("cache-control", "no-store")
      .header("referrer-policy", "no-referrer")
      .header("set-cookie", `saml_chaos_run=; Max-Age=0; Path=/; HttpOnly; ${cookieSecurity}`)
      .send(
        autoPostForm(
          project.acsUrl,
          generated.xml,
          generated.relayState ?? authnRequest.relayState,
          nonce,
        ),
      );
  });

  return app;
}
