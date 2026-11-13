import { describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { request } from "node:http";
import { createPinnedProxy } from "../packages/browser-runner/src/pinned-proxy.js";
import {
  ActivationService,
  buildHostResolverRules,
  extractSamlTimingFromFormBody,
  observeScenario,
  parseReplayFormBody,
  replayWasRejected,
  requestAllowed,
  sanitizeObservedUrl,
  shouldCaptureSamlPost,
  type BrowserSession,
} from "@saml-chaos/browser-runner";

it.each(["GET", "CONNECT"])(
  "denies a %s request when proxy authorization throws",
  async (method) => {
    const authorizeRequest = vi.fn(async () => {
      throw new Error("resolver unavailable");
    });
    const proxy = await createPinnedProxy({
      allowedHosts: ["sp.example"],
      pinnedAddresses: new Map([["sp.example", ["127.0.0.1"]]]),
      authorizeRequest,
    });
    try {
      const status = await new Promise<number | undefined>((resolve, reject) => {
        const req = request(proxy.serverUrl, {
          method,
          path: method === "CONNECT" ? "sp.example:443" : "http://sp.example/login",
          signal: AbortSignal.timeout(2_000),
        });
        req.on("response", (res) => {
          res.resume();
          resolve(res.statusCode);
        });
        req.on("connect", (res, socket) => {
          socket.destroy();
          resolve(res.statusCode);
        });
        req.on("error", reject);
        req.end();
      });
      expect(status).toBe(403);
      expect(authorizeRequest).toHaveBeenCalledOnce();
    } finally {
      await proxy.close();
    }
  },
);

function session(overrides: Partial<BrowserSession> = {}): BrowserSession {
  return {
    activate: async () => undefined,
    goto: async () => undefined,
    currentUrl: () => "https://sp.example/success",
    httpStatus: () => 200,
    hasSelector: async () => true,
    screenshot: async () => Buffer.from("safe"),
    consoleErrors: () => [],
    blockedRequest: () => false,
    blockedUrl: () => undefined,
    containsText: async () => false,
    redirectLocation: () => undefined,
    assertionTiming: () => undefined,
    close: async () => undefined,
    ...overrides,
  };
}

describe("browser outcome observation", () => {
  it("issues short-lived single-use activation tokens scoped to browser session", async () => {
    let now = 1_000_000;
    const service = new ActivationService(randomBytes(32), () => now);
    const token = await service.issue(
      {
        projectId: "p1",
        runId: "r1",
        scenarioId: "SAML-TIME-001",
        browserSessionId: "b1",
      },
      60,
    );
    await expect(
      service.consume(token, { projectId: "p1", browserSessionId: "b1" }),
    ).resolves.toMatchObject({ runId: "r1", scenarioId: "SAML-TIME-001" });
    await expect(
      service.consume(token, { projectId: "p1", browserSessionId: "b1" }),
    ).rejects.toThrow("activation_replayed");
    const wrong = await service.issue(
      {
        projectId: "p1",
        runId: "r2",
        scenarioId: "SAML-AUD-001",
        browserSessionId: "b2",
      },
      60,
    );
    await expect(
      service.consume(wrong, { projectId: "p2", browserSessionId: "b2" }),
    ).rejects.toThrow("activation_scope_mismatch");
    expect(service.replayCacheSize).toBe(1);
    now += 61_000;
    const fresh = await service.issue(
      {
        projectId: "p1",
        runId: "r3",
        scenarioId: "SAML-BASE-001",
        browserSessionId: "b3",
      },
      60,
    );
    await service.consume(fresh, { projectId: "p1", browserSessionId: "b3" });
    expect(service.replayCacheSize).toBe(1);
  });

  it("rejects activation replay across IdP replicas through an atomic shared store", async () => {
    const secret = randomBytes(32);
    const consumed = new Set<string>();
    const replayStore = {
      consume: async (jti: string) => {
        if (consumed.has(jti)) return false;
        consumed.add(jti);
        return true;
      },
    };
    const firstReplica = new ActivationService(secret, Date.now, replayStore);
    const secondReplica = new ActivationService(secret, Date.now, replayStore);
    const token = await firstReplica.issue({
      projectId: "p1",
      runId: "r1",
      scenarioId: "SAML-TIME-001",
      browserSessionId: "b1",
    });

    await firstReplica.consume(token, {
      projectId: "p1",
      browserSessionId: "b1",
    });
    await expect(
      secondReplica.consume(token, { projectId: "p1", browserSessionId: "b1" }),
    ).rejects.toThrow("activation_replayed");
  });

  it("classifies success using URL and optional selector", async () => {
    await expect(
      observeScenario(session(), {
        activationUrl: "https://idp.example/activate",
        loginUrl: "https://sp.example/login",
        allowedHosts: ["idp.example", "sp.example"],
        successUrl: /\/success$/,
        successSelector: "#account",
        timeoutMs: 1000,
      }),
    ).resolves.toMatchObject({
      outcome: "success",
      finalUrl: "https://sp.example/success",
    });
  });

  it("flags spoofed identities and normal success on strict-reject scenarios", async () => {
    const base = {
      activationUrl: "https://idp.example/activate",
      loginUrl: "https://sp.example/login",
      allowedHosts: ["idp.example", "sp.example"],
      successUrl: /\/success$/,
      timeoutMs: 1000,
      strictReject: true,
    };
    await expect(
      observeScenario(session({ containsText: async () => true }), base),
    ).resolves.toMatchObject({
      outcome: "success",
      signal: "spoofed_identity_accepted",
    });
    await expect(observeScenario(session(), base)).resolves.toMatchObject({
      outcome: "success",
      signal: "unexpected_authenticated_session",
    });
  });

  it("records external redirects before the blocked navigation can leave allowed hosts", async () => {
    await expect(
      observeScenario(session({ redirectLocation: () => "https://evil.invalid/callback" }), {
        activationUrl: "https://idp.example/activate",
        loginUrl: "https://sp.example/login",
        allowedHosts: ["idp.example", "sp.example"],
        successUrl: /\/success$/,
        strictReject: true,
        timeoutMs: 1000,
      }),
    ).resolves.toMatchObject({
      outcome: "success",
      signal: "external_redirect",
    });
  });

  it("classifies explicit rejection and blocks host escape", async () => {
    await expect(
      observeScenario(
        session({
          currentUrl: () => "https://sp.example/saml/error",
          hasSelector: async () => false,
        }),
        {
          activationUrl: "https://idp.example/activate",
          loginUrl: "https://sp.example/login",
          allowedHosts: ["idp.example", "sp.example"],
          successUrl: /\/success$/,
          failureUrls: [/\/saml\/error$/],
          timeoutMs: 1000,
        },
      ),
    ).resolves.toMatchObject({ outcome: "rejected" });
    await expect(
      observeScenario(session({ currentUrl: () => "https://evil.example/escape" }), {
        activationUrl: "https://idp.example/activate",
        loginUrl: "https://sp.example/login",
        allowedHosts: ["idp.example", "sp.example"],
        successUrl: /\/success$/,
        timeoutMs: 1000,
      }),
    ).resolves.toMatchObject({ outcome: "blocked", signal: "unexpected_host" });
  });

  it("classifies final HTTP error responses as explicit rejection", async () => {
    await expect(
      observeScenario(
        session({
          currentUrl: () => "https://sp.example/saml/acs",
          httpStatus: () => 403,
          hasSelector: async () => false,
        }),
        {
          activationUrl: "https://idp.example/activate",
          loginUrl: "https://sp.example/login",
          allowedHosts: ["idp.example", "sp.example"],
          successUrl: /\/success$/,
          timeoutMs: 1000,
        },
      ),
    ).resolves.toMatchObject({
      outcome: "rejected",
      signal: "http_rejection",
      httpStatus: 403,
    });
  });

  it("closes browser and reports timeout/error safely", async () => {
    let closed = false;
    const result = await observeScenario(
      session({
        goto: async () => {
          throw new Error("Timeout 1000ms cookie=secret");
        },
        close: async () => {
          closed = true;
        },
      }),
      {
        activationUrl: "https://idp.example/activate",
        loginUrl: "https://sp.example/login",
        allowedHosts: ["idp.example", "sp.example"],
        successUrl: /\/success$/,
        timeoutMs: 1000,
      },
    );
    expect(result).toMatchObject({ outcome: "timeout" });
    expect(result.signal).not.toContain("secret");
    expect(closed).toBe(true);
  });

  it("does not start browser work when its signal is already aborted", async () => {
    const activate = vi.fn().mockResolvedValue(undefined);
    const goto = vi.fn().mockResolvedValue(undefined);
    let closed = false;
    const controller = new AbortController();
    controller.abort(new Error("lease_lost"));

    const result = await observeScenario(
      session({
        activate,
        goto,
        close: async () => {
          closed = true;
        },
      }),
      {
        activationUrl: "https://idp.example/activate",
        loginUrl: "https://sp.example/login",
        allowedHosts: ["idp.example", "sp.example"],
        signal: controller.signal,
        successUrl: /\/success$/,
        timeoutMs: 1000,
      },
    );

    expect(result).toMatchObject({ outcome: "error", signal: "browser_error" });
    expect(activate).not.toHaveBeenCalled();
    expect(goto).not.toHaveBeenCalled();
    expect(closed).toBe(true);
  });

  it("reports an intercepted browser escape as blocked instead of a generic error", async () => {
    const result = await observeScenario(
      session({
        goto: async () => {
          throw new Error("net::ERR_BLOCKED_BY_CLIENT");
        },
        blockedRequest: () => true,
      }),
      {
        activationUrl: "https://idp.example/activate",
        loginUrl: "https://sp.example/login",
        allowedHosts: ["idp.example", "sp.example"],
        successUrl: /\/success$/,
        timeoutMs: 1000,
      },
    );

    expect(result).toMatchObject({
      outcome: "blocked",
      signal: "unexpected_host",
    });
  });

  it("enforces exact origins and redacts query values in stored observations", () => {
    expect(
      requestAllowed("https://sp.example:8443/app.js", ["sp.example"], ["https://sp.example:8443"]),
    ).toBe(true);
    expect(
      requestAllowed("https://sp.example:9443/app.js", ["sp.example"], ["https://sp.example:8443"]),
    ).toBe(false);
    expect(requestAllowed("https://evil.example/pixel", ["sp.example"])).toBe(false);
    expect(sanitizeObservedUrl("https://sp.example/error?SAMLRequest=secret&reason=bad")).toBe(
      "https://sp.example/error?SAMLRequest=%5BREDACTED%5D&reason=%5BREDACTED%5D",
    );
  });

  it("builds deterministic Chromium DNS pinning rules from verified addresses", () => {
    expect(
      buildHostResolverRules(
        new Map([
          ["sp.example", ["93.184.216.34", "93.184.216.35"]],
          ["idp.example", ["2001:4860:4860::8888"]],
        ]),
      ),
    ).toBe("MAP idp.example [2001:4860:4860::8888],MAP sp.example 93.184.216.34");
  });

  it("preserves the signed response and RelayState when rebuilding a browser replay form", () => {
    expect(parseReplayFormBody("SAMLResponse=abc%2B123%3D%3D&RelayState=return%2Fhome")).toEqual([
      ["SAMLResponse", "abc+123=="],
      ["RelayState", "return/home"],
    ]);
  });

  it("extracts only assertion timing metadata from an in-memory SAML POST", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="2026-07-17T00:00:00.000Z"><saml:Conditions NotBefore="2026-07-16T23:59:30.000Z" NotOnOrAfter="2026-07-17T00:05:00.000Z"/></saml:Assertion></samlp:Response>`;
    const body = new URLSearchParams({
      SAMLResponse: Buffer.from(xml).toString("base64"),
    }).toString();

    expect(extractSamlTimingFromFormBody(body)).toEqual({
      issuedAt: "2026-07-17T00:00:00.000Z",
      notBefore: "2026-07-16T23:59:30.000Z",
      notOnOrAfter: "2026-07-17T00:05:00.000Z",
    });
    expect(extractSamlTimingFromFormBody("SAMLResponse=not-base64")).toBeUndefined();
  });

  it("captures SAML timing only from the configured ACS POST", () => {
    expect(
      shouldCaptureSamlPost("POST", "https://sp.example/saml/acs", "https://sp.example/saml/acs"),
    ).toBe(true);
    expect(
      shouldCaptureSamlPost("POST", "https://sp.example/telemetry", "https://sp.example/saml/acs"),
    ).toBe(false);
    expect(
      shouldCaptureSamlPost("GET", "https://sp.example/saml/acs", "https://sp.example/saml/acs"),
    ).toBe(false);
    expect(shouldCaptureSamlPost("POST", "https://sp.example/saml/acs", undefined)).toBe(false);
  });

  it("treats an HTTP error from the second replay submission as rejection", () => {
    expect(replayWasRejected("https://sp.example/saml/acs", 409, [])).toBe(true);
    expect(replayWasRejected("https://sp.example/saml/acs", 200, [/\/saml\/error$/])).toBe(false);
    expect(replayWasRejected("https://sp.example/saml/error", 200, [/\/saml\/error$/])).toBe(true);
  });
});
