import { createHash, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { jwtVerify, SignJWT } from "jose";
import { DOMParser } from "@xmldom/xmldom";
import { createPinnedProxy } from "./pinned-proxy.js";

export interface ActivationScope {
  projectId: string;
  runId: string;
  scenarioId: string;
  browserSessionId: string;
}

export interface ActivationReplayStore {
  consume(jti: string, expiresAt: Date): Promise<boolean>;
}

export class ActivationService {
  private readonly used = new Map<string, number>();
  constructor(
    private readonly secret: Uint8Array,
    private readonly now: () => number = Date.now,
    private readonly replayStore?: ActivationReplayStore,
  ) {
    if (secret.byteLength < 32) throw new Error("activation_secret_too_short");
  }

  async issue(scope: ActivationScope, ttlSeconds = 120): Promise<string> {
    const issuedAt = Math.floor(this.now() / 1000);
    return new SignJWT({ ...scope })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setJti(randomUUID())
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + ttlSeconds)
      .sign(this.secret);
  }

  async consume(
    token: string,
    expected: Pick<ActivationScope, "projectId" | "browserSessionId">,
  ): Promise<ActivationScope> {
    const now = this.now();
    for (const [jti, expiresAt] of this.used) {
      if (expiresAt <= now) this.used.delete(jti);
    }
    const { payload } = await jwtVerify(token, this.secret, {
      algorithms: ["HS256"],
      currentDate: new Date(now),
    });
    if (!payload.jti) throw new Error("activation_missing_jti");
    if (typeof payload.exp !== "number") throw new Error("activation_missing_expiry");
    if (this.used.has(payload.jti)) throw new Error("activation_replayed");
    const scope = {
      projectId: payload.projectId,
      runId: payload.runId,
      scenarioId: payload.scenarioId,
      browserSessionId: payload.browserSessionId,
    };
    if (!Object.values(scope).every((value) => typeof value === "string")) {
      throw new Error("activation_invalid_scope");
    }
    if (
      scope.projectId !== expected.projectId ||
      scope.browserSessionId !== expected.browserSessionId
    ) {
      throw new Error("activation_scope_mismatch");
    }
    if (
      this.replayStore &&
      !(await this.replayStore.consume(payload.jti, new Date(payload.exp * 1000)))
    ) {
      throw new Error("activation_replayed");
    }
    this.used.set(payload.jti, payload.exp * 1000);
    return scope as ActivationScope;
  }

  get replayCacheSize(): number {
    return this.used.size;
  }
}

export interface BrowserSession {
  activate(url: string, timeoutMs: number): Promise<void>;
  goto(url: string, timeoutMs: number): Promise<void>;
  currentUrl(): string;
  httpStatus(): number | undefined;
  hasSelector(selector: string): Promise<boolean>;
  screenshot(): Promise<Buffer>;
  consoleErrors(): string[];
  blockedRequest(): boolean;
  blockedUrl(): string | undefined;
  containsText(value: string): Promise<boolean>;
  redirectLocation(): string | undefined;
  assertionTiming(): AssertionTiming | undefined;
  close(): Promise<void>;
}

export interface AssertionTiming {
  issuedAt: string;
  notBefore: string;
  notOnOrAfter: string;
}

export interface ObservationOptions {
  activationUrl: string;
  loginUrl: string;
  acsUrl?: string;
  allowedHosts: string[];
  allowedOrigins?: string[];
  authorizeRequest?: (url: string) => Promise<boolean>;
  pinnedAddresses?: ReadonlyMap<string, readonly string[]>;
  signal?: AbortSignal;
  successUrl: RegExp;
  successSelector?: string;
  failureUrls?: RegExp[];
  timeoutMs: number;
  spoofedIdentityToken?: string;
  strictReject?: boolean;
}

export interface BrowserObservation {
  outcome: "success" | "rejected" | "inconclusive" | "blocked" | "timeout" | "error";
  finalUrl?: string;
  httpStatus?: number;
  signal: string;
  screenshotHash?: string;
  issuedAt?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  consoleErrorCount: number;
  durationMs: number;
}

export function requestAllowed(
  value: string,
  allowedHosts: string[],
  allowedOrigins?: string[],
): boolean {
  try {
    const url = new URL(value);
    if (["about:", "blob:", "data:"].includes(url.protocol)) return true;
    if (!allowedHosts.map((host) => host.toLowerCase()).includes(url.hostname.toLowerCase())) {
      return false;
    }
    return !allowedOrigins || allowedOrigins.includes(url.origin.toLowerCase());
  } catch {
    return false;
  }
}

export function sanitizeObservedUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const key of url.searchParams.keys()) url.searchParams.set(key, "[REDACTED]");
    return url.toString();
  } catch {
    return "[REDACTED]";
  }
}

async function outboundAllowed(value: string, options: ObservationOptions): Promise<boolean> {
  if (!requestAllowed(value, options.allowedHosts, options.allowedOrigins)) return false;
  return options.authorizeRequest ? options.authorizeRequest(value) : true;
}

export async function observeScenario(
  session: BrowserSession,
  options: ObservationOptions,
): Promise<BrowserObservation> {
  const started = Date.now();
  const base = { consoleErrorCount: 0, durationMs: 0 };
  try {
    options.signal?.throwIfAborted();
    if (
      !requestAllowed(options.activationUrl, options.allowedHosts, options.allowedOrigins) ||
      !requestAllowed(options.loginUrl, options.allowedHosts, options.allowedOrigins)
    ) {
      return {
        ...base,
        outcome: "blocked",
        signal: "unexpected_host",
        durationMs: Date.now() - started,
      };
    }
    await session.activate(options.activationUrl, options.timeoutMs);
    await session.goto(options.loginUrl, options.timeoutMs);
    const finalUrl = session.currentUrl();
    const consoleErrorCount = session.consoleErrors().length;
    const redirectLocation = session.redirectLocation();
    if (
      redirectLocation &&
      !requestAllowed(redirectLocation, options.allowedHosts, options.allowedOrigins)
    ) {
      const redirectStatus = session.httpStatus();
      return {
        outcome: "success",
        signal: "external_redirect",
        finalUrl: sanitizeObservedUrl(redirectLocation),
        ...(redirectStatus === undefined ? {} : { httpStatus: redirectStatus }),
        consoleErrorCount,
        durationMs: Date.now() - started,
      };
    }
    if (!requestAllowed(finalUrl, options.allowedHosts, options.allowedOrigins)) {
      return {
        outcome: "blocked",
        signal: "unexpected_host",
        finalUrl: "[REDACTED]",
        consoleErrorCount,
        durationMs: Date.now() - started,
      };
    }
    const selectorMatches = options.successSelector
      ? await session.hasSelector(options.successSelector)
      : true;
    const httpStatus = session.httpStatus();
    let outcome: BrowserObservation["outcome"] = "inconclusive";
    let signal = "no_configured_signal";
    if (options.successUrl.test(finalUrl) && selectorMatches) {
      outcome = "success";
      signal = "success_signal";
      const spoofedIdentityToken = options.spoofedIdentityToken ?? "chaos-spoofed-admin";
      if (
        (finalUrl.includes(spoofedIdentityToken) ||
          (await session.containsText(spoofedIdentityToken))) &&
        spoofedIdentityToken.length > 0
      ) {
        signal = "spoofed_identity_accepted";
      } else if (options.strictReject) {
        signal = "unexpected_authenticated_session";
      }
    } else if ((options.failureUrls ?? []).some((pattern) => pattern.test(finalUrl))) {
      outcome = "rejected";
      signal = "failure_url";
    } else if (httpStatus !== undefined && httpStatus >= 400) {
      outcome = "rejected";
      signal = "http_rejection";
    }
    const screenshot = await session.screenshot();
    const timing = session.assertionTiming();
    return {
      outcome,
      signal,
      finalUrl: sanitizeObservedUrl(finalUrl),
      consoleErrorCount,
      screenshotHash: createHash("sha256").update(screenshot).digest("hex"),
      ...(timing ?? {}),
      durationMs: Date.now() - started,
      ...(httpStatus === undefined ? {} : { httpStatus }),
    };
  } catch (error) {
    const blockedUrl = session.blockedUrl();
    if (
      blockedUrl &&
      blockedUrl === session.currentUrl() &&
      !requestAllowed(blockedUrl, options.allowedHosts, options.allowedOrigins)
    ) {
      return {
        ...base,
        outcome: "success",
        signal: "external_redirect",
        finalUrl: sanitizeObservedUrl(blockedUrl),
        durationMs: Date.now() - started,
      };
    }
    const redirectLocation = session.redirectLocation();
    if (
      redirectLocation &&
      !requestAllowed(redirectLocation, options.allowedHosts, options.allowedOrigins)
    ) {
      return {
        ...base,
        outcome: "success",
        signal: "external_redirect",
        finalUrl: sanitizeObservedUrl(redirectLocation),
        durationMs: Date.now() - started,
      };
    }
    if (session.blockedRequest()) {
      return {
        ...base,
        outcome: "blocked",
        signal: "unexpected_host",
        durationMs: Date.now() - started,
      };
    }
    const timedOut = error instanceof Error && /timeout/i.test(error.message);
    return {
      ...base,
      outcome: timedOut ? "timeout" : "error",
      signal: timedOut ? "step_timeout" : "browser_error",
      durationMs: Date.now() - started,
    };
  } finally {
    await session.close();
  }
}

export function buildHostResolverRules(
  pinnedAddresses: ReadonlyMap<string, readonly string[]>,
): string {
  return [...pinnedAddresses.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([hostname, addresses]) => {
      const address = addresses[0];
      if (!address || !isIP(address)) return [];
      return [`MAP ${hostname} ${isIP(address) === 6 ? `[${address}]` : address}`];
    })
    .join(",");
}

export function parseReplayFormBody(body: string): [string, string][] {
  const parameters = new URLSearchParams(body);
  const response = parameters.get("SAMLResponse");
  if (!response) throw new Error("replay_response_missing");
  const fields: [string, string][] = [["SAMLResponse", response]];
  const relayState = parameters.get("RelayState");
  if (relayState !== null) fields.push(["RelayState", relayState]);
  return fields;
}

export function extractSamlTimingFromFormBody(body: string): AssertionTiming | undefined {
  try {
    const encoded = new URLSearchParams(body).get("SAMLResponse");
    if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return undefined;
    const raw = Buffer.from(encoded, "base64");
    if (raw.length === 0 || raw.length > 1024 * 1024) return undefined;
    const xml = raw.toString("utf8");
    if (/<!DOCTYPE|<!ENTITY/i.test(xml)) return undefined;
    const document = new DOMParser().parseFromString(xml, "application/xml");
    const assertion = document
      .getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
      .item(0);
    const conditions = document
      .getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Conditions")
      .item(0);
    const issuedAt = assertion?.getAttribute("IssueInstant");
    const notBefore = conditions?.getAttribute("NotBefore");
    const notOnOrAfter = conditions?.getAttribute("NotOnOrAfter");
    if (
      !issuedAt ||
      !notBefore ||
      !notOnOrAfter ||
      ![issuedAt, notBefore, notOnOrAfter].every((value) => Number.isFinite(Date.parse(value)))
    ) {
      return undefined;
    }
    return { issuedAt, notBefore, notOnOrAfter };
  } catch {
    return undefined;
  }
}

export function shouldCaptureSamlPost(
  method: string,
  requestUrl: string,
  acsUrl: string | undefined,
): boolean {
  return method === "POST" && acsUrl !== undefined && requestUrl === acsUrl;
}

export function replayWasRejected(
  finalUrl: string,
  httpStatus: number | undefined,
  failureUrls: RegExp[],
): boolean {
  return (
    (httpStatus !== undefined && httpStatus >= 400) ||
    failureUrls.some((pattern) => pattern.test(finalUrl))
  );
}

function browserCleanup(browser: { close(): Promise<void> }, proxy: { close(): Promise<void> }) {
  let closing: Promise<void> | undefined;
  return () => (closing ??= browser.close().finally(() => proxy.close()));
}

export async function createPlaywrightSession(options: {
  allowedHosts: string[];
  acsUrl?: string;
  allowedOrigins?: string[];
  authorizeRequest?: (url: string) => Promise<boolean>;
  pinnedAddresses?: ReadonlyMap<string, readonly string[]>;
  headless?: boolean;
  navigationBudget?: number;
}): Promise<BrowserSession> {
  const { chromium } = await import("@playwright/test");
  const navigationBudget = options.navigationBudget ?? 10;
  let blocked = false;
  let blockedUrl: string | undefined;
  let documentRequests = 0;
  const resetNavigationBudget = () => {
    documentRequests = 0;
  };
  const resolverRules = buildHostResolverRules(options.pinnedAddresses ?? new Map());
  const proxy = await createPinnedProxy({
    allowedHosts: options.allowedHosts,
    ...(options.allowedOrigins ? { allowedOrigins: options.allowedOrigins } : {}),
    ...(options.authorizeRequest ? { authorizeRequest: options.authorizeRequest } : {}),
    pinnedAddresses: options.pinnedAddresses ?? new Map(),
    onBlocked: (url) => {
      blocked = true;
      blockedUrl ??= url;
    },
  });
  let browser;
  try {
    browser = await chromium.launch({
      headless: options.headless ?? true,
      proxy: { server: proxy.serverUrl, bypass: "<-loopback>" },
      args: [
        ...(resolverRules ? [`--host-resolver-rules=${resolverRules}`] : []),
        "--proxy-bypass-list=<-loopback>",
      ],
    });
  } catch (error) {
    await proxy.close();
    throw error;
  }
  const close = browserCleanup(browser, proxy);
  const failSetup = async (error: unknown): Promise<never> => {
    await close();
    throw error;
  };
  const context = await browser
    .newContext({
      ignoreHTTPSErrors: false,
      acceptDownloads: false,
      serviceWorkers: "block",
    })
    .catch(failSetup);
  const page = await context.newPage().catch(failSetup);
  const errors: string[] = [];
  let status: number | undefined;
  let timing: AssertionTiming | undefined;
  let redirectLocation: string | undefined;
  page.on("console", (message) => {
    if (message.type() === "error") errors.push("browser_console_error");
  });
  page.on("request", (request) => {
    if (!shouldCaptureSamlPost(request.method(), request.url(), options.acsUrl)) return;
    const captured = extractSamlTimingFromFormBody(request.postData() ?? "");
    if (captured) timing = captured;
  });
  page.on("response", (response) => {
    if (response.status() < 300 || response.status() >= 400) return;
    const location = response.headers().location;
    if (location) {
      try {
        redirectLocation = new URL(location, response.url()).toString();
      } catch {
        redirectLocation = undefined;
      }
    }
  });
  await context
    .route("**/*", async (route) => {
      const request = route.request();
      let allowed = false;
      try {
        allowed =
          requestAllowed(request.url(), options.allowedHosts, options.allowedOrigins) &&
          (!options.authorizeRequest || (await options.authorizeRequest(request.url())));
      } catch {
        allowed = false;
      }
      if (allowed && request.resourceType() === "document") {
        if (documentRequests >= navigationBudget) {
          blocked = true;
          await route.abort("blockedbyclient");
          return;
        }
        documentRequests += 1;
      }
      if (!allowed) {
        blocked = true;
        await route.abort("blockedbyclient");
      } else {
        await route.continue();
      }
    })
    .catch(failSetup);
  await context.routeWebSocket("**/*", (socket) => socket.close()).catch(failSetup);
  return {
    activate: async (url, timeoutMs) => {
      if (
        !requestAllowed(url, options.allowedHosts, options.allowedOrigins) ||
        (options.authorizeRequest && !(await options.authorizeRequest(url)))
      ) {
        throw new Error("blocked_request");
      }
      redirectLocation = undefined;
      resetNavigationBudget();
      const response = await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
      });
      if (!response?.ok()) throw new Error("activation_failed");
      status = response.status();
    },
    goto: async (url, timeoutMs) => {
      redirectLocation = undefined;
      resetNavigationBudget();
      const response = await page.goto(url, {
        waitUntil: "networkidle",
        timeout: timeoutMs,
      });
      status = response?.status();
    },
    currentUrl: () => page.url(),
    httpStatus: () => status,
    hasSelector: async (selector) => (await page.locator(selector).count()) > 0,
    screenshot: async () => page.screenshot({ type: "png", fullPage: false }),
    consoleErrors: () => [...errors],
    blockedRequest: () => blocked,
    blockedUrl: () => blockedUrl,
    containsText: async (value) => (await page.locator("body").innerText()).includes(value),
    redirectLocation: () => redirectLocation,
    assertionTiming: () => timing,
    close,
  };
}

export async function runWithPlaywright(options: ObservationOptions): Promise<BrowserObservation> {
  options.signal?.throwIfAborted();
  const session = await createPlaywrightSession({
    allowedHosts: options.allowedHosts,
    ...(options.acsUrl ? { acsUrl: options.acsUrl } : {}),
    ...(options.allowedOrigins ? { allowedOrigins: options.allowedOrigins } : {}),
    ...(options.authorizeRequest ? { authorizeRequest: options.authorizeRequest } : {}),
    ...(options.pinnedAddresses ? { pinnedAddresses: options.pinnedAddresses } : {}),
  });
  const abort = () => void session.close().catch(() => undefined);
  options.signal?.addEventListener("abort", abort, { once: true });
  try {
    return await observeScenario(session, options);
  } finally {
    options.signal?.removeEventListener("abort", abort);
  }
}

export async function runReplayWithPlaywright(
  options: ObservationOptions & { acsUrl: string },
): Promise<BrowserObservation> {
  options.signal?.throwIfAborted();
  const started = Date.now();
  const { chromium } = await import("@playwright/test");
  const resolverRules = buildHostResolverRules(options.pinnedAddresses ?? new Map());
  let blocked = false;
  const proxy = await createPinnedProxy({
    allowedHosts: options.allowedHosts,
    ...(options.allowedOrigins ? { allowedOrigins: options.allowedOrigins } : {}),
    ...(options.authorizeRequest ? { authorizeRequest: options.authorizeRequest } : {}),
    pinnedAddresses: options.pinnedAddresses ?? new Map(),
    onBlocked: () => {
      blocked = true;
    },
  });
  const browser = await chromium
    .launch({
      headless: true,
      proxy: { server: proxy.serverUrl, bypass: "<-loopback>" },
      args: [
        ...(resolverRules ? [`--host-resolver-rules=${resolverRules}`] : []),
        "--proxy-bypass-list=<-loopback>",
      ],
    })
    .catch(async (error: unknown) => {
      await proxy.close();
      throw error;
    });
  let capturedBody: string | null = null;
  const navigationBudget = 10;
  let documentRequests = 0;
  const close = browserCleanup(browser, proxy);
  const abort = () => void close().catch(() => undefined);
  options.signal?.addEventListener("abort", abort, { once: true });
  try {
    options.signal?.throwIfAborted();
    const context = await browser.newContext({ serviceWorkers: "block" });
    const page = await context.newPage();
    await context.route("**/*", async (route) => {
      const request = route.request();
      let allowed = false;
      try {
        allowed = await outboundAllowed(request.url(), options);
      } catch {
        allowed = false;
      }
      if (allowed && request.resourceType() === "document") {
        if (documentRequests >= navigationBudget) {
          blocked = true;
          await route.abort("blockedbyclient");
          return;
        }
        documentRequests += 1;
      }
      if (!allowed) {
        blocked = true;
        await route.abort("blockedbyclient");
      } else {
        await route.continue();
      }
    });
    await context.routeWebSocket("**/*", (socket) => socket.close());
    page.on("request", (request) => {
      if (request.method() === "POST" && request.url() === options.acsUrl) {
        capturedBody = request.postData();
      }
    });
    if (!(await outboundAllowed(options.activationUrl, options))) {
      return {
        outcome: "blocked",
        signal: "unexpected_host",
        consoleErrorCount: 0,
        durationMs: Date.now() - started,
      };
    }
    const activation = await page.goto(options.activationUrl, {
      waitUntil: "domcontentloaded",
      timeout: options.timeoutMs,
    });
    if (!activation?.ok()) throw new Error("activation_failed");
    await page.goto(options.loginUrl, {
      waitUntil: "networkidle",
      timeout: options.timeoutMs,
    });
    if (!capturedBody || !options.successUrl.test(page.url())) {
      return {
        outcome: "inconclusive",
        signal: "replay_first_submission_unobserved",
        consoleErrorCount: 0,
        durationMs: Date.now() - started,
      };
    }
    if (!(await outboundAllowed(options.acsUrl, options))) {
      return {
        outcome: "blocked",
        signal: "unexpected_host",
        consoleErrorCount: 0,
        durationMs: Date.now() - started,
      };
    }
    const fields = parseReplayFormBody(capturedBody);
    const timing = extractSamlTimingFromFormBody(capturedBody);
    const replayPage = await context.newPage();
    await replayPage.setContent("<!doctype html><html><body></body></html>");
    const [replay] = await Promise.all([
      replayPage.waitForNavigation({
        waitUntil: "domcontentloaded",
        timeout: options.timeoutMs,
      }),
      replayPage.evaluate(
        ({ action, values }) => {
          const form = document.createElement("form");
          form.method = "post";
          form.action = action;
          for (const [name, value] of values) {
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = name;
            input.value = value;
            form.append(input);
          }
          document.body.append(form);
          form.submit();
        },
        { action: options.acsUrl, values: fields },
      ),
    ]);
    const finalUrl = replayPage.url();
    const replayStatus = replay?.status();
    if (!(await outboundAllowed(finalUrl, options))) {
      return {
        outcome: "blocked",
        signal: "unexpected_host",
        finalUrl: "[REDACTED]",
        consoleErrorCount: 0,
        durationMs: Date.now() - started,
        ...(replayStatus === undefined ? {} : { httpStatus: replayStatus }),
      };
    }
    const rejected = replayWasRejected(finalUrl, replayStatus, options.failureUrls ?? []);
    return {
      outcome: rejected
        ? "rejected"
        : options.successUrl.test(finalUrl)
          ? "success"
          : "inconclusive",
      signal: rejected
        ? "replay_rejected"
        : options.successUrl.test(finalUrl)
          ? "replay_authenticated"
          : "replay_ambiguous",
      finalUrl: sanitizeObservedUrl(finalUrl),
      ...(timing ?? {}),
      consoleErrorCount: 0,
      durationMs: Date.now() - started,
      ...(replayStatus === undefined ? {} : { httpStatus: replayStatus }),
    };
  } catch (error) {
    if (blocked) {
      return {
        outcome: "blocked",
        signal: "unexpected_host",
        consoleErrorCount: 0,
        durationMs: Date.now() - started,
      };
    }
    const timedOut = error instanceof Error && /timeout/i.test(error.message);
    return {
      outcome: timedOut ? "timeout" : "error",
      signal: timedOut ? "step_timeout" : "browser_error",
      consoleErrorCount: 0,
      durationMs: Date.now() - started,
    };
  } finally {
    options.signal?.removeEventListener("abort", abort);
    await close();
  }
}
