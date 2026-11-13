import { createHash, randomBytes, randomUUID } from "node:crypto";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { lookup } from "node:dns/promises";
import { ActivationService, runWithPlaywright } from "@saml-chaos/browser-runner";
import { scenarioCatalog } from "@saml-chaos/scenarios";
import { normalizeExactUrl, verifyDestination } from "@saml-chaos/target-safety";
import { buildIdp, type IdpProject } from "../../../apps/idp/src/app.js";
import {
  optionString,
  parseOptions,
  pinTargetUrls,
  readState,
  reservePort,
  severityRank,
  statusFor,
  writeMetadata,
  type RunnerState,
  type ScenarioCheckResult,
} from "./helpers.js";

export {
  optionString,
  parseOptions,
  pinTargetUrls,
  readState,
  reservePort,
  severityRank,
  statusFor,
  writeMetadata,
  type RunnerState,
  type ScenarioCheckResult,
};

export interface CliResult {
  exitCode: number;
  executed: number;
}

const BASELINE_DISCLAIMER =
  "Point-in-time deterministic synthetic check on the tested SP endpoint; not an exhaustive certification.";

function summaryMarkdown(results: ScenarioCheckResult[]) {
  const rows = results
    .map((result) => `| ${result.scenarioId} | ${result.status} | ${result.signal} |`)
    .join("\n");
  return `## SAML Chaos Lab (Open-Core Baseline)\n\n| Scenario | Result | Signal |\n| --- | --- | --- |\n${rows}\n\n> ${BASELINE_DISCLAIMER}\n`;
}

export async function runLocalTest(options: Record<string, string | boolean>): Promise<CliResult> {
  const loginUrl = normalizeExactUrl(optionString(options, "login-url"), true);
  const acsUrl = normalizeExactUrl(optionString(options, "acs-url"), true);
  const spEntityId = optionString(options, "sp-entity-id");
  const successUrlPattern = optionString(options, "success-url");
  const successSelector =
    typeof options["dom-selector"] === "string" ? options["dom-selector"] : undefined;
  const failOn = optionString(options, "fail-on", "high");
  if (failOn !== "high" && failOn !== "critical") throw new Error("invalid_fail_on_level");
  const stateDir = resolve(optionString(options, "state-dir", ".saml-chaos-lab"));
  const state = await readState(stateDir);
  const scenarios = scenarioCatalog;
  const current = state.current;
  const next = state.next;
  const idpProject: IdpProject = {
    id: state.projectId,
    entityId: state.entityId,
    ssoUrl: state.ssoUrl,
    spEntityId,
    acsUrl,
    nameId: "synthetic-user@invalid.example",
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    attributes: { role: ["saml-chaos-lab"] },
    current,
    next,
    nextCertificate: next.certificate,
    verificationStatus: "verified",
  };
  const activation = new ActivationService(randomBytes(32));
  const app = await buildIdp({
    projects: new Map([[idpProject.id, idpProject]]),
    activationService: activation,
  });
  const login = new URL(loginUrl);
  const acs = new URL(acsUrl);
  const idpOrigin = new URL(state.ssoUrl).origin;
  const allowedHosts = [...new Set([login.hostname, acs.hostname, new URL(idpOrigin).hostname])];
  const allowedOrigins = [...new Set([login.origin, acs.origin, idpOrigin])];
  const pinnedAddresses = await pinTargetUrls([
    loginUrl,
    acsUrl,
    `${idpOrigin}/activate/${state.projectId}`,
    `${idpOrigin}/sso/${state.projectId}`,
  ]);
  const authorizeRequest = async (value: string) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    if (["about:", "blob:", "data:"].includes(url.protocol)) return true;
    const expected = pinnedAddresses.get(url.hostname.toLowerCase());
    if (!expected) return false;
    const decision = await verifyDestination({
      candidateUrl: value,
      verifiedUrl: value,
      resolve: async (hostname) =>
        (await lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address),
      previousAddresses: expected,
      allowLocal: true,
    });
    return decision.allowed;
  };
  const successUrl = new RegExp(successUrlPattern);
  const results: ScenarioCheckResult[] = [];
  const runId = randomUUID();
  let executedCount = 0;
  try {
    await app.listen({ host: "127.0.0.1", port: state.port });
    for (const scenario of scenarios) {
      const browserSessionId = randomUUID();
      const token = await activation.issue(
        {
          projectId: state.projectId,
          runId,
          scenarioId: scenario.id,
          browserSessionId,
        },
        300,
      );
      const activationUrl = new URL(`/activate/${state.projectId}`, idpOrigin);
      activationUrl.searchParams.set("token", token);
      activationUrl.searchParams.set("browserSessionId", browserSessionId);
      const observation = await runWithPlaywright({
        activationUrl: activationUrl.toString(),
        loginUrl,
        acsUrl,
        allowedHosts,
        allowedOrigins,
        authorizeRequest,
        pinnedAddresses,
        successUrl,
        failureUrls: [/\/saml\/error(?:\?|$)/],
        spoofedIdentityToken: "chaos-spoofed-admin",
        ...(scenario.expectedOutcome === "reject" ? { strictReject: true } : {}),
        ...(successSelector ? { successSelector } : {}),
        timeoutMs: 30_000,
      });
      const status =
        observation.signal === "external_redirect"
          ? "failed"
          : statusFor(scenario.expectedOutcome, observation.outcome);
      const fingerprint = createHash("sha256")
        .update(`${scenario.catalogVersion}:${scenario.id}:${status}:${observation.signal}`)
        .digest("hex");
      results.push({
        scenarioId: scenario.id,
        catalogVersion: scenario.catalogVersion,
        status,
        expectedOutcome: scenario.expectedOutcome,
        ...(observation.finalUrl ? { observedUrl: observation.finalUrl } : {}),
        ...(observation.httpStatus === undefined ? {} : { httpStatus: observation.httpStatus }),
        signal: observation.signal,
        correlationId: randomUUID(),
        durationMs: observation.durationMs,
        retryCount: 0,
        ...(observation.issuedAt ? { issuedAt: observation.issuedAt } : {}),
        ...(observation.notBefore ? { notBefore: observation.notBefore } : {}),
        ...(observation.notOnOrAfter ? { notOnOrAfter: observation.notOnOrAfter } : {}),
        evidenceRefs: observation.screenshotHash ? [`sha256:${observation.screenshotHash}`] : [],
        remediation: scenario.remediation,
        fingerprint,
        severity: scenario.severity,
        cveRefs: [...scenario.cveRefs],
      });
      executedCount += 1;
      if (scenario.id === "SAML-BASE-001" && status !== "passed") break;
    }
  } finally {
    await app.close();
  }
  if (results.length < scenarios.length) {
    const completedScenarioIds = new Set(results.map((result) => result.scenarioId));
    for (const scenario of scenarios) {
      if (completedScenarioIds.has(scenario.id)) continue;
      results.push({
        scenarioId: scenario.id,
        catalogVersion: scenario.catalogVersion,
        status: "blocked",
        expectedOutcome: scenario.expectedOutcome,
        signal: "not_executed",
        correlationId: randomUUID(),
        durationMs: 0,
        retryCount: 0,
        evidenceRefs: [],
        remediation: scenario.remediation,
        fingerprint: createHash("sha256")
          .update(`${scenario.catalogVersion}:${scenario.id}:blocked:not_executed`)
          .digest("hex"),
        severity: scenario.severity,
        cveRefs: [...scenario.cveRefs],
      });
    }
  }
  const failThreshold = failOn === "critical" ? 3 : 2;
  const incomplete =
    results.length !== scenarios.length ||
    results.some(
      (result) =>
        result.status === "blocked" ||
        result.status === "error" ||
        (result.status === "inconclusive" && result.expectedOutcome !== "observe"),
    );
  const exitCode = results.some(
    (result) => result.status === "failed" && severityRank(result.severity) >= failThreshold,
  )
    ? 1
    : incomplete
      ? 2
      : 0;
  const markdown = summaryMarkdown(results);
  process.stdout.write(markdown);
  if (process.env.GITHUB_STEP_SUMMARY)
    await appendFile(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`);
  return { exitCode, executed: executedCount };
}

export async function runCliCommand(
  args: string[],
): Promise<CliResult | { metadata: string; out: string; entityId: string; ssoUrl: string }> {
  const [command, ...rest] = args;
  const options = parseOptions(rest);
  if (options.help || command === "--help" || command === undefined) {
    process.stdout.write(
      "Usage: saml-chaos-lab metadata --out <file> | test --login-url <url> --acs-url <url> --sp-entity-id <id> --success-url <pattern>\n",
    );
    return { exitCode: 0, executed: 0 };
  }
  if (command === "metadata") {
    const result = await writeMetadata({
      ...(typeof options.out === "string" ? { out: options.out } : {}),
      ...(typeof options["state-dir"] === "string" ? { stateDir: options["state-dir"] } : {}),
    });
    process.stdout.write(
      `EntityID: ${result.entityId}\nSSO Redirect URL: ${result.ssoUrl}\nMetadata: ${result.out}\n`,
    );
    return result;
  }
  if (command === "test") return runLocalTest(options);
  throw new Error(`unknown_command:${command}`);
}

export async function main(args: string[]) {
  try {
    const result = await runCliCommand(args);
    return "exitCode" in result ? result.exitCode : 0;
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "cli_error"}\n`);
    return 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exitCode = await main(process.argv.slice(2));
}
