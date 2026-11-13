import { randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import {
  createProjectCertificates,
  decryptPrivateKey,
  generateMetadata,
  type SigningMaterial,
} from "@saml-chaos/saml-core";
import { normalizeExactUrl, verifyDestination } from "@saml-chaos/target-safety";

export interface RunnerState {
  port: number;
  projectId: string;
  entityId: string;
  ssoUrl: string;
  current: SigningMaterial;
  next: SigningMaterial;
}

export interface ScenarioCheckResult {
  scenarioId: string;
  catalogVersion: string;
  status: "passed" | "failed" | "inconclusive" | "blocked" | "error";
  expectedOutcome: string;
  observedUrl?: string;
  httpStatus?: number;
  signal: string;
  issuedAt?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  correlationId: string;
  durationMs: number;
  retryCount: number;
  evidenceRefs: string[];
  remediation: string;
  fingerprint: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cveRefs: string[];
}

export async function pinTargetUrls(urls: string[]) {
  const pinned = new Map<string, string[]>();
  const resolveHost = async (hostname: string) =>
    (await lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address);
  for (const value of urls) {
    const normalized = normalizeExactUrl(value, true);
    const hostname = new URL(normalized).hostname.toLowerCase();
    const decision = await verifyDestination({
      candidateUrl: normalized,
      verifiedUrl: normalized,
      resolve: resolveHost,
      ...(pinned.has(hostname) ? { previousAddresses: pinned.get(hostname)! } : {}),
      allowLocal: true,
    });
    if (!decision.allowed || !decision.addresses?.length) {
      throw new Error(`blocked_target:${decision.reason ?? "unknown"}`);
    }
    const loopback = decision.addresses.find((address) => address === "127.0.0.1");
    pinned.set(
      hostname,
      loopback
        ? [loopback, ...decision.addresses.filter((address) => address !== loopback)]
        : decision.addresses,
    );
  }
  return pinned;
}

export function parseOptions(args: string[]): Record<string, string | boolean> {
  const options: Record<string, string | boolean> = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("--")) throw new Error(`unexpected_argument:${arg}`);
    const key = arg.slice(2);
    if (["help"].includes(key)) {
      options[key] = true;
      continue;
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing_option_value:${key}`);
    options[key] = value;
    index += 1;
  }
  return options;
}

export function optionString(
  options: Record<string, string | boolean>,
  key: string,
  fallback?: string,
) {
  const value = options[key];
  if (typeof value === "string") return value;
  if (fallback !== undefined) return fallback;
  throw new Error(`required_option_missing:${key}`);
}

export async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("ephemeral_port_unavailable");
  const port = address.port;
  await new Promise<void>((resolveClose, reject) =>
    server.close((error) => (error ? reject(error) : resolveClose())),
  );
  return port;
}

export async function readState(stateDir: string): Promise<RunnerState> {
  try {
    return JSON.parse(await readFile(resolve(stateDir, "runner.json"), "utf8")) as RunnerState;
  } catch {
    throw new Error("runner_metadata_missing: run `saml-chaos-lab metadata` first");
  }
}

export async function writeMetadata(options: { out?: string; stateDir?: string } = {}) {
  const stateDir = resolve(options.stateDir ?? ".saml-chaos-lab");
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const projectId = "local";
  const port = await reservePort();
  const entityId = `http://127.0.0.1:${port}/metadata/${projectId}`;
  const ssoUrl = `http://127.0.0.1:${port}/sso/${projectId}`;
  const masterKey = randomBytes(32);
  const certificates = await createProjectCertificates(projectId, masterKey);
  const current: SigningMaterial = {
    certificate: certificates.current.certificate,
    privateKey: decryptPrivateKey(certificates.current.encryptedPrivateKey, masterKey, projectId),
  };
  const next: SigningMaterial = {
    certificate: certificates.next.certificate,
    privateKey: decryptPrivateKey(certificates.next.encryptedPrivateKey, masterKey, projectId),
  };
  const state: RunnerState = {
    port,
    projectId,
    entityId,
    ssoUrl,
    current,
    next,
  };
  await writeFile(resolve(stateDir, "runner.json"), `${JSON.stringify(state, null, 2)}\n`, {
    mode: 0o600,
  });
  const metadata = generateMetadata({
    entityId,
    ssoUrl,
    certificates: [current.certificate, next.certificate],
  });
  const out = resolve(options.out ?? "./idp-metadata.xml");
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, metadata, "utf8");
  return { out, entityId, ssoUrl, metadata };
}

export function statusFor(
  expected: "accept" | "reject" | "observe",
  outcome: string,
): ScenarioCheckResult["status"] {
  if (outcome === "blocked") return "blocked";
  if (outcome === "error") return "error";
  if (outcome === "timeout" || outcome === "inconclusive") return "inconclusive";
  if (expected === "observe") return "passed";
  return (expected === "accept" && outcome === "success") ||
    (expected === "reject" && outcome === "rejected")
    ? "passed"
    : "failed";
}

export function severityRank(severity: string): number {
  return severity === "critical" ? 3 : severity === "high" ? 2 : severity === "medium" ? 1 : 0;
}
