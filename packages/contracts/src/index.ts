import { z } from "zod";
import safeRegex from "safe-regex2";

export type RunState =
  | "created"
  | "validating_target"
  | "queued"
  | "running_baseline"
  | "running_scenarios"
  | "generating_report"
  | "completed"
  | "failed"
  | "cancelled"
  | "blocked";

export function canTransition(_from: RunState, _to: RunState): boolean {
  const next: Partial<Record<RunState, RunState>> = {
    created: "validating_target",
    validating_target: "queued",
    queued: "running_baseline",
    running_baseline: "running_scenarios",
    running_scenarios: "generating_report",
    generating_report: "completed",
  };
  const terminal: RunState[] = ["failed", "cancelled", "blocked"];
  const active: RunState[] = [
    "created",
    "validating_target",
    "queued",
    "running_baseline",
    "running_scenarios",
    "generating_report",
  ];
  return next[_from] === _to || (active.includes(_from) && terminal.includes(_to));
}

const redirectHostSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(1)
  .max(253)
  .refine((value) => {
    try {
      const url = new URL(`https://${value}`);
      return (
        !url.username &&
        !url.password &&
        !url.port &&
        url.pathname === "/" &&
        !url.search &&
        !url.hash
      );
    } catch {
      return false;
    }
  }, "invalid redirect hostname");

export const ProjectConfigSchema = z
  .object({
    displayName: z.string().trim().min(1).max(100),
    spEntityId: z.string().trim().min(1).max(2048),
    loginStartUrl: z.url(),
    acsUrl: z.url(),
    successUrlPattern: z.string().min(1).max(1024),
    successSelector: z.string().max(512).optional(),
    failureUrlPatterns: z.array(z.string().max(1024)).max(20).default([]),
    nameIdFormat: z.string().min(1).max(512),
    syntheticNameId: z.string().min(1).max(512),
    attributes: z.record(z.string().max(128), z.array(z.string().max(1024)).max(20)).default({}),
    allowedRedirectHosts: z.array(redirectHostSchema).min(1).max(20),
    environment: z.literal("staging"),
    safetyAcknowledged: z.literal(true),
    retentionDays: z.number().int().min(1).max(90).default(30),
  })
  .superRefine((value, context) => {
    for (const [index, pattern] of [
      value.successUrlPattern,
      ...value.failureUrlPatterns,
    ].entries()) {
      try {
        const expression = new RegExp(pattern);
        if (!safeRegex(expression)) throw new Error("unsafe regular expression");
      } catch {
        context.addIssue({
          code: "custom",
          path: index === 0 ? ["successUrlPattern"] : ["failureUrlPatterns", index - 1],
          message: "invalid or unsafe regular expression",
        });
      }
    }
  });
export type ProjectConfig = z.infer<typeof ProjectConfigSchema>;

const normalizeHost = (value: string): string =>
  value
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");

/** Distinct hostnames a run will actually contact, derived from the project config. */
export function distinctConfigHosts(config: {
  loginStartUrl: string;
  acsUrl: string;
  allowedRedirectHosts: string[];
}): string[] {
  const hosts = new Set<string>();
  try {
    hosts.add(normalizeHost(new URL(config.loginStartUrl).hostname));
  } catch {
    // Validation upstream guarantees parseable URLs; skip defensively.
  }
  try {
    hosts.add(normalizeHost(new URL(config.acsUrl).hostname));
  } catch {
    // See above.
  }
  for (const host of config.allowedRedirectHosts) hosts.add(normalizeHost(host));
  return [...hosts].filter((host) => host.length > 0).sort();
}

export const ScenarioResultSchema = z.object({
  scenarioId: z.string(),
  catalogVersion: z.string(),
  status: z.enum(["passed", "failed", "inconclusive", "blocked", "error"]),
  expectedOutcome: z.string(),
  observedUrl: z.string().optional(),
  httpStatus: z.number().int().optional(),
  signal: z.string(),
  certificateId: z.string().optional(),
  issuedAt: z.iso.datetime().optional(),
  notBefore: z.iso.datetime().optional(),
  notOnOrAfter: z.iso.datetime().optional(),
  correlationId: z.string(),
  durationMs: z.number().nonnegative(),
  retryCount: z.number().int().nonnegative(),
  evidenceRefs: z.array(z.string()),
  remediation: z.string(),
  fingerprint: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
});
