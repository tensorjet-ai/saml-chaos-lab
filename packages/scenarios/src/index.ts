import {
  generateResponse,
  type GeneratedResponse,
  type ResponsePlan,
  type SigningMaterial,
} from "@saml-chaos/saml-core";

export type FreeScenarioId =
  | "SAML-BASE-001"
  | "SAML-TIME-001"
  | "SAML-AUD-001"
  | "SAML-DEST-001"
  | "SAML-ISS-001"
  | "SAML-SIG-001";

export type ScenarioId = FreeScenarioId;
export type Severity = "critical" | "high" | "medium" | "info";

export interface ScenarioDefinition {
  id: ScenarioId;
  catalogVersion: "2.0.0";
  tier: "free";
  cveRefs: readonly string[];
  name: string;
  expectedOutcome: "accept" | "reject" | "observe";
  severity: Severity;
  remediation: string;
}

const define = (
  id: ScenarioId,
  name: string,
  expectedOutcome: ScenarioDefinition["expectedOutcome"],
  severity: Severity,
  remediation: string,
): ScenarioDefinition => ({
  id,
  name,
  expectedOutcome,
  severity,
  remediation,
  catalogVersion: "2.0.0",
  tier: "free",
  cveRefs: [],
});

export const scenarioCatalog: ScenarioDefinition[] = [
  define(
    "SAML-BASE-001",
    "Valid baseline response",
    "accept",
    "info",
    "Verify baseline SAML login succeeds before running negative checks.",
  ),
  define(
    "SAML-TIME-001",
    "Expired assertion",
    "reject",
    "critical",
    "Enforce Conditions NotOnOrAfter with documented bounded clock skew.",
  ),
  define(
    "SAML-AUD-001",
    "Wrong audience",
    "reject",
    "critical",
    "Match Audience exactly to SP entity ID.",
  ),
  define(
    "SAML-DEST-001",
    "Wrong response destination",
    "reject",
    "critical",
    "Match Response Destination exactly to ACS URL.",
  ),
  define(
    "SAML-ISS-001",
    "Wrong issuer",
    "reject",
    "critical",
    "Pin and verify trusted IdP issuer.",
  ),
  define(
    "SAML-SIG-001",
    "Post-signature mutation",
    "reject",
    "critical",
    "Validate XML signature and reference before consuming assertion fields.",
  ),
];

export interface CertificateSet {
  current: SigningMaterial;
  next: SigningMaterial;
}

export interface BuiltScenario {
  plan: ResponsePlan;
  mutations: string[];
  postSign?: "tamper";
}

export function buildScenarioPlan(
  id: string,
  base: ResponsePlan,
  _certificates: CertificateSet,
): BuiltScenario {
  const now = base.now ?? new Date();
  const plan: ResponsePlan = {
    ...base,
    attributes: structuredClone(base.attributes),
  };
  const mutations: string[] = [];
  switch (id as ScenarioId) {
    case "SAML-BASE-001":
      break;
    case "SAML-TIME-001":
      plan.conditionsNotOnOrAfter = new Date(now.getTime() - 5 * 60_000);
      mutations.push("expired");
      break;
    case "SAML-AUD-001":
      plan.audience = "urn:saml-chaos:wrong-audience";
      mutations.push("wrong_audience");
      break;
    case "SAML-DEST-001":
      plan.responseDestination = "https://invalid.example/wrong-destination";
      mutations.push("wrong_destination");
      break;
    case "SAML-ISS-001":
      plan.issuer = "https://invalid.example/wrong-issuer";
      mutations.push("wrong_issuer");
      break;
    case "SAML-SIG-001":
      return { plan, mutations: ["post_signature_tamper"], postSign: "tamper" };
    default:
      throw new Error("unknown_scenario");
  }
  return { plan, mutations };
}

export interface RenderedScenario extends GeneratedResponse {
  scenarioId: string;
  mutations: string[];
  deliveryDestination: string;
  relayState?: string;
}

export function renderScenario(
  id: string,
  base: ResponsePlan,
  certificates: CertificateSet,
): RenderedScenario {
  const built = buildScenarioPlan(id, base, certificates);
  const generated = generateResponse(built.plan);
  const xml =
    built.postSign === "tamper"
      ? generated.xml.replace(base.nameId, "tampered-user@invalid.example")
      : generated.xml;
  return {
    ...generated,
    xml,
    scenarioId: id,
    mutations: built.mutations,
    deliveryDestination: base.destination,
  };
}
