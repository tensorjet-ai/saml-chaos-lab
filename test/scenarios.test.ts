import { describe, expect, it } from "vitest";
import {
  generateSigningMaterial,
  verifyXmlSignature,
  type ResponsePlan,
} from "@saml-chaos/saml-core";
import { buildScenarioPlan, renderScenario, scenarioCatalog } from "@saml-chaos/scenarios";

const current = generateSigningMaterial();
const next = generateSigningMaterial();
const base: ResponsePlan = {
  issuer: "https://idp.example/metadata/p1",
  requestId: "_request",
  destination: "https://sp.example/saml/acs",
  audience: "urn:sp",
  nameId: "synthetic@invalid.example",
  nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  attributes: { role: ["tester"] },
  signing: current,
  now: new Date("2026-07-16T00:00:00Z"),
};

describe("open-core baseline scenario catalog", () => {
  it("contains six deterministic baseline scenarios", () => {
    expect(scenarioCatalog).toHaveLength(6);
    expect(new Set(scenarioCatalog.map((item) => item.id)).size).toBe(6);
    expect(scenarioCatalog.every((item) => item.catalogVersion === "2.0.0")).toBe(true);
    expect(scenarioCatalog.every((item) => item.tier === "free")).toBe(true);
  });

  it.each([
    ["SAML-TIME-001", "expired"],
    ["SAML-AUD-001", "wrong_audience"],
    ["SAML-DEST-001", "wrong_destination"],
    ["SAML-ISS-001", "wrong_issuer"],
  ])("applies only declared pre-sign mutation for %s", (id, mutation) => {
    const built = buildScenarioPlan(id, base, { current, next });
    expect(built.mutations).toEqual([mutation]);
  });

  it("produces valid baseline and invalid post-sign tamper mutation", () => {
    const baseline = renderScenario("SAML-BASE-001", base, { current, next });
    const tampered = renderScenario("SAML-SIG-001", base, { current, next });
    expect(verifyXmlSignature(baseline.xml, current.certificate)).toBe(true);
    expect(verifyXmlSignature(tampered.xml, current.certificate)).toBe(false);
  });

  it("expires TIME-001 beyond the documented two-minute clock-skew boundary", () => {
    const built = buildScenarioPlan("SAML-TIME-001", base, { current, next });
    expect(built.plan.conditionsNotOnOrAfter?.getTime()).toBeLessThanOrEqual(
      base.now!.getTime() - 5 * 60_000,
    );
  });
});
