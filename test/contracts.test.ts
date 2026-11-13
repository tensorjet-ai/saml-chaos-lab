import { describe, expect, it } from "vitest";
import { canTransition, ProjectConfigSchema } from "@saml-chaos/contracts";

describe("run state machine", () => {
  it("allows only ordered progress and active-state terminal transitions", () => {
    expect(canTransition("created", "validating_target")).toBe(true);
    expect(canTransition("running_baseline", "running_scenarios")).toBe(true);
    expect(canTransition("running_baseline", "failed")).toBe(true);
    expect(canTransition("completed", "running_scenarios")).toBe(false);
    expect(canTransition("created", "completed")).toBe(false);
  });
});

describe("project URL signals", () => {
  const project = {
    displayName: "Fixture staging",
    spEntityId: "urn:fixture:sp",
    loginStartUrl: "https://sp.example/login",
    acsUrl: "https://sp.example/saml/acs",
    successUrlPattern: "^https://sp\\.example/success$",
    failureUrlPatterns: ["/saml/error$"],
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    syntheticNameId: "synthetic-user@invalid.example",
    attributes: {},
    allowedRedirectHosts: ["sp.example"],
    environment: "staging" as const,
    safetyAcknowledged: true as const,
    retentionDays: 30,
  };

  it("rejects catastrophic success and failure regular expressions", () => {
    expect(
      ProjectConfigSchema.safeParse({
        ...project,
        successUrlPattern: "^(a+)+$",
      }).success,
    ).toBe(false);
    expect(
      ProjectConfigSchema.safeParse({
        ...project,
        failureUrlPatterns: ["(a|a?)+$"],
      }).success,
    ).toBe(false);
  });

  it("rejects redirect host entries containing URL components", () => {
    for (const host of ["sp.example?next=evil", "sp.example#fragment"]) {
      expect(
        ProjectConfigSchema.safeParse({
          ...project,
          allowedRedirectHosts: [host],
        }).success,
      ).toBe(false);
    }
  });
});
