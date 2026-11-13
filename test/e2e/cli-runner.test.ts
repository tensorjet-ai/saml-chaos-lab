import { execFile } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildFixtureSp } from "../../fixtures/vulnerable-sp/src/app.js";
import { runLocalTest } from "../../packages/cli/src/index.js";

describe("local OSS CLI runner", () => {
  const stateDir = resolve(tmpdir(), `saml-chaos-oss-cli-${Date.now()}`);
  let workspaceDir = "";
  let fixture: ReturnType<typeof buildFixtureSp> | undefined;
  let fixturePort = 0;

  beforeAll(async () => {
    workspaceDir = await mkdtemp(resolve(tmpdir(), "saml-chaos-oss-cli-"));
    const metadataFile = resolve(workspaceDir, "idp-metadata.xml");
    await promisify(execFile)(process.execPath, [
      resolve("packages/cli/bin/saml-chaos-lab.mjs"),
      "metadata",
      "--state-dir",
      stateDir,
      "--out",
      metadataFile,
    ]);
    const state = JSON.parse(await readFile(resolve(stateDir, "runner.json"), "utf8")) as {
      entityId: string;
      ssoUrl: string;
      current: { certificate: string };
      next: { certificate: string };
    };
    const portServer = createServer();
    await new Promise<void>((resolveListen, reject) => {
      portServer.once("error", reject);
      portServer.listen(0, "127.0.0.1", resolveListen);
    });
    const address = portServer.address();
    if (!address || typeof address === "string") throw new Error("fixture_port_unavailable");
    fixturePort = address.port;
    await new Promise<void>((resolveClose, reject) =>
      portServer.close((error) => (error ? reject(error) : resolveClose())),
    );
    const acsUrl = `http://127.0.0.1:${fixturePort}/saml/acs`;
    fixture = buildFixtureSp({
      spEntityId: "urn:cli:fixture:sp",
      idpEntityId: state.entityId,
      idpSsoUrl: state.ssoUrl,
      acsUrl,
      trustedCertificates: async () => [state.current.certificate, state.next.certificate],
    });
    fixture.get("/external-redirect", (_request, reply) => reply.redirect("http://127.0.0.1:1/"));
    await fixture.listen({ host: "127.0.0.1", port: fixturePort });
    expect(await readFile(metadataFile, "utf8")).toContain("EntityDescriptor");
  });

  afterAll(async () => {
    await fixture?.close();
    await Promise.all([
      rm(stateDir, { recursive: true, force: true }),
      rm(workspaceDir, { recursive: true, force: true }),
    ]);
  });

  it("runs all six baseline checks and fails closed on inconclusive or external-redirect baselines", async () => {
    const common = {
      "login-url": `http://127.0.0.1:${fixturePort}/login`,
      "acs-url": `http://127.0.0.1:${fixturePort}/saml/acs`,
      "sp-entity-id": "urn:cli:fixture:sp",
      "success-url": "^http://127\\.0\\.0\\.1:[0-9]+/success$",
      "state-dir": stateDir,
      "fail-on": "critical",
    };
    const free = await runLocalTest(common);
    expect(free).toEqual({ exitCode: 0, executed: 6 });

    const incomplete = await runLocalTest({
      ...common,
      "success-url": "^https://never-matches.invalid/$",
    });
    expect(incomplete).toEqual({ exitCode: 2, executed: 1 });

    const redirected = await runLocalTest({
      ...common,
      "login-url": `http://127.0.0.1:${fixturePort}/external-redirect`,
    });
    expect(redirected).toEqual({ exitCode: 2, executed: 1 });
  }, 180_000);
});
