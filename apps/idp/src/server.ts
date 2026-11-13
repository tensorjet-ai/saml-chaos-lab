import { ActivationService } from "@saml-chaos/browser-runner";
import {
  createProjectCertificates,
  decryptPrivateKeyWith,
  masterKeyDecryptAdapter,
  type KeyDecryptAdapter,
  type SigningMaterial,
  type StoredCertificate,
} from "@saml-chaos/saml-core";
import { buildIdp, type IdpProject } from "./app.js";
import { resolveMasterKey } from "./config.js";

const projectId = process.env.FIXTURE_PROJECT_ID ?? "fixture";
const baseUrl = process.env.PUBLIC_BASE_URL ?? "http://localhost:3001";
const masterKey = resolveMasterKey(process.env.MASTER_KEY_BASE64, false);
const decryptKey: KeyDecryptAdapter = masterKeyDecryptAdapter(masterKey);
const material = async (stored: StoredCertificate, id = projectId): Promise<SigningMaterial> => ({
  certificate: stored.certificate,
  privateKey: await decryptPrivateKeyWith(decryptKey, stored.encryptedPrivateKey, id),
});

const fixtureBundle = await createProjectCertificates(projectId, masterKey);
const fixtureProject: IdpProject = {
  id: projectId,
  entityId: `${baseUrl}/metadata/${projectId}`,
  ssoUrl: `${baseUrl}/sso/${projectId}`,
  spEntityId: process.env.FIXTURE_SP_ENTITY_ID ?? "urn:fixture:sp",
  acsUrl: process.env.FIXTURE_ACS_URL ?? "http://localhost:4000/saml/acs",
  nameId: "synthetic-user@invalid.example",
  nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  attributes: { role: ["tester"], environment: ["synthetic"] },
  current: await material(fixtureBundle.current),
  next: await material(fixtureBundle.next),
  nextCertificate: fixtureBundle.next.certificate,
};

const activationSecret = Buffer.from(
  process.env.ACTIVATION_SECRET ?? "local-development-activation-secret-32-bytes",
);
const app = await buildIdp({
  projects: new Map([[fixtureProject.id, fixtureProject]]),
  logger: true,
  activationService: new ActivationService(
    activationSecret.byteLength >= 32
      ? activationSecret
      : Buffer.from(activationSecret.toString("utf8").padEnd(32, "0")),
  ),
});

const port = Number(process.env.PORT ?? 3001);
await app.listen({ host: "0.0.0.0", port });
