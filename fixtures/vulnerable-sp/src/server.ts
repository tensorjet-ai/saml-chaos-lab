import { buildFixtureSp } from "./app.js";

const metadataUrl = process.env.IDP_METADATA_URL ?? "http://localhost:3001/metadata/fixture";
async function trustedCertificates(): Promise<string[]> {
  const response = await fetch(metadataUrl, {
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error("metadata_unavailable");
  const xml = await response.text();
  return [...xml.matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map(
    (match) =>
      `-----BEGIN CERTIFICATE-----\n${match[1]!.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----`,
  );
}
async function resolveIdp(projectId: string) {
  const internalUrl = `http://idp:3001/metadata/${encodeURIComponent(projectId)}`;
  const response = await fetch(internalUrl, {
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error("metadata_unavailable");
  const xml = await response.text();
  const entityId = xml.match(/entityID="([^"]+)"/)?.[1];
  const ssoUrl = xml.match(/SingleSignOnService[^>]+Location="([^"]+)"/)?.[1];
  if (!entityId || !ssoUrl) throw new Error("metadata_invalid");
  return {
    entityId,
    ssoUrl,
    trustedCertificates: async () =>
      [...xml.matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map(
        (match) =>
          `-----BEGIN CERTIFICATE-----\n${match[1]!.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----`,
      ),
  };
}
const app = buildFixtureSp({
  spEntityId: process.env.SP_ENTITY_ID ?? "urn:fixture:sp",
  idpEntityId: process.env.IDP_ENTITY_ID ?? "http://localhost:3001/metadata/fixture",
  idpSsoUrl: process.env.IDP_SSO_URL ?? "http://localhost:3001/sso/fixture",
  acsUrl: process.env.ACS_URL ?? "http://localhost:4000/saml/acs",
  trustedCertificates,
  resolveIdp,
});
await app.listen({ host: "0.0.0.0", port: Number(process.env.PORT ?? 4000) });
