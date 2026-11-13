import "reflect-metadata";
import {
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  webcrypto,
} from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { DOMParser } from "@xmldom/xmldom";
import { PemConverter, X509CertificateGenerator, cryptoProvider } from "@peculiar/x509";
import { XMLParser, XMLValidator } from "fast-xml-parser";
import { SignedXml } from "xml-crypto";

export interface SigningMaterial {
  privateKey: string;
  certificate: string;
}

export interface EncryptedPrivateKey {
  version: 1;
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface StoredCertificate {
  id: string;
  certificate: string;
  encryptedPrivateKey: EncryptedPrivateKey;
  notBefore: string;
  notAfter: string;
}

export interface ProjectCertificates {
  current: StoredCertificate;
  next: StoredCertificate;
}

function requireMasterKey(masterKey: Buffer): void {
  if (masterKey.length !== 32) throw new Error("master_key_must_be_32_bytes");
}

export function encryptPrivateKey(
  privateKey: string,
  masterKey: Buffer,
  projectId: string,
): EncryptedPrivateKey {
  requireMasterKey(masterKey);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey, iv);
  cipher.setAAD(Buffer.from(projectId));
  const ciphertext = Buffer.concat([cipher.update(privateKey, "utf8"), cipher.final()]);
  return {
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

export function decryptPrivateKey(
  encrypted: EncryptedPrivateKey,
  masterKey: Buffer,
  projectId: string,
): string {
  requireMasterKey(masterKey);
  if (encrypted.version !== 1) throw new Error("unsupported_key_envelope");
  const decipher = createDecipheriv("aes-256-gcm", masterKey, Buffer.from(encrypted.iv, "base64"));
  decipher.setAAD(Buffer.from(projectId));
  decipher.setAuthTag(Buffer.from(encrypted.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

/**
 * Seam for external key services (KMS, HSM). The default adapter unwraps the
 * AES-256-GCM envelope locally; hosted deployments can replace it without
 * touching signing code.
 */
export type KeyDecryptAdapter = (
  encrypted: EncryptedPrivateKey,
  projectId: string,
) => Promise<string>;

export function masterKeyDecryptAdapter(masterKey: Buffer): KeyDecryptAdapter {
  requireMasterKey(masterKey);
  return async (encrypted, projectId) => decryptPrivateKey(encrypted, masterKey, projectId);
}

export async function decryptPrivateKeyWith(
  adapter: KeyDecryptAdapter,
  encrypted: EncryptedPrivateKey,
  projectId: string,
): Promise<string> {
  return adapter(encrypted, projectId);
}

async function createStoredCertificate(
  projectId: string,
  masterKey: Buffer,
  label: string,
): Promise<StoredCertificate> {
  cryptoProvider.set(webcrypto as unknown as Crypto);
  const keys = (await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 366 * 24 * 60 * 60 * 1000);
  const certificate = await X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: randomBytes(16).toString("hex"),
      name: `CN=SAML Chaos Lab ${projectId} ${label}`,
      notBefore,
      notAfter,
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      keys,
    },
    webcrypto as unknown as Crypto,
  );
  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  const privateKey = PemConverter.encode(pkcs8, "PRIVATE KEY");
  return {
    id: randomUUID(),
    certificate: certificate.toString("pem"),
    encryptedPrivateKey: encryptPrivateKey(privateKey, masterKey, projectId),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  };
}

export async function createProjectCertificates(
  projectId: string,
  masterKey: Buffer,
): Promise<ProjectCertificates> {
  requireMasterKey(masterKey);
  const [current, next] = await Promise.all([
    createStoredCertificate(projectId, masterKey, "current"),
    createStoredCertificate(projectId, masterKey, "next"),
  ]);
  return { current, next };
}

export function generateSigningMaterial(): SigningMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKey, certificate: publicKey };
}

const C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

export function signXml(xml: string, material: SigningMaterial, referenceXPath: string): string {
  const signature = new SignedXml({
    privateKey: material.privateKey,
    publicCert: material.certificate,
    canonicalizationAlgorithm: C14N,
    signatureAlgorithm: RSA_SHA256,
  });
  signature.addReference({
    xpath: referenceXPath,
    transforms: [ENVELOPED, C14N],
    digestAlgorithm: SHA256,
  });
  signature.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='Issuer']", action: "after" },
  });
  return signature.getSignedXml();
}

export function verifyXmlSignature(xml: string, certificate: string): boolean {
  try {
    const document = new DOMParser().parseFromString(xml, "application/xml");
    const node = document
      .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature")
      .item(0);
    if (!node) return false;
    const verifier = new SignedXml({ publicCert: certificate });
    verifier.loadSignature(node as unknown as Parameters<typeof verifier.loadSignature>[0]);
    return verifier.checkSignature(xml);
  } catch {
    return false;
  }
}

function xmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function certificateBody(certificate: string): string {
  return certificate.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
}

export function generateMetadata(options: {
  entityId: string;
  ssoUrl: string;
  certificates: string[];
}): string {
  const keys = options.certificates
    .map(
      (certificate) =>
        `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certificateBody(certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join("");
  return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${xmlEscape(options.entityId)}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false">${keys}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${xmlEscape(options.ssoUrl)}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

export interface ParsedAuthnRequest {
  id: string;
  issuer: string;
  acsUrl: string;
  destination: string;
  relayState: string;
}

export interface AuthnRequestBinding {
  expectedEntityId: string;
  verifiedAcsUrl: string;
  expectedDestination: string;
  maxCompressedBytes?: number;
  maxInflatedBytes?: number;
}

export function parseRedirectAuthnRequest(
  encoded: string,
  relayState: string,
  binding: AuthnRequestBinding,
): ParsedAuthnRequest {
  if (relayState.length > 1024) throw new Error("relay_state_too_large");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error("invalid_base64");
  const compressed = Buffer.from(encoded, "base64");
  if (compressed.length > (binding.maxCompressedBytes ?? 128 * 1024))
    throw new Error("request_too_large");
  let xml: string;
  try {
    xml = inflateRawSync(compressed, {
      maxOutputLength: binding.maxInflatedBytes ?? 256 * 1024,
    }).toString("utf8");
  } catch {
    throw new Error("invalid_compression");
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("xml_declaration_forbidden");
  if (XMLValidator.validate(xml) !== true) throw new Error("malformed_xml");
  const document = new DOMParser().parseFromString(xml, "application/xml");
  const root = document.documentElement;
  if (
    !root ||
    root.localName !== "AuthnRequest" ||
    root.namespaceURI !== "urn:oasis:names:tc:SAML:2.0:protocol"
  ) {
    throw new Error("invalid_root");
  }
  if (root.getAttribute("Version") !== "2.0") throw new Error("invalid_version");
  const parsed = new XMLParser({
    ignoreAttributes: false,
    removeNSPrefix: true,
    processEntities: false,
    parseTagValue: false,
    trimValues: true,
  }).parse(xml) as Record<string, unknown>;
  const request = parsed.AuthnRequest as Record<string, unknown> | undefined;
  if (!request) throw new Error("invalid_root");
  const issuerValue = request.Issuer;
  const issuer = typeof issuerValue === "string" ? issuerValue : undefined;
  const id = request["@_ID"];
  const acsUrl = request["@_AssertionConsumerServiceURL"];
  const destination = request["@_Destination"];
  if (![id, acsUrl, destination].every((value) => typeof value === "string") || !issuer)
    throw new Error("missing_required_field");
  if (issuer !== binding.expectedEntityId) throw new Error("issuer_mismatch");
  if (acsUrl !== binding.verifiedAcsUrl) throw new Error("acs_mismatch");
  if (destination !== binding.expectedDestination) throw new Error("destination_mismatch");
  return {
    id: id as string,
    issuer,
    acsUrl: acsUrl as string,
    destination: destination as string,
    relayState,
  };
}

export interface ResponsePlan {
  issuer: string;
  requestId: string;
  destination: string;
  audience: string;
  nameId: string;
  nameIdFormat: string;
  attributes: Record<string, string[]>;
  signing: SigningMaterial;
  now?: Date;
  validitySeconds?: number;
  conditionsNotBefore?: Date;
  conditionsNotOnOrAfter?: Date;
  responseDestination?: string;
  recipient?: string;
  unsigned?: boolean;
}

export interface GeneratedResponse {
  responseId: string;
  assertionId: string;
  sessionId: string;
  xml: string;
  issuedAt: string;
  notBefore: string;
  notOnOrAfter: string;
}

export function generateResponse(plan: ResponsePlan): GeneratedResponse {
  const now = plan.now ?? new Date();
  const validitySeconds = plan.validitySeconds ?? 300;
  const responseId = `_${randomUUID()}`;
  const assertionId = `_${randomUUID()}`;
  const sessionId = `_${randomUUID()}`;
  const issuedAt = now.toISOString();
  const notBefore = (plan.conditionsNotBefore ?? new Date(now.getTime() - 30_000)).toISOString();
  const notOnOrAfter = (
    plan.conditionsNotOnOrAfter ?? new Date(now.getTime() + validitySeconds * 1000)
  ).toISOString();
  const responseDestination = plan.responseDestination ?? plan.destination;
  const recipient = plan.recipient ?? plan.destination;
  const attributes = Object.entries(plan.attributes)
    .map(
      ([name, values]) =>
        `<saml:Attribute Name="${xmlEscape(name)}">${values.map((value) => `<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema">${xmlEscape(value)}</saml:AttributeValue>`).join("")}</saml:Attribute>`,
    )
    .join("");
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${issuedAt}"><saml:Issuer>${xmlEscape(plan.issuer)}</saml:Issuer><saml:Subject><saml:NameID Format="${xmlEscape(plan.nameIdFormat)}">${xmlEscape(plan.nameId)}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${xmlEscape(plan.requestId)}" Recipient="${xmlEscape(recipient)}" NotOnOrAfter="${notOnOrAfter}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${xmlEscape(plan.audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${issuedAt}" SessionIndex="${sessionId}" SessionNotOnOrAfter="${notOnOrAfter}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>${attributes}</saml:AttributeStatement></saml:Assertion>`;
  const signedAssertion = plan.unsigned
    ? assertion
    : signXml(assertion, plan.signing, "//*[local-name(.)='Assertion']");
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${responseId}" Version="2.0" IssueInstant="${issuedAt}" Destination="${xmlEscape(responseDestination)}" InResponseTo="${xmlEscape(plan.requestId)}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${xmlEscape(plan.issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${signedAssertion}</samlp:Response>`;
  return {
    responseId,
    assertionId,
    sessionId,
    xml,
    issuedAt,
    notBefore,
    notOnOrAfter,
  };
}

export function autoPostForm(
  destination: string,
  responseXml: string,
  relayState: string,
  nonce = randomBytes(18).toString("base64url"),
): string {
  const response = Buffer.from(responseXml).toString("base64");
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; form-action ${xmlEscape(destination)}; script-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'"></head><body><form id="saml" method="post" action="${xmlEscape(destination)}"><input type="hidden" name="SAMLResponse" value="${response}"><input type="hidden" name="RelayState" value="${xmlEscape(relayState)}"><noscript><button type="submit">Continue</button></noscript></form><script nonce="${nonce}">document.getElementById('saml').submit()</script></body></html>`;
}
