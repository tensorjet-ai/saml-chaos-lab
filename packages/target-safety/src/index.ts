import { isIP } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { request as httpsRequest, type RequestOptions } from "node:https";

export interface DestinationDecision {
  allowed: boolean;
  normalizedUrl?: string;
  addresses?: string[];
  reason?: string;
}

export interface DestinationOptions {
  candidateUrl: string;
  verifiedUrl: string;
  resolve: (hostname: string) => Promise<string[]>;
  previousAddresses?: string[];
  allowLocal?: boolean;
}

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, part) => (value << 8) + Number(part), 0) >>> 0;
}

function inV4Range(address: string, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(base) & mask);
}

function ipv6Number(address: string): bigint | undefined {
  let normalized = address.toLowerCase().split("%")[0] ?? address;
  const dottedIndex = normalized.lastIndexOf(":");
  const dotted = normalized.slice(dottedIndex + 1);
  if (dotted.includes(".")) {
    if (isIP(dotted) !== 4) return undefined;
    const value = ipv4Number(dotted);
    normalized = `${normalized.slice(0, dottedIndex)}:${(value >>> 16).toString(16)}:${(
      value & 0xffff
    ).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return undefined;
  const parts = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (parts.length !== 8 || parts.some((part) => !/^[a-f0-9]{1,4}$/.test(part))) return undefined;
  return parts.reduce((value, part) => (value << 16n) | BigInt(`0x${part}`), 0n);
}

function inV6Range(address: string, base: string, bits: number): boolean {
  const value = ipv6Number(address);
  const baseValue = ipv6Number(base);
  if (value === undefined || baseValue === undefined) return false;
  const shift = BigInt(128 - bits);
  return value >> shift === baseValue >> shift;
}

export function classifyIp(address: string): "public" | "blocked" {
  const normalized = address.toLowerCase().split("%")[0] ?? address;
  if (normalized.startsWith("::ffff:")) return classifyIp(normalized.slice(7));
  const version = isIP(normalized);
  if (version === 4) {
    const blocked = [
      ["0.0.0.0", 8],
      ["10.0.0.0", 8],
      ["100.64.0.0", 10],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
      ["172.16.0.0", 12],
      ["192.0.0.0", 24],
      ["192.0.2.0", 24],
      ["192.168.0.0", 16],
      ["198.18.0.0", 15],
      ["198.51.100.0", 24],
      ["203.0.113.0", 24],
      ["224.0.0.0", 4],
      ["240.0.0.0", 4],
    ] as const;
    return blocked.some(([base, bits]) => inV4Range(normalized, base, bits)) ? "blocked" : "public";
  }
  if (version === 6) {
    const numeric = ipv6Number(normalized);
    if (numeric === undefined) return "blocked";
    const prefix96 = numeric >> 32n;
    if (prefix96 === 0xffffn) {
      const embedded = Number(numeric & 0xffffffffn);
      return classifyIp(
        [embedded >>> 24, (embedded >>> 16) & 0xff, (embedded >>> 8) & 0xff, embedded & 0xff].join(
          ".",
        ),
      );
    }
    // IPv4-compatible IPv6 addresses are deprecated and can be interpreted as IPv4 by peers.
    if (prefix96 === 0n) return "blocked";
    // IANA currently allocates global unicast addresses only from 2000::/3.
    if (!inV6Range(normalized, "2000::", 3)) return "blocked";
    const blocked = [
      ["::", 128],
      ["::1", 128],
      ["100::", 64],
      ["64:ff9b::", 96],
      ["64:ff9b:1::", 48],
      ["2001::", 32],
      ["2001:2::", 48],
      ["2001:10::", 28],
      ["2001:20::", 28],
      ["2001:db8::", 32],
      ["2002::", 16],
      ["3fff::", 20],
      ["fc00::", 7],
      ["fe80::", 10],
      ["fec0::", 10],
      ["ff00::", 8],
    ] as const;
    return blocked.some(([base, bits]) => inV6Range(normalized, base, bits)) ? "blocked" : "public";
  }
  return "blocked";
}

function isLoopbackAddress(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized.startsWith("::ffff:")) return isLoopbackAddress(normalized.slice(7));
  return normalized === "::1" || (isIP(normalized) === 4 && inV4Range(normalized, "127.0.0.0", 8));
}

function isLocalDevelopmentHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized === "host.docker.internal" ||
    isLoopbackAddress(normalized)
  );
}

export function normalizeExactUrl(value: string, allowLocal = false): string {
  const url = new URL(value);
  if (
    url.protocol !== "https:" &&
    !(allowLocal && url.protocol === "http:" && isLocalDevelopmentHostname(url.hostname))
  )
    throw new Error("https_required");
  if (url.username || url.password) throw new Error("credentials_forbidden");
  if (url.hash) throw new Error("fragment_forbidden");
  if (!url.hostname || url.hostname.endsWith(".")) throw new Error("invalid_hostname");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(hostname) && !(allowLocal && isLoopbackAddress(hostname)))
    throw new Error("ip_literal_forbidden");
  if (!allowLocal && (hostname === "localhost" || hostname.endsWith(".localhost")))
    throw new Error("localhost_forbidden");
  return url.toString();
}

function sameAddresses(left: string[], right: string[]): boolean {
  return [...new Set(left)].sort().join(",") === [...new Set(right)].sort().join(",");
}

export async function verifyDestination(options: DestinationOptions): Promise<DestinationDecision> {
  let candidate: string;
  let verified: string;
  try {
    candidate = normalizeExactUrl(options.candidateUrl, options.allowLocal);
    verified = normalizeExactUrl(options.verifiedUrl, options.allowLocal);
  } catch (error) {
    return {
      allowed: false,
      reason: error instanceof Error ? error.message : "invalid_url",
    };
  }
  if (candidate !== verified) return { allowed: false, reason: "exact_url_mismatch" };
  const hostname = new URL(candidate).hostname;
  const localException = options.allowLocal && isLocalDevelopmentHostname(hostname);
  let first: string[];
  try {
    first = await options.resolve(hostname);
  } catch {
    return { allowed: false, reason: "dns_error" };
  }
  if (first.length === 0) return { allowed: false, reason: "dns_empty" };
  if (first.some((address) => classifyIp(address) === "blocked") && !localException) {
    return { allowed: false, reason: "blocked_ip" };
  }
  if (options.previousAddresses && !sameAddresses(first, options.previousAddresses)) {
    return { allowed: false, reason: "dns_rebinding" };
  }
  let second: string[];
  try {
    second = await options.resolve(hostname);
  } catch {
    return { allowed: false, reason: "dns_error" };
  }
  if (!sameAddresses(first, second)) return { allowed: false, reason: "dns_rebinding" };
  if (second.some((address) => classifyIp(address) === "blocked") && !localException) {
    return { allowed: false, reason: "blocked_ip" };
  }
  return {
    allowed: true,
    normalizedUrl: candidate,
    addresses: [...new Set(second)].sort(),
  };
}

export function buildPinnedHttpsRequestOptions(value: string, address: string): RequestOptions {
  const url = new URL(value);
  if (url.protocol !== "https:") throw new Error("https_required");
  if (!isIP(address)) throw new Error("invalid_pinned_address");
  const servername = url.hostname.replace(/^\[|\]$/g, "");
  return {
    protocol: "https:",
    hostname: address,
    port: url.port || 443,
    path: `${url.pathname}${url.search}`,
    method: "GET",
    servername,
    rejectUnauthorized: true,
    headers: { host: url.host, accept: "text/plain" },
  };
}

export async function fetchPinnedHttpsText(
  value: string,
  address: string,
  options: { timeoutMs?: number; maxBytes?: number } = {},
): Promise<string> {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maxBytes = options.maxBytes ?? 4_096;
  const requestOptions = buildPinnedHttpsRequestOptions(value, address);
  return new Promise<string>((resolve, reject) => {
    const request = httpsRequest(
      { ...requestOptions, signal: AbortSignal.timeout(timeoutMs) },
      (response) => {
        const status = response.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          response.resume();
          reject(new Error("verification_http_error"));
          return;
        }
        const contentLength = Number(response.headers["content-length"] ?? 0);
        if (Number.isFinite(contentLength) && contentLength > maxBytes) {
          response.destroy(new Error("verification_body_too_large"));
          reject(new Error("verification_body_too_large"));
          return;
        }
        const chunks: Buffer[] = [];
        let received = 0;
        response.on("data", (chunk: Buffer | string) => {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          received += buffer.length;
          if (received > maxBytes) {
            response.destroy(new Error("verification_body_too_large"));
            return;
          }
          chunks.push(buffer);
        });
        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      },
    );
    request.on("error", reject);
    request.end();
  });
}

export type OwnershipMethod = "dns_txt" | "https";
export interface OwnershipChallenge {
  id: string;
  projectId: string;
  hostname: string;
  method: OwnershipMethod;
  token: string;
  recordName?: string;
  wellKnownUrl?: string;
  expiresAt: number;
  consumed: boolean;
}

/** Persistence contract so challenges survive restarts and work across replicas. */
export interface OwnershipChallengeStore {
  saveOwnershipChallenge(challenge: OwnershipChallenge): Promise<void>;
  getOwnershipChallenge(challengeId: string): Promise<OwnershipChallenge | undefined>;
  markOwnershipChallengeConsumed(challengeId: string, consumed: boolean): Promise<void>;
  replaceOwnershipChallengesForHost(projectId: string, hostname: string): Promise<void>;
  deleteExpiredOwnershipChallenges(now: number): Promise<void>;
}

export class OwnershipVerificationService {
  private readonly challenges = new Map<string, OwnershipChallenge>();
  constructor(
    private readonly now: () => number = Date.now,
    private readonly allowLocal = false,
    private readonly store?: OwnershipChallengeStore,
  ) {}
  private cleanupExpired(): void {
    const current = this.now();
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt <= current) this.challenges.delete(id);
    }
  }
  get challengeCount(): number {
    return this.challenges.size;
  }
  create(
    projectId: string,
    hostname: string,
    method: OwnershipMethod,
    ttlSeconds = 900,
  ): Promise<OwnershipChallenge> {
    const normalized = hostname.toLowerCase().replace(/\.$/, "");
    if (!normalized || (!this.allowLocal && normalized === "localhost") || isIP(normalized))
      throw new Error("invalid_verification_hostname");
    const token = randomBytes(24).toString("base64url");
    const challenge: OwnershipChallenge = {
      id: randomUUID(),
      projectId,
      hostname: normalized,
      method,
      token,
      expiresAt: this.now() + ttlSeconds * 1000,
      consumed: false,
      ...(method === "dns_txt"
        ? { recordName: `_saml-chaos-challenge.${normalized}` }
        : {
            wellKnownUrl: `https://${normalized}/.well-known/saml-chaos/${token}`,
          }),
    };
    if (!this.store) {
      this.cleanupExpired();
      // One live challenge per (project, host): replace only that host's prior challenge.
      for (const [id, existing] of this.challenges) {
        if (existing.projectId === projectId && existing.hostname === normalized) {
          this.challenges.delete(id);
        }
      }
      this.challenges.set(challenge.id, challenge);
      return Promise.resolve(structuredClone(challenge));
    }
    return (async () => {
      await this.store!.replaceOwnershipChallengesForHost(projectId, normalized);
      await this.store!.saveOwnershipChallenge(challenge);
      return structuredClone(challenge);
    })();
  }
  async verify(
    challengeId: string,
    adapters: {
      lookupTxt: (recordName: string) => Promise<string[][]>;
      fetchText: (url: string) => Promise<string>;
    },
    commit?: (result: {
      verified: true;
      projectId: string;
      hostname: string;
      verifiedAt: number;
    }) => Promise<void>,
  ): Promise<{
    verified: true;
    projectId: string;
    hostname: string;
    verifiedAt: number;
  }> {
    let challenge: OwnershipChallenge | undefined;
    let memoryChallenge: OwnershipChallenge | undefined;
    if (this.store) {
      challenge = await this.store.getOwnershipChallenge(challengeId);
    } else {
      this.cleanupExpired();
      memoryChallenge = this.challenges.get(challengeId);
      challenge = memoryChallenge;
    }
    if (!challenge) throw new Error("challenge_not_found");
    if (challenge.consumed) throw new Error("challenge_consumed");
    if (challenge.expiresAt <= this.now()) {
      if (!this.store) this.challenges.delete(challengeId);
      throw new Error("challenge_expired");
    }
    if (this.store) {
      await this.store.markOwnershipChallengeConsumed(challengeId, true);
    } else if (memoryChallenge) {
      memoryChallenge.consumed = true;
    }
    try {
      let valid = false;
      if (this.allowLocal && isLocalDevelopmentHostname(challenge.hostname)) {
        valid = true;
      } else if (challenge.method === "dns_txt") {
        const records = await adapters.lookupTxt(challenge.recordName!);
        valid = records.some((parts) => parts.join("") === challenge.token);
      } else {
        valid = (await adapters.fetchText(challenge.wellKnownUrl!)).trim() === challenge.token;
      }
      if (!valid) throw new Error("challenge_mismatch");
      if (!this.store && memoryChallenge && this.challenges.get(challengeId) !== memoryChallenge) {
        throw new Error("challenge_replaced");
      }
      const result = {
        verified: true as const,
        projectId: challenge.projectId,
        hostname: challenge.hostname,
        verifiedAt: this.now(),
      };
      await commit?.(result);
      return result;
    } catch (error) {
      if (this.store) {
        await this.store.markOwnershipChallengeConsumed(challengeId, false).catch(() => undefined);
      } else if (memoryChallenge) {
        memoryChallenge.consumed = false;
      }
      throw error;
    }
  }
}
