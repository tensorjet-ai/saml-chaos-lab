import { randomUUID } from "node:crypto";

export const correlationHeader = "x-correlation-id";
export function correlationId(value?: string): string {
  return value && /^[a-zA-Z0-9_-]{8,128}$/.test(value) ? value : randomUUID();
}

const secretKeys = /samlresponse|cookie|authorization|activation|private.?key|email/i;
export function redactRequestUrl(value: string): string {
  try {
    const url = new URL(value, "http://redaction.invalid");
    return `${url.pathname}${url.search ? "?[REDACTED]" : ""}`;
  } catch {
    return "[REDACTED_URL]";
  }
}

function redactString(value: string): string {
  let output = value.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[REDACTED_EMAIL]");
  output = output.replace(
    /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g,
    "[REDACTED_PRIVATE_KEY]",
  );
  try {
    const url = new URL(output);
    for (const key of url.searchParams.keys()) url.searchParams.set(key, "[REDACTED]");
    output = url.toString();
  } catch {
    // Non-URL strings are returned after pattern redaction.
  }
  return output;
}
export function redact(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        secretKeys.test(key) ? "[REDACTED]" : redact(item),
      ]),
    );
  }
  return value;
}

export interface AuditEvent {
  id: string;
  eventType: string;
  metadata: Readonly<Record<string, unknown>>;
  createdAt: string;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    Object.freeze(value);
    for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  }
  return value;
}

export class AuditLog {
  private readonly events: AuditEvent[] = [];
  constructor(private readonly now: () => Date = () => new Date()) {}
  record(eventType: string, metadata: Record<string, unknown>): AuditEvent {
    const event = deepFreeze({
      id: randomUUID(),
      eventType,
      metadata: redact(structuredClone(metadata)) as Record<string, unknown>,
      createdAt: this.now().toISOString(),
    });
    this.events.push(event);
    return event;
  }
  list(): readonly AuditEvent[] {
    return deepFreeze(structuredClone(this.events));
  }
}

interface ExpiringRecord {
  id: string;
  expiresAt: Date;
}
interface AuditRecord {
  id: string;
  createdAt: Date;
}
export function cleanupExpiredRecords<
  T extends ExpiringRecord,
  R extends ExpiringRecord,
  A extends AuditRecord,
>(input: { now: Date; evidence: T[]; reports: R[]; audit: A[] }) {
  const active = <V extends ExpiringRecord>(records: V[]) =>
    records.filter((item) => item.expiresAt > input.now);
  return {
    evidence: active(input.evidence),
    reports: active(input.reports),
    audit: [...input.audit],
  };
}

const allowedMetricLabels = new Set(["reason", "class", "operation", "status", "scenario"]);
const histogramDefaultBucketsMs = [1_000, 5_000, 15_000, 60_000, 300_000, 900_000];
export class OperationalMetrics {
  private readonly values = new Map<string, number>();
  private readonly histograms = new Map<
    string,
    { buckets: number[]; counts: number[]; sum: number; count: number }
  >();
  private key(name: string, labels: Record<string, string>): string {
    if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error("invalid_metric_name");
    for (const [label, value] of Object.entries(labels)) {
      if (!allowedMetricLabels.has(label)) throw new Error("metric_label_not_allowed");
      if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(value)) throw new Error("invalid_metric_label");
    }
    const suffix = Object.entries(labels)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([label, value]) => `${label}="${value}"`)
      .join(",");
    return suffix ? `${name}{${suffix}}` : name;
  }
  increment(name: string, labels: Record<string, string> = {}, amount = 1): void {
    if (!Number.isFinite(amount) || amount < 0) throw new Error("invalid_metric_value");
    const key = this.key(name, labels);
    this.values.set(key, (this.values.get(key) ?? 0) + amount);
  }
  set(name: string, value: number, labels: Record<string, string> = {}): void {
    if (!Number.isFinite(value)) throw new Error("invalid_metric_value");
    this.values.set(this.key(name, labels), value);
  }
  observe(name: string, valueMs: number, labels: Record<string, string> = {}): void {
    if (!Number.isFinite(valueMs) || valueMs < 0) throw new Error("invalid_metric_value");
    const base = this.key(name, labels);
    let histogram = this.histograms.get(base);
    if (!histogram) {
      histogram = {
        buckets: histogramDefaultBucketsMs,
        counts: new Array(histogramDefaultBucketsMs.length + 1).fill(0),
        sum: 0,
        count: 0,
      };
      this.histograms.set(base, histogram);
    }
    let index = histogram.buckets.findIndex((bucket) => valueMs <= bucket);
    if (index === -1) index = histogram.buckets.length;
    histogram.counts[index] = (histogram.counts[index] ?? 0) + 1;
    histogram.sum += valueMs;
    histogram.count += 1;
  }
  render(): string {
    const lines: string[] = [];
    for (const [key, value] of [...this.values.entries()].sort(([left], [right]) =>
      left.localeCompare(right),
    )) {
      lines.push(`${key} ${value}`);
    }
    for (const [base, histogram] of [...this.histograms.entries()].sort(([left], [right]) =>
      left.localeCompare(right),
    )) {
      const [name, labelPart] = base.includes("{")
        ? [base.slice(0, base.indexOf("{")), base.slice(base.indexOf("{") + 1, base.length - 1)]
        : [base, ""];
      const withLabel = (extra: string) => (labelPart ? `{${labelPart},${extra}}` : `{${extra}}`);
      for (let index = 0; index < histogram.buckets.length; index += 1) {
        const cumulative = histogram.counts
          .slice(0, index + 1)
          .reduce((sum, count) => sum + count, 0);
        lines.push(`${name}_bucket${withLabel(`le="${histogram.buckets[index]}"`)} ${cumulative}`);
      }
      lines.push(`${name}_bucket${withLabel('le="+Inf"')} ${histogram.count}`);
      lines.push(`${name}_sum${labelPart ? `{${labelPart}}` : ""} ${histogram.sum}`);
      lines.push(`${name}_count${labelPart ? `{${labelPart}}` : ""} ${histogram.count}`);
    }
    return lines.join("\n") + "\n";
  }
}
