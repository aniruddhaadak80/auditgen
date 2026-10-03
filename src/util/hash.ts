import { createHash } from "node:crypto";

/**
 * Deterministic JSON serialization.
 *
 * Key order must not affect the output, otherwise an evidence record could be
 * re-serialized with its keys shuffled and appear as a different record in the
 * chain. Arrays keep their order because it is meaningful.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return "null";
    return JSON.stringify(value);
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`)
      .join(",")}}`;
  }
  return JSON.stringify(String(value));
}

export function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Fields of an evidence record that participate in its hash. */
export interface HashableEvidence {
  controlId: string;
  collector: string;
  title: string;
  observedAt: string;
  source: string;
  passed: boolean;
  details: Record<string, unknown>;
  excerpt?: string;
}

export function hashEvidence(
  record: HashableEvidence & { hash?: string; prevHash?: string },
  prevHash: string,
): { hash: string; prevHash: string } {
  // Only the evidence fields participate. Anything already attached to the
  // record (including its own digest) is excluded, so re-verifying a stored
  // record reproduces the original digest rather than hashing it recursively.
  const payload: HashableEvidence = {
    controlId: record.controlId,
    collector: record.collector,
    title: record.title,
    observedAt: record.observedAt,
    source: record.source,
    passed: record.passed,
    details: record.details,
    ...(record.excerpt !== undefined ? { excerpt: record.excerpt } : {}),
  };
  const digest = sha256(canonicalize({ ...payload, prevHash }) + prevHash);
  return { hash: digest, prevHash };
}

export const GENESIS = "genesis";

/**
 * Walks records in order, linking each to the previous one, and returns the
 * records with hashes attached plus the resulting chain head.
 */
export function chainEvidence<T extends HashableEvidence>(
  records: T[],
): { records: (T & { hash: string; prevHash: string })[]; root: string } {
  let prev = GENESIS;
  const out: (T & { hash: string; prevHash: string })[] = [];
  for (const record of records) {
    const { hash, prevHash } = hashEvidence(record, prev);
    out.push({ ...record, hash, prevHash });
    prev = hash;
  }
  return { records: out, root: prev };
}

/** Re-derives the chain and reports the first index where it diverges. */
export function verifyChain(
  records: (HashableEvidence & { hash: string; prevHash: string })[],
): { valid: boolean; brokenAt: number | null; root: string } {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const record = records[i]!;
    const { hash, prevHash } = hashEvidence(record, prev);
    if (record.prevHash !== prevHash || record.hash !== hash) {
      return { valid: false, brokenAt: i, root: prev };
    }
    prev = record.hash;
  }
  return { valid: true, brokenAt: null, root: prev };
}