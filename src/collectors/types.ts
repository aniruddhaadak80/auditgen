import type { Declarations, RepoTarget } from "../types.js";
import type { GitHubClient } from "../util/github.js";

export type { Declarations, RepoTarget } from "../types.js";

export const EMPTY_DECLARATIONS: Declarations = {};

export interface CollectorContext {
  gh: GitHubClient;
  target: RepoTarget;
  defaultBranch: string;
  /** Absolute local path, when the repository is present on disk. */
  localPath?: string;
  declarations: Declarations;
  /** Collectors push non-fatal problems here. */
  warnings: string[];
  /** True when no GitHub token is available. */
  offline: boolean;
  /** Repository file index, built once from a single recursive tree request. */
  tree: TreeIndex;
}

/** Paths present on the default branch, keyed by exact path. */
export interface TreeIndex {
  available: boolean;
  truncated: boolean;
  files: Map<string, { sha: string; size?: number }>;
  has(...paths: string[]): boolean;
  /** Every path matching a predicate. */
  find(pred: (path: string) => boolean): string[];
  blobUrl(path: string): string | undefined;
}

export interface CollectorResult {
  /** Verbatim assertion an auditor can read. */
  title: string;
  passed: boolean;
  /** URL or path the reviewer opens independently. */
  source: string;
  details: Record<string, unknown>;
  excerpt?: string;
  /** True when the assertion rests on operator attestation, not observation. */
  declared?: boolean;
  /** True when the underlying signal is not observable through any API. */
  unverifiable?: boolean;
  /** Shortfalls contributed to the finding's gap list. */
  gaps?: string[];
  /**
   * Advisory remarks that are not shortfalls. A satisfied operator attestation
   * still carries a note telling the reader to attach the source document, and
   * that note must not be allowed to downgrade the status to partial.
   */
  notes?: string[];
}

export interface Collector {
  name: string;
  /**
   * Collectors are run once and their results attributed to every control that
   * references them. A single observation of "CODEOWNERS is present and binds
   * CI config to two owners" legitimately supports A.5.15, A.8.3 and CC6.2
   * without three identical API round trips.
   */
  run(ctx: CollectorContext): Promise<CollectorResult[]>;
}

/** Convenience for a single-assertion collector. */
export function one(result: CollectorResult): CollectorResult[] {
  return [result];
}