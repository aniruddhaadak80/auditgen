import { type Collector, type CollectorResult, type TreeIndex } from "./types.js";
import { GITHUB_COLLECTORS } from "./github.js";
import { GIT_COLLECTORS } from "./git.js";
import { WEB_COLLECTORS } from "./web.js";

export * from "./types.js";
export { GITHUB_COLLECTORS } from "./github.js";
export { GIT_COLLECTORS } from "./git.js";
export { WEB_COLLECTORS, candidateBaseUrls, parseSecurityTxt } from "./web.js";
export { manualResultFor, MANUAL_SPECS, MANUAL_KEYS } from "./manual.js";

import type { GitHubClient } from "../util/github.js";

export const COLLECTORS: Collector[] = [
  ...GITHUB_COLLECTORS,
  ...GIT_COLLECTORS,
  ...WEB_COLLECTORS,
];

const BY_NAME = new Map(COLLECTORS.map((c) => [c.name, c]));

export function getCollector(name: string): Collector | undefined {
  return BY_NAME.get(name);
}

export function emptyTree(): TreeIndex {
  return {
    available: false,
    truncated: false,
    files: new Map(),
    has: () => false,
    find: () => [],
    blobUrl: () => undefined,
  };
}

/**
 * Builds the repository file index from one recursive tree request. Most
 * file-presence assertions in auditgen come from here, which is what keeps a
 * full audit to a handful of API calls.
 */
export async function buildTreeIndex(
  gh: GitHubClient,
  branch: string,
  onWarning?: (message: string) => void,
): Promise<TreeIndex> {
  const res = await gh.treeRecursive(branch);
  if (!res.ok || !res.data) {
    onWarning?.(
      `Repository tree unavailable (${res.reason ?? "unknown"}). File-presence checks will report as unverifiable.`,
    );
    return emptyTree();
  }
  const files = new Map<string, { sha: string; size?: number }>();
  for (const entry of res.data.tree ?? []) {
    if (entry.type !== "blob") continue;
    files.set(entry.path, { sha: entry.sha, ...(entry.size !== undefined ? { size: entry.size } : {}) });
  }
  if (res.data.truncated) {
    onWarning?.(
      "GitHub truncated the tree response (over 100k entries or 7MB). File-presence checks cover a subset of the repository.",
    );
  }
  const prefix = `https://github.com/`;
  return {
    available: true,
    truncated: Boolean(res.data.truncated),
    files,
    has: (...paths: string[]) => paths.some((p) => files.has(p)),
    find: (pred) => [...files.keys()].filter(pred).sort(),
    blobUrl: (path) => {
      const entry = files.get(path);
      if (!entry) return undefined;
      return `${prefix}${gh.owner}/${gh.repo}/blob/${branch}/${path}#L${entry.size ?? ""}`;
    },
  };
}

/**
 * Runs each collector at most once, regardless of how many controls reference
 * it, and returns the results keyed by collector name.
 */
export async function runCollectors(
  ctx: Parameters<Collector["run"]>[0],
  names: string[],
): Promise<Map<string, CollectorResult[]>> {
  const out = new Map<string, CollectorResult[]>();
  for (const name of [...new Set(names)]) {
    if (name === "manual") continue; // handled per control
    const collector = getCollector(name);
    if (!collector) {
      ctx.warnings.push(`No collector registered for "${name}".`);
      out.set(name, []);
      continue;
    }
    try {
      out.set(name, await collector.run(ctx));
    } catch (err) {
      ctx.warnings.push(
        `Collector "${name}" failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      out.set(name, [
        {
          title: `Collector "${name}" failed before producing evidence`,
          passed: false,
          source: "internal",
          details: { error: String(err).slice(0, 300) },
          unverifiable: true,
          gaps: ["This control could not be evaluated. Fix the collector error and re-run."],
        },
      ]);
    }
  }
  return out;
}