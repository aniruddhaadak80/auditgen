import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import type { Declarations, RepoTarget } from "./types.js";

export const CONFIG_FILENAMES = ["auditgen.json", "auditgen.jsonc"];

export interface AuditgenConfig extends Declarations {
  /** Repositories to audit, when auditing several from one config. */
  repositories?: string[];
  /** Default frameworks when none are passed on the command line. */
  frameworks?: ("soc2" | "iso27001")[];
  /** Merged PRs to sample when checking review practice. */
  samplePullRequests?: number;
  /** Path for generated documents. */
  outputDir?: string;
}

/** Finds the nearest config by walking up from startDir. */
export function findConfigFile(startDir: string): string | undefined {
  let dir = resolve(startDir);
  const { root } = parse(dir);
  for (;;) {
    for (const name of CONFIG_FILENAMES) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    if (dir === root) return undefined;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export function loadConfigFile(path: string): AuditgenConfig {
  const raw = readFileSync(path, "utf8");
  const stripped = path.endsWith(".jsonc")
    ? raw
        .replace(/^\s*\/\/.*$/gm, "")
        // Removes /* ... */ blocks that do not sit inside a string literal.
        .replace(/\/\*[\s\S]*?\*\//g, "")
    : raw;
  const parsed = JSON.parse(stripped) as AuditgenConfig;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${path}: expected a JSON object`);
  }
  return parsed;
}

export function loadDeclarations(startDir: string): {
  declarations: Declarations;
  config: AuditgenConfig;
  path?: string;
} {
  const path = findConfigFile(startDir);
  if (!path) return { declarations: {}, config: {} };
  const config = loadConfigFile(path);
  return { declarations: config, config, path };
}

/**
 * Resolves owner/repo from a git remote. Handles the three shapes that matter:
 *   https://github.com/owner/repo.git
 *   git@github.com:owner/repo.git
 *   ssh://git@github.com/owner/repo
 */
export function parseGitHubRemote(
  remote: string,
): { owner: string; repo: string } | undefined {
  const cleaned = remote.trim();
  const patterns = [
    /github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/i,
    /github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/i,
  ];
  for (const re of patterns) {
    const m = re.exec(cleaned);
    if (m?.[1] && m?.[2]) {
      return { owner: m[1], repo: m[2].replace(/\.git$/i, "") };
    }
  }
  return undefined;
}

export function readOriginRemote(cwd: string): string | undefined {
  try {
    return execFileSync("git", ["remote", "get-url", "origin"], {
      cwd,
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
    }).trim();
  } catch {
    return undefined;
  }
}

export function resolveTarget(cwd: string): RepoTarget | undefined {
  const remote = readOriginRemote(cwd);
  if (!remote) return undefined;
  const parsed = parseGitHubRemote(remote);
  if (!parsed) return undefined;
  return {
    owner: parsed.owner,
    repo: parsed.repo,
    localPath: resolve(cwd),
  };
}

/** Splits an "owner/repo" or GitHub URL into its parts. */
export function parseRepoSpec(spec: string): { owner: string; repo: string } {
  const trimmed = spec.trim().replace(/\/+$/, "");
  const direct = parseGitHubRemote(trimmed);
  if (direct) return direct;
  const parts = trimmed.split("/").filter(Boolean);
  if (parts.length >= 2) {
    const owner = parts[parts.length - 2]!;
    const repo = parts[parts.length - 1]!.replace(/\.git$/i, "");
    return { owner, repo };
  }
  throw new Error(`Cannot parse repository from "${spec}". Expected owner/repo.`);
}