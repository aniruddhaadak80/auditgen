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

/**
 * Removes JSONC comments without touching string contents.
 *
 * A naive regular-expression strip corrupts every URL and date in the file,
 * because both contain a double slash. This walks the text tracking whether it
 * is inside a string literal, which is the only correct way to do it.
 */
export function stripJsonComments(input: string): string {
  let out = "";
  let inString = false;
  let escaped = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    const next = input[i + 1];

    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      while (i < input.length && input[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < input.length && !(input[i] === "*" && input[i + 1] === "/")) {
        if (input[i] === "\n") out += "\n";
        i++;
      }
      i++; // land on the closing '*'
      continue;
    }
    out += ch;
  }
  return out;
}

export function loadConfigFile(path: string): AuditgenConfig {
  const raw = readFileSync(path, "utf8");
  // Strip a UTF-8 BOM. Windows PowerShell 5.1 writes one by default for
  // Set-Content and Out-File -Encoding utf8, and JSON.parse rejects U+FEFF, so a
  // config written from the most common shell on Windows would fail to load.
  const withoutBom = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  const stripped = path.endsWith(".jsonc")
    ? stripJsonComments(withoutBom)
    : withoutBom;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripped);
  } catch (err) {
    throw new Error(
      `${path}: invalid JSON. ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${path}: expected a JSON object`);
  }
  return parsed as AuditgenConfig;
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