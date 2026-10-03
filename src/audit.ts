import {
  AUDITGEN_VERSION,
  type AuditOptions,
  type Framework,
  type Report,
} from "./types.js";
import type { AuditgenConfig } from "./config.js";
import { controlsFor, collectorsNeeded } from "./controls/index.js";
import {
  buildTreeIndex,
  emptyTree,
  runCollectors,
} from "./collectors/index.js";
import type { CollectorContext } from "./collectors/types.js";
import { GitHubClient, resolveToken } from "./util/github.js";
import { evaluate, summarize } from "./engine/evaluate.js";
import { enrichFindings } from "./engine/judge.js";
import { parseGitHubRemote, readOriginRemote } from "./config.js";

export interface AuditRun {
  report: Report;
  /** Non-fatal notes about the AI narrative pass, not part of the report. */
  judgeNote?: string;
}

/**
 * Guards against the most damaging failure mode available to this tool:
 * reporting that the wrong repository is clean.
 *
 * A caller may pass owner/repo explicitly while standing in some unrelated
 * checkout. Running the local git collectors in that case would produce a
 * confident "no committed credentials found" about a repository that was never
 * examined. If the local directory's origin does not match the target, the local
 * path is discarded rather than silently scanned.
 */
export function reconcileLocalPath(
  target: AuditOptions["target"],
): { localPath?: string; mismatch?: string } {
  const { localPath, owner, repo } = target;
  if (!localPath) return {};
  const remote = readOriginRemote(localPath);
  if (!remote) {
    return {
      mismatch: `Local path ${localPath} has no origin remote, so local history checks were skipped rather than run against an unverified directory.`,
    };
  }
  const parsed = parseGitHubRemote(remote);
  if (!parsed) {
    return {
      mismatch: `Origin "${remote}" is not a GitHub remote, so local history checks were skipped for ${owner}/${repo}.`,
    };
  }
  if (
    parsed.owner.toLowerCase() !== owner.toLowerCase() ||
    parsed.repo.toLowerCase() !== repo.toLowerCase()
  ) {
    return {
      mismatch: `Local checkout is ${parsed.owner}/${parsed.repo} but the audit target is ${owner}/${repo}. Local history checks were skipped to avoid reporting on the wrong repository.`,
    };
  }
  return { localPath };
}

/**
 * Runs a full audit.
 *
 * Collection order matters: the tree index is built once and shared, because
 * most collectors answer from it, and building it after the collectors would mean
 * every one of them fetching it separately.
 */
export async function runAudit(
  options: AuditOptions,
  config: AuditgenConfig = {},
): Promise<AuditRun> {
  const started = Date.now();
  const warnings: string[] = [];

  const frameworks: Framework[] = options.frameworks.length
    ? options.frameworks
    : (config.frameworks ?? ["soc2"]);

  let selected = controlsFor(frameworks);
  if (options.onlyControls?.length) {
    const wanted = new Set(options.onlyControls.map((c) => c.toUpperCase()));
    selected = selected.filter((c) => wanted.has(c.id.toUpperCase()));
    if (selected.length === 0) {
      throw new Error(
        `No controls matched --only ${options.onlyControls.join(",")}. Known controls: ${controlsFor(frameworks)
          .map((c) => c.id)
          .join(", ")}`,
      );
    }
  }

  const token = resolveToken(options.token);
  const offline = Boolean(options.offline) || !token;
  if (offline) {
    warnings.push(
      "No GitHub token available. GitHub-hosted controls are reported as unverifiable; only local repository controls were evaluated.",
    );
  }

  const gh = new GitHubClient(options.target.owner, options.target.repo, token);
  let defaultBranch = options.target.defaultBranch ?? "main";
  let tree = emptyTree();

  if (!offline) {
    const resolved = await gh.defaultBranch();
    if (resolved) defaultBranch = resolved;
    tree = await buildTreeIndex(gh, defaultBranch, (m) => warnings.push(m));
  }

  const { localPath, mismatch } = reconcileLocalPath(options.target);
  if (mismatch) warnings.push(mismatch);

  const ctx: CollectorContext = {
    gh,
    target: { ...options.target, ...(localPath ? { localPath } : {}) },
    defaultBranch,
    ...(localPath ? { localPath } : {}),
    declarations: { ...config },
    warnings,
    offline,
    tree,
  };

  const needed = collectorsNeeded(selected).filter(
    (name: string) =>
      name !== "manual" && !options.skipCollectors?.includes(name),
  );

  const resultsByCollector = await runCollectors(ctx, needed);

  const observedAt = new Date().toISOString();
  const { findings, evidence, evidenceRoot } = evaluate({
    controls: selected,
    resultsByCollector,
    ctx,
    observedAt,
  });

  let judgeNote: string | undefined;
  if (options.noAi) {
    judgeNote = "AI narrative disabled (--no-ai).";
  } else {
    // Prose pass is optional and works offline against a local endpoint. It
    // must never be able to change a status.
    const result = await enrichFindings(findings, {
      ...(options.aiBaseUrl ? { baseUrl: options.aiBaseUrl } : {}),
      ...(options.aiApiKey ? { apiKey: options.aiApiKey } : {}),
      ...(options.aiModel ? { model: options.aiModel } : {}),
    });
    if (result.error) judgeNote = result.error;
    else if (result.skippedReason) judgeNote = result.skippedReason;
    else if (result.applied > 0) {
      judgeNote = `Narrative generated for ${result.applied} finding(s) using ${result.model}.`;
    }
  }

  return {
    report: {
      schemaVersion: 1,
      generatedAt: observedAt,
      generator: { name: "auditgen", version: AUDITGEN_VERSION },
      target: { ...options.target, defaultBranch },
      frameworks,
      findings,
      summary: summarize(findings),
      evidenceRoot,
      warnings,
      durationMs: Date.now() - started,
    },
    ...(judgeNote ? { judgeNote } : {}),
  };
}

export { emptyTree };