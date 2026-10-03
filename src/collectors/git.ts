import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import {
  type Collector,
  type CollectorContext,
  type CollectorResult,
  one,
} from "./types.js";

const run = promisify(execFile);

const GIT_TIMEOUT_MS = 120_000;

async function git(
  cwd: string,
  args: string[],
  maxBuffer = 32 * 1024 * 1024,
): Promise<{ stdout: string; stderr: string }> {
  return run("git", args, {
    cwd,
    maxBuffer,
    timeout: GIT_TIMEOUT_MS,
    windowsHide: true,
  });
}

async function isGitRepo(path: string): Promise<boolean> {
  try {
    const { stdout } = await git(path, ["rev-parse", "--is-inside-work-tree"]);
    return stdout.trim() === "true";
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// git.commit_signatures  ->  A.8.25
// ---------------------------------------------------------------------------

/**
 * `%G?` is git's own signature verdict:
 *   G good | B bad | U good, unknown validity | X expired key
 *   Y expired key | R revoked key | E cannot check (no key) | N unsigned
 */
const VERDICT: Record<string, string> = {
  G: "good",
  B: "bad",
  U: "goodWithUnknownValidity",
  X: "goodButExpired",
  Y: "goodButExpiredKey",
  R: "goodButRevokedKey",
  E: "cannotCheck",
  N: "unsigned",
};

export const commitSignaturesCollector: Collector = {
  name: "git.commit_signatures",
  async run(ctx) {
    if (!ctx.localPath || !(await isGitRepo(ctx.localPath))) {
      return one({
        title: "Commit history is not available locally",
        passed: false,
        source: ctx.localPath ?? "(no local path)",
        details: { reason: "not a git repository" },
        unverifiable: true,
        gaps: [
          "Clone the repository with full history and re-run so change attribution can be verified.",
        ],
      });
    }

    let log: string;
    try {
      log = (
        await git(ctx.localPath, [
          "log",
          "--no-merges",
          "--pretty=format:%H%x1f%G?%x1f%an%x1f%ae%x1f%aI%x1f%s",
        ])
      ).stdout;
    } catch (err) {
      return one({
        title: "Commit history could not be read",
        passed: false,
        source: ctx.localPath,
        details: { error: String(err).slice(0, 300) },
        unverifiable: true,
        gaps: ["Ensure the clone includes full history rather than a shallow copy."],
      });
    }

    const lines = log.split("\n").filter(Boolean);
    const total = lines.length;

    if (total === 0) {
      return one({
        title: "No commits found",
        passed: false,
        source: ctx.localPath,
        details: { totalCommits: 0 },
        gaps: ["Nothing to verify; a repository needs a commit history."],
      });
    }

    const verdicts: Record<string, number> = {};
    const authors = new Set<string>();
    const unsignedSubjects: { sha: string; subject: string; author: string }[] = [];
    const unverifiableCount: { sha: string; subject: string; author: string }[] = [];

    for (const line of lines) {
      const [sha, rawVerdict, name, email, iso, subject] = line.split("\x1f");
      if (!sha) continue;
      authors.add(`${name} <${email}>`);
      const verdict = VERDICT[rawVerdict ?? ""] ?? `unknown(${rawVerdict})`;
      verdicts[verdict] = (verdicts[verdict] ?? 0) + 1;
      if (verdict === "unsigned" && unsignedSubjects.length < 15) {
        unsignedSubjects.push({ sha: sha.slice(0, 12), subject: subject ?? "", author: name ?? "" });
      }
      if (verdict === "cannotCheck" && unverifiableCount.length < 15) {
        unverifiableCount.push({ sha: sha.slice(0, 12), subject: subject ?? "", author: name ?? "" });
      }
    }

    const signed = (verdicts["good"] ?? 0) + (verdicts["goodWithUnknownValidity"] ?? 0);
    const unsigned = verdicts["unsigned"] ?? 0;
    const bad = (verdicts["bad"] ?? 0) + (verdicts["goodButRevokedKey"] ?? 0);
    const cannotCheck = verdicts["cannotCheck"] ?? 0;
    const signedShare = signed / total;

    const gaps: string[] = [];
    if (unsigned > 0) {
      gaps.push(
        `${unsigned} of ${total} commits are unsigned (${((unsigned / total) * 100).toFixed(1)}%). Enforce signing so every change carries non-repudiable attribution.`,
      );
    }
    if (bad > 0) {
      gaps.push(
        `${bad} commit(s) carry an invalid or revoked signature. Treat those changes as unattributed and investigate.`,
      );
    }
    if (cannotCheck > 0) {
      gaps.push(
        `${cannotCheck} commit(s) cannot be verified because the signing key is unavailable. Publish the public key so verifiers can check the signature.`,
      );
    }
    if (signedShare < 0.9 && unsigned === 0 && cannotCheck === 0) {
      gaps.push("Signature coverage is below 90%; raise it before the audit window.");
    }

    return one({
      title:
        unsigned === 0 && bad === 0
          ? `All ${total} commits carry a valid signature`
          : `${signed} of ${total} commits carry a valid signature`,
      passed: unsigned === 0 && bad === 0 && signedShare >= 0.9,
      source: `${ctx.localPath} (git log --pretty=%G?)`,
      details: {
        totalCommits: total,
        signedShare: Number(signedShare.toFixed(4)),
        verdictCounts: verdicts,
        distinctAuthors: authors.size,
        authors: [...authors].slice(0, 20),
        unsignedSamples: unsignedSubjects,
        unverifiableSamples: unverifiableCount,
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// git.secret_history  ->  CC6.7, A.8.12
// ---------------------------------------------------------------------------

interface SecretRule {
  id: string;
  label: string;
  re: RegExp;
}

/**
 * High-precision patterns only. A scanner that cries wolf gets disabled, and a
 * disabled scanner is a worse outcome than an absent one.
 */
const SECRET_RULES: SecretRule[] = [
  { id: "aws-access-key", label: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "github-pat-classic", label: "GitHub classic PAT", re: /\bghp_[A-Za-z0-9]{36}\b/g },
  { id: "github-pat-fine", label: "GitHub fine-grained PAT", re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { id: "github-oauth", label: "GitHub OAuth token", re: /\bgho_[A-Za-z0-9]{36}\b/g },
  { id: "github-app", label: "GitHub app token", re: /\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b/g },
  { id: "slack", label: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: "openai", label: "OpenAI API key", re: /\bsk-(?!ant-)[A-Za-z0-9]{32,}\b/g },
  { id: "anthropic", label: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9-]{32,}\b/g },
  { id: "google-api", label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "stripe-secret", label: "Stripe secret key", re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: "npm-token", label: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "private-key", label: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: "heroku", label: "Heroku API key", re: /(?<![A-Za-z0-9-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![A-Za-z0-9-])/g },
  { id: "sendgrid", label: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { id: "twilio", label: "Twilio API key", re: /\bSK[0-9a-fA-F]{32}\b/g },
];

/** Lines that look like a secret but are obviously documentation. */
const PLACEHOLDER = [
  /example/i,
  /placeholder/i,
  // "your-api-key", "YOUR_TOKEN", "yourSecretKey", "your key"
  /your[-_\s]*[\w-]*[-_\s]?(key|token|secret|password|credential|id)/i,
  /replace[-_ ]?me/i,
  /dummy|fake|sample|redacted|xxxx/i,
  /\$\{[^}]+\}|<[^>]+>|\{\{[^}]+\}\}/,
  /process\.env|os\.environ|getenv/i,
  /^[*_`#.\-\/\s]*$/,
];

function isPlaceholder(line: string): boolean {
  return PLACEHOLDER.some((p) => p.test(line));
}

/** Never store the secret. Prefix, length and a digest only. */
function redact(value: string): string {
  const digest = createHash("sha256").update(value, "utf8").digest("hex");
  const prefix = value.slice(0, 4);
  return `${prefix}${"*".repeat(Math.max(0, Math.min(12, value.length - 4)))} (len=${value.length}, sha256=${digest.slice(0, 16)})`;
}

export interface SecretFinding {
  rule: string;
  label: string;
  commit: string;
  path: string;
  redacted: string;
}

const MAX_COMMITS = 4000;
const MAX_BUFFER = 96 * 1024 * 1024;

export const secretHistoryCollector: Collector = {
  name: "git.secret_history",
  async run(ctx) {
    if (!ctx.localPath || !(await isGitRepo(ctx.localPath))) {
      return one({
        title: "Commit history is not available locally",
        passed: false,
        source: ctx.localPath ?? "(no local path)",
        details: { reason: "not a git repository" },
        unverifiable: true,
        gaps: ["Clone with full history and re-run to scan for committed credentials."],
      });
    }

    let revs: string[];
    try {
      revs = (
        await git(ctx.localPath, [
          "rev-list",
          "--all",
          "--max-count=" + MAX_COMMITS,
        ])
      ).stdout
        .split("\n")
        .filter(Boolean);
    } catch (err) {
      return one({
        title: "Commit list could not be read",
        passed: false,
        source: ctx.localPath,
        details: { error: String(err).slice(0, 300) },
        unverifiable: true,
        gaps: ["Ensure the clone is not shallow."],
      });
    }

    const findings: SecretFinding[] = [];
    const byRule = new Map<string, number>();
    const commitsWithSecrets = new Set<string>();
    let scannedCommits = 0;
    let truncated = false;
    let streamError: string | undefined;

    // One pass over added lines. `--diff-filter` is intentionally absent: a
    // secret deleted in a later commit is still exposed to anyone who cloned
    // before the deletion, so history is scanned as-is.
    try {
      const { stdout } = await git(
        ctx.localPath,
        ["log", "--all", "-p", "--no-color", "-U0", "--no-merges", "--pretty=format:%x00commit%x00%H%x00"],
        MAX_BUFFER,
      );
      let commit = "";
      let path = "";
      for (const raw of stdout.split("\n")) {
        const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
        if (line.includes("\0commit\0")) {
          const parts = line.split("\0");
          commit = (parts[2] ?? "").slice(0, 12);
          scannedCommits++;
          if (scannedCommits > MAX_COMMITS) {
            truncated = true;
            break;
          }
          continue;
        }
        if (line.startsWith("+++ b/")) {
          path = line.slice(6);
          continue;
        }
        if (!line.startsWith("+") || line.startsWith("+++")) continue;
        if (isPlaceholder(line)) continue;

        const candidate = line.slice(1);
        for (const rule of SECRET_RULES) {
          rule.re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = rule.re.exec(candidate)) !== null) {
            const value = m[0];
            if (isPlaceholder(value)) continue;
            findings.push({
              rule: rule.id,
              label: rule.label,
              commit,
              path,
              redacted: redact(value),
            });
            byRule.set(rule.id, (byRule.get(rule.id) ?? 0) + 1);
            commitsWithSecrets.add(commit);
            if (findings.length > 500) break;
          }
          if (findings.length > 500) break;
        }
        if (findings.length > 500) break;
      }
    } catch (err) {
      streamError = String(err).slice(0, 300);
    }

    const gaps: string[] = [];
    if (findings.length > 0) {
      const types = [...byRule.entries()]
        .map(([id, n]) => `${id} (${n})`)
        .join(", ");
      gaps.push(
        `${findings.length} committed credential-shaped value(s) across ${commitsWithSecrets.size} commit(s): ${types}.`,
      );
      gaps.push(
        "Rotate every exposed credential first. Rewriting history without rotation does not remediate the exposure: clones and forks retain the original objects.",
      );
      gaps.push(
        "Then enable secret scanning push protection so the class of leak cannot recur, and record the rotation as evidence.",
      );
    }
    if (streamError) {
      gaps.push(
        `History scan terminated early (${streamError}). Treat the result as incomplete and re-run with a larger buffer.`,
      );
    }
    if (revs.length >= MAX_COMMITS || truncated) {
      gaps.push(
        `Scan covered the most recent ${MAX_COMMITS} commits only. Confirm the full history has been swept before the audit period.`,
      );
    }

    return one({
      title:
        findings.length === 0
          ? `No committed credentials found across ${scannedCommits} commit(s)`
          : `${findings.length} committed credential(s) found across ${commitsWithSecrets.size} commit(s)`,
      passed: findings.length === 0 && !streamError,
      source: `${ctx.localPath} (git log --all -p)`,
      details: {
        commitsScanned: scannedCommits,
        totalCommits: revs.length,
        findings: findings.length,
        commitsAffected: commitsWithSecrets.size,
        byRule: Object.fromEntries(byRule),
        scanTruncated: truncated,
        // Redacted values only. The raw credential is never persisted or printed.
        samples: findings.slice(0, 25),
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// git.authorship  ->  CC6.2, A.5.18, A.8.4
// ---------------------------------------------------------------------------

/**
 * Access rights, inferred from who has actually been able to write.
 *
 * There is no API that lists a repository's writers. But a push-access account
 * necessarily has an author identity in the history, so the author set is the
 * observable shadow of the access list. Useful to an auditor: an unexpectedly
 * broad author set is a provisioning finding, and author identities that do not
 * correspond to named people are a shared-account problem.
 */
export const authorshipCollector: Collector = {
  name: "git.authorship",
  async run(ctx) {
    if (!ctx.localPath || !(await isGitRepo(ctx.localPath))) {
      return one({
        title: "Commit authorship is not available locally",
        passed: false,
        source: ctx.localPath ?? "(no local path)",
        details: { reason: "not a git repository" },
        unverifiable: true,
        gaps: [
          "Clone the repository with full history so author identities can be enumerated.",
        ],
      });
    }

    let log: string;
    try {
      log = (
        await git(ctx.localPath, [
          "log",
          "--no-merges",
          "--pretty=format:%an%x1f%ae",
          "--max-count=3000",
        ])
      ).stdout;
    } catch (err) {
      return one({
        title: "Commit authorship could not be read",
        passed: false,
        source: ctx.localPath,
        details: { error: String(err).slice(0, 200) },
        unverifiable: true,
        gaps: ["Ensure the clone includes full history."],
      });
    }

    const counts = new Map<string, number>();
    let total = 0;
    for (const line of log.split("\n")) {
      const [name, email] = line.split("\x1f");
      if (!name || !email) continue;
      total++;
      const key = `${name} <${email}>`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }

    if (total === 0) {
      return one({
        title: "No commits available to attribute",
        passed: false,
        source: ctx.localPath,
        details: { commits: 0 },
        gaps: ["Nothing to attribute."],
      });
    }

    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const identities = sorted.length;
    const topShare = (sorted[0]?.[1] ?? 0) / total;

    // One identity doing all the work means no segregation of duties and no way
    // to attribute a change to a person.
    const singleAuthor = identities === 1;
    // Automations legitimately author commits (renovate, dependabot, github-actions).
    const looksAutomated = sorted.every(([id]) =>
      /\[bot\]|bot@|renovate|dependabot|github-actions|actions\[bot\]/i.test(id),
    );

    const gaps: string[] = [];
    if (singleAuthor && !looksAutomated) {
      gaps.push(
        `All ${total} commits share a single identity. Changes cannot be attributed to an individual, which is both an access-control weakness and an audit finding.`,
      );
    }
    if (topShare > 0.9 && identities > 1) {
      gaps.push(
        `One identity authored ${(topShare * 100).toFixed(0)}% of commits (${sorted[0]?.[0]}). Confirm this reflects intentional ownership rather than a shared account.`,
      );
    }
    if (looksAutomated) {
      gaps.push(
        "Every commit is authored by an automated account. Record who operates these accounts, or changes are not attributable to a person.",
      );
    }

    return one({
      title: `${identities} author identit${identities === 1 ? "y" : "ies"} across ${total} commit(s)`,
      passed: !singleAuthor && !looksAutomated,
      source: `${ctx.localPath} (git log --pretty=%an <%ae>)`,
      details: {
        commitsSampled: total,
        distinctIdentities: identities,
        topIdentityShare: Number(topShare.toFixed(4)),
        allAutomated: looksAutomated,
        authors: sorted.slice(0, 40).map(([id, n]) => ({ identity: id, commits: n })),
      },
      gaps,
    });
  },
};

export const GIT_COLLECTORS: Collector[] = [
  commitSignaturesCollector,
  authorshipCollector,
  secretHistoryCollector,
];

/** Exported for tests. */
export const __testing = { isPlaceholder, redact, parseThirdParty: SECRET_RULES };