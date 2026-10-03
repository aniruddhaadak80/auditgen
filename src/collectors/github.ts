import {
  type Collector,
  type CollectorContext,
  type CollectorResult,
  one,
} from "./types.js";
import type { BranchProtection } from "../util/github.js";

/**
 * Shared helpers.
 */

const OFFLINE = (
  collector: string,
  ctx: CollectorContext,
): CollectorResult[] =>
  one({
    title: `${collector} requires a GitHub token and network access`,
    passed: false,
    source: "https://docs.github.com/en/rest",
    details: { reason: "offline" },
    unverifiable: true,
    gaps: [
      `Set GITHUB_TOKEN to a token with read access to ${ctx.target.owner}/${ctx.target.repo} so ${collector} can collect evidence.`,
    ],
  });

const INACCESSIBLE = (
  collector: string,
  ctx: CollectorContext,
  reason: string,
  gap: string,
): CollectorResult[] =>
  one({
    title: `${collector}: evidence endpoint not accessible`,
    passed: false,
    source: `https://api.github.com/repos/${ctx.target.owner}/${ctx.target.repo}`,
    details: { reason },
    unverifiable: true,
    gaps: [gap],
  });

function webUrl(ctx: CollectorContext, path: string): string {
  return `https://github.com/${ctx.target.owner}/${ctx.target.repo}/blob/${ctx.defaultBranch}/${path}`;
}

function repoUrl(ctx: CollectorContext, path = ""): string {
  return `https://github.com/${ctx.target.owner}/${ctx.target.repo}${path}`;
}

/** Loads branch protection once per run, since most collectors need it. */
export async function loadBranchProtection(
  ctx: CollectorContext,
): Promise<BranchProtection | undefined> {
  const res = await ctx.gh.branchProtection(ctx.defaultBranch);
  return res.ok ? res.data : undefined;
}

// ---------------------------------------------------------------------------
// github.branch_protection  ->  CC6.6, A.8.9
// ---------------------------------------------------------------------------

export const branchProtectionCollector: Collector = {
  name: "github.branch_protection",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const bp = await loadBranchProtection(ctx);
    if (!bp) {
      return INACCESSIBLE(
        this.name,
        ctx,
        "protection settings not readable",
        `Branch protection on "${ctx.defaultBranch}" could not be read. Confirm the token has administration:read and that protection is configured.`,
      );
    }

    const reviews = bp.required_pull_request_reviews;
    const statusChecks = bp.required_status_checks;
    const checks: Record<string, { pass: boolean; value: unknown }> = {
      protectionEnabled: { pass: true, value: true },
      requiredPullRequestReviews: {
        pass: Boolean(reviews),
        value: reviews
          ? {
              requiredApprovingReviewCount:
                reviews.required_approving_review_count ?? 0,
              dismissStaleReviews: Boolean(reviews.dismiss_stale_reviews),
              requireCodeOwnerReviews:
                Boolean(reviews.require_code_owner_reviews),
            }
          : null,
      },
      requiredStatusChecks: {
        pass: Boolean(statusChecks),
        value: statusChecks
          ? { strict: statusChecks.strict, contexts: statusChecks.contexts }
          : null,
      },
      forcePushesBlocked: { pass: !bp.allow_force_pushes?.enabled, value: !bp.allow_force_pushes?.enabled },
      branchDeletionBlocked: { pass: !bp.allow_deletions?.enabled, value: !bp.allow_deletions?.enabled },
      adminsEnforced: { pass: Boolean(bp.enforce_admins?.enabled), value: bp.enforce_admins?.enabled ?? false },
      conversationResolutionRequired: {
        pass: Boolean(bp.required_conversation_resolution?.enabled),
        value: bp.required_conversation_resolution?.enabled ?? false,
      },
    };

    const gaps: string[] = [];
    if (!reviews) {
      gaps.push(
        `Enable "Require a pull request before merging" on "${ctx.defaultBranch}" so no change lands without review.`,
      );
    }
    if (!statusChecks) {
      gaps.push(
        "Require a status check to pass before merging, so automated verification gates every change.",
      );
    }
    if (bp.allow_force_pushes?.enabled) {
      gaps.push(
        "Disable force pushes: they let a reviewer-approved change be discarded after approval.",
      );
    }
    if (!bp.enforce_admins?.enabled) {
      gaps.push(
        "Enable \"Require branches to be protected before allowing bypass\" so administrators cannot skip review.",
      );
    }

    // Pass requires a real gate: reviews or status checks, plus no force pushes.
    const hasGate = Boolean(reviews) || Boolean(statusChecks);
    const passed = hasGate && !bp.allow_force_pushes?.enabled;

    return one({
      title: hasGate
        ? `Branch protection on "${ctx.defaultBranch}" requires ${reviews ? "pull request review" : "status checks"} before merge`
        : `Branch protection on "${ctx.defaultBranch}" enforces no merge gate`,
      passed,
      source: repoUrl(
        ctx,
        `/settings/branches?branch=${encodeURIComponent(ctx.defaultBranch)}`,
      ),
      details: {
        branch: ctx.defaultBranch,
        ...checks,
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.codeowners  ->  CC6.2, A.5.15, A.8.3
// ---------------------------------------------------------------------------

const CODEOWNERS_PATHS = [
  ".github/CODEOWNERS",
  "CODEOWNERS",
  "docs/CODEOWNERS",
];

export const codeownersCollector: Collector = {
  name: "github.codeowners",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const found = CODEOWNERS_PATHS.find((p) => ctx.tree.has(p));
    if (!found) {
      return one({
        title: "No CODEOWNERS file: sensitive paths have no enforced reviewer",
        passed: false,
        source: repoUrl(ctx, "/blob/" + ctx.defaultBranch + "/.github/CODEOWNERS"),
        details: { searchedPaths: CODEOWNERS_PATHS },
        gaps: [
          `Add a CODEOWNERS file (${CODEOWNERS_PATHS[0]}) binding CI configuration, infrastructure, and dependency manifests to a named team or individual.`,
          "Enable branch protection with \"Require review from Code Owners\" so the binding is enforced rather than advisory.",
        ],
      });
    }

    const entry = ctx.tree.files.get(found)!;
    const blob = await ctx.gh.blob(entry.sha);
    const text = blob.ok ? (blob.data ?? "") : "";
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));

    const parsed = lines
      .map((l) => {
        const at = l.lastIndexOf("@");
        if (at === -1) return undefined;
        return { pattern: l.slice(0, at).trim(), owners: l.slice(at + 1).trim() };
      })
      .filter((x): x is { pattern: string; owners: string } => Boolean(x));

    // Wildcard-only files grant ownership to everyone, which authorizes nobody.
    const effective = parsed.filter((e) => !/^[*!?]*$/.test(e.pattern));
    const placeholders = parsed.filter((e) =>
      /\b(TODO|REPLACE|your[-_]?(org|team|handle))\b/i.test(e.owners),
    );

    const gaps: string[] = [];
    if (effective.length === 0) {
      gaps.push(
        "CODEOWNERS contains no effective rules. Ownership must name real principals.",
      );
    }
    if (placeholders.length > 0) {
      gaps.push(
        `Replace ${placeholders.length} placeholder owner(s) in CODEOWNERS with real GitHub principals.`,
      );
    }

    return one({
      title: `CODEOWNERS defines ${effective.length} rule(s) at ${found}`,
      passed: effective.length > 0 && placeholders.length === 0,
      source: webUrl(ctx, found),
      details: {
        path: found,
        ruleCount: effective.length,
        placeholderOwners: placeholders.length,
        rules: effective.slice(0, 40),
      },
      excerpt: lines.slice(0, 12).join("\n") || undefined,
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.two_factor  ->  CC6.1, A.8.5
// ---------------------------------------------------------------------------

export const twoFactorCollector: Collector = {
  name: "github.two_factor",
  async run(ctx) {
    if (ctx.declarations.twoFactorEnforced) {
      return one({
        title: "Operator declares multi-factor authentication is enforced organisation-wide",
        passed: true,
        source: "auditgen.json#/twoFactorEnforced",
        details: { declaredBy: "operator", org: ctx.declarations.organizationName },
        declared: true,
        gaps: [
          "This assertion is attested, not observed. Confirm it in Settings > Authentication security and attach the screenshot to your auditor pack.",
        ],
      });
    }

    const repo = await ctx.gh.getRepo();
    const sa = repo?.security_and_analysis;

    // GitHub exposes no API for whether an org enforces MFA. Rather than
    // infer a pass from unrelated signals, report partial and name the check.
    return one({
      title:
        "Multi-factor authentication enforcement cannot be observed through the GitHub API",
      passed: false,
      source: `https://github.com/organizations/${ctx.target.owner}/settings/authentication`,
      details: {
        verifiableViaApi: false,
        repositorySecurityAndAnalysis: sa ?? null,
      },
      unverifiable: true,
      gaps: [
        `Verify MFA is enforced at ${ctx.target.owner} under Settings > Authentication security, or set "twoFactorEnforced": true in auditgen.json to attest it.`,
        "Exempt any automation or bot accounts from the requirement and document the exception; auditors ask about service accounts specifically.",
      ],
    });
  },
};

// ---------------------------------------------------------------------------
// github.secret_scanning  ->  CC6.8, A.5.17, A.8.24
// ---------------------------------------------------------------------------

export const secretScanningCollector: Collector = {
  name: "github.secret_scanning",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const repo = await ctx.gh.getRepo();
    if (!repo) {
      return INACCESSIBLE(this.name, ctx, "repository not readable", "Provide a token with read access to the repository.");
    }
    const sa = repo.security_and_analysis;
    const scanning = sa?.secret_scanning?.status === "enabled";
    const pushProtection = sa?.secret_scanning_push_protection?.status === "enabled";

    let openAlerts: number | undefined;
    let resolvedAlerts: number | undefined;
    const alertsRes = await ctx.gh.secretScanningAlerts();
    if (alertsRes.ok && Array.isArray(alertsRes.data)) {
      openAlerts = alertsRes.data.filter((a: any) => a.state === "open").length;
      resolvedAlerts = alertsRes.data.filter((a: any) => a.state === "resolved").length;
    }

    const gaps: string[] = [];
    if (!scanning) {
      gaps.push(
        "Enable secret scanning in Settings > Code security. GitHub scans pushes for provider-issued credentials.",
      );
    }
    if (!pushProtection) {
      gaps.push(
        "Enable secret scanning push protection. Detection after the fact leaves the credential already published in history.",
      );
    }
    if (scanning && (openAlerts ?? 0) > 0) {
      gaps.push(
        `Resolve ${openAlerts} open secret scanning alert(s) and rotate the exposed credentials. An open alert is a known-vulnerability finding.`,
      );
    }
    if (repo.private && !repo.security_and_analysis) {
      gaps.push(
        "security_and_analysis was omitted from the response, which normally means the token lacks the security-events permission. Secret scanning status is unverified.",
      );
    }

    const passed = scanning && pushProtection && (openAlerts ?? 0) === 0;

    // The title must not read as a pass when the control fails, or the report
    // contradicts itself in the same block.
    const title = !scanning
      ? "Secret scanning is not enabled"
      : !pushProtection
        ? "Secret scanning is enabled but push protection is not"
        : (openAlerts ?? 0) > 0
          ? `Secret scanning and push protection enabled, with ${openAlerts} unresolved alert(s)`
          : "Secret scanning and push protection enabled with no open alerts";

    return one({
      title,
      passed,
      source: repoUrl(ctx, "/settings/security_analysis"),
      details: {
        visibility: repo.visibility ?? (repo.private ? "private" : "public"),
        secretScanning: scanning,
        pushProtection,
        openAlerts,
        resolvedAlerts,
        alertsReachable: alertsRes.ok,
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.security_md  ->  CC7.4, A.5.24
// ---------------------------------------------------------------------------

const SECURITY_PATHS = [
  "SECURITY.md",
  ".github/SECURITY.md",
  "docs/SECURITY.md",
  "CONTRIBUTING.md",
];

const RESPONSE_COMMITMENT =
  /within\s+(?:\d+|one|two|three|seven|a|few|business)\s*\(?\s*(?:business\s+)?(hours?|days?|weeks?)/i;
const CONTACT =
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|https?:\/\/\S+/i;

export const securityMdCollector: Collector = {
  name: "github.security_md",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const found = SECURITY_PATHS.find((p) => ctx.tree.has(p));
    if (!found) {
      return one({
        title: "No published security policy",
        passed: false,
        source: repoUrl(ctx, "/blob/" + ctx.defaultBranch + "/SECURITY.md"),
        details: { searchedPaths: SECURITY_PATHS },
        gaps: [
          "Publish a SECURITY.md declaring a private reporting channel, supported versions, and a response-time commitment. Reporters will not use an unlisted address.",
        ],
      });
    }

    const entry = ctx.tree.files.get(found)!;
    const blob = await ctx.gh.blob(entry.sha);
    const text = blob.ok ? (blob.data ?? "") : "";

    const commitment = RESPONSE_COMMITMENT.exec(text)?.[0];
    const contact = CONTACT.exec(text)?.[0];
    const hasPrivateChannel =
      /private|security@|vdp|report.*(email|channel)/i.test(text);

    const gaps: string[] = [];
    if (!commitment) {
      gaps.push(
        "State an explicit response-time commitment, for example \"we aim to acknowledge reports within 3 business days\". Without one there is no response objective to test.",
      );
    }
    if (!contact) {
      gaps.push("Include a reachable reporting address or URL.");
    }

    return one({
      title: commitment
        ? `Security policy published at ${found} with a response commitment`
        : `Security policy published at ${found} without a response-time commitment`,
      passed: Boolean(commitment && contact && hasPrivateChannel),
      source: webUrl(ctx, found),
      details: {
        path: found,
        hasResponseCommitment: Boolean(commitment),
        commitment: commitment ?? null,
        hasPrivateChannel,
        lengthBytes: text.length,
      },
      excerpt: text.slice(0, 600) || undefined,
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.dependabot  ->  CC5.2, CC7.1, A.8.8
// ---------------------------------------------------------------------------

export const dependabotCollector: Collector = {
  name: "github.dependabot",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const manifest =
      ctx.tree.has(".github/dependabot.yml") ||
      ctx.tree.has(".github/dependabot.yaml");
    const alertsRes = await ctx.gh.dependabotAlerts();

    if (!alertsRes.ok) {
      if (manifest) {
        return one({
          title: "Dependabot is configured but alerts could not be read by this token",
          passed: false,
          source: webUrl(ctx, ".github/dependabot.yml"),
          details: {
            manifestPresent: true,
            alertsReachable: false,
            reason: alertsRes.reason,
          },
          unverifiable: true,
          gaps: [
            "Grant the token security_events access to read Dependabot alerts, or triage them manually and record the disposition so evidence of response exists.",
          ],
        });
      }
      return one({
        title: "No dependency vulnerability detection configured",
        passed: false,
        source: repoUrl(ctx, "/security/dependabot"),
        details: { manifestPresent: false, alertsReachable: false },
        gaps: [
          "Add .github/dependabot.yml with a weekly update schedule, or enable Dependabot security updates in Settings > Code security.",
          "Detection that produces no recorded disposition is not a control. Record triage outcomes for the advisories it raises.",
        ],
      });
    }

    const alerts = alertsRes.data ?? [];
    const open = alerts.filter((a: any) => a.state === "open");
    const dismissed = alerts.filter((a: any) => a.state === "dismissed");
    const fixed = alerts.filter((a: any) => a.state === "fixed");
    const critical = open.filter((a: any) => {
      const sev = a.security_advisory?.severity;
      return sev === "critical" || sev === "high";
    });

    const gaps: string[] = [];
    if (!manifest) {
      gaps.push(
        "Dependabot alerts exist but .github/dependabot.yml is absent, so update scheduling and grouping are undefined.",
      );
    }
    if (open.length > 0) {
      gaps.push(
        `Triage ${open.length} open dependency alert(s)${critical.length ? `, ${critical.length} of them high or critical` : ""}. Fix, dismiss with a justification, or accept the risk explicitly.`,
      );
    }
    if (open.length === 0 && fixed.length === 0 && dismissed.length === 0) {
      gaps.push(
        "No advisory has ever been triaged. A control with no history of operation cannot be shown to operate; introduce a recurring dependency review.",
      );
    }

    return one({
      title:
        open.length === 0
          ? `Dependency detection active with ${fixed.length + dismissed.length} alert(s) dispositioned and none open`
          : `Dependency detection active with ${open.length} open alert(s)`,
      passed: open.length === 0 && Boolean(manifest),
      source: repoUrl(ctx, "/security/dependabot"),
      details: {
        manifestPresent: manifest,
        totalAlerts: alerts.length,
        open: open.length,
        fixed: fixed.length,
        dismissed: dismissed.length,
        highSeverityOpen: critical.length,
        sampledOpen: open.slice(0, 10).map((a: any) => ({
          number: a.number,
          package: a.dependency?.package?.name,
          severity: a.security_advisory?.severity,
          state: a.state,
          dismissedReason: a.dismissed_reason ?? null,
        })),
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.ci_workflows  ->  CC7.2, A.8.15, A.8.16, A.8.28, A.8.29
// ---------------------------------------------------------------------------

const SECURITY_JOB_HINTS = [
  "codeql",
  "sast",
  "semgrep",
  "gitleaks",
  "trivy",
  "audit",
  "dependency-review",
  "secret",
  "security",
  "lint",
  "test",
  "snyk",
  "bandit",
  "gosec",
  "cargo audit",
  "npm audit",
];

export const ciWorkflowsCollector: Collector = {
  name: "github.ci_workflows",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const workflowsRes = await ctx.gh.actionWorkflows();
    if (!workflowsRes.ok || !workflowsRes.data) {
      return INACCESSIBLE(
        this.name,
        ctx,
        workflowsRes.reason ?? "unknown",
        "Provide a token with actions:read to enumerate workflows.",
      );
    }

    const workflows = workflowsRes.data.workflows ?? [];
    const active = workflows.filter((w) => w.state === "active");
    const workflowFiles = ctx.tree.find(
      (p) => p.startsWith(".github/workflows/") && /\.(ya?ml)$/i.test(p),
    );

    // Name-based detection of security-relevant jobs. Deliberately conservative:
    // an unrecognized workflow is reported as unknown rather than assumed safe.
    const hinted = workflows.filter((w) => {
      const hay = w.name.toLowerCase();
      return SECURITY_JOB_HINTS.some((h) => hay.includes(h));
    });

    const perms = await ctx.gh.actionPermissions();

    const gaps: string[] = [];
    if (active.length === 0) {
      gaps.push(
        "No active GitHub Actions workflow. Nothing is verified automatically on change.",
      );
    }
    if (workflows.length > 0 && hinted.length === 0) {
      gaps.push(
        `None of the ${workflows.length} workflow(s) appear to run tests, linting, or security scanning. Add a required check that gates merges.`,
      );
    }
    if (perms.ok && perms.data?.allowed_actions === "all") {
      gaps.push(
        'Workflow permissions are set to "All actions", so any action from any repository can run with repository secrets. Restrict to "Selected actions" or add an allow-list.',
      );
    }

    const passed = active.length > 0 && hinted.length > 0;

    return one({
      title:
        active.length === 0
          ? "No active CI workflow found"
          : `${active.length} active workflow(s); ${hinted.length} appear to perform security-relevant verification`,
      passed,
      source: repoUrl(ctx, "/actions/workflows"),
      details: {
        totalWorkflows: workflows.length,
        activeWorkflows: active.length,
        securityRelevantWorkflows: hinted.map((w) => ({
          name: w.name,
          path: w.path,
          state: w.state,
        })),
        allowedActions: perms.ok ? perms.data?.allowed_actions ?? null : null,
        shaPinningRequired: perms.ok ? perms.data?.sha_pinning_required ?? null : null,
        workflowFiles,
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.env_protection  ->  CC6.3, A.8.2
// ---------------------------------------------------------------------------

export const envProtectionCollector: Collector = {
  name: "github.env_protection",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const envRes = await ctx.gh.environments();
    const bp = await loadBranchProtection(ctx);

    const envs = envRes.ok && envRes.data ? envRes.data.environments ?? [] : [];
    const protectedEnvs = envs.filter((e) =>
      (e.protection_rules ?? []).some(
        (r) =>
          r.type === "required_reviewers" ||
          r.type === "wait_timer" ||
          (r.type === "deployment_branch_policy" &&
            e.deployment_branch_policy?.protected_branches),
      ),
    );
    const reviewGated = envs.filter((e) =>
      (e.protection_rules ?? []).some((r) => r.type === "required_reviewers"),
    );

    const gaps: string[] = [];
    if (envRes.ok && envs.length === 0) {
      gaps.push(
        "No GitHub Environment is defined. Deployments therefore run without a separate identity boundary; create a production environment with required reviewers.",
      );
    } else if (envRes.ok && envs.length > 0 && protectedEnvs.length === 0) {
      gaps.push(
        `${envs.length} environment(s) exist but none carries protection rules, so any contributor with write access can trigger them.`,
      );
    }
    if (bp && !bp.enforce_admins?.enabled) {
      gaps.push(
        "Branch protection is not enforced for administrators, so the release path can bypass the review gate.",
      );
    }

    const passed = envRes.ok && reviewGated.length > 0;

    return one({
      title: reviewGated.length
        ? `${reviewGated.length} environment(s) require reviewer approval before deployment`
        : "No environment requires approval before deployment",
      passed,
      source: repoUrl(ctx, "/settings/environments"),
      details: {
        environmentsReachable: envRes.ok,
        totalEnvironments: envs.length,
        protectedEnvironments: protectedEnvs.map((e) => e.name),
        reviewGatedEnvironments: reviewGated.map((e) => e.name),
        enforceAdmins: bp?.enforce_admins?.enabled ?? null,
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.pr_review  ->  CC2.2, CC8.1, A.8.32
// ---------------------------------------------------------------------------

export const prReviewCollector: Collector = {
  name: "github.pr_review",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const bp = await loadBranchProtection(ctx);
    const bpReadable = Boolean(bp);
    const requiredCount =
      bp?.required_pull_request_reviews?.required_approving_review_count ?? 0;

    const sampleSize = Number(ctx.tree ? 15 : 15);
    const pullsRes = await ctx.gh.closedPulls(sampleSize);

    let merged = 0;
    let withApprovalByOther = 0;
    let checked = 0;
    const reviewError: string | undefined = pullsRes.ok ? undefined : pullsRes.reason;

    if (pullsRes.ok && Array.isArray(pullsRes.data)) {
      const candidates = pullsRes.data.filter((p) => p.merged_at).slice(0, sampleSize);
      merged = candidates.length;
      for (const pr of candidates.slice(0, 10)) {
        const reviewsRes = await ctx.gh.pullReviews(pr.number);
        if (!reviewsRes.ok || !Array.isArray(reviewsRes.data)) continue;
        checked++;
        const author = pr.user?.login;
        const approvedByOther = reviewsRes.data.some(
          (r) =>
            r.state.toUpperCase() === "APPROVED" && r.user?.login !== author,
        );
        if (approvedByOther) withApprovalByOther++;
        ctx.gh; // keep reference for rate-limit visibility
      }
    }

    const releases = await ctx.gh.releases();
    const releaseCount =
      releases.ok && Array.isArray(releases.data) ? releases.data.length : 0;

    const gaps: string[] = [];
    if (!bpReadable) {
      // Without read access to protection settings, "no reviews required" cannot
      // be distinguished from "cannot see the rules". Report the uncertainty
      // instead of asserting a failure that may not exist.
      gaps.push(
        "Branch protection settings could not be read with this token, so whether approving reviews are required is unconfirmed. Re-run with administration:read to verify.",
      );
    } else if (requiredCount === 0) {
      gaps.push(
        "Branch protection does not require approving reviews, so a change can merge on a single account's authority. This is the most commonly cited SOC 2 gap.",
      );
    }
    if (merged > 0 && checked > 0 && withApprovalByOther === 0) {
      gaps.push(
        `None of ${checked} sampled merged pull requests carries an approval from someone other than the author.`,
      );
    }
    if (merged === 0) {
      gaps.push(
        "No merged pull requests were found in the sample window, so there is no change-management history to examine.",
      );
    }
    if (releaseCount === 0) {
      gaps.push(
        "No GitHub releases found. A tagged, released trail makes each production change individually identifiable to an auditor.",
      );
    }

    const passed =
      bpReadable &&
      requiredCount > 0 &&
      (merged === 0 || withApprovalByOther > 0) &&
      releaseCount > 0;

    const title = !bpReadable
      ? `Review requirement could not be read; ${releaseCount} release(s) recorded`
      : requiredCount > 0
        ? `Merges require ${requiredCount} approving review(s); ${releaseCount} release(s) recorded`
        : "Merges require no approving review";

    return one({
      title,
      passed,
      source: repoUrl(ctx, "/pulls?q=is%3Apr+is%3Amerged"),
      details: {
        branchProtectionReadable: bpReadable,
        requiredApprovingReviewCount: requiredCount,
        dismissStaleReviews: Boolean(
          bp?.required_pull_request_reviews?.dismiss_stale_reviews,
        ),
        requireCodeOwnerReviews: Boolean(
          bp?.required_pull_request_reviews?.require_code_owner_reviews,
        ),
        sampledMergedPullRequests: merged,
        pullRequestsReviewed: checked,
        withIndependentApproval: withApprovalByOther,
        releases: releaseCount,
        reviewLookupError: reviewError ?? null,
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.advisories  ->  CC4.1, CC7.3
// ---------------------------------------------------------------------------

export const advisoriesCollector: Collector = {
  name: "github.advisories",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const res = await ctx.gh.securityAdvisories();
    if (!res.ok) {
      return INACCESSIBLE(
        this.name,
        ctx,
        res.reason ?? "unknown",
        "Repository security advisories require write access to the repository. Re-run with a token that has it, or record advisory triage elsewhere.",
      );
    }

    const advisories = res.data ?? [];
    const published = advisories.filter((a: any) => !a.draft);
    const closed = advisories.filter((a: any) => a.closed_at);
    const withCve = advisories.filter((a: any) => a.cve_id);

    const gaps: string[] = [];
    if (advisories.length === 0) {
      gaps.push(
        "No repository security advisories exist. That may be a clean history, but it also means there is no evidence the vulnerability-reporting path has been exercised.",
      );
    } else {
      if (published.length === 0) {
        gaps.push(
          `${advisories.length} advisory draft(s) exist but none has been published to the reporter.`,
        );
      }
      if (advisories.some((a: any) => !a.closed_at)) {
        gaps.push(
          "One or more advisories remain open. Publish a resolution, or record why the report is not actionable.",
        );
      }
    }

    return one({
      title: advisories.length
        ? `${advisories.length} advisory record(s), ${published.length} published, ${closed.length} closed`
        : "No advisory history; reporting path is unproven",
      passed: advisories.length > 0 && published.length > 0 && closed.length === advisories.length,
      source: repoUrl(ctx, "/security/advisories"),
      details: {
        total: advisories.length,
        published: published.length,
        closed: closed.length,
        withCveIdentifier: withCve.length,
        items: advisories.slice(0, 10).map((a: any) => ({
          ghsaId: a.ghsa_id,
          cveId: a.cve_id,
          severity: a.severity,
          draft: Boolean(a.draft),
          publishedAt: a.published_at ?? null,
          closedAt: a.closed_at ?? null,
        })),
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.actions_permissions  ->  CC9.2
// ---------------------------------------------------------------------------

/** Matches `uses: owner/action@ref` and reports whether ref is a commit sha. */
export function parseThirdPartyActions(
  workflowText: string,
): { action: string; ref: string; pinned: boolean }[] {
  const out: { action: string; ref: string; pinned: boolean }[] = [];
  const re = /uses:\s*["']?([A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+)@([^\s"'#]+)["']?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(workflowText)) !== null) {
    const [, action, ref] = m;
    if (!action || !ref) continue;
    // Local actions and the official actions org are treated differently: a
    // mutable tag from actions/ is low risk, a tag from a third party is not.
    out.push({
      action,
      ref,
      pinned: /^[0-9a-f]{40}$/i.test(ref),
    });
  }
  return out;
}

export const actionsPermissionsCollector: Collector = {
  name: "github.actions_permissions",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const perms = await ctx.gh.actionPermissions();
    const allowed = perms.ok ? (perms.data?.allowed_actions ?? null) : null;
    const shaRequired = perms.ok ? (perms.data?.sha_pinning_required ?? null) : null;

    // Fetch workflow bodies to measure actual pinning practice.
    const workflowPaths = ctx.tree.find(
      (p) => p.startsWith(".github/workflows/") && /\.(ya?ml)$/i.test(p),
    );
    const all: { action: string; ref: string; pinned: boolean; file: string }[] = [];
    for (const p of workflowPaths.slice(0, 20)) {
      const entry = ctx.tree.files.get(p);
      if (!entry) continue;
      const blob = await ctx.gh.blob(entry.sha);
      if (!blob.ok || !blob.data) continue;
      for (const a of parseThirdPartyActions(blob.data)) {
        all.push({ ...a, file: p });
      }
    }

    const thirdParty = all.filter(
      (a) => !a.action.startsWith("actions/") && !a.action.startsWith("github/"),
    );
    const unpinnedThirdParty = thirdParty.filter((a) => !a.pinned);

    const gaps: string[] = [];
    if (allowed === "all") {
      gaps.push(
        'Actions permissions allow all actions. Set to "Selected actions" so only reviewed dependencies can execute with repository secrets.',
      );
    }
    if (shaRequired === false) {
      gaps.push(
        "SHA pinning is not required for actions. Enable it so a compromised tag cannot be moved under you.",
      );
    }
    if (unpinnedThirdParty.length > 0) {
      gaps.push(
        `Pin ${unpinnedThirdParty.length} third-party action reference(s) to a full commit sha (${unpinnedThirdParty
          .slice(0, 4)
          .map((a) => `${a.action}@${a.ref}`)
          .join(", ")}). Tags are mutable and can be repointed at malicious code.`,
      );
    }

    const passed =
      allowed === "selected" &&
      unpinnedThirdParty.length === 0 &&
      (shaRequired === true || thirdParty.length === 0);

    return one({
      title:
        allowed !== "selected"
          ? `Workflow actions are not restricted${allowed === "all" ? " (all actions permitted)" : ""}`
          : unpinnedThirdParty.length > 0
            ? `${unpinnedThirdParty.length} third-party action(s) referenced by a mutable tag`
            : thirdParty.length === 0
              ? "No third-party actions referenced; workflow actions are restricted"
              : `All ${thirdParty.length} third-party action references are pinned to a commit sha`,
      passed,
      source: repoUrl(ctx, "/settings/actions"),
      details: {
        allowedActions: allowed,
        shaPinningRequired: shaRequired,
        permissionsReachable: perms.ok,
        workflowsScanned: workflowPaths.length,
        actionReferences: all.length,
        thirdPartyReferences: thirdParty.length,
        unpinnedThirdParty: unpinnedThirdParty.slice(0, 20),
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.ci_runs  ->  CC2.1, CC3.4, CC4.1, CC5.1, A.5.33, A.5.36
// ---------------------------------------------------------------------------

/**
 * Operating effectiveness.
 *
 * Every other collector answers "is this configured". This one answers "did it
 * ever actually run, and does it keep passing". A required status check that has
 * never executed is an aspiration, not a control, and a control that has been
 * failing for weeks is worse than no control because it manufactures evidence.
 */
export const ciRunsCollector: Collector = {
  name: "github.ci_runs",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const res = await ctx.gh.actionRuns(50);
    if (!res.ok || !res.data) {
      return INACCESSIBLE(
        this.name,
        ctx,
        res.reason ?? "unknown",
        "Provide a token with actions:read to inspect workflow run history.",
      );
    }

    const runs = res.data.workflow_runs ?? [];
    const conclusions = runs.filter((r) => r.conclusion !== null);
    const failed = conclusions.filter((r) => r.conclusion !== "success");
    const total = conclusions.length;
    const successRate = total > 0 ? (total - failed.length) / total : 0;

    const latest = runs.length > 0 ? runs[0] : undefined;
    const latestAt = latest?.created_at ? Date.parse(latest.created_at) : NaN;
    const ageDays =
      Number.isNaN(latestAt)
        ? null
        : Math.floor((Date.now() - latestAt) / 86_400_000);

    // Which branches changes actually landed on, as a proxy for whether the gate
    // covers the whole surface rather than one long-lived branch.
    const branches = [...new Set(runs.map((r) => r.head_branch))].sort();
    const defaultRuns = runs.filter((r) => r.head_branch === ctx.defaultBranch).length;

    const gaps: string[] = [];
    if (total === 0) {
      gaps.push(
        "No completed workflow runs are visible. Configured checks that have never executed cannot be shown to operate.",
      );
    }
    if (failed.length > 0) {
      const recent = failed.slice(0, 5).map((r) => `${r.name}#${r.run_number} (${r.conclusion})`);
      gaps.push(
        `${failed.length} of the last ${total} completed runs concluded ${failed.length === 1 ? "unsuccessfully" : "unsuccessfully"}: ${recent.join(", ")}. A red check that is not triaged is an open known issue.`,
      );
    }
    if (ageDays !== null && ageDays > 30) {
      gaps.push(
        `The most recent workflow run was ${ageDays} days ago. Monitoring that has stopped running is not monitoring.`,
      );
    }
    if (defaultRuns === 0 && branches.length > 0) {
      gaps.push(
        `No runs recorded against the default branch "${ctx.defaultBranch}"; observed branches were ${branches.slice(0, 5).join(", ")}.`,
      );
    }

    const passed = total > 0 && failed.length === 0 && (ageDays === null || ageDays <= 30);

    return one({
      title:
        total === 0
          ? "No completed workflow runs are visible"
          : `${total} completed run(s), ${(successRate * 100).toFixed(0)}% successful, most recent ${ageDays ?? "?"} day(s) ago`,
      passed,
      source: repoUrl(ctx, "/actions"),
      details: {
        completedRuns: total,
        successful: total - failed.length,
        failed: failed.length,
        successRate: Number(successRate.toFixed(4)),
        mostRecentRunAt: latest?.created_at ?? null,
        daysSinceLastRun: ageDays,
        distinctBranches: branches.slice(0, 20),
        defaultBranchRuns: defaultRuns,
        recentFailures: failed.slice(0, 10).map((r) => ({
          workflow: r.name,
          runNumber: r.run_number,
          conclusion: r.conclusion,
          branch: r.head_branch,
          createdAt: r.created_at,
        })),
      },
      gaps,
    });
  },
};

// ---------------------------------------------------------------------------
// github.governance  ->  CC1.2, CC5.3, A.5.31, A.5.37
// ---------------------------------------------------------------------------

const GOVERNANCE_FILES: Record<string, string> = {
  "LICENSE": "Licence terms",
  "LICENSE.md": "Licence terms",
  "LICENCE": "Licence terms",
  "CODE_OF_CONDUCT.md": "Code of conduct",
  "CONTRIBUTING.md": "Contribution process",
  ".github/CONTRIBUTING.md": "Contribution process",
  ".github/pull_request_template.md": "Pull request template",
  "PULL_REQUEST_TEMPLATE.md": "Pull request template",
  ".github/CODEOWNERS": "Ownership definitions",
  "SECURITY.md": "Security policy",
  ".github/SECURITY.md": "Security policy",
  "SUPPORT.md": "Support policy",
  "CHANGELOG.md": "Change history",
};

export const governanceCollector: Collector = {
  name: "github.governance",
  async run(ctx) {
    if (ctx.offline) return OFFLINE(this.name, ctx);

    const present = Object.keys(GOVERNANCE_FILES).filter((p) =>
      ctx.tree.has(p),
    );
    const kinds = [...new Set(present.map((p) => GOVERNANCE_FILES[p]!))].sort();

    const repo = await ctx.gh.getRepo();
    const spdx = repo?.license?.spdx_id ?? null;

    const gaps: string[] = [];
    if (!present.some((p) => p.toUpperCase().startsWith("LICEN"))) {
      gaps.push(
        "No LICENSE file. Absence of licence terms is a governance finding and blocks reuse of the code.",
      );
    }
    if (!ctx.tree.has("CODE_OF_CONDUCT.md")) {
      gaps.push(
        "No code of conduct published, which is an expected artefact under the organisational criteria.",
      );
    }
    if (!present.some((p) => p.toUpperCase().includes("CONTRIBUTING"))) {
      gaps.push(
        "No CONTRIBUTING guide, so the documented procedure for contributing changes is missing.",
      );
    }

    return one({
      title: `Repository publishes ${kinds.length} governance artefact(s)${spdx ? ` under ${spdx}` : ""}`,
      passed: present.some((p) => p.toUpperCase().startsWith("LICEN")),
      source: repoUrl(ctx),
      details: {
        spdxLicense: spdx,
        licenseName: repo?.license?.name ?? null,
        artefactsPresent: kinds,
        files: present,
        archived: repo?.archived ?? null,
      },
      gaps,
    });
  },
};

export const GITHUB_COLLECTORS: Collector[] = [
  branchProtectionCollector,
  codeownersCollector,
  twoFactorCollector,
  secretScanningCollector,
  securityMdCollector,
  dependabotCollector,
  ciWorkflowsCollector,
  ciRunsCollector,
  governanceCollector,
  envProtectionCollector,
  prReviewCollector,
  advisoriesCollector,
  actionsPermissionsCollector,
];