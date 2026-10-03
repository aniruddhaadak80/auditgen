import type { ControlStatus, Finding, Report } from "../types.js";

/**
 * Compares two audits.
 *
 * The question an auditor actually asks at the start of an examination is not
 * "what does this repository look like" but "what changed since the period
 * under review, and did anything regress". No incumbent answers that from its own
 * history, because it has none. A tool that runs from source has to.
 *
 * Both reports must come from the same repository. Comparing a report for one
 * repository against another would produce a diff that means nothing.
 */

export interface ControlDelta {
  id: string;
  title: string;
  framework: string;
  before: ControlStatus | null;
  after: ControlStatus | null;
  change: "improved" | "regressed" | "added" | "removed" | "unchanged";
  /** Evidence strength movement, when both reports measured the control. */
  strengthDelta?: number;
}

export interface DiffSummary {
  improved: number;
  regressed: number;
  added: number;
  removed: number;
  unchanged: number;
}

export interface DiffResult {
  before: { generatedAt: string; root: string; repository: string };
  after: { generatedAt: string; root: string; repository: string };
  summary: DiffSummary;
  deltas: ControlDelta[];
  /** Repositories differ; every delta is meaningless. */
  mismatchedRepository: boolean;
}

const RANK: Record<ControlStatus, number> = {
  gap: 0,
  manual: 1,
  not_applicable: 2,
  partial: 3,
  satisfied: 4,
};

function indexById(findings: Finding[]): Map<string, Finding> {
  const map = new Map<string, Finding>();
  for (const f of findings) map.set(f.control.id, f);
  return map;
}

export function diffReports(before: Report, after: Report): DiffResult {
  const repositoryOf = (r: Report) => `${r.target.owner}/${r.target.repo}`;
  const mismatched = repositoryOf(before) !== repositoryOf(after);

  const a = indexById(before.findings);
  const b = indexById(after.findings);
  const ids = [...new Set([...a.keys(), ...b.keys()])].sort((x, y) => {
    // Worst-first ordering makes the regressions easy to find.
    const ra = a.get(x)?.status;
    const rb = b.get(x)?.status;
    if (ra && rb && ra !== rb) return RANK[ra] - RANK[rb];
    return x.localeCompare(y);
  });

  const deltas: ControlDelta[] = [];
  const summary: DiffSummary = {
    improved: 0,
    regressed: 0,
    added: 0,
    removed: 0,
    unchanged: 0,
  };

  for (const id of ids) {
    const beforeF = a.get(id);
    const afterF = b.get(id);
    const title = (afterF ?? beforeF)!.control.title;
    const framework = (afterF ?? beforeF)!.control.framework;

    let change: ControlDelta["change"];
    let strengthDelta: number | undefined;

    if (!beforeF && afterF) {
      change = "added";
      summary.added++;
    } else if (beforeF && !afterF) {
      change = "removed";
      summary.removed++;
    } else if (beforeF && afterF) {
      strengthDelta = Number((afterF.score - beforeF.score).toFixed(4));
      if (beforeF.status === afterF.status) {
        change = "unchanged";
        summary.unchanged++;
      } else if (RANK[afterF.status] > RANK[beforeF.status]) {
        change = "improved";
        summary.improved++;
      } else {
        change = "regressed";
        summary.regressed++;
      }
    } else {
      continue;
    }

    deltas.push({
      id,
      title,
      framework,
      before: beforeF?.status ?? null,
      after: afterF?.status ?? null,
      change,
      ...(strengthDelta !== undefined ? { strengthDelta } : {}),
    });
  }

  const sortOrder: Record<ControlDelta["change"], number> = {
    regressed: 0,
    added: 1,
    removed: 2,
    improved: 3,
    unchanged: 4,
  };
  deltas.sort((x, y) => {
    const d = sortOrder[x.change] - sortOrder[y.change];
    return d !== 0 ? d : x.id.localeCompare(y.id);
  });

  return {
    before: {
      generatedAt: before.generatedAt,
      root: before.evidenceRoot,
      repository: repositoryOf(before),
    },
    after: {
      generatedAt: after.generatedAt,
      root: after.evidenceRoot,
      repository: repositoryOf(after),
    },
    summary,
    deltas,
    mismatchedRepository: mismatched,
  };
}

export function renderDiff(diff: DiffResult): string {
  const lines: string[] = [];

  lines.push(
    `${diff.before.repository}   ${diff.before.generatedAt} -> ${diff.after.generatedAt}`,
  );
  if (diff.mismatchedRepository) {
    lines.push("");
    lines.push(
      "!! These reports are for different repositories. Every delta below is meaningless.",
    );
  }
  lines.push("");
  lines.push(
    `${diff.summary.improved} improved · ${diff.summary.regressed} regressed · ` +
      `${diff.summary.added} added · ${diff.summary.removed} removed · ${diff.summary.unchanged} unchanged`,
  );
  lines.push("");
  lines.push(`before root: ${diff.before.root}`);
  lines.push(`after root:  ${diff.after.root}`);
  lines.push("");

  const notable = diff.deltas.filter((d) => d.change !== "unchanged");

  if (notable.length === 0) {
    lines.push("No control changed status between these two reports.");
    return lines.join("\n");
  }

  lines.push("Changed controls, regressions first:");
  lines.push("");
  const TAGS: Record<ControlDelta["change"], string> = {
    regressed: "WORSE ",
    improved: "better",
    added: "new  ",
    removed: "gone ",
    unchanged: "same ",
  };

  for (const d of notable) {
    const transition =
      d.before && d.after ? `${d.before} -> ${d.after}` : d.change;
    lines.push(`  ${TAGS[d.change]}  ${d.id.padEnd(8)} ${transition}`);
    lines.push(`         ${d.title}`);
  }

  return lines.join("\n");
}