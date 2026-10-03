import type { Finding, Report } from "../types.js";
import { canonicalize } from "../util/hash.js";

const STATUS_LABEL: Record<string, string> = {
  satisfied: "Satisfied",
  partial: "Partial",
  gap: "Gap",
  manual: "Needs attestation",
  not_applicable: "Not applicable",
};

const STATUS_ORDER: Record<string, number> = {
  gap: 0,
  partial: 1,
  manual: 2,
  satisfied: 3,
  not_applicable: 4,
};

export function serializeReport(report: Report): string {
  return JSON.stringify(report, null, 2) + "\n";
}

/** Bar rendered with block characters so it survives a monospace terminal. */
function coverageBar(ratio: number, width = 24): string {
  const filled = Math.max(0, Math.min(width, Math.round(ratio * width)));
  return "█".repeat(filled) + "░".repeat(width - filled);
}

function pct(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

function frameLabel(f: string): string {
  return f === "soc2" ? "SOC 2 (Trust Services Criteria)" : "ISO/IEC 27001:2022 (Annex A)";
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function renderMarkdown(report: Report): string {
  const { summary } = report;
  const out: string[] = [];

  out.push(`# Compliance report — ${report.target.owner}/${report.target.repo}`);
  out.push("");
  out.push(
    `Generated ${report.generatedAt} by ${report.generator.name} ${report.generator.version} in ${report.durationMs}ms.`,
  );
  out.push("");

  out.push("> This is tool-generated readiness evidence, not an attestation. Only an independent");
  out.push("> licensed auditor can issue a SOC 2 report or ISO 27001 certificate.");
  out.push("");

  // ---- Summary ----------------------------------------------------------
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("| --- | --- |");
  out.push(`| Controls evaluated | ${summary.total} |`);
  out.push(`| Satisfied | ${summary.satisfied} |`);
  out.push(`| Partial | ${summary.partial} |`);
  out.push(`| Gap | ${summary.gap} |`);
  out.push(`| Needs attestation | ${summary.manual} |`);
  out.push(`| **Satisfied overall** | **${pct(summary.overall)}** |`);
  out.push(
    `| Satisfied among observable controls | ${pct(summary.observedCoverage)} |`,
  );
  out.push("");
  out.push("```");
  out.push(`${coverageBar(summary.overall)} ${pct(summary.overall)} of all evaluated controls satisfied`);
  out.push("```");
  out.push("");
  out.push(
    `\`overall\` counts a control nobody could observe against you, because an auditor will. ` +
      `\`observedCoverage\` excludes the ${summary.manual} control(s) awaiting attestation; ` +
      "quote it only alongside the overall figure.",
  );
  out.push("");

  // ---- Per framework ----------------------------------------------------
  out.push("## Coverage by framework");
  out.push("");
  out.push("| Framework | Evaluated | Satisfied | Partial | Gap | Needs attestation |");
  out.push("| --- | --- | --- | --- | --- | --- |");
  for (const framework of report.frameworks) {
    const subset = report.findings.filter((f) => f.control.framework === framework);
    const count = (s: string) => subset.filter((f) => f.status === s).length;
    out.push(
      `| ${frameLabel(framework)} | ${subset.length} | ${count("satisfied")} | ${count("partial")} | ${count("gap")} | ${count("manual")} |`,
    );
  }
  out.push("");

  // ---- Gaps first -------------------------------------------------------
  const problems = report.findings
    .filter((f) => f.status !== "satisfied" && f.status !== "not_applicable")
    .sort((a, b) => {
      const d = STATUS_ORDER[a.status]! - STATUS_ORDER[b.status]!;
      return d !== 0 ? d : a.score - b.score;
    });

  out.push(`## Findings requiring action (${problems.length})`);
  out.push("");
  if (problems.length === 0) {
    out.push("No findings. Every evaluated control has passing evidence.");
    out.push("");
  } else {
    for (const finding of problems) {
      out.push(
        `### ${finding.control.id} — ${finding.control.title} · **${STATUS_LABEL[finding.status]}**`,
      );
      out.push("");
      out.push(`*${frameLabel(finding.control.framework)}* — ${finding.control.requirement}`);
      out.push("");
      if (finding.rationale) {
        out.push(finding.rationale);
        out.push("");
      }
      if (finding.notes.length > 0) {
        for (const note of finding.notes) out.push(`_Note: ${note}_`);
        out.push("");
      }
      if (finding.gaps.length > 0) {
        out.push("**Detected shortfalls**");
        out.push("");
        for (const gap of finding.gaps) out.push(`- ${gap}`);
        out.push("");
      }
      if (finding.remediation.length > 0) {
        out.push("**Remediation**");
        out.push("");
        finding.remediation.forEach((step, i) => {
          out.push(`${i + 1}. ${step}`);
        });
        out.push("");
      }
      out.push("**Evidence**");
      out.push("");
      for (const e of finding.evidence) {
        out.push(
          `- ${e.passed ? "PASS" : "FAIL"} · ${e.title} — [source](${e.source}) · \`${e.hash.slice(0, 16)}\``,
        );
      }
      out.push("");
    }
  }

  // ---- Full matrix ------------------------------------------------------
  out.push("## Control matrix");
  out.push("");
  for (const framework of report.frameworks) {
    const subset = report.findings.filter((f) => f.control.framework === framework);
    if (subset.length === 0) continue;
    out.push(`### ${frameLabel(framework)}`);
    out.push("");
    out.push("| Control | Title | Category | Status | Strength |");
    out.push("| --- | --- | --- | --- | --- |");
    for (const f of subset) {
      out.push(
        `| \`${f.control.id}\` | ${escapeCell(f.control.title)} | ${escapeCell(f.control.category)} | ${STATUS_LABEL[f.status]} | ${pct(f.score)} |`,
      );
    }
    out.push("");
  }

  // ---- Provenance -------------------------------------------------------
  out.push("## Evidence integrity");
  out.push("");
  out.push(
    "Every assertion above is part of a SHA-256 hash chain. Any edit to a recorded",
    );
  out.push(
    "observation changes that record's digest and every digest after it.",
  );
  out.push("");
  out.push("```");
  out.push(`chain root: ${report.evidenceRoot}`);
  out.push(`records:    ${report.findings.reduce((n, f) => n + f.evidence.length, 0)}`);
  out.push(`generated:  ${report.generatedAt}`);
  out.push("```");
  out.push("");
  out.push("Verify with:");
  out.push("");
  out.push("```bash");
  out.push("npx auditgen verify auditgen-report.json");
  out.push("```");
  out.push("");

  if (report.warnings.length > 0) {
    out.push("## Collection warnings");
    out.push("");
    for (const w of report.warnings) out.push(`- ${w}`);
    out.push("");
  }

  out.push("---");
  out.push("");
  out.push(`Chain root digest: \`${report.evidenceRoot}\``);
  out.push("");

  return out.join("\n");
}

/** Compact terminal summary used by the CLI default output. */
export function renderTerminal(report: Report): string {
  const { summary } = report;
  const lines: string[] = [];
  const repo = `${report.target.owner}/${report.target.repo}`;
  lines.push(`${repo}  ${report.generatedAt}`);
  lines.push("");
  lines.push(
    `${summary.satisfied}/${summary.total} controls satisfied  ${coverageBar(summary.overall)} ${pct(summary.overall)}`,
  );
  lines.push(
    `  ${summary.partial} partial · ${summary.gap} gap · ${summary.manual} need attestation`,
  );
  if (summary.manual > 0) {
    lines.push(
      `  (${pct(summary.observedCoverage)} of the ${summary.total - summary.manual - summary.notApplicable} observable control(s); unattested controls are not free)`,
    );
  }
  lines.push("");

  const problems = report.findings
    .filter((f) => f.status === "gap" || f.status === "partial")
    .sort((a, b) => STATUS_ORDER[a.status]! - STATUS_ORDER[b.status]! || a.score - b.score);

  if (problems.length > 0) {
    lines.push("Needs work:");
    for (const f of problems.slice(0, 8)) {
      const tag = f.status === "gap" ? "GAP " : "PART";
      lines.push(
        `  ${tag}  ${f.control.id.padEnd(8)} ${f.control.title.slice(0, 56)}`,
      );
    }
    if (problems.length > 8) {
      lines.push(`  ...and ${problems.length - 8} more`);
    }
    lines.push("");
  }

  for (const warning of report.warnings.slice(0, 5)) {
    lines.push(`  ! ${warning}`);
  }
  if (report.warnings.length > 0) lines.push("");

  return lines.join("\n");
}