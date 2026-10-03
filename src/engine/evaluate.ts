import type {
  Control,
  ControlStatus,
  Evidence,
  Finding,
} from "../types.js";
import type { CollectorContext, CollectorResult } from "../collectors/types.js";
import { manualResultFor } from "../collectors/manual.js";
import { chainEvidence } from "../util/hash.js";

/** An evidence record before the hash chain is applied. */
export type DraftEvidence = Omit<Evidence, "hash" | "prevHash">;

function toDraft(
  controlId: string,
  collector: string,
  result: CollectorResult,
  observedAt: string,
): DraftEvidence {
  return {
    controlId,
    collector,
    title: result.title,
    observedAt,
    source: result.source,
    passed: result.passed,
    details: {
      ...result.details,
      ...(result.declared ? { attestation: "operator-declared" } : {}),
      ...(result.unverifiable ? { unverifiable: true } : {}),
    },
    ...(result.excerpt ? { excerpt: result.excerpt } : {}),
  };
}

export interface EvaluateInput {
  controls: Control[];
  resultsByCollector: Map<string, CollectorResult[]>;
  ctx: CollectorContext;
  observedAt: string;
}

export interface Evaluated {
  findings: Finding[];
  /** Every evidence record in report order, chained. */
  evidence: Evidence[];
  evidenceRoot: string;
}

const REMEDIATION_FALLBACK =
  "Enable this control and re-run auditgen so the assertion can be verified from the repository.";

/**
 * Turns collector output into per-control findings and one tamper-evident
 * evidence chain covering the whole report.
 *
 * Status logic is intentionally conservative. A control with no passing
 * assertion is never reported as satisfied, and an assertion that passed while
 * still reporting a gap is downgraded to partial rather than being allowed to
 * read as a pass.
 */
export function evaluate(input: EvaluateInput): Evaluated {
  const { controls, resultsByCollector, ctx, observedAt } = input;

  const drafts: DraftEvidence[] = [];
  const findings: Finding[] = [];

  for (const control of controls) {
    let results: CollectorResult[];
    if (control.manual) {
      results = [manualResultFor(control.id, ctx)];
    } else {
      results = resultsByCollector.get(control.collector) ?? [];
    }

    for (const result of results) {
      drafts.push(toDraft(control.id, control.collector, result, observedAt));
    }

    const total = results.length;
    const passed = results.filter((r) => r.passed);
    const unverifiable = results.filter((r) => r.unverifiable);
    const gaps = [...new Set(results.flatMap((r) => r.gaps ?? []))];
    const notes = [...new Set(results.flatMap((r) => r.notes ?? []))];

    let status: ControlStatus;
    let score: number;

    if (total === 0) {
      status = "gap";
      score = 0;
      gaps.push(
        `No evidence was collected for ${control.id}. Either its collector failed or the control has no implementation.`,
      );
    } else {
      score = passed.length / total;
      if (passed.length === total && gaps.length === 0) {
        status = "satisfied";
      } else if (passed.length > 0) {
        status = "partial";
      } else if (unverifiable.length === total) {
        status = "manual";
      } else {
        status = "gap";
      }
    }

    const declaredOnly =
      total > 0 &&
      results.every((r) => r.declared === true) &&
      status === "satisfied";

    findings.push({
      control,
      status,
      score: Number(score.toFixed(4)),
      evidence: [],
      gaps,
      notes,
      remediation: gaps.length > 0 || status !== "satisfied" ? [...gaps] : [],
      rationale: buildRationale(control, status, score, results, declaredOnly),
      aiGenerated: false,
    });
  }

  // Chain the whole report at once so a single root hash commits to every
  // assertion made, and re-attach the chained records to their findings.
  const { records, root } = chainEvidence(drafts);
  const byControl = new Map<string, Evidence[]>();
  for (const record of records) {
    const list = byControl.get(record.controlId) ?? [];
    list.push(record);
    byControl.set(record.controlId, list);
  }
  for (const finding of findings) {
    finding.evidence = byControl.get(finding.control.id) ?? [];
  }

  return { findings, evidence: records, evidenceRoot: root };
}

function buildRationale(
  control: Control,
  status: ControlStatus,
  score: number,
  results: CollectorResult[],
  declaredOnly: boolean,
): string {
  const pct = Math.round(score * 100);
  const label = control.id.split(/[.:]/)[0]!;

  if (status === "satisfied" && declaredOnly) {
    return `${control.id} is marked satisfied on the basis of an operator attestation rather than an observed configuration. ${control.guidance} The attestation is not independently verifiable by this tool and should be backed by the referenced document.`;
  }
  if (status === "satisfied") {
    return `${control.id} is supported by ${results.length} passing assertion(s). ${control.guidance}`;
  }
  if (status === "partial") {
    return `${control.id} is partially evidenced: ${pct}% of its assertions passed and the remainder reported a shortfall. ${control.guidance}`;
  }
  if (status === "manual") {
    return `${control.id} could not be resolved automatically because the signal is not exposed through any available interface. ${control.guidance}`;
  }
  return `${control.id} has no passing evidence (0 of ${results.length} assertion(s)). ${control.guidance} This is reported against the ${label} criterion family.`;
}

/** Aggregates findings into the report summary block. */
export function summarize(findings: Finding[]): {
  total: number;
  satisfied: number;
  partial: number;
  gap: number;
  manual: number;
  notApplicable: number;
  overall: number;
  observedCoverage: number;
} {
  const count = (s: ControlStatus) =>
    findings.filter((f) => f.status === s).length;

  const total = findings.length;
  const satisfied = count("satisfied");
  const partial = count("partial");
  const gap = count("gap");
  const manual = count("manual");
  const notApplicable = count("not_applicable");

  const observable = total - manual - notApplicable;

  return {
    total,
    satisfied,
    partial,
    gap,
    manual,
    notApplicable,
    overall: total > 0 ? Number((satisfied / total).toFixed(4)) : 0,
    observedCoverage:
      observable > 0 ? Number((satisfied / observable).toFixed(4)) : 0,
  };
}

export { REMEDIATION_FALLBACK };