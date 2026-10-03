import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluate, summarize } from "../src/engine/evaluate.js";
import { getControl } from "../src/controls/index.js";
import type { Control } from "../src/types.js";
import type { CollectorContext, CollectorResult } from "../src/collectors/types.js";
import { emptyTree } from "../src/collectors/index.js";

/**
 * The status logic is the product's credibility claim, so it gets tested
 * adversarially: every path that could report a false pass is exercised.
 */

const observedAt = "2026-10-03T12:00:00.000Z";

function ctx(declarations: Record<string, unknown> = {}): CollectorContext {
  return {
    gh: {} as CollectorContext["gh"],
    target: { owner: "acme", repo: "widget" },
    defaultBranch: "main",
    declarations: declarations as CollectorContext["declarations"],
    warnings: [],
    offline: false,
    tree: emptyTree(),
  };
}

function result(partial: Partial<CollectorResult>): CollectorResult {
  return {
    title: "assertion",
    passed: false,
    source: "https://example.test",
    details: {},
    ...partial,
  };
}

function run(
  control: Control,
  results: CollectorResult[],
  declarations?: Record<string, unknown>,
) {
  return evaluate({
    controls: [control],
    resultsByCollector: new Map([[control.collector, results]]),
    ctx: ctx(declarations ?? {}),
    observedAt,
  });
}

describe("evaluate status logic", () => {
  const cc61 = getControl("CC6.1")!;

  it("marks a control satisfied only when every assertion passes with no gaps", () => {
    const { findings } = run(cc61, [
      result({ passed: true }),
      result({ passed: true }),
    ]);
    assert.equal(findings[0]!.status, "satisfied");
    assert.equal(findings[0]!.score, 1);
    assert.deepEqual(findings[0]!.gaps, []);
  });

  it("downgrades to partial when one assertion fails", () => {
    const { findings } = run(cc61, [
      result({ passed: true }),
      result({ passed: false }),
    ]);
    assert.equal(findings[0]!.status, "partial");
    assert.equal(findings[0]!.score, 0.5);
  });

  it("refuses to report satisfied when an assertion passed but reported a gap", () => {
    const { findings } = run(cc61, [
      result({ passed: true, gaps: ["still missing something"] }),
    ]);
    assert.equal(findings[0]!.status, "partial");
    assert.deepEqual(findings[0]!.gaps, ["still missing something"]);
  });

  it("reports a gap when nothing passed and the failure is observable", () => {
    const { findings } = run(cc61, [result({ passed: false })]);
    assert.equal(findings[0]!.status, "gap");
    assert.equal(findings[0]!.score, 0);
  });

  it("reports manual rather than gap when every assertion is unverifiable", () => {
    const { findings } = run(cc61, [
      result({ passed: false, unverifiable: true }),
      result({ passed: false, unverifiable: true }),
    ]);
    assert.equal(findings[0]!.status, "manual");
  });

  it("reports a gap when no evidence was collected at all", () => {
    const { findings } = run(cc61, []);
    assert.equal(findings[0]!.status, "gap");
    assert.match(findings[0]!.gaps[0]!, /No evidence was collected/);
  });

  it("never marks an unresolved manual control satisfied", () => {
    const manualControl = ALL_MANUAL();
    const { findings } = evaluate({
      controls: [manualControl],
      resultsByCollector: new Map(),
      ctx: ctx(),
      observedAt,
    });
    assert.equal(findings[0]!.status, "manual");
    assert.match(findings[0]!.gaps[0]!, /auditgen\.json/);
  });

  it("honours a genuine manual attestation without downgrading it", () => {
    const { findings } = evaluate({
      controls: [ALL_MANUAL()],
      resultsByCollector: new Map(),
      ctx: ctx({ riskRegisterMaintained: true }),
      observedAt,
    });
    assert.equal(findings[0]!.status, "satisfied");
    assert.ok(findings[0]!.evidence[0]!.details.attestation);
    assert.deepEqual(findings[0]!.gaps, []);
    // The advisory survives without being counted as a shortfall.
    assert.equal(findings[0]!.notes.length, 1);
    assert.match(findings[0]!.notes[0]!, /attested, not observed/);
  });

  it("ignores a manual attestation that is explicitly false", () => {
    const { findings } = evaluate({
      controls: [ALL_MANUAL()],
      resultsByCollector: new Map(),
      ctx: ctx({ riskRegisterMaintained: false }),
      observedAt,
    });
    assert.equal(findings[0]!.status, "manual");
  });
});

function ALL_MANUAL(): Control {
  return getControl("CC3.2")!;
}

describe("evidence chaining during evaluation", () => {
  it("chains every record across all controls into one root", () => {
    const controls = [getControl("CC6.1")!, getControl("CC8.1")!];
    const { findings, evidence, evidenceRoot } = evaluate({
      controls,
      resultsByCollector: new Map([
        ["github.two_factor", [result({ passed: true })]],
        ["github.pr_review", [result({ passed: false })]],
      ]),
      ctx: ctx(),
      observedAt,
    });

    assert.equal(evidence.length, 2);
    assert.equal(evidence[0]!.prevHash, "genesis");
    assert.equal(evidence[1]!.prevHash, evidence[0]!.hash);
    assert.equal(evidenceRoot, evidence[1]!.hash);
    // Records are attributed back to the right findings.
    assert.equal(findings[0]!.evidence[0]!.controlId, "CC6.1");
    assert.equal(findings[1]!.evidence[0]!.controlId, "CC8.1");
  });

  it("stamps the observation time on every record", () => {
    const { evidence } = evaluate({
      controls: [getControl("CC6.1")!],
      resultsByCollector: new Map([
        ["github.two_factor", [result({ passed: true })]],
      ]),
      ctx: ctx(),
      observedAt,
    });
    assert.equal(evidence[0]!.observedAt, observedAt);
  });
});

describe("summarize", () => {
  const mk = (status: Control["framework"] extends never ? never : string, manual = false) => ({
    control: { ...getControl("CC6.1")!, manual },
    status,
    score: status === "satisfied" ? 1 : 0,
    evidence: [
      {
        controlId: "CC6.1",
        collector: "c",
        title: "t",
        observedAt,
        source: "s",
        passed: status === "satisfied",
        details: {},
        hash: "h",
        prevHash: "genesis",
      },
    ],
    gaps: [],
    remediation: [],
    rationale: "",
    aiGenerated: false,
  });

  it("counts unattested controls against the overall figure", () => {
    const s = summarize([
      mk("satisfied"),
      mk("gap"),
      mk("manual", true),
    ] as never);
    assert.equal(s.total, 3);
    assert.equal(s.manual, 1);
    // One of three is satisfied overall, even though both observable controls
    // are accounted for: a control nobody can observe is not a free pass.
    assert.equal(s.overall, 0.3333);
    assert.equal(s.observedCoverage, 0.5);
  });

  it("reports zero rather than dividing by zero", () => {
    const s = summarize([mk("manual", true)] as never);
    assert.equal(s.overall, 0);
    assert.equal(s.observedCoverage, 0);
  });

  it("counts every bucket", () => {
    const s = summarize([
      mk("satisfied"),
      mk("satisfied"),
      mk("partial"),
      mk("gap"),
      mk("manual"),
      mk("not_applicable"),
    ] as never);
    assert.deepEqual(
      {
        total: s.total,
        satisfied: s.satisfied,
        partial: s.partial,
        gap: s.gap,
        manual: s.manual,
        notApplicable: s.notApplicable,
      },
      { total: 6, satisfied: 2, partial: 1, gap: 1, manual: 1, notApplicable: 1 },
    );
  });
});