import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { diffReports, renderDiff } from "../src/report/diff.js";
import type { ControlStatus, Report } from "../src/types.js";
import { getControl } from "../src/controls/index.js";

function report(
  statuses: Record<string, ControlStatus>,
  generatedAt: string,
  repo = "acme/widget",
): Report {
  const findings = Object.entries(statuses).map(([id, status]) => {
    const control = getControl(id)!;
    return {
      control,
      status,
      score: status === "satisfied" ? 1 : status === "partial" ? 0.5 : 0,
      evidence: [],
      gaps: [],
      notes: [],
      remediation: [],
      rationale: "",
      aiGenerated: false,
    };
  });
  return {
    schemaVersion: 1,
    generatedAt,
    generator: { name: "auditgen", version: "0.1.0" },
    target: { owner: repo.split("/")[0]!, repo: repo.split("/")[1]! },
    frameworks: ["soc2"],
    findings,
    summary: {
      total: findings.length,
      satisfied: findings.filter((f) => f.status === "satisfied").length,
      partial: findings.filter((f) => f.status === "partial").length,
      gap: findings.filter((f) => f.status === "gap").length,
      manual: findings.filter((f) => f.status === "manual").length,
      notApplicable: 0,
      overall: 0,
      observedCoverage: 0,
    },
    evidenceRoot: generatedAt,
    warnings: [],
    durationMs: 1,
  };
}

describe("diffReports", () => {
  const before = report(
    { "CC6.1": "gap", "CC8.1": "satisfied", "CC7.4": "partial" },
    "2026-10-01T00:00:00.000Z",
  );

  it("detects an improvement", () => {
    const after = report(
      { "CC6.1": "satisfied", "CC8.1": "satisfied", "CC7.4": "partial" },
      "2026-10-03T00:00:00.000Z",
    );
    const d = diffReports(before, after);
    assert.equal(d.summary.improved, 1);
    assert.equal(d.deltas.find((x) => x.id === "CC6.1")?.change, "improved");
  });

  it("detects a regression", () => {
    const after = report(
      { "CC6.1": "gap", "CC8.1": "gap", "CC7.4": "partial" },
      "2026-10-03T00:00:00.000Z",
    );
    const d = diffReports(before, after);
    assert.equal(d.summary.regressed, 1);
    assert.equal(d.deltas.find((x) => x.id === "CC8.1")?.change, "regressed");
  });

  it("treats satisfied to partial as a regression, not an improvement", () => {
    const b = report({ "CC6.1": "satisfied" }, "2026-10-01T00:00:00.000Z");
    const a = report({ "CC6.1": "partial" }, "2026-10-03T00:00:00.000Z");
    assert.equal(diffReports(b, a).summary.regressed, 1);
  });

  it("treats partial to manual as a regression", () => {
    const b = report({ "CC6.1": "partial" }, "2026-10-01T00:00:00.000Z");
    const a = report({ "CC6.1": "manual" }, "2026-10-03T00:00:00.000Z");
    assert.equal(diffReports(b, a).summary.regressed, 1);
  });

  it("identifies controls added and removed between versions", () => {
    const after = report(
      {
        "CC6.1": "gap",
        "CC8.1": "satisfied",
        "CC7.4": "partial",
        "CC5.2": "gap",
      },
      "2026-10-03T00:00:00.000Z",
    );
    const d = diffReports(before, after);
    assert.equal(d.summary.added, 1);
    assert.equal(d.deltas.find((x) => x.id === "CC5.2")?.change, "added");
  });

  it("flags a comparison across different repositories", () => {
    const other = report({ "CC6.1": "satisfied" }, "2026-10-03T00:00:00.000Z", "acme/other");
    const d = diffReports(before, other);
    assert.equal(d.mismatchedRepository, true);
    assert.match(renderDiff(d), /different repositories/);
  });

  it("puts regressions first in the rendering", () => {
    const after = report(
      {
        "CC6.1": "satisfied",
        "CC8.1": "gap",
        "CC7.4": "partial",
      },
      "2026-10-03T00:00:00.000Z",
    );
    const out = renderDiff(diffReports(before, after));
    assert.ok(out.indexOf("CC8.1") < out.indexOf("CC6.1"));
  });

  it("reports no change when statuses are identical", () => {
    const after = report(
      { "CC6.1": "gap", "CC8.1": "satisfied", "CC7.4": "partial" },
      "2026-10-03T00:00:00.000Z",
    );
    const d = diffReports(before, after);
    assert.equal(d.summary.unchanged, 3);
    assert.match(renderDiff(d), /No control changed status/);
  });
});