import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ALL_CONTROLS,
  SOC2_CONTROLS,
  ISO27001_CONTROLS,
  controlsFor,
  getControl,
  collectorsNeeded,
} from "../src/controls/index.js";
import { getCollector, COLLECTORS } from "../src/collectors/index.js";
import { MANUAL_KEYS, MANUAL_SPECS } from "../src/collectors/manual.js";

describe("control registry", () => {
  it("has no duplicate control ids", () => {
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const c of ALL_CONTROLS) {
      if (seen.has(c.id)) dupes.push(c.id);
      seen.add(c.id);
    }
    assert.deepEqual(dupes, []);
  });

  it("maps every control to a collector that is actually registered", () => {
    const missing = ALL_CONTROLS.filter(
      (c) => c.collector !== "manual" && !getCollector(c.collector),
    ).map((c) => `${c.id} -> ${c.collector}`);
    assert.deepEqual(missing, [], `unregistered collectors: ${missing.join(", ")}`);
  });

  it("maps every manual control to a declaration key", () => {
    const manual = ALL_CONTROLS.filter((c) => c.manual);
    assert.ok(manual.length > 0, "expected some manual controls");
    // Every manual control must have an attestation spec, otherwise a satisfied
    // declaration could never be expressed and the control is permanently stuck.
    const unmapped = manual.filter((c) => !MANUAL_SPECS[c.id]);
    assert.deepEqual(
      unmapped.map((c) => c.id),
      [],
      `manual controls without an attestation key: ${unmapped.map((c) => c.id).join(", ")}`,
    );
    for (const key of Object.values(MANUAL_SPECS)) {
      assert.equal(
        ALL_CONTROLS.some((c) => c.manual && c.id in MANUAL_SPECS),
        true,
      );
      assert.ok(key.requirement.length > 20, "each spec needs a requirement");
      assert.ok(key.reference.length > 5, "each spec needs a reference");
    }
  });

  it("gives every control a requirement, guidance and category", () => {
    for (const c of ALL_CONTROLS) {
      assert.ok(c.requirement.length > 30, `${c.id} requirement too short`);
      assert.ok(c.guidance.length > 30, `${c.id} guidance too short`);
      assert.ok(c.category.length > 0, `${c.id} has no category`);
      assert.match(c.id, /^(CC\d+\.\d+|A\.\d+\.\d+|A1\.\d+)$/, `${c.id} malformed`);
    }
  });

  it("assigns each control the framework matching its id", () => {
    for (const c of ALL_CONTROLS) {
      if (c.id.startsWith("CC") || c.id.startsWith("A1")) {
        assert.equal(c.framework, "soc2", `${c.id} should be soc2`);
      } else {
        assert.equal(c.framework, "iso27001", `${c.id} should be iso27001`);
      }
    }
  });

  it("filters by framework", () => {
    assert.equal(controlsFor(["soc2"]).length, SOC2_CONTROLS.length);
    assert.equal(controlsFor(["iso27001"]).length, ISO27001_CONTROLS.length);
    assert.equal(
      controlsFor(["soc2", "iso27001"]).length,
      ALL_CONTROLS.length,
    );
    assert.deepEqual(controlsFor([]), []);
  });

  it("resolves a control by id", () => {
    assert.equal(getControl("CC6.1")?.title, "Logical access security");
    assert.equal(getControl("A.8.15")?.title, "Logging");
    assert.equal(getControl("nope"), undefined);
  });

  it("reports the collectors a control set needs, deduplicated", () => {
    const needed = collectorsNeeded(controlsFor(["soc2", "iso27001"]));
    assert.equal(new Set(needed).size, needed.length);
    assert.ok(needed.includes("github.branch_protection"));
    assert.ok(needed.includes("git.secret_history"));
    assert.ok(needed.includes("manual"));
  });

  it("registers every collector under its own name", () => {
    for (const c of COLLECTORS) {
      assert.equal(getCollector(c.name), c, `${c.name} not resolvable by name`);
      assert.match(
        c.name,
        /^(github|git|web)\.[a-z_]+$/,
        `${c.name} naming`,
      );
    }
  });

  it("covers a meaningful share of both frameworks", () => {
    // A registry that quietly shrinks is worse than one that never grew.
    assert.ok(
      controlsFor(["soc2"]).length >= 25,
      "expected at least 25 SOC 2 controls",
    );
    assert.ok(
      controlsFor(["iso27001"]).length >= 40,
      "expected at least 40 ISO 27001 controls",
    );
  });

  it("never routes two frameworks through the same collector name mismatch", () => {
    for (const c of ALL_CONTROLS) {
      if (c.manual) continue;
      assert.match(
        c.collector,
        /^(github|git|web)\./,
        `${c.id} has a malformed collector: ${c.collector}`,
      );
    }
  });
});