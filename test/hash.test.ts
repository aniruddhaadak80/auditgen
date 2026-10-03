import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalize,
  chainEvidence,
  verifyChain,
  sha256,
  GENESIS,
} from "../src/util/hash.js";

describe("canonicalize", () => {
  it("is independent of key insertion order", () => {
    const a = canonicalize({ b: 1, a: 2, c: { y: 1, x: 2 } });
    const b = canonicalize({ c: { x: 2, y: 1 }, a: 2, b: 1 });
    assert.equal(a, b);
  });

  it("preserves array order", () => {
    assert.notEqual(canonicalize([1, 2]), canonicalize([2, 1]));
  });

  it("drops undefined values so an absent key and an undefined key hash alike", () => {
    assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }));
  });

  it("serializes non-finite numbers as null rather than invalid JSON", () => {
    assert.equal(canonicalize({ n: NaN }), '{"n":null}');
    assert.equal(canonicalize({ n: Infinity }), '{"n":null}');
  });
});

describe("chainEvidence", () => {
  const base = [
    {
      controlId: "CC6.1",
      collector: "c1",
      title: "first",
      observedAt: "2026-10-03T00:00:00.000Z",
      source: "https://example.test/a",
      passed: true,
      details: { x: 1 },
    },
    {
      controlId: "CC8.1",
      collector: "c2",
      title: "second",
      observedAt: "2026-10-03T00:00:01.000Z",
      source: "https://example.test/b",
      passed: false,
      details: { y: "z" },
    },
  ];

  it("links the first record to genesis", () => {
    const { records } = chainEvidence(base);
    assert.equal(records[0]!.prevHash, GENESIS);
    assert.equal(records[1]!.prevHash, records[0]!.hash);
  });

  it("produces a stable root across runs", () => {
    const first = chainEvidence(base).root;
    const second = chainEvidence([...base].reverse().reverse()).root;
    assert.equal(first, second);
    assert.match(first, /^[0-9a-f]{64}$/);
  });

  it("changes the root when any record changes", () => {
    const original = chainEvidence(base).root;
    const tampered = structuredClone(base);
    tampered[1]!.passed = true;
    assert.notEqual(chainEvidence(tampered).root, original);
  });

  it("changes the root when records are reordered", () => {
    const reordered = [base[1]!, base[0]!];
    assert.notEqual(chainEvidence(reordered).root, chainEvidence(base).root);
  });

  it("verifies an untouched chain", () => {
    const { records, root } = chainEvidence(base);
    const result = verifyChain(records);
    assert.equal(result.valid, true);
    assert.equal(result.root, root);
  });

  it("detects an edited assertion and reports where", () => {
    const { records } = chainEvidence(base);
    records[1]!.title = "quietly changed";
    const result = verifyChain(records);
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 1);
  });

  it("detects an inserted record", () => {
    const { records } = chainEvidence(base);
    const inserted = records.slice(0, 1);
    inserted.push({
      ...records[0]!,
      controlId: "CC9.9",
      title: "inserted",
      prevHash: records[0]!.prevHash,
      hash: records[0]!.hash,
    });
    inserted.push(records[1]!);
    assert.equal(verifyChain(inserted).valid, false);
  });

  it("detects a deleted record", () => {
    const { records } = chainEvidence(base);
    assert.equal(verifyChain(records.slice(0, 1)).valid, true);
    // Deleting the tail leaves a valid prefix but a root that no longer matches
    // the report, which is exactly why the report carries the root.
    assert.notEqual(verifyChain(records.slice(0, 1)).root, chainEvidence(base).root);
  });

  it("handles an empty chain", () => {
    const { records, root } = chainEvidence([]);
    assert.equal(records.length, 0);
    assert.equal(root, GENESIS);
    assert.equal(verifyChain([]).valid, true);
  });
});

describe("sha256", () => {
  it("matches a known vector", () => {
    assert.equal(
      sha256("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});