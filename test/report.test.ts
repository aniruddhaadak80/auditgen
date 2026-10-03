import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseGitHubRemote,
  parseRepoSpec,
  loadConfigFile,
  findConfigFile,
} from "../src/config.js";
import { parseThirdPartyActions } from "../src/collectors/github.js";
import { __testing as gitInternals } from "../src/collectors/git.js";
import { extractJsonObject, resolveJudgeConfig } from "../src/engine/judge.js";
import { renderMarkdown, renderTerminal, serializeReport } from "../src/report/markdown.js";
import {
  generateSystemDescription,
  generateStatementOfApplicability,
} from "../src/report/docs.js";
import { evaluate } from "../src/engine/evaluate.js";
import { getControl } from "../src/controls/index.js";
import type { CollectorContext, CollectorResult } from "../src/collectors/types.js";
import { emptyTree } from "../src/collectors/index.js";
import { summarize } from "../src/engine/evaluate.js";
import type { Report } from "../src/types.js";

describe("parseGitHubRemote", () => {
  const cases: [string, string, string][] = [
    ["https://github.com/aniruddhaadak80/auditgen.git", "aniruddhaadak80", "auditgen"],
    ["https://github.com/aniruddhaadak80/auditgen", "aniruddhaadak80", "auditgen"],
    ["git@github.com:aniruddhaadak80/auditgen.git", "aniruddhaadak80", "auditgen"],
    ["ssh://git@github.com/aniruddhaadak80/auditgen.git", "aniruddhaadak80", "auditgen"],
    ["https://github.com/org/repo.with.dots", "org", "repo.with.dots"],
    ["  https://github.com/org/thing  ", "org", "thing"],
  ];
  for (const [input, owner, repo] of cases) {
    it(`parses ${input}`, () => {
      assert.deepEqual(parseGitHubRemote(input), { owner, repo });
    });
  }

  it("returns undefined for a non-GitHub remote", () => {
    assert.equal(parseGitHubRemote("https://gitlab.com/o/r.git"), undefined);
    assert.equal(parseGitHubRemote("not a url"), undefined);
  });
});

describe("parseRepoSpec", () => {
  it("accepts owner/repo", () => {
    assert.deepEqual(parseRepoSpec("acme/widget"), {
      owner: "acme",
      repo: "widget",
    });
  });

  it("accepts a full GitHub URL", () => {
    assert.deepEqual(parseRepoSpec("https://github.com/acme/widget"), {
      owner: "acme",
      repo: "widget",
    });
  });

  it("rejects a bare name", () => {
    assert.throws(() => parseRepoSpec("widget"), /Cannot parse/);
  });
});

describe("parseThirdPartyActions", () => {
  it("detects an unpinned third-party tag", () => {
    const out = parseThirdPartyActions(
      "jobs:\n  steps:\n    - uses: someorg/action@v1.2.3\n",
    );
    assert.equal(out.length, 1);
    assert.equal(out[0]!.action, "someorg/action");
    assert.equal(out[0]!.pinned, false);
  });

  it("treats a 40-character sha as pinned", () => {
    const out = parseThirdPartyActions(
      "      - uses: someorg/action@" +
        "a".repeat(40) +
        "\n",
    );
    assert.equal(out[0]!.pinned, true);
  });

  it("ignores local actions", () => {
    assert.deepEqual(parseThirdPartyActions("      - uses: ./.github/actions/x\n"), []);
  });
});

describe("git secret scanner internals", () => {
  it("does not flag documentation placeholders", () => {
    for (const line of [
      'api_key = "your-api-key-here"',
      "token: ${GITHUB_TOKEN}",
      "password: <your-password>",
      "AWS_KEY=AKIAIOSFODNN7EXAMPLE  # example",
      "key = process.env.OPENAI_API_KEY",
    ]) {
      assert.equal(gitInternals.isPlaceholder(line), true, line);
    }
  });

  it("does flag a bare credential", () => {
    assert.equal(
      gitInternals.isPlaceholder('aws_key = "AKIA3JKL2M9N8P7Q6R5T4V3W2X"'),
      false,
    );
  });

  it("treats AWS's documented example key as a placeholder", () => {
    // AKIAIOSFODNN7EXAMPLE is the key AWS prints in its own documentation. It is
    // not a credential, so flagging it would train operators to ignore findings.
    assert.equal(gitInternals.isPlaceholder("AKIAIOSFODNN7EXAMPLE"), true);
  });

  it("redacts a secret rather than storing it", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const out = gitInternals.redact(secret);
    assert.ok(!out.includes(secret), "redaction leaked the secret");
    assert.ok(out.startsWith("AKIA"));
    assert.match(out, /len=20/);
    assert.match(out, /sha256=[0-9a-f]{16}/);
  });
});

describe("judge", () => {
  it("requires a base URL and says which variable to set", () => {
    const prior = { ...process.env };
    delete process.env.AUDITGEN_AI_BASE_URL;
    delete process.env.OPENAI_BASE_URL;
    delete process.env.OPENROUTER_BASE_URL;
    const res = resolveJudgeConfig();
    assert.ok("error" in res);
    assert.match(res.error, /AUDITGEN_AI_BASE_URL/);
    process.env = prior;
  });

  it("refuses to guess a model for an unknown provider", () => {
    const prior = { ...process.env };
    delete process.env.AUDITGEN_AI_MODEL;
    const res = resolveJudgeConfig({ baseUrl: "https://some.gguf.host/v1" });
    assert.ok("error" in res);
    assert.match(res.error, /AUDITGEN_AI_MODEL/);
    process.env = prior;
  });

  it("uses a known default model for the OpenAI API", () => {
    const res = resolveJudgeConfig({ baseUrl: "https://api.openai.com/v1" });
    assert.ok(!("error" in res));
    assert.equal(res.model, "gpt-4o-mini");
  });

  it("extracts JSON from fenced and prose-wrapped output", () => {
    assert.deepEqual(extractJsonObject('```json\n{"a":1}\n```'), '{"a":1}');
    assert.deepEqual(extractJsonObject('Here you go: {"a":1} done'), '{"a":1}');
    assert.deepEqual(extractJsonObject('{"a":1}'), '{"a":1}');
  });
});

function buildReport(): Report {
  const controls = [
    getControl("CC6.1")!,
    getControl("CC8.1")!,
    getControl("CC3.2")!,
  ];
  const results = (
    id: string,
    r: Partial<CollectorResult>,
  ): CollectorResult => ({
    title: `${id} assertion`,
    passed: true,
    source: "https://example.test",
    details: {},
    ...r,
  });

  const context: CollectorContext = {
    gh: {} as CollectorContext["gh"],
    target: { owner: "acme", repo: "widget", localPath: "/tmp/widget" },
    defaultBranch: "main",
    declarations: {},
    warnings: ["one warning"],
    offline: false,
    tree: emptyTree(),
  };

  const { findings, evidenceRoot } = evaluate({
    controls,
    resultsByCollector: new Map([
      ["github.two_factor", [results("CC6.1", { passed: false, unverifiable: true })]],
      [
        "github.pr_review",
        [results("CC8.1", { passed: false, gaps: ["no approving reviews required"] })],
      ],
    ]),
    ctx: context,
    observedAt: "2026-10-03T12:00:00.000Z",
  });

  return {
    schemaVersion: 1,
    generatedAt: "2026-10-03T12:00:00.000Z",
    generator: { name: "auditgen", version: "0.1.0" },
    target: context.target,
    frameworks: ["soc2"],
    findings,
    summary: summarize(findings),
    evidenceRoot,
    warnings: context.warnings,
    durationMs: 42,
  };
}

describe("report rendering", () => {
  const report = buildReport();

  it("renders markdown with every control id", () => {
    const md = renderMarkdown(report);
    assert.match(md, /# Compliance report — acme\/widget/);
    for (const f of report.findings) {
      assert.ok(md.includes(f.control.id), `missing ${f.control.id}`);
    }
  });

  it("states plainly that it is not an attestation", () => {
    assert.match(renderMarkdown(report), /not an attestation/);
  });

  it("surfaces gaps before the full matrix", () => {
    const md = renderMarkdown(report);
    assert.ok(
      md.indexOf("Findings requiring action") < md.indexOf("## Control matrix"),
    );
  });

  it("publishes the evidence chain root and the verify command", () => {
    const md = renderMarkdown(report);
    assert.ok(md.includes(report.evidenceRoot));
    assert.match(md, /auditgen verify/);
  });

  it("includes collection warnings", () => {
    assert.match(renderMarkdown(report), /one warning/);
  });

  it("renders a terminal summary with a coverage bar", () => {
    const out = renderTerminal(report);
    assert.match(out, /[█░]/);
    assert.match(out, /acme\/widget/);
    assert.match(out, /Needs work/);
  });

  it("round-trips JSON", () => {
    const parsed = JSON.parse(serializeReport(report)) as Report;
    assert.equal(parsed.evidenceRoot, report.evidenceRoot);
    assert.equal(parsed.findings.length, report.findings.length);
  });
});

describe("document generation", () => {
  const report = buildReport();

  it("marks the System Description as a draft with explicit TODOs", () => {
    const doc = generateSystemDescription({
      report,
      config: { organizationName: "Acme" },
    });
    assert.match(doc, /^# System Description/);
    assert.match(doc, /DRAFT generated by auditgen/);
    assert.ok(doc.includes("TODO"));
    assert.match(doc, /## 4\. Components of the system/);
    assert.match(doc, /## 7\. Criteria in scope/);
  });

  it("does not treat a blank system description as a described one", () => {
    const doc = generateSystemDescription({ report, config: {} });
    assert.ok(
      doc.includes("<!-- TODO: complete before submitting to the auditor -->"),
    );
    // The commitments section must still ask the operator, not assert one.
    assert.match(doc, /TODO: state the commitments made to customers/);
  });

  it("marks the Statement of Applicability as partial coverage of Annex A", () => {
    const reportAll = { ...report, frameworks: ["iso27001"] as const };
    const doc = generateStatementOfApplicability({
      report: { ...reportAll, frameworks: ["iso27001"] },
      config: { organizationName: "Acme" },
    });
    assert.match(doc, /^# Statement of Applicability/);
    assert.match(doc, /Controls in this statement \| \d+ of 93/);
    assert.match(doc, /ISO\/IEC 27001:2022 permits exclusion/);
  });
});