#!/usr/bin/env node
import { existsSync, writeFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import {
  loadConfigFile,
  findConfigFile,
  parseRepoSpec,
  resolveTarget,
  type AuditgenConfig,
} from "./config.js";
import { runAudit } from "./audit.js";
import { ALL_CONTROLS, controlsFor } from "./controls/index.js";
import { listCollectorNames } from "./controls/index.js";
import type { AuditOptions, Framework, Report } from "./types.js";
import { renderMarkdown, renderTerminal, serializeReport } from "./report/markdown.js";
import {
  generateStatementOfApplicability,
  generateSystemDescription,
} from "./report/docs.js";
import { verifyChain } from "./util/hash.js";
import { serveStdio } from "./mcp/server.js";

const VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Argument parsing. Small on purpose: auditgen ships with no dependencies, and
// a flag grammar this narrow does not justify a parser library.
// ---------------------------------------------------------------------------

interface Args {
  command: string;
  positional: string[];
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const [command = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!;
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const body = token.slice(2);
    const eq = body.indexOf("=");
    if (eq !== -1) {
      flags.set(body.slice(0, eq), body.slice(eq + 1));
      continue;
    }
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(body, next);
      i++;
    } else {
      flags.set(body, true);
    }
  }
  return { command, positional, flags };
}

function flagString(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function flagBool(args: Args, name: string): boolean {
  const v = args.flags.get(name);
  return v === true || v === "true";
}

function parseFrameworks(value: string | undefined): Framework[] | undefined {
  if (!value) return undefined;
  const parts = value
    .split(",")
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);
  const invalid = parts.filter((p) => p !== "soc2" && p !== "iso27001");
  if (invalid.length > 0) {
    throw new Error(
      `Unknown framework(s): ${invalid.join(", ")}. Valid: soc2, iso27001.`,
    );
  }
  return parts as Framework[];
}

function loadConfig(cwd: string): AuditgenConfig {
  const path = findConfigFile(cwd);
  if (!path) return {};
  return loadConfigFile(path);
}

function print(message: string): void {
  process.stdout.write(message.endsWith("\n") ? message : message + "\n");
}

function fail(message: string, code = 2): never {
  process.stderr.write(`auditgen: ${message}\n`);
  process.exit(code);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function help(): never {
  print(`auditgen ${VERSION} — git-native SOC 2 / ISO 27001 readiness auditor

Usage
  auditgen audit [owner/repo] [options]     Run an audit and print a report
  auditgen doc <type> [options]             Generate an auditor-facing document
  auditgen controls [options]               List every evaluable control
  auditgen verify <report.json>             Verify an evidence hash chain
  auditgen init                             Write a starter auditgen.json
  auditgen serve [owner/repo]               Run the MCP server on stdio
  auditgen --help

Audit options
  --framework <list>   soc2, iso27001, or both (default soc2, or from config)
  --format <fmt>       terminal | markdown | json   (default terminal)
  --out <path>         Write the report to a file
  --only <ids>         Comma-separated control ids, e.g. CC6.1,A.8.15
  --skip <names>       Comma-separated collectors to skip
  --no-ai              Do not call an AI endpoint for narrative text
  --offline            Skip GitHub API calls; use local repository checks only
  --config <path>      Load a specific auditgen.json
  --period <text>      Period covered, used by generated documents
  --prepared-by <text> Author of a generated document

Document types
  system_description            SOC 2 System Description
  statement_of_applicability   ISO/IEC 27001:2022 Statement of Applicability

Environment
  GITHUB_TOKEN / GH_TOKEN   GitHub token (repo scope is enough)
  AUDITGEN_REPO             default repository for \`auditgen serve\`

Exit codes
  0  no gaps    1  gaps found    2  error

Examples
  auditgen audit
  auditgen audit opencode-ai/opencode --framework soc2,iso27001 --format markdown
  auditgen audit --offline
  auditgen doc system_description --period "1 Apr 2026 to 30 Jun 2026"`);
  process.exit(0);
}

function resolveTargetArg(args: Args, cwd: string) {
  const explicit = args.positional[0];
  if (explicit) {
    const { owner, repo } = parseRepoSpec(explicit);
    return { owner, repo, localPath: cwd };
  }
  const fromGit = resolveTarget(cwd);
  if (!fromGit) {
    fail(
      "Could not determine the repository. Run inside a git clone with an origin remote, or pass owner/repo explicitly.",
    );
  }
  return fromGit;
}

async function commandAudit(args: Args): Promise<number> {
  const cwd = process.cwd();
  const configPath = flagString(args, "config");
  const config = configPath
    ? loadConfigFile(resolve(cwd, configPath))
    : loadConfig(cwd);

  const target = resolveTargetArg(args, cwd);
  const frameworks = parseFrameworks(flagString(args, "framework")) ?? [];

  const options: AuditOptions = {
    target,
    frameworks,
    ...(flagString(args, "only")
      ? { onlyControls: flagString(args, "only")!.split(",").map((s) => s.trim()) }
      : {}),
    ...(flagString(args, "skip")
      ? { skipCollectors: flagString(args, "skip")!.split(",").map((s) => s.trim()) }
      : {}),
    noAi: flagBool(args, "no-ai"),
    offline: flagBool(args, "offline"),
    ...(flagString(args, "token") ? { token: flagString(args, "token")! } : {}),
  };

  const { report, judgeNote } = await runAudit(options, config);

  const format = (flagString(args, "format") ?? "terminal").toLowerCase();
  const body =
    format === "json"
      ? serializeReport(report)
      : format === "markdown"
        ? renderMarkdown(report)
        : renderTerminal(report);

  const outPath = flagString(args, "out");
  if (outPath) {
    const full = resolve(cwd, outPath);
    writeFileSync(full, body.endsWith("\n") ? body : body + "\n", "utf8");
    print(`wrote ${outPath}`);
    if (judgeNote) print(`note: ${judgeNote}`);
  } else {
    process.stdout.write(body.endsWith("\n") ? body : body + "\n");
    if (judgeNote) process.stderr.write(`note: ${judgeNote}\n`);
  }

  return report.summary.gap > 0 || report.summary.partial > 0 ? 1 : 0;
}

async function commandDoc(args: Args): Promise<number> {
  const cwd = process.cwd();
  const type = args.positional[0];
  if (type !== "system_description" && type !== "statement_of_applicability") {
    fail(
      `Unknown document type "${type ?? "(none)"}". Expected system_description or statement_of_applicability.`,
    );
  }

  const configPath = flagString(args, "config");
  const config = configPath
    ? loadConfigFile(resolve(cwd, configPath))
    : loadConfig(cwd);

  const target = resolveTargetArg(args, cwd);
  const frameworks: Framework[] =
    type === "system_description" ? ["soc2"] : ["iso27001"];

  const { report } = await runAudit(
    {
      target,
      frameworks,
      noAi: flagBool(args, "no-ai"),
      offline: flagBool(args, "offline"),
    },
    config,
  );

  const input = {
    report,
    config,
    ...(flagString(args, "period") ? { period: flagString(args, "period")! } : {}),
    ...(flagString(args, "prepared-by")
      ? { preparedBy: flagString(args, "prepared-by")! }
      : {}),
  };

  const markdown =
    type === "system_description"
      ? generateSystemDescription(input)
      : generateStatementOfApplicability(input);

  const outPath = flagString(args, "out") ?? `${type}.md`;
  writeFileSync(resolve(cwd, outPath), markdown, "utf8");
  print(`wrote ${outPath}`);
  print(
    "This is a draft. Fields marked TODO cannot be derived from the repository and need a human.",
  );
  return 0;
}

function commandControls(args: Args): never {
  const framework = parseFrameworks(flagString(args, "framework"))?.[0];
  const list = framework
    ? controlsFor([framework])
    : ALL_CONTROLS;

  print(`${list.length} controls\n`);
  for (const c of list) {
    const via = c.manual ? "operator attested" : `via ${c.collector}`;
    print(`${c.id.padEnd(8)} ${c.framework.padEnd(9)} ${c.title}`);
    print(`${" ".repeat(8)} ${via}`);
    print(`${" ".repeat(8)} ${c.requirement.slice(0, 100)}`);
    print("");
  }
  print(`collectors: ${listCollectorNames().join(", ")}`);
  process.exit(0);
}

function commandVerify(args: Args): number {
  const path = args.positional[0];
  if (!path) fail("Provide a report path: auditgen verify auditgen-report.json");
  const full = resolve(process.cwd(), path);
  if (!existsSync(full)) fail(`No such file: ${path}`);

  let report: Report;
  try {
    report = JSON.parse(readFileSync(full, "utf8")) as Report;
  } catch (err) {
    fail(`${path} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }

  const evidence = report.findings.flatMap((f) => f.evidence);
  const result = verifyChain(evidence);

  if (result.valid && result.root === report.evidenceRoot) {
    print(`ok  ${evidence.length} evidence records`);
    print(`    chain root matches report: ${result.root}`);
    return 0;
  }

  if (!result.valid) {
    process.stderr.write(
      `FAILED  evidence record ${result.brokenAt} does not match its hash\n`,
    );
    process.stderr.write(
      "A record was modified after the report was generated. Treat the report as untrustworthy.\n",
    );
  } else {
    process.stderr.write(
      `FAILED  chain root is ${result.root} but the report claims ${report.evidenceRoot}\n`,
    );
    process.stderr.write(
      "Evidence was reordered, added, or removed after generation.\n",
    );
  }
  return 1;
}

function commandInit(): number {
  const target = resolve(process.cwd(), "auditgen.json");
  if (existsSync(target)) {
    fail("auditgen.json already exists. Edit it directly rather than overwriting.");
  }
  const { owner, repo } = (() => {
    const t = resolveTarget(process.cwd());
    return t ?? { owner: "<owner>", repo: "<repo>" };
  })();

  const template = {
    $schema: "https://auditgen.dev/schema.json",
    organizationName: "",
    systemName: `${owner}/${repo}`,
    systemDescription:
      "",
    hostingEnvironment: "",
    dataCategories: [],
    trustServicesCriteria: ["Security (Common Criteria, CC1-CC9)"],
    frameworks: ["soc2"],
    twoFactorEnforced: false,
    riskRegisterMaintained: false,
    backupRecoveryTested: false,
    physicalSecurityCovered: false,
  };
  writeFileSync(target, JSON.stringify(template, null, 2) + "\n", "utf8");
  print("wrote auditgen.json");
  print("");
  print("Fill in organizationName and systemDescription, then set any attestation");
  print("you can genuinely evidence. Every false stays false until you have proof.");
  return 0;
}

function commandServe(args: Args): never {
  const cwd = process.cwd();
  const positional = args.positional[0];
  const repo =
    positional ??
    process.env.AUDITGEN_REPO ??
    process.env.GITHUB_REPOSITITY ??
    (() => {
      const t = resolveTarget(cwd);
      return t ? `${t.owner}/${t.repo}` : undefined;
    })();

  serveStdio({
    cwd,
    ...(repo ? { repo } : {}),
    frameworks: parseFrameworks(flagString(args, "framework")) ?? ["soc2", "iso27001"],
    noAi: flagBool(args, "no-ai"),
  });
  process.exit(0);
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (flagBool(args, "help") || flagBool(args, "h") || args.command === "help") {
    help();
  }
  if (flagBool(args, "version") || flagBool(args, "v")) {
    print(VERSION);
    process.exit(0);
  }

  let code = 0;
  switch (args.command) {
    case "audit":
      code = await commandAudit(args);
      break;
    case "doc":
      code = await commandDoc(args);
      break;
    case "controls":
      commandControls(args);
      break;
    case "verify":
      code = commandVerify(args);
      break;
    case "init":
      code = commandInit();
      break;
    case "serve":
      commandServe(args);
      break;
    default:
      process.stderr.write(
        `auditgen: unknown command "${args.command}". Run \`auditgen --help\`.\n`,
      );
      code = 2;
  }

  process.exit(code);
}

main().catch((err: unknown) => {
  process.stderr.write(
    `auditgen: ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(2);
});