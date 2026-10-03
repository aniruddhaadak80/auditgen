import { createInterface } from "node:readline";
import { runAudit } from "../audit.js";
import { ALL_CONTROLS, getControl } from "../controls/index.js";
import { loadConfigFile, parseRepoSpec } from "../config.js";
import type { AuditOptions, Report } from "../types.js";
import { generateStatementOfApplicability, generateSystemDescription } from "../report/docs.js";
import { renderMarkdown } from "../report/markdown.js";

/**
 * MCP stdio server.
 *
 * Exposes an audit to any MCP-capable agent, so "are we audit ready, and what is
 * our weakest control" is answerable by the model without reading a single file.
 * Implemented directly against JSON-RPC rather than through the SDK to keep the
 * package dependency-free.
 */

const PROTOCOL_VERSION = "2025-06-18";

interface RpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface RpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string };
}

export interface ServerOptions {
  /** owner/repo to audit. Defaults to AUDITGEN_REPO. */
  repo?: string;
  cwd: string;
  frameworks?: ("soc2" | "iso27001")[];
  noAi?: boolean;
}

const TOOLS = [
  {
    name: "audit_status",
    description:
      "Run or reuse a SOC 2 / ISO 27001 readiness audit and return the coverage summary plus the highest-priority findings. Use this first to learn whether the repository is audit ready.",
    inputSchema: {
      type: "object",
      properties: {
        refresh: {
          type: "boolean",
          description:
            "Re-run collection instead of returning the cached report. Needed when the repository changed since the last audit.",
          default: false,
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_findings",
    description:
      "List control findings, worst first. Filter by status (gap, partial, manual, satisfied) and framework (soc2, iso27001).",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["gap", "partial", "manual", "satisfied", "any"],
          default: "any",
        },
        framework: {
          type: "string",
          enum: ["soc2", "iso27001", "any"],
          default: "any",
        },
        limit: { type: "integer", default: 20, minimum: 1, maximum: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_control",
    description:
      "Return the full record for one control: criterion text, status, every evidence assertion with its source link and hash, detected shortfalls and remediation steps.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: 'Control identifier, for example "CC6.1" or "A.8.15".',
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "generate_document",
    description:
      "Generate an auditor-facing draft document. type=system_description produces a SOC 2 System Description; type=statement_of_applicability produces an ISO 27001:2022 Statement of Applicability. Both need a human to complete fields auditgen cannot know.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: ["system_description", "statement_of_applicability"],
        },
        period: {
          type: "string",
          description:
            "Period covered, for example '1 April 2026 to 30 June 2026'.",
        },
        preparedBy: { type: "string" },
      },
      required: ["type"],
      additionalProperties: false,
    },
  },
  {
    name: "list_controls",
    description:
      "List every control auditgen can evaluate, with its framework, title and the collector that gathers its evidence.",
    inputSchema: {
      type: "object",
      properties: {
        framework: { type: "string", enum: ["soc2", "iso27001", "any"] },
      },
      additionalProperties: false,
    },
  },
];

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

export class AuditgenMcpServer {
  private cache?: Report;
  private inflight?: Promise<Report>;

  constructor(private readonly options: ServerOptions) {}

  private resolveRepoArg(): { owner: string; repo: string } {
    const spec =
      this.options.repo ??
      process.env.AUDITGEN_REPO ??
      process.env.GITHUB_REPOSITORY;
    if (!spec) {
      throw new Error(
        "No repository configured. Set AUDITGEN_REPO to owner/repo when starting the server.",
      );
    }
    return parseRepoSpec(spec);
  }

  private async report(force = false): Promise<Report> {
    if (!force && this.cache) return this.cache;
    if (!force && this.inflight) return this.inflight;

    const { owner, repo } = this.resolveRepoArg();
    const { config } = (() => {
      try {
        return { config: loadConfigFile(`${this.options.cwd}/auditgen.json`) };
      } catch {
        return { config: {} };
      }
    })();

    const auditOptions: AuditOptions = {
      target: { owner, repo, localPath: this.options.cwd },
      frameworks: this.options.frameworks ?? ["soc2"],
      noAi: this.options.noAi ?? true,
    };

    this.inflight = runAudit(auditOptions, config).then((r) => {
      this.cache = r.report;
      this.inflight = undefined;
      return r.report;
    });
    return this.inflight;
  }

  async handle(req: RpcRequest): Promise<RpcResponse | undefined> {
    const id = req.id ?? null;

    switch (req.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: "auditgen", version: "0.1.0" },
          },
        };

      case "notifications/initialized":
        return undefined;

      case "ping":
        return { jsonrpc: "2.0", id, result: {} };

      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: TOOLS } };

      case "tools/call": {
        const name = req.params?.name as string | undefined;
        const args = (req.params?.arguments ?? {}) as Record<string, unknown>;
        try {
          return {
            jsonrpc: "2.0",
            id,
            result: textResult(await this.callTool(name ?? "", args)),
          };
        } catch (err) {
          return {
            jsonrpc: "2.0",
            id,
            error: {
              code: -32000,
              message: err instanceof Error ? err.message : String(err),
            },
          };
        }
      }

      default:
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Unknown method: ${req.method}` },
        };
    }
  }

  private async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<string> {
    switch (name) {
      case "audit_status": {
        const report = await this.report(Boolean(args.refresh));
        const worst = report.findings
          .filter((f) => f.status === "gap" || f.status === "partial")
          .slice(0, 8)
          .map(
            (f) =>
              `- ${f.control.id} (${f.status}) ${f.control.title}: ${f.gaps[0] ?? f.rationale}`,
          );
        return [
          `Audit of ${report.target.owner}/${report.target.repo} generated ${report.generatedAt}.`,
          `${report.summary.satisfied} of ${report.summary.total} controls satisfied (${(report.summary.overall * 100).toFixed(0)}% overall).`,
          `${report.summary.gap} gaps, ${report.summary.partial} partial, ${report.summary.manual} awaiting operator attestation.`,
          report.summary.manual > 0
            ? `Of the ${report.summary.total - report.summary.manual - report.summary.notApplicable} observable control(s), ${(report.summary.observedCoverage * 100).toFixed(0)}% are satisfied. Unattested controls are not free.`
            : "Every evaluated control was observable.",
          "",
          "Highest priority findings:",
          ...(worst.length ? worst : ["- none"]),
          "",
          `Evidence chain root: ${report.evidenceRoot}`,
        ].join("\n");
      }

      case "list_findings": {
        const report = await this.report();
        const status = String(args.status ?? "any");
        const framework = String(args.framework ?? "any");
        const limit = Number(args.limit ?? 20);
        const order: Record<string, number> = {
          gap: 0,
          partial: 1,
          manual: 2,
          satisfied: 3,
        };
        const list = report.findings
          .filter((f) => status === "any" || f.status === status)
          .filter(
            (f) =>
              framework === "any" || f.control.framework === framework,
          )
          .sort(
            (a, b) =>
              (order[a.status] ?? 9) - (order[b.status] ?? 9) ||
              a.score - b.score,
          )
          .slice(0, Math.max(1, Math.min(200, limit)));
        if (list.length === 0) return "No findings matched those filters.";
        return list
          .map((f) =>
            [
              `${f.control.id} [${f.status}] ${f.control.title}`,
              `  ${f.rationale}`,
              ...f.gaps.map((g) => `  gap: ${g}`),
              ...f.remediation.slice(0, 3).map((r) => `  fix: ${r}`),
            ].join("\n"),
          )
          .join("\n\n");
      }

      case "get_control": {
        const id = String(args.id ?? "").toUpperCase();
        const report = await this.report();
        const finding = report.findings.find(
          (f) => f.control.id.toUpperCase() === id,
        );
        if (!finding) {
          const known = getControl(id);
          return known
            ? `${id} exists in this build but was not in scope for this run. Re-run with the framework that includes it.`
            : `Unknown control "${id}". Known: ${ALL_CONTROLS.map((c) => c.id).join(", ")}`;
        }
        const lines = [
          `${finding.control.id} — ${finding.control.title}`,
          `Framework: ${finding.control.framework}`,
          `Status: ${finding.status} (evidence strength ${(finding.score * 100).toFixed(0)}%)`,
          "",
          `Requirement: ${finding.control.requirement}`,
          "",
          `Rationale: ${finding.rationale}`,
          "",
          "Evidence:",
          ...finding.evidence.map(
            (e) =>
              `  ${e.passed ? "PASS" : "FAIL"} ${e.title}\n    source: ${e.source}\n    hash: ${e.hash}`,
          ),
        ];
        if (finding.gaps.length) {
          lines.push("", "Detected shortfalls:", ...finding.gaps.map((g) => `  - ${g}`));
        }
        if (finding.remediation.length) {
          lines.push(
            "",
            "Remediation:",
            ...finding.remediation.map((r, i) => `  ${i + 1}. ${r}`),
          );
        }
        return lines.join("\n");
      }

      case "generate_document": {
        const type = String(args.type);
        const report = await this.report();
        const { config } = (() => {
          try {
            return { config: loadConfigFile(`${this.options.cwd}/auditgen.json`) };
          } catch {
            return { config: {} };
          }
        })();
        const input = {
          report,
          config,
          ...(typeof args.period === "string" ? { period: args.period } : {}),
          ...(typeof args.preparedBy === "string"
            ? { preparedBy: args.preparedBy }
            : {}),
        };
        return type === "system_description"
          ? generateSystemDescription(input)
          : generateStatementOfApplicability(input);
      }

      case "list_controls": {
        const framework = String(args.framework ?? "any");
        const list = ALL_CONTROLS.filter(
          (c) => framework === "any" || c.framework === framework,
        );
        return list
          .map(
            (c) =>
              `${c.id.padEnd(8)} ${c.framework.padEnd(9)} ${c.title} (via ${c.collector}${c.manual ? ", operator attested" : ""})`,
          )
          .join("\n");
      }

      default:
        throw new Error(
          `Unknown tool "${name}". Available: ${TOOLS.map((t) => t.name).join(", ")}`,
        );
    }
  }
}

/** Reads newline-delimited JSON-RPC from stdin and writes responses to stdout. */
export function serveStdio(options: ServerOptions): void {
  const server = new AuditgenMcpServer(options);
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  // A full audit can take many seconds. Exiting the moment stdin closes would
  // kill every in-flight tool call, so shutdown waits for outstanding work.
  let inFlight = 0;
  let closing = false;

  const maybeExit = () => {
    if (closing && inFlight === 0) process.exit(0);
  };

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req: RpcRequest;
    try {
      req = JSON.parse(trimmed) as RpcRequest;
    } catch {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        }) + "\n",
      );
      return;
    }

    inFlight++;
    void server
      .handle(req)
      .then((res) => {
        if (res) process.stdout.write(JSON.stringify(res) + "\n");
      })
      .catch((err: unknown) => {
        process.stdout.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: req.id ?? null,
            error: {
              code: -32603,
              message: err instanceof Error ? err.message : String(err),
            },
          }) + "\n",
        );
      })
      .finally(() => {
        inFlight--;
        maybeExit();
      });
  });

  rl.on("close", () => {
    closing = true;
    maybeExit();
  });
}

export { renderMarkdown };