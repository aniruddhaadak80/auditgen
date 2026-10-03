/**
 * auditgen — git-native SOC 2 and ISO 27001 readiness auditor.
 *
 * Design commitments, in order of importance:
 *
 * 1. Statuses are computed from deterministic repository observation only. A
 *    language model can write the narrative and order the remediation. It cannot
 *    promote a control, close a gap, or alter a status.
 *
 * 2. Absence of evidence is never reported as compliance. A control that could
 *    not be evaluated is reported as needing attestation, with the exact manual
 *    check named.
 *
 * 3. Evidence is tamper-evident. Every assertion is in a SHA-256 hash chain and
 *    the report commits to a single chain root, so an edited observation breaks
 *    every digest after it.
 */

export { runAudit } from "./audit.js";
export type { AuditRun } from "./audit.js";

export {
  AUDITGEN_VERSION,
  type AuditOptions,
  type Control,
  type ControlStatus,
  type Evidence,
  type Finding,
  type Framework,
  type Report,
  type RepoTarget,
} from "./types.js";

export {
  ALL_CONTROLS,
  SOC2_CONTROLS,
  ISO27001_CONTROLS,
  controlsFor,
  getControl,
  collectorsNeeded,
  listCollectorNames,
} from "./controls/index.js";

export {
  COLLECTORS,
  buildTreeIndex,
  getCollector,
  runCollectors,
} from "./collectors/index.js";
export type {
  Collector,
  CollectorContext,
  CollectorResult,
  Declarations,
  TreeIndex,
} from "./collectors/types.js";

export { evaluate, summarize } from "./engine/evaluate.js";
export { enrichFindings, resolveJudgeConfig } from "./engine/judge.js";

export {
  renderMarkdown,
  renderTerminal,
  serializeReport,
} from "./report/markdown.js";
export {
  generateSystemDescription,
  generateStatementOfApplicability,
} from "./report/docs.js";

export {
  canonicalize,
  chainEvidence,
  verifyChain,
  sha256,
} from "./util/hash.js";

export { GitHubClient, resolveToken } from "./util/github.js";

export {
  findConfigFile,
  loadConfigFile,
  loadDeclarations,
  parseGitHubRemote,
  parseRepoSpec,
  resolveTarget,
} from "./config.js";
export type { AuditgenConfig } from "./config.js";

export { AuditgenMcpServer, serveStdio } from "./mcp/server.js";