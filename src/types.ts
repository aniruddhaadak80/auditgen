/**
 * Core domain types.
 *
 * Design note: evidence records are treated as append-only and hash-chained.
 * An auditor's objection to any automated compliance tool is "how do I know this
 * wasn't written by hand to look good". The chain in the report exists so that
 * objection has an answer: altering one record breaks every hash after it.
 */

export type Framework = "soc2" | "iso27001";

export type ControlStatus =
  | "satisfied"
  | "partial"
  | "gap"
  | "manual"
  | "not_applicable";

/** A criterion an auditor will actually cite, plus the evidence it wants. */
export interface Control {
  /** Canonical identifier, e.g. "CC6.1" or "A.8.15". */
  id: string;
  framework: Framework;
  /** Short name shown in the matrix. */
  title: string;
  /** Verbatim-ish requirement language, as an auditor would read it. */
  requirement: string;
  /** Grouping used in the report, e.g. "Logical and Physical Access". */
  category: string;
  /** Name of the collector that gathers evidence for this control. */
  collector: string;
  /**
   * True when evidence cannot be derived from a repository and must be supplied
   * by the operator (policies, training records, physical security).
   */
  manual: boolean;
  /** What a reviewer looks for. Used as grounding for the AI narrative. */
  guidance: string;
  /** Optional per-control overrides passed to the collector. */
  params?: Record<string, unknown>;
}

export interface Evidence {
  controlId: string;
  collector: string;
  /** Human-readable assertion, e.g. "Default branch is protected". */
  title: string;
  /** ISO-8601. */
  observedAt: string;
  /** Link or path an auditor can independently open. */
  source: string;
  passed: boolean;
  /** Structured observations backing the assertion. */
  details: Record<string, unknown>;
  /** Short verbatim excerpt, where one exists. */
  excerpt?: string;
  /** sha256 over the canonical serialization of this record. */
  hash: string;
  /** Hash of the previous record in the chain, or "genesis". */
  prevHash: string;
}

export interface Finding {
  control: Control;
  status: ControlStatus;
  /**
   * Strength of the evidence backing this status, 0..1: the share of assertions
   * for this control that passed. Distinct from confidence, which is not
   * something a deterministic check can honestly claim.
   */
  score: number;
  evidence: Evidence[];
  /** Human-readable shortfalls against this control. */
  gaps: string[];
  /** Advisory remarks that are not shortfalls. Never affect status. */
  notes: string[];
  /** Ordered, concrete remediation steps. */
  remediation: string[];
  /** One-paragraph explanation of why this status was assigned. */
  rationale: string;
  /** True when remediation text came from a model rather than the rule set. */
  aiGenerated: boolean;
}

export interface RepoTarget {
  owner: string;
  repo: string;
  /** Absolute path when the repository was inspected from disk. */
  localPath?: string;
  /** Default branch name. */
  defaultBranch?: string;
}

/**
 * Operator declarations.
 *
 * Some controls cannot be established from a repository. Rather than silently
 * passing them, auditgen accepts an explicit declaration, records that it came
 * from an operator rather than an observation, and marks the evidence as
 * declared so the report can distinguish verified from attested.
 */
export interface Declarations {
  /** Organisation enforces MFA for all members. */
  twoFactorEnforced?: boolean;
  /** Immutable, tested backups with documented RTO/RPO. */
  backupRecoveryTested?: boolean;
  /** Documented risk register exists and is current. */
  riskRegisterMaintained?: boolean;
  /** Physical or cloud-provider security attestation covers premises. */
  physicalSecurityCovered?: boolean;
  /** Documented fraud risk assessment exists and is current. */
  fraudRiskAssessed?: boolean;
  /** Security awareness training delivered and recorded. */
  trainingCompleted?: boolean;
  /** Capacity is monitored against projected requirements. */
  capacityManaged?: boolean;
  /** Organisation name for the generated documents. */
  organizationName?: string;
  /** System name for the generated documents. */
  systemName?: string;
  /** Describes what the system is and does, for the System Description. */
  systemDescription?: string;
  /** Data the system processes. */
  dataCategories?: string[];
  /** Where the system runs, e.g. "GitHub Enterprise Cloud, us-east-1". */
  hostingEnvironment?: string;
  /** Trust services criteria in scope. */
  trustServicesCriteria?: string[];
  /**
   * Websites to check for published policies: security.txt, privacy notice,
   * status page, trust centre, subprocessor list. Repository metadata is used as
   * a fallback. Every URL is treated as untrusted input.
   */
  websiteUrls?: string[];
}

export interface AuditOptions {
  target: RepoTarget;
  frameworks: Framework[];
  /** Collectors to skip, by name. */
  skipCollectors?: string[];
  /** Only audit these control ids. */
  onlyControls?: string[];
  /** Token for GitHub API. Falls back to GITHUB_TOKEN / GH_TOKEN. */
  token?: string;
  /** Disable network calls and use only local git collectors. */
  offline?: boolean;
  /** Base URL of an OpenAI-compatible endpoint for narrative generation. */
  aiBaseUrl?: string;
  aiApiKey?: string;
  aiModel?: string;
  /** Skip the AI narrative pass; statuses still get computed. */
  noAi?: boolean;
}

export interface Report {
  schemaVersion: 1;
  generatedAt: string;
  generator: { name: string; version: string };
  target: RepoTarget;
  frameworks: Framework[];
  findings: Finding[];
  summary: {
    total: number;
    satisfied: number;
    partial: number;
    gap: number;
    manual: number;
    notApplicable: number;
    /**
     * Satisfied share of every evaluated control, 0..1. This is the honest
     * headline figure: a control nobody could observe counts against you.
     */
    overall: number;
    /**
     * Satisfied share of controls that were actually observable, 0..1. Excludes
     * manual and not-applicable. Useful for tracking progress on the controls in
     * a team's reach, but never quote it without `overall` beside it, because a
     * repository where everything is unobservable scores 100% here.
     */
    observedCoverage: number;
  };
  /** Chain head over all evidence in report order. */
  evidenceRoot: string;
  /** Non-fatal problems encountered while collecting. */
  warnings: string[];
  durationMs: number;
}

export const AUDITGEN_VERSION = "0.1.0";