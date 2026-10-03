import {
  type Collector,
  type CollectorContext,
  type CollectorResult,
  one,
} from "./types.js";
import type { Declarations } from "./types.js";

/**
 * Controls that no repository can evidence.
 *
 * These exist so the report is complete rather than quietly absent. A control
 * that is listed as "manual" and unresolved is a known, owned gap; a control
 * missing from the report entirely is invisible, and invisible gaps are what
 * fail an audit.
 */

interface ManualSpec {
  /** Declaration key that satisfies this control. */
  key: keyof Declarations;
  /** What the operator has to supply. */
  requirement: string;
  /** How the assertion should be worded once attested. */
  satisfiedTitle: string;
  /** Where the supporting document lives. */
  reference: string;
}

const MANUAL_SPECS: Record<string, ManualSpec> = {
  "CC3.2": {
    key: "riskRegisterMaintained",
    requirement:
      "A documented risk register: identified risks, likelihood and impact, treatment decision, owner, and last review date.",
    satisfiedTitle:
      "Operator declares a current risk register exists for the system",
    reference: "risk register / threat model",
  },
  "A1.2": {
    key: "backupRecoveryTested",
    requirement:
      "Evidence that backups are restored successfully on a schedule, with documented RTO and RPO targets and their last test date.",
    satisfiedTitle:
      "Operator declares backups have been restore-tested against a documented RTO/RPO",
    reference: "restore test log, RTO/RPO policy",
  },
  "A.7.4": {
    key: "physicalSecurityCovered",
    requirement:
      "For a remote organization, a record that physical and environmental security is inherited from the cloud provider's attestation rather than self-managed.",
    satisfiedTitle:
      "Operator declares physical security is covered by the hosting provider's attestation",
    reference: "provider attestation (for example AWS, Azure, GCP)",
  },
};

export const manualCollector: Collector = {
  name: "manual",
  async run(ctx: CollectorContext): Promise<CollectorResult[]> {
    void ctx;
    return [];
  },
};

/**
 * Build a result for a specific manual control. Kept separate from the collector
 * interface because each manual control has its own attestation key.
 */
export function manualResultFor(
  controlId: string,
  ctx: CollectorContext,
): CollectorResult {
  const spec: ManualSpec | undefined = MANUAL_SPECS[controlId];
  if (!spec) {
    return {
      title: `${controlId} is operator-attested and no attestation is defined for it`,
      passed: false,
      source: "auditgen.json",
      details: { controlId },
      unverifiable: true,
      gaps: [
        `No declaration key is mapped to ${controlId}. Supply the supporting document manually.`,
      ],
    };
  }

  const declared = ctx.declarations[spec.key];
  if (declared === true) {
    return {
      title: spec.satisfiedTitle,
      passed: true,
      source: `auditgen.json#/${String(spec.key)}`,
      details: { declarationKey: String(spec.key) },
      declared: true,
      notes: [
        `This assertion is attested, not observed. Attach the ${spec.reference} to the auditor pack.`,
      ],
    };
  }

  return {
    title: `${controlId} has no evidence: operator attestation required`,
    passed: false,
    source: `auditgen.json#/${String(spec.key)}`,
    details: { declarationKey: String(spec.key), required: spec.requirement },
    unverifiable: true,
    gaps: [
      `${spec.requirement} Set "${String(spec.key)}": true in auditgen.json once it exists, with the ${spec.reference} as supporting evidence.`,
    ],
  };
}

export { MANUAL_SPECS };
export const MANUAL_KEYS = Object.values(MANUAL_SPECS).map((s) => s.key);
export { one };