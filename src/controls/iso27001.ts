import type { Control } from "../types.js";

/**
 * ISO/IEC 27001:2022 Annex A controls.
 *
 * Scope note: covers the technical and access-control subset of Annex A that is
 * observable from a repository and its hosting configuration. Organisational
 * controls A.5 (policies, people, supplier) and physical A.7 are mostly manual.
 */
export const ISO27001_CONTROLS: Control[] = [
  {
    id: "A.5.15",
    framework: "iso27001",
    title: "Access control",
    requirement:
      "Rules to control physical and logical access to information shall be established and implemented based on business and information security requirements.",
    category: "Organizational",
    collector: "github.codeowners",
    manual: false,
    guidance:
      "Access to source and sensitive configuration paths must be bound to named principals. CODEOWNERS plus protected branches is the primary artifact.",
  },
  {
    id: "A.5.17",
    framework: "iso27001",
    title: "Authentication information",
    requirement:
      "Allocation and management of authentication information shall be controlled by a management system, including the administration of authentication information and the provision of authenticated secure services.",
    category: "Organizational",
    collector: "github.secret_scanning",
    manual: false,
    guidance:
      "Covers passwords, tokens, keys and certificates. Reviewer expects a control that detects committed credentials and evidences remediation.",
  },
  {
    id: "A.5.24",
    framework: "iso27001",
    title: "Incident management planning",
    requirement:
      "The organization shall plan and establish incident management processes, including the definition of incident classification, responsibilities, and communication.",
    category: "Organizational",
    collector: "github.security_md",
    manual: false,
    guidance:
      "A published security policy with a reporting channel and response commitment is the observable minimum for a hosted project.",
  },
  {
    id: "A.8.2",
    framework: "iso27001",
    title: "Privileged access rights",
    requirement:
      "The allocation and use of privileged access rights shall be restricted and managed.",
    category: "Technological",
    collector: "github.env_protection",
    manual: false,
    guidance:
      "Privileged operations, meaning production secrets, release rights, and branch protection changes, must require elevated authorization rather than ambient contributor access.",
  },
  {
    id: "A.8.3",
    framework: "iso27001",
    title: "Information access restriction",
    requirement:
      "Access to information shall be restricted in accordance with the established information classification and access policy.",
    category: "Organizational",
    collector: "github.codeowners",
    manual: false,
    guidance:
      "Classification in a repository maps to directory and path scope. Reviewer expects sensitive paths to have an explicit owner and enforced reviewer.",
  },
  {
    id: "A.8.5",
    framework: "iso27001",
    title: "Secure authentication",
    requirement:
      "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the information classification policy.",
    category: "Technological",
    collector: "github.two_factor",
    manual: false,
    guidance:
      "Multi-factor authentication must be enforced rather than recommended, and privileged users must not be able to bypass it.",
  },
  {
    id: "A.8.8",
    framework: "iso27001",
    title: "Management of technical vulnerabilities",
    requirement:
      "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken.",
    category: "Technological",
    collector: "github.dependabot",
    manual: false,
    guidance:
      "Detection of known vulnerabilities in dependencies. Reviewer checks detection is enabled and that resulting findings carry a recorded disposition.",
  },
  {
    id: "A.8.9",
    framework: "iso27001",
    title: "Configuration management",
    requirement:
      "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
    category: "Technological",
    collector: "github.branch_protection",
    manual: false,
    guidance:
      "Security configuration of the source repository is in scope. Reviewer inspects branch protection rules and reviews them on a cadence.",
  },
  {
    id: "A.8.12",
    framework: "iso27001",
    title: "Data leakage prevention",
    requirement:
      "Data leakage prevention measures shall be applied to systems, networks, and any other devices that process, store, or transmit sensitive information.",
    category: "Technological",
    collector: "git.secret_history",
    manual: false,
    guidance:
      "Commit history is a data movement channel. Reviewer expects a full-history secret scan plus evidence of credential rotation for anything ever committed.",
  },
  {
    id: "A.8.15",
    framework: "iso27001",
    title: "Logging",
    requirement:
      "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
    category: "Technological",
    collector: "github.ci_workflows",
    manual: false,
    guidance:
      "Audit trail for changes to the system. A CI system that records who changed what, and when, is the observable logging control for a software repository.",
  },
  {
    id: "A.8.16",
    framework: "iso27001",
    title: "Monitoring activities",
    requirement:
      "The organization shall monitor and record the use of information processing facilities and networks for the occurrence of anomalies indicative of malicious acts.",
    category: "Technological",
    collector: "github.ci_workflows",
    manual: false,
    guidance:
      "Ongoing detection, not a one-time assessment. Reviewer wants to see continuous automated checks that produce records.",
  },
  {
    id: "A.8.24",
    framework: "iso27001",
    title: "Use of cryptography",
    requirement:
      "Rules for the effective use of cryptography, including cryptographic controls across the lifecycle of keys, shall be defined and implemented.",
    category: "Technological",
    collector: "github.secret_scanning",
    manual: false,
    guidance:
      "Covers key handling. Push protection and secret scanning are the observable controls preventing plaintext key material entering the repository.",
  },
  {
    id: "A.8.25",
    framework: "iso27001",
    title: "Secure development life cycle",
    requirement:
      "Rules for the secure development life cycle shall be established and applied.",
    category: "Technizational",
    collector: "git.commit_signatures",
    manual: false,
    guidance:
      "Traceable authorship of every change is the backbone of a secure development lifecycle. Commit signing provides non-repudiation for the audit trail.",
  },
  {
    id: "A.8.28",
    framework: "iso27001",
    title: "Secure coding",
    requirement:
      "Secure coding principles shall be applied to software development.",
    category: "Technological",
    collector: "github.ci_workflows",
    manual: false,
    guidance:
      "Reviewer looks for automated static analysis or security linting enforced in the pipeline, blocking merges rather than warning.",
  },
  {
    id: "A.8.29",
    framework: "iso27001",
    title: "Security testing in development and acceptance",
    requirement:
      "Security testing processes shall be defined and implemented in the development life cycle.",
    category: "Technological",
    collector: "github.ci_workflows",
    manual: false,
    guidance:
      "Tests that must pass before a change is accepted. Reviewer verifies the gate is a required check, not an optional job.",
  },
  {
    id: "A.8.32",
    framework: "iso27001",
    title: "Change management",
    requirement:
      "Changes to production or development information processing facilities and information processing systems shall be subject to change management procedures.",
    category: "Organizational",
    collector: "github.pr_review",
    manual: false,
    guidance:
      "Every change reviewed, tested and approved before it lands. Protected branches with required reviews and a required status check are the artifacts.",
  },
  {
    id: "A.7.4",
    framework: "iso27001",
    title: "Physical security",
    requirement:
      "Premises and information processing facilities shall be physically secured against unauthorized physical access.",
    category: "Physical",
    collector: "manual",
    manual: true,
    guidance:
      "Out of scope for a repository-level tool. For a fully remote organization, record the cloud provider's attestation instead.",
  },
];