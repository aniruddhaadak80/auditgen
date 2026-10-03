import type { Control } from "../types.js";

/**
 * SOC 2 Trust Services Criteria (2017, revised 2022 Points of Focus).
 *
 * Scope note: this covers the Security criterion (CC) plus the change-management
 * and monitoring criteria a software company is most often examined on. It does
 * not cover Availability, Confidentiality, Processing Integrity or Privacy; a
 * report generated here is input to a SOC 2 examination, never a substitute for
 * one, and carries no auditor's opinion.
 */
export const SOC2_CONTROLS: Control[] = [
  {
    id: "CC2.2",
    framework: "soc2",
    title: "Internal communication of objectives and responsibilities",
    requirement:
      "The entity communicates, internally, information about the objectives and responsibilities for achieving its internal control objectives.",
    category: "Control Environment",
    collector: "github.pr_review",
    manual: false,
    guidance:
      "Reviewer looks for a working record that changes are reviewed by someone other than the author. Branch protection with required reviews is the primary artifact.",
  },
  {
    id: "CC3.2",
    framework: "soc2",
    title: "Risk identification and analysis",
    requirement:
      "The entity identifies risks to the achievement of its objectives across the entity and analyzes them as a basis for determining how the risks should be managed.",
    category: "Risk Assessment",
    collector: "manual",
    manual: true,
    guidance:
      "Requires a documented risk register. Cannot be derived from a repository. Typical artifact: a threat model or risk register with owners and review dates.",
  },
  {
    id: "CC4.1",
    framework: "soc2",
    title: "Ongoing and separate evaluations",
    requirement:
      "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.",
    category: "Monitoring Activities",
    collector: "github.advisories",
    manual: false,
    guidance:
      "Reviewer looks for evidence that controls are tested on a cadence, not just designed. Security advisory history and alert-driven tickets are the artifacts.",
  },
  {
    id: "CC5.2",
    framework: "soc2",
    title: "Technology general controls",
    requirement:
      "The entity selects and develops general control activities over technology to support the achievement of internal control objectives.",
    category: "Control Activities",
    collector: "github.dependabot",
    manual: false,
    guidance:
      "Automated dependency management and update policy is the general control over technology. Reviewer checks that vulnerability scanning is configured and acting.",
  },
  {
    id: "CC6.1",
    framework: "soc2",
    title: "Logical access security",
    requirement:
      "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
    category: "Logical and Physical Access",
    collector: "github.two_factor",
    manual: false,
    guidance:
      "Authentication strength for all human access to code and infrastructure. Primary artifact is enforced multi-factor authentication with no bypass path.",
  },
  {
    id: "CC6.2",
    framework: "soc2",
    title: "User registration and authorization",
    requirement:
      "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity.",
    category: "Logical and Physical Access",
    collector: "github.codeowners",
    manual: false,
    guidance:
      "Reviewer wants to see that access to sensitive paths is constrained to named principals. CODEOWNERS is the direct technical expression of authorization.",
  },
  {
    id: "CC6.3",
    framework: "soc2",
    title: "Role-based access and least privilege",
    requirement:
      "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to concepts of least privilege and segregation of duties.",
    category: "Logical and Physical Access",
    collector: "github.env_protection",
    manual: false,
    guidance:
      "Least privilege in a repository context is separation of duties: production secrets must not be reachable from untrusted workflows, and write access must require review.",
  },
  {
    id: "CC6.6",
    framework: "soc2",
    title: "Protection against external threats",
    requirement:
      "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
    category: "Logical and Physical Access",
    collector: "github.branch_protection",
    manual: false,
    guidance:
      "Repository is a system boundary. Reviewer checks that the default branch cannot be written directly and that force pushes are constrained.",
  },
  {
    id: "CC6.7",
    framework: "soc2",
    title: "Restriction of data transmission, movement, and removal",
    requirement:
      "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, and removal.",
    category: "Logical and Physical Access",
    collector: "git.secret_history",
    manual: false,
    guidance:
      "Secrets committed to history are an uncontrolled movement channel. Reviewer expects a full-history scan and a documented rotation procedure.",
  },
  {
    id: "CC6.8",
    framework: "soc2",
    title: "Prevention and detection of unauthorized or malicious software",
    requirement:
      "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
    category: "Logical and Physical Access",
    collector: "github.secret_scanning",
    manual: false,
    guidance:
      "Push protection and secret scanning must be enabled and have produced findings that were remediated, demonstrating the control operates rather than merely exists.",
  },
  {
    id: "CC7.1",
    framework: "soc2",
    title: "Detection of configuration changes and vulnerabilities",
    requirement:
      "The entity monitors and evaluates system components and the operation of those components for anomalies indicative of malicious acts, natural disasters, and errors affecting its ability to meet its objectives.",
    category: "System Operations",
    collector: "github.dependabot",
    manual: false,
    guidance:
      "Dependency vulnerability detection with a trackable disposition per advisory. Reviewer samples advisories and checks whether they were triaged.",
  },
  {
    id: "CC7.2",
    framework: "soc2",
    title: "Monitoring for anomalies indicative of malicious acts",
    requirement:
      "The entity monitors system components and the operation of those components for anomalies indicative of malicious acts, natural disasters, and errors affecting its ability to meet its objectives.",
    category: "System Operations",
    collector: "github.ci_workflows",
    manual: false,
    guidance:
      "Automated checks that run on every change are the monitoring activity. Reviewer wants to see the pipeline enforces something rather than reporting.",
  },
  {
    id: "CC7.3",
    framework: "soc2",
    title: "Evaluation of security events",
    requirement:
      "The entity evaluates security events to determine whether they could or have resulted in a failure and takes actions to address the failure.",
    category: "System Operations",
    collector: "github.advisories",
    manual: false,
    guidance:
      "Advisories and vulnerability reports that received a recorded disposition. Zero findings with zero disposition records is a gap, not a pass.",
  },
  {
    id: "CC7.4",
    framework: "soc2",
    title: "Response to identified security incidents",
    requirement:
      "The entity responds to identified security incidents by executing a defined incident-response program to understand, contain, remediate, and communicate security incidents.",
    category: "System Operations",
    collector: "github.security_md",
    manual: false,
    guidance:
      "A documented, published vulnerability disclosure process with a stated response target. Reviewer checks for a reporting channel and a remediation commitment.",
  },
  {
    id: "CC8.1",
    framework: "soc2",
    title: "Change management",
    requirement:
      "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
    category: "Change Management",
    collector: "github.pr_review",
    manual: false,
    guidance:
      "The central change-control control for a software company. Artifacts: required reviews on protected branches, a CI gate, and a tagged release trail.",
  },
  {
    id: "CC9.2",
    framework: "soc2",
    title: "Vendor and business partner risk",
    requirement:
      "The entity assesses and manages risks associated with vendors and business partners associated with the entity.",
    category: "Risk Mitigation",
    collector: "github.actions_permissions",
    manual: false,
    guidance:
      "Third-party code supply chain is a vendor risk. Reviewer checks that third-party actions are pinned and that workflows declare minimum permissions.",
  },
  {
    id: "A1.2",
    framework: "soc2",
    title: "Recovery of information",
    requirement:
      "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its objectives.",
    category: "Availability",
    collector: "manual",
    manual: true,
    guidance:
      "Requires operational evidence: restore test results, RTO/RPO definitions, backup retention. Cannot be derived from source code.",
  },
];