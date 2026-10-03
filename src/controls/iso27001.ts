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
  {
    id: "A.5.1",
    framework: "iso27001",
    title: "Policies for information security",
    requirement:
      "Information security policy and topic-specific policies shall be defined, approved by management, published and communicated to, and acknowledged by, relevant personnel.",
    category: "Organizational",
    collector: "github.governance",
    manual: false,
    guidance:
      "Managerial approval and staff acknowledgement are documentary. The publishable part of a policy set is observable: a security policy, a contribution policy, a licence.",
  },
  {
    id: "A.5.7",
    framework: "iso27001",
    title: "Threat intelligence",
    requirement:
      "Information relating to information security threats shall be collected and analysed to produce threat intelligence.",
    category: "Organizational",
    collector: "github.advisories",
    manual: false,
    guidance:
      "Intelligence in a software organisation is the vulnerability advisory stream and the dispositions made against it. A stream with no dispositions is not intelligence, it is noise.",
  },
  {
    id: "A.5.12",
    framework: "iso27001",
    title: "Classification of information",
    requirement:
      "Information shall be classified according to the information security needs of the organization based on confidentiality, integrity, availability and relevant interested party requirements.",
    category: "Organizational",
    collector: "github.codeowners",
    manual: false,
    guidance:
      "Classification in a repository reduces to which paths are sensitive. CODEOWNERS is the mechanism that binds a sensitive path to an accountable owner.",
  },
  {
    id: "A.5.16",
    framework: "iso27001",
    title: "Information security incident management planning",
    requirement:
      "The organization shall plan and establish information security incident management processes, including responsibilities, procedures and communication.",
    category: "Organizational",
    collector: "github.security_md",
    manual: false,
    guidance:
      "The published half of incident management: a reporting channel and stated response expectations, both visible to an external reporter.",
  },
  {
    id: "A.5.18",
    framework: "iso27001",
    title: "Access rights",
    requirement:
      "Access rights to information and information processing facilities shall be provisioned, reviewed, modified and removed in accordance with the organization's topic-specific policy on access control and rules on segregation of duties.",
    category: "Organizational",
    collector: "git.authorship",
    manual: false,
    guidance:
      "Git history is the observable shadow of the access list, because anyone who could push appears as an author. Reviewer samples it to test whether access was provisioned to the right people.",
  },
  {
    id: "A.5.19",
    framework: "iso27001",
    title: "Information security in supplier relationships",
    requirement:
      "Processes and procedures shall be defined and implemented to manage the information security risks associated with the use of supplier's products or services.",
    category: "Organizational",
    collector: "github.actions_permissions",
    manual: false,
    guidance:
      "Third-party actions are the supplier relationship a software organisation actually has. Unrestricted action permissions mean an unreviewed supplier can execute with repository secrets.",
  },
  {
    id: "A.5.20",
    framework: "iso27001",
    title: "Addressing information security within supplier agreements",
    requirement:
      "Relevant information security requirements shall be established and agreed with each supplier based on the type of supplier relationship.",
    category: "Organizational",
    collector: "github.actions_permissions",
    manual: false,
    guidance:
      "Requirements are expressed as technical constraints in workflow configuration. Restricting which actions may run is a supplier requirement enforced in code.",
  },
  {
    id: "A.5.22",
    framework: "iso27001",
    title: "Monitoring, review and change management of supplier services",
    requirement:
      "The organization shall regularly monitor, review, evaluate and manage change in supplier information security practices and service delivery.",
    category: "Organizational",
    collector: "github.advisories",
    manual: false,
    guidance:
      "Ongoing review of the supply chain includes the actions your workflows depend on. Unpinned references move; a review record does not.",
  },
  {
    id: "A.5.23",
    framework: "iso27001",
    title: "Information security for use of cloud services",
    requirement:
      "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements.",
    category: "Organizational",
    collector: "github.env_protection",
    manual: false,
    guidance:
      "For a GitHub-hosted project the cloud boundary is the repository. Environment protection rules define the separation between who can merge and who can deploy.",
  },
  {
    id: "A.5.25",
    framework: "iso27001",
    title: "Assessment and decision on information security events",
    requirement:
      "The organization shall assess information security events and decide if they are to be categorized as information security incidents.",
    category: "Organizational",
    collector: "github.advisories",
    manual: false,
    guidance:
      "A triage decision recorded against each event. Advisories that were closed carry a disposition; those still open do not.",
  },
  {
    id: "A.5.26",
    framework: "iso27001",
    title: "Response to information security incidents",
    requirement:
      "Information security incidents shall be responded to in accordance with the documented procedures.",
    category: "Organizational",
    collector: "github.security_md",
    manual: false,
    guidance:
      "A reporter needs to know what happens after they send a report. A published commitment with a timeframe is the observable half of the response procedure.",
  },
  {
    id: "A.5.27",
    framework: "iso27001",
    title: "Learning from information security incidents",
    requirement:
      "Knowledge gained from information security incidents shall be used to strengthen and improve the information security controls.",
    category: "Organizational",
    collector: "github.dependabot",
    manual: false,
    guidance:
      "Learning is visible as a changed control. An organization that has triaged advisories and enabled scanning has demonstrably acted on what it learned.",
  },
  {
    id: "A.5.28",
    framework: "iso27001",
    title: "Collection of evidence",
    requirement:
      "The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence related to information security events.",
    category: "Organizational",
    collector: "github.ci_runs",
    manual: false,
    guidance:
      "Evidence is the run history. Reviewer samples a CI run and expects timestamps, actor and conclusion to survive long enough to be produced on request.",
  },
  {
    id: "A.5.31",
    framework: "iso27001",
    title: "Legal, statutory, regulatory and contractual requirements",
    requirement:
      "Legal, statutory, regulatory and contractual requirements relevant to information security and the organization's approach to meet these requirements shall be identified, documented and kept up to date.",
    category: "Organizational",
    collector: "github.governance",
    manual: false,
    guidance:
      "The licence file is the baseline record of the terms the organization has agreed to. Absence of one means terms are unstated.",
  },
  {
    id: "A.5.33",
    framework: "iso27001",
    title: "Protection of records",
    requirement:
      "Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release.",
    category: "Organizational",
    collector: "github.ci_runs",
    manual: false,
    guidance:
      "Audit records in a software system are the CI run log and the release trail. Their protection is the retention and immutability you configure on the platform.",
  },
  {
    id: "A.5.36",
    framework: "iso27001",
    title: "Compliance with policies, rules and standards for information security",
    requirement:
      "Compliance with the organization's information security policy, topic-specific policies, rules and standards shall be regularly reviewed.",
    category: "Organizational",
    collector: "github.ci_runs",
    manual: false,
    guidance:
      "Compliance review is continuous checking. A required check that passes on every merge is the reviewed, enforced state of the policy-as-code.",
  },
  {
    id: "A.5.37",
    framework: "iso27001",
    title: "Documented operating procedures",
    requirement:
      "Operating procedures for information processing facilities shall be documented and made available to personnel who need them.",
    category: "Organizational",
    collector: "github.governance",
    manual: false,
    guidance:
      "Contribution and security policies are the documented procedures a contributor can actually follow.",
  },
  {
    id: "A.6.3",
    framework: "iso27001",
    title: "Information security awareness, education and training",
    requirement:
      "Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training and regular updates of the organization's information security policy.",
    category: "People",
    collector: "manual",
    manual: true,
    guidance:
      "Requires training records and awareness attestations. Not derivable from source code. Commit signing policy and a security policy are supporting artefacts, not evidence of training.",
  },
  {
    id: "A.6.8",
    framework: "iso27001",
    title: "Information security event reporting",
    requirement:
      "The organization shall provide a means for personnel and interested parties to report observed or suspected information security events through appropriate channels.",
    category: "People",
    collector: "github.security_md",
    manual: false,
    guidance:
      "The channel must exist and be reachable by someone outside the team. A private reporting address in a published policy is the artefact.",
  },
  {
    id: "A.8.10",
    framework: "iso27001",
    title: "Information deletion",
    requirement:
      "Information stored in information processing facilities shall be deleted when no longer required.",
    category: "Technological",
    collector: "git.secret_history",
    manual: false,
    guidance:
      "Deletion from the tip of a branch is not deletion from history. Reviewer expects to know whether removal was accompanied by rotation.",
  },
  {
    id: "A.8.21",
    framework: "iso27001",
    title: "Security of network services",
    requirement:
      "Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.",
    category: "Technological",
    collector: "github.branch_protection",
    manual: false,
    guidance:
      "In a repository the network service is the hosting platform's API surface. The controls protecting it are the branch and permission rules that govern write access.",
  },
  {
    id: "A.8.22",
    framework: "iso27001",
    title: "Segregation of networks",
    requirement:
      "Groups of information services, users and information systems shall be segregated in the organization's networks.",
    category: "Technological",
    collector: "github.env_protection",
    manual: false,
    guidance:
      "Segregation here means separating who may change code from who may deploy. A protected environment with required reviewers is the boundary.",
  },
  {
    id: "A.8.26",
    framework: "iso27001",
    title: "Application security requirements",
    requirement:
      "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
    category: "Technological",
    collector: "github.ci_workflows",
    manual: false,
    guidance:
      "Requirements become real when a pipeline step fails a build that violates them. Reviewer looks for enforcement, not documentation.",
  },
  {
    id: "A.8.27",
    framework: "iso27001",
    title: "Secure system architecture and engineering principles",
    requirement:
      "Principles for engineering secure systems shall be established, documented, maintained and applied to any information system development activities.",
    category: "Technological",
    collector: "github.branch_protection",
    manual: false,
    guidance:
      "Architectural principles are expressed as structural constraints. Enforced branch protection is a principle that cannot be bypassed; a wiki page is not.",
  },
  {
    id: "A.8.30",
    framework: "iso27001",
    title: "Outsourced development",
    requirement:
      "The organization shall direct, monitor and review the activities related to outsourced system development.",
    category: "Technological",
    collector: "github.actions_permissions",
    manual: false,
    guidance:
      "External contributions and third-party actions are outsourced development in the operational sense. Reviewer checks both are reviewed before they can execute.",
  },
  {
    id: "A.8.31",
    framework: "iso27001",
    title: "Separation of development, test and production environments",
    requirement:
      "Development, testing and production environments shall be separated and secured.",
    category: "Technological",
    collector: "github.env_protection",
    manual: false,
    guidance:
      "The testable claim is that a production deployment requires an authorization a contributor cannot grant themselves. Environments with required reviewers demonstrate that.",
  },
  {
    id: "A.8.33",
    framework: "iso27001",
    title: "Protection of test information",
    requirement:
      "Test information shall be appropriately selected, protected and managed.",
    category: "Technological",
    collector: "git.secret_history",
    manual: false,
    guidance:
      "Test fixtures, examples and CI config are test information. Real credentials committed among them are the failure this control exists to catch.",
  },
];