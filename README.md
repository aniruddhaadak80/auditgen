# auditgen

**Git-native SOC 2 and ISO 27001 readiness auditor.** Reads your repository and
GitHub configuration, proves each control with tamper-evident evidence, and
generates the two documents an auditor actually asks for.

Self-hosted. Model-agnostic. Zero runtime dependencies.

```bash
npx auditgen audit
```

```
aniruddhaadak80/promptfoo  2026-10-03T07:44:59.442Z

1/17 controls satisfied  █░░░░░░░░░░░░░░░░░░░░░░░ 6%
  1 partial · 10 gap · 5 need attestation
  (8% of the 12 observable control(s); unattested controls are not free)

Needs work:
  GAP   CC2.2    Internal communication of objectives and responsibilities
  GAP   CC5.2    Technology general controls
  GAP   CC6.3    Role-based access and least privilege
  GAP   CC6.8    Prevention and detection of unauthorized or malicious software
  ...
```

## Why this exists

Vanta and Drata will not sell you self-serve. No public pricing, demo required,
300+ SaaS integrations, and a human customer success manager attached to every
account. They start by asking you to connect all of it.

Nobody starts by reading your repository.

But for a software company the evidence an auditor wants is already sitting in
git: signed commits are change management, `CODEOWNERS` is access control,
branch protection is the SDLC, secret-scanning history is credential management,
and CI logs are the operations log. That evidence is free, it is continuously
maintained, and it is the part incumbents cannot generate at all.

auditgen reads it.

## What it will not do

These are design constraints, not limitations to work around.

**It will not report compliance it cannot see.** GitHub's API exposes no endpoint
for whether an organisation enforces MFA. Rather than infer a pass from an
unrelated signal, that control is reported as *needs attestation* with the exact
menu path to verify it. Across the 34 controls in this build, 10 require an
operator attestation by design.

**A language model cannot change a status.** Status is computed from
deterministic repository observation in `src/engine/evaluate.ts`. The model pass
may write the narrative paragraph and order the remediation steps. It cannot
promote a control, close a gap, or alter a verdict. An auditor's worst fear about
"AI-generated compliance evidence" is a model deciding it is compliant.

**It will not report one repository's cleanliness against another.** If you pass
`owner/repo` while standing in an unrelated checkout, the local history scanners
are skipped rather than pointed at the wrong directory. This guard is
`reconcileLocalPath` in `src/audit.ts` and it has its own test file.

**It does not overwrite your findings.** When the model supplies remediation
steps, the detected gaps stay in the report. You can see what the tool actually
found versus what was advised.

**It is not an attestation.** auditgen produces readiness evidence. Only an
independent licensed auditor can issue a SOC 2 report or an ISO 27001
certificate. Every generated document says so at the top.

## Install

```bash
npm install -g auditgen      # or: npx auditgen
```

Requires Node 20.10+. A GitHub token with `repo` scope enables the hosted
controls; without one, local repository checks still run.

```bash
export GITHUB_TOKEN=ghp_...  # or GH_TOKEN, or AUDITGEN_GITHUB_TOKEN
```

## Usage

```bash
# audit the repo you are standing in
auditgen audit

# audit anything, both frameworks, markdown to a file
auditgen audit acme/widget --framework soc2,iso27001 --format markdown --out report.md

# just the controls you care about
auditgen audit --only CC6.1,CC8.1,A.8.15

# local history only, no network
auditgen audit --offline

# the two auditor-facing documents
auditgen doc system_description --period "1 Apr 2026 to 30 Jun 2026"
auditgen doc statement_of_applicability

# what is actually covered
auditgen controls --framework iso27001

# prove nobody edited the report
auditgen verify auditgen-report.json
```

Exit codes: `0` no gaps, `1` gaps found, `2` error. The `1` makes it usable as a
CI gate today:

```yaml
- run: npx auditgen audit "${{ github.repository }}" --no-ai
```

### Configuration

`auditgen init` writes a starter `auditgen.json`. Every attestation defaults to
`false` and stays there until you have proof:

```json
{
  "organizationName": "Acme",
  "systemName": "acme/widget",
  "systemDescription": "Customer-facing billing dashboard for Acme customers.",
  "hostingEnvironment": "GitHub Enterprise Cloud, us-east-1, AWS EC2 t3.large",
  "dataCategories": ["customer PII", "billing records"],
  "trustServicesCriteria": ["Security (Common Criteria, CC1-CC9)"],
  "twoFactorEnforced": true,
  "riskRegisterMaintained": false,
  "backupRecoveryTested": false,
  "physicalSecurityCovered": false
}
```

A control satisfied only by a declaration is marked `Implemented` but carries an
`attestation: operator-declared` marker in its evidence, and is excluded from the
observed-coverage figure.

## Tamper-evident evidence

An auditor's objection to any automated compliance tool is "how do I know this
was not written by hand to look good". Every assertion is in a SHA-256 hash
chain, and the report commits to a single chain root. Editing one record breaks
every digest after it:

```console
$ auditgen verify auditgen-report.json
ok  17 evidence records
    chain root matches report: c87f7e6c677909d7b759ccd6335c791ac448a58e6b5ce05e953d0c3dc0e564d8

$ # hand-edit one assertion to make it look compliant
$ auditgen verify tampered.json
FAILED  evidence record 1 does not match its hash
A record was modified after the report was generated. Treat the report as untrustworthy.
```

This is the feature most worth having. A green report you cannot prove is worth
less than a red one you can.

## Controls

34 controls across two frameworks, each mapped to exactly one collector so a
control can never silently end up with no evidence and look satisfied.

| Framework | Controls | Source |
| --- | --- | --- |
| SOC 2 Trust Services Criteria | 17 | CC2.2 – CC9.2, A1.2 |
| ISO/IEC 27001:2022 Annex A | 17 | A.5.15 – A.8.32 |

Collectors read branch protection, `CODEOWNERS`, `SECURITY.md`, secret-scanning
and push-protection status, Dependabot alerts and their dispositions, Actions
workflows and permission scopes, environment protection rules, merged-PR review
practice, releases, security advisories, commit signatures, and full-history
secret scanning.

```bash
auditgen controls
```

## MCP server

Exposes the audit to any MCP-capable agent, so the model can answer "are we audit
ready" and "what is our weakest control" without reading a file.

```json
{
  "mcpServers": {
    "auditgen": {
      "command": "auditgen",
      "args": ["serve", "acme/widget"]
    }
  }
}
```

Tools: `audit_status`, `list_findings`, `get_control`, `generate_document`,
`list_controls`. Results are cached, so five questions cost one API sweep.

## Narrative pass

Optional. Point it at any OpenAI-compatible endpoint to have the prose written
and the remediation ordered:

```bash
export AUDITGEN_AI_BASE_URL=https://openrouter.ai/api/v1
export AUDITGEN_AI_API_KEY=...
export AUDITGEN_AI_MODEL=<model-id>
auditgen audit
```

Without these, `--no-ai` is implied and the deterministic remediation is used.
The model id is never guessed for an unfamiliar provider, because a wrong model
produces confident garbage rather than an error.

## How the score works

Two numbers, and quoting the wrong one is how these tools mislead people.

- **`overall`** — satisfied share of *all* evaluated controls. A control nobody
  could observe counts against you, because an auditor will.
- **`observedCoverage`** — satisfied share of controls that were actually
  observable. Useful for tracking progress on what your team can reach.

A repository where every control is unobservable scores 100% on
`observedCoverage`. That is why it is never the headline.

## Development

```bash
npm install
npm run typecheck
npm test          # 75 tests, node:test
npm run build
```

## Limitations

- **Not an attestation.** Readiness evidence, not a SOC 2 report or ISO 27001
  certificate.
- **Partial coverage.** 34 of the ~93 ISO 27001 Annex A controls, weighted
  toward what a repository can actually prove. Organisational and physical
  controls are listed as needing attestation.
- **GitHub only.** No GitLab, Bitbucket or Azure DevOps.
- **Branch protection needs `administration:read`.** Without it, controls that
  depend on it are reported as unconfirmed rather than failed. This is
  deliberate: "cannot see the rule" and "the rule is absent" are different
  findings.
- **Secret scanning covers committed history,** not the working tree or CI logs.

## License

MIT