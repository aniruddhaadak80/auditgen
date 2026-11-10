# auditgen

**Git-native SOC 2 and ISO 27001 readiness auditor.** Reads your repository and
GitHub configuration, proves each control with tamper-evident evidence, and
generates the two documents an auditor actually asks for.

Self-hosted. Model-agnostic. Zero runtime dependencies.

```bash
npx auditgen audit
```

```
aniruddhaadak80/promptfoo  2026-10-03T08:36:17.237Z

9/72 controls satisfied  ███░░░░░░░░░░░░░░░░░░░░░ 13%
  6 partial · 37 gap · 20 need attestation
  (17% of the 52 observable control(s); unattested controls are not free)

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
menu path to verify it. Of the 72 controls in this build, 7 require an operator
attestation that no tool can make on your behalf.

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
auditgen controls

# prove nobody edited the report
auditgen verify auditgen-report.json

# what changed since last quarter
auditgen diff baseline.json report.json
```

`diff` exits `1` on a regression, so a control that silently degraded between
audit periods fails the pipeline just like a fresh gap does.

```console
$ auditgen diff q3.json q4.json
acme/widget   2026-09-30T00:00:00.000Z -> 2026-12-31T00:00:00.000Z

4 improved · 1 regressed · 0 added · 0 removed · 67 unchanged

Changed controls, regressions first:

  WORSE  CC7.2    satisfied -> partial
         Monitoring for anomalies indicative of malicious acts
  better CC6.1    gap -> satisfied
         Logical access security
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
  "websiteUrls": ["https://acme.example"],
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

## Published policies

Auditors ask for your `security.txt`, privacy notice, status page, trust centre
and subprocessor list. None of them live in git, so `web.policy_publication`
fetches them:

```console
$ node dist/cli.js audit acme/widget --only CC2.3
PASS  security.txt published with 2 contact(s) and a valid expiry
PASS  Privacy notice published at /privacy/
FAIL  Terms of service not found
FAIL  Public status page not found
PASS  Trust centre published at /trust
FAIL  Subprocessor list not found
```

It reads `websiteUrls` from `auditgen.json`, falling back to the repository
`homepage` and then `owner.github.io`. Candidates are tried in order, so a stale
homepage does not mask a live declared URL.

**It only evidences that a document is published, never that a claim in it is
true.** A trust-centre page containing the words "SOC 2 Type II" is a claim by
whoever wrote the page. Anyone can put text on a page, so substantive claims stay
operator attestations. What auditgen *does* check is structure and freshness:
`security.txt` must have a `Contact`, must have an `Expires`, and must not have
lapsed. An expired `security.txt` is treated as no contact by researchers and most
tooling, which makes it a real finding rather than a formatting nit.

### Why the fetch guard is strict

The URLs come from repository metadata, which an attacker controls. auditgen runs
in CI, often on a cloud runner holding instance credentials, so this is an SSRF
target with credentials at the end of it. `src/util/fetchSafe.ts` allows only
http/https, resolves DNS and rejects if **any** returned address is private,
blocks `169.254.169.254` and every other private and link-local range including
IPv4-mapped IPv6 forms, follows redirects manually so every hop is re-validated,
and caps time and response size. It fails closed on anything unrecognised.

## Controls

72 controls across two frameworks, each mapped to exactly one collector so a
control can never silently end up with no evidence and look satisfied.

| Framework | Controls | Coverage |
| --- | --- | --- |
| SOC 2 Trust Services Criteria | 28 | CC1.2 – CC9.2, A1.1 – A1.3 |
| ISO/IEC 27001:2022 Annex A | 44 | A.5.1 – A.8.33 |

Collectors read branch protection, `CODEOWNERS`, `SECURITY.md`, secret-scanning
and push-protection status, Dependabot alerts and their dispositions, Actions
workflows and permission scopes, **recent workflow run outcomes**, environment
protection rules, merged-PR review practice, releases, security advisories,
governance artefacts, commit signatures, **author identity concentration**, and
full-history secret scanning.

Two of these deserve a note. `github.ci_runs` tests **operating effectiveness**:
every other collector answers "is this configured", and this one answers "did it
ever run, and does it keep passing", because a required check that has never
executed is an aspiration rather than a control. `git.authorship` infers the
access list from the author set, since anyone who could push necessarily appears
in history, which makes an unexpectedly broad author set a provisioning finding.

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
- **Partial Annex A coverage.** 44 of 93 controls, weighted toward what a
  repository can actually prove. Organisational, physical and people controls
  are listed as needing attestation rather than omitted.
- **GitHub only** for hosted controls. No GitLab, Bitbucket or Azure DevOps.
- **Published-policy checks are reachability and structure only.** auditgen
  confirms a privacy notice or trust centre exists and can be fetched. It does not
  read what the page claims, because a claim on a page is not evidence.
- **Branch protection needs `administration:read`.** Without it, controls that
  depend on it are reported as unconfirmed rather than failed. This is
  deliberate: "cannot see the rule" and "the rule is absent" are different
  findings.
- **Secret scanning covers committed history,** not the working tree or CI logs.
- **Preflight SOC 2 is not a full examination.** Covering the Security criterion
  is not sufficient for a SOC 2 report; availability, confidentiality and
  processing integrity are assessed separately against your commitments.

## Project status

`0.1.x`, pre-1.0. The report schema and CLI flags may change. `SECURITY.md` has
the supported-versions table.

## Licence

MIT