# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `0.1.x` | yes |
| `< 0.1` | no |

auditgen is pre-1.0. Expect breaking changes to the report schema and CLI flags
until `1.0.0`.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via GitHub Security Advisories:
<https://github.com/aniruddhaadak80/auditgen/security/advisories/new>

Include the commit or npm version, the input that triggers it, and the observed
behaviour. You should get an acknowledgement within 72 hours.

If advisories are unavailable to you, open a regular issue containing only a
`security:` label request and the reporter contact in the body, with no
technical detail.

## What matters most

The threat model here is unusual and worth stating plainly.

**auditgen does not hold data. It produces assurance.** The valuable attack is not
an exploit against running code — it is convincing someone that a repository is
compliant when it is not, or that a finding has been fixed when it has not.

Reports in this order are prioritised highest:

1. **A false pass.** Any path where a control reaches `satisfied` without
   supporting evidence, or where a real gap is silently dropped. This is the
   defect class that makes the tool actively harmful, because its output gets
   signed off on.
2. **Report tampering going undetected.** Editing an assertion in the JSON report
   without `auditgen verify` noticing, or producing two different chain roots for
   the same evidence.
3. **Credential disclosure in output.** Any path that writes a live secret into a
   report, log, error message or MCP response. Committed secrets must be
   redacted to a prefix, a length and a digest.
4. **Wrong-repository reporting.** Evidence from one repository attributed to
   another. See `reconcileLocalPath` in `src/audit.ts`.
5. **Token over-reach.** Requesting scopes or endpoints beyond what a collector
   documents, or transmitting tokens anywhere other than `api.github.com`.

Lower priority: denial of service via a hostile repository, and crashes on
malformed API responses.

## Out of scope

- **Findings in the audited repository.** auditgen reports that a repository has
  a gap. It does not fix it, and a gap is not a vulnerability in auditgen.
- **Coverage gaps in the control set.** Adding controls is a feature request.
- **Weaknesses in a language model.** The narrative pass is advisory prose and
  cannot change a status. If model output degrades the report it is still a bug
  in auditgen.
- **Absence of an attestation.** auditgen having no mechanism to verify MFA
  enforcement is documented behaviour, not a vulnerability.

## Token handling

- Tokens are read from `GITHUB_TOKEN`, `GH_TOKEN` or `AUDITGEN_GITHUB_TOKEN`, or
  passed with `--token`. They are never written to a report, never included in
  evidence details, never logged, and never sent anywhere except the
  `api.github.com` host you configure.
- `repo` scope is sufficient for most collectors. `administration:read` unlocks
  branch protection. Controls depending on an unavailable endpoint are reported
  as unverifiable, never as passing.
- Prefer a fine-grained token limited to a single repository if you use auditgen
  against private code.

## Operational guidance

- Run auditgen in CI rather than only on a workstation, so the evidence chain
  root is anchored to commits anyone can re-derive.
- Treat a green audit as a readiness signal, not a certificate. Only an
  independent auditor can attest.
- Commit generated reports if you need an audit trail. The chain root is only
  meaningful if something immutable records it.