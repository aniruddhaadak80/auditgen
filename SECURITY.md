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

## URL fetching

`web.policy_publication` fetches URLs derived from a repository's `homepage`
field or from `websiteUrls` in `auditgen.json`. **Both are attacker-controllable**:
anyone can set a homepage on a repository they control. auditgen usually runs in
CI, often on a cloud runner holding instance credentials, which makes this a
server-side request forgery target with a credential at the end of it.

The guard in `src/util/fetchSafe.ts` is therefore treated as security-critical
and is expected to stay that way:

- **Scheme allow-list.** Only `http` and `https`. No `file`, `gopher`, `data` or
  `javascript`.
- **No credentials in the authority**, so a URL cannot smuggle userinfo to a
  host.
- **DNS resolution, then every returned address checked.** A hostname with both a
  public and a private A record is a DNS rebinding attempt, so one public address
  does not excuse one that is not.
- **All private, loopback, link-local, CGNAT, multicast and reserved ranges are
  blocked**, including `169.254.169.254` cloud instance metadata, and including
  IPv4-mapped and NAT64 IPv6 forms that could otherwise smuggle a v4 target past a
  v6 check.
- **Redirects are followed manually and re-validated at every hop.** Handing a
  validated URL to `fetch` with automatic redirects would validate only the first.
- **Unrecognised address forms fail closed.**
- **10s timeout and a 512 KB response cap**, so a hostile endpoint cannot hang the
  audit or exhaust memory.

Rules for changes here:

1. Do not relax a range check without a threat-model note explaining why.
2. Any new fetch path must go through `safeFetch`, not global `fetch`.
3. `isPrivateAddress` must return `true` for anything unrecognised.
4. Redirects must be followed manually. If you add automatic redirect following
   anywhere, that is a vulnerability.

## Content is never treated as evidence

`web.policy_publication` may only evidence that a document is **published**, never
that a **claim** inside it is true. A trust-centre page containing the words
"SOC 2 Type II" is a claim by whoever wrote the page. Auto-passing on page content
would manufacture exactly the false assurance this tool exists to avoid.

If you add a collector that reads web content, keep it to structural checks:
does it exist, is it reachable, is it well-formed, is it fresh. Substantive
claims are operator attestations and must go through `Declarations`.

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