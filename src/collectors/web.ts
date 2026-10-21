import {
  type Collector,
  type CollectorContext,
  type CollectorResult,
  one,
} from "./types.js";
import { safeFetch } from "../util/fetchSafe.js";

/**
 * Published organisational artefacts.
 *
 * Auditors ask for your security.txt, privacy notice, status page and subprocessor
 * list, and none of them live in git. This collector fetches them.
 *
 * The hard rule: this may only evidence that something is **published**, never
 * that a **claim** inside it is true. A trust-centre page containing the words
 * "SOC 2 Type II" is not evidence that anyone holds SOC 2. Anyone can put text on
 * a page. Auto-passing on page content would manufacture a false assurance, which
 * is the single defect class this project treats as most severe. So content is
 * read only to judge structure and freshness, and every substantive claim is left
 * to operator attestation.
 */

export interface ProbeTarget {
  key: string;
  label: string;
  url: string;
}

/** Well-known paths, ordered by likelihood. */
const PROBES: Record<string, { label: string; paths: string[] }> = {
  securityTxt: {
    label: "RFC 9116 security.txt",
    paths: ["/.well-known/security.txt"],
  },
  privacy: {
    label: "Privacy notice",
    paths: [
      "/privacy",
      "/privacy-policy",
      "/legal/privacy",
      "/policies/privacy",
      "/legal/privacy-policy",
      "/en/privacy",
    ],
  },
  terms: {
    label: "Terms of service",
    paths: [
      "/terms",
      "/legal/terms",
      "/policies/terms",
      "/terms-of-service",
      "/en/terms",
    ],
  },
  status: {
    label: "Public status page",
    paths: ["/status", "/status/", "/uptime"],
  },
  trust: {
    label: "Trust centre",
    paths: ["/trust", "/trust-center", "/trustcentre", "/security/trust"],
  },
  subprocessors: {
    label: "Subprocessor list",
    paths: ["/subprocessors", "/sub-processors", "/legal/subprocessors", "/dpa/subprocessors"],
  },
};

/**
 * Derives candidate base URLs in priority order.
 *
 * Repository metadata is attacker-controllable, so every URL is treated as
 * untrusted input and validated by safeFetch. The first candidate is tried first
 * and the caller falls through the list, so a dead `homepage` still lets an
 * explicitly declared URL or the owner's Pages site be found.
 */
export function candidateBaseUrls(
  declared: string[],
  homepage: string | undefined,
  owner: string,
): string[] {
  const out: string[] = [];
  const push = (value: string | undefined) => {
    if (!value) return;
    const trimmed = value.trim();
    if (!trimmed) return;
    const withScheme = /^https?:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed}`;
    const normalized = withScheme.replace(/\/+$/, "");
    if (!out.includes(normalized)) out.push(normalized);
  };

  for (const u of declared) push(u);
  push(homepage);
  // A common default: an org's GitHub Pages site. Reached only if nothing else
  // resolved, since guessing costs a request and may not exist.
  if (out.length === 0) push(`${owner}.github.io`);
  return out;
}

/** Minimal RFC 9116 field reader. Tolerant of CRLF, comments and unknown fields. */
export function parseSecurityTxt(text: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!key) continue;
    // Repeated fields (Contact, Acknowledgments) are kept as a list.
    if (fields[key]) fields[key] = `${fields[key]}, ${value}`;
    else fields[key] = value;
  }
  return fields;
}

export const webPolicyCollector: Collector = {
  name: "web.policy_publication",
  async run(ctx) {
    const declared = (ctx.declarations.websiteUrls ?? []).filter(
      (u): u is string => typeof u === "string",
    );

    const repo = await ctx.gh.getRepo();

    // Candidates are tried in priority order. The first base URL that answers
    // anything wins, so a stale repository homepage does not mask a declared URL
    // that is live. Bounded by bases.length * paths.
    const bases = candidateBaseUrls(
      declared,
      repo?.homepage ?? undefined,
      ctx.target.owner,
    );

    if (bases.length === 0) {
      return one({
        title: "No website to check for published policies",
        passed: false,
        source: `https://github.com/${ctx.target.owner}/${ctx.target.repo}`,
        details: { declaredUrls: declared },
        gaps: [
          "Set `websiteUrls` in auditgen.json, or set a homepage on the repository, so published policies can be evidenced. Auditors ask for these artefacts and they are not in git.",
        ],
      });
    }

    const keys = Object.keys(PROBES) as (keyof typeof PROBES)[];
    const results: CollectorResult[] = [];
    const blocked: string[] = [];
    const attempted: { base: string; found: number }[] = [];

    let base = bases[0]!;
    let findings: Record<string, { url: string; status: number }> = {};
    let securityTxt: Awaited<ReturnType<typeof probeOnce>> = null;
    let baseSource =
      declared.length > 0
        ? "auditgen.json websiteUrls"
        : repo?.homepage
          ? "repository homepage"
          : "owner.github.io";

    // Declared first regardless of position, so the flag wins over discovered data.
    const ordered = [
      ...bases.filter((b) => declared.some((d) => (d.startsWith("https") ? d : `https://${d}`).replace(/\/+$/, "") === b)),
      ...bases.filter((b) => !declared.some((d) => (d.startsWith("https") ? d : `https://${d}`).replace(/\/+$/, "") === b)),
    ];

    for (const candidate of ordered) {
      const found: Record<string, { url: string; status: number }> = {};
      let txt: Awaited<ReturnType<typeof probeOnce>> = null;
      for (const key of keys) {
        const hit = await probeOnce(candidate, key);
        if (hit) {
          found[key] = { url: hit.url, status: hit.status };
          if (key === "securityTxt") txt = hit;
        }
      }
      attempted.push({ base: candidate, found: Object.keys(found).length });
      if (Object.keys(found).length > 0) {
        base = candidate;
        findings = found;
        securityTxt = txt;
        if (candidate !== bases[0]) {
          baseSource = `${baseSource} (fell through to a lower-priority candidate)`;
        }
        break;
      }
      // Keep probing later candidates only if this one yielded nothing at all.
      base = candidate;
      securityTxt = txt;
    }

    const baseDetails = {
      baseUrl: base,
      baseUrlSource: baseSource,
      candidateUrls: bases,
      candidatesAttempted: attempted,
      probes: findings,
      blockedRequests: blocked,
      securityPolicyContentChecked: false,
      claimVerification: "none: published text is not evidence a claim is true",
    };

    async function probeOnce(
      baseUrl: string,
      key: keyof typeof PROBES,
    ): Promise<{ url: string; status: number; body?: string } | null> {
      const spec = PROBES[key]!;
      for (const path of spec.paths) {
        const url = `${baseUrl}${path}`;
        const res = await safeFetch(url, { readBody: true });
        if (res.blocked) {
          if (blocked.length < 10) {
            blocked.push(`${baseUrl}${path}: ${res.blocked}`);
          }
          continue;
        }
        if (res.ok) return { url: res.url, status: res.status, ...(res.body !== undefined ? { body: res.body } : {}) };
      }
      return null;
    }

    if (blocked.length > 0) {
      ctx.warnings.push(
        `${blocked.length} policy probe(s) were blocked by the URL safety guard: ${blocked[0]}`,
      );
    }

    // ---- Assertion 1: security.txt -------------------------------------
    if (securityTxt?.body !== undefined) {
      const fields = parseSecurityTxt(securityTxt.body);
      const contacts = (fields["contact"] ?? "")
        .split(",")
        .map((c) => c.trim())
        .filter(Boolean);
      const expiresRaw = fields["expires"];
      const expiresAt = expiresRaw ? Date.parse(expiresRaw) : NaN;
      const expired = !Number.isNaN(expiresAt) && expiresAt < Date.now();
      const hasContact = contacts.length > 0;

      const gaps: string[] = [];
      if (!hasContact) {
        gaps.push(
          "security.txt has no Contact field. RFC 9116 requires one, and without it a reporter has nowhere to send a finding.",
        );
      }
      if (!expiresRaw) {
        gaps.push(
          "security.txt has no Expires field. RFC 9116 requires it, and it is what stops the file silently going stale.",
        );
      } else if (expired) {
        gaps.push(
          `security.txt expired on ${expiresRaw}. A lapsed security contact is treated as no contact by most tooling and by researchers.`,
        );
      }

      results.push(
        ...one({
          title: hasContact && !expired
            ? `security.txt published with ${contacts.length} contact(s) and a valid expiry`
            : !expiresRaw
              ? "security.txt published without an Expires field"
              : expired
                ? `security.txt expired on ${expiresRaw}`
                : "security.txt published without a Contact field",
          passed: hasContact && Boolean(expiresRaw) && !expired,
          source: securityTxt.url,
          details: {
            ...baseDetails,
            fieldNames: Object.keys(fields),
            contactCount: contacts.length,
            hasExpires: Boolean(expiresRaw),
            expires: expiresRaw ?? null,
            expired,
            hasPolicyField: Boolean(fields["policy"]),
            hasAcknowledgments: Boolean(fields["acknowledgments"]),
            hasEncryption: Boolean(fields["encryption"]),
          },
          gaps,
        }),
      );
    } else {
      results.push(
        ...one({
          title: "No security.txt at /.well-known/security.txt",
          passed: false,
          source: `${base}/.well-known/security.txt`,
          details: { ...baseDetails, searchedPaths: PROBES["securityTxt"]!.paths },
          gaps: [
            "Publish an RFC 9116 security.txt at /.well-known/security.txt with a Contact and a future Expires. It is the one policy artefact that costs nothing and researchers check it first.",
          ],
        }),
      );
    }

    // ---- Assertions 2-6: published policies -----------------------------
    const policyGaps: Record<string, string> = {
      privacy:
        "Publish a privacy notice stating what personal data is collected, the lawful basis, retention periods and contact details. Without one you cannot answer a data-subject request or a customer security questionnaire.",
      terms:
        "Publish terms of service covering acceptable use, liability and jurisdiction. Customers' vendor reviews ask for this and cannot be satisfied by a login wall.",
      status:
        "Publish a status page or incident history. A trust-centre page claiming reliability is unfalsifiable; a status page with timestamps is not.",
      trust:
        "Publish a trust centre or security page summarising your posture. Note that published claims are your assertion, not verified by auditgen; auditgen checks that it is reachable, never that a claim on it is true.",
      subprocessors:
        "Publish a subprocessor list. Customers must be able to see who processes their data; this is also the external face of the supplier-risk controls.",
    };

    for (const key of ["privacy", "terms", "status", "trust", "subprocessors"] as const) {
      const found = findings[key];
      results.push(
        ...one({
          title: found
            ? `${PROBES[key]!.label} published at ${new URL(found.url).pathname}`
            : `${PROBES[key]!.label} not found`,
          passed: Boolean(found),
          source: found?.url ?? `${base}${PROBES[key]!.paths[0]}`,
          details: {
            ...baseDetails,
            artefact: key,
            reachable: Boolean(found),
            finalUrl: found?.url ?? null,
            statusCode: found?.status ?? null,
            searchedPaths: PROBES[key]!.paths,
          },
          ...(found ? {} : { gaps: [policyGaps[key]!] }),
        }),
      );
    }

    return results;
  },
};

export const WEB_COLLECTORS: Collector[] = [webPolicyCollector];