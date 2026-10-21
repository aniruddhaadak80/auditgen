import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * SSRF-safe fetching for URLs discovered from repository metadata.
 *
 * This exists because auditgen runs in CI, often on a cloud runner that has
 * instance credentials in its environment, and it is being pointed at a URL
 * taken from a repository's `homepage` field. A repository under an attacker's
 * control can set that to anything, including `http://169.254.169.254/`, and a
 * naive fetch would hand back the instance metadata, IAM role name, or a token.
 *
 * A tool whose job is reporting on trust cannot be the weakest link in the trust
 * chain, so: scheme allow-list, DNS resolution with every returned address
 * checked, manual redirect following with re-validation at each hop, a hard
 * timeout, and a response size cap.
 */

export class BlockedUrlError extends Error {
  constructor(
    message: string,
    readonly url: string,
  ) {
    super(message);
    this.name = "BlockedUrlError";
  }
}

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 3;
const MAX_BYTES = 512 * 1024;

/**
 * True when an address must never be reached from a tool that follows
 * repository-supplied URLs.
 */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateV4(ip);
  if (version === 6) return isPrivateV6(ip);
  // Not an IP literal; caller should have resolved it.
  return true;
}

function isPrivateV4(ip: string): boolean {
  const p = ip.split(".").map(Number) as [number, number, number, number];
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = p;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 192 && b === 0) return true; // IETF protocol assignments
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 192 && b === 88) return true; // 6to4 relay anycast
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast and reserved, incl. broadcast
  return false;
}

function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (lower.startsWith("fe80")) return true; // link-local
  if (/^f[cd]/.test(lower)) return true; // unique local fc00::/7
  if (lower.startsWith("ff")) return true; // multicast
  // IPv4-mapped and IPv4-compatible forms can smuggle a v4 target past a v6 check.
  const mapped = /^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped?.[1]) return isPrivateV4(mapped[1]);
  if (lower.startsWith("64:ff9b")) return true; // NAT64
  if (lower.startsWith("2002:")) return true; // 6to4
  if (lower.startsWith("100:")) return true; // discard-only
  return false;
}

/** Validates scheme and host shape without touching the network. */
export function assertFetchableUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new BlockedUrlError(`Not a valid URL: ${raw}`, raw);
  }
  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new BlockedUrlError(
      `Blocked scheme "${url.protocol}". Only http and https are fetched.`,
      raw,
    );
  }
  if (url.username || url.password) {
    throw new BlockedUrlError(
      "Blocked URL containing credentials in the authority.",
      raw,
    );
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  // A literal address skips DNS, so check it directly.
  if (isIP(host) && isPrivateAddress(host)) {
    throw new BlockedUrlError(
      `Blocked request to the literal address ${host}.`,
      raw,
    );
  }
  return url;
}

/**
 * Resolves the host and rejects if any returned address is private. All
 * addresses are checked, not just the first: a hostname with both a public and a
 * private A record is a rebinding attempt.
 */
export async function assertPublicHost(url: URL): Promise<void> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) return; // already validated by assertFetchableUrl
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host, { all: true });
  } catch (err) {
    throw new BlockedUrlError(
      `Could not resolve "${host}": ${err instanceof Error ? err.message : String(err)}`,
      url.toString(),
    );
  }
  if (addresses.length === 0) {
    throw new BlockedUrlError(`"${host}" resolved to no addresses.`, url.toString());
  }
  for (const { address } of addresses) {
    if (isPrivateAddress(address)) {
      throw new BlockedUrlError(
        `Blocked: "${host}" resolves to the private address ${address}.`,
        url.toString(),
      );
    }
  }
}

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  /** Final URL after redirects. */
  url: string;
  contentType: string | null;
  /** Body, truncated to MAX_BYTES. Absent for non-2xx unless requested. */
  body?: string;
  /** Populated when the request was blocked or failed. */
  blocked?: string;
}

/**
 * Fetch with SSRF protection, manual redirect handling, a timeout and a size
 * cap. Redirects are followed by hand so every hop is re-validated; handing this
 * to fetch() would validate only the first URL.
 */
export async function safeFetch(
  raw: string,
  options: { method?: string; readBody?: boolean; timeoutMs?: number } = {},
): Promise<SafeFetchResult> {
  const { method = "GET", readBody = true } = options;
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;
  let current = raw;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let url: URL;
    try {
      url = assertFetchableUrl(current);
      await assertPublicHost(url);
    } catch (err) {
      return {
        ok: false,
        status: 0,
        url: current,
        contentType: null,
        blocked: err instanceof BlockedUrlError
          ? err.message
          : String(err),
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "auditgen (+https://github.com/aniruddhaadak80/auditgen)",
          Accept: "text/html,application/xhtml+xml,text/plain,*/*",
        },
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) {
          return {
            ok: false,
            status: res.status,
            url: url.toString(),
            contentType: null,
          };
        }
        current = new URL(location, url).toString();
        continue;
      }

      const contentType = res.headers.get("content-type");
      let body: string | undefined;
      if (readBody && res.ok) {
        body = await readCapped(res);
      }
      return {
        ok: res.ok,
        status: res.status,
        url: url.toString(),
        contentType,
        ...(body !== undefined ? { body } : {}),
      };
    } catch (err) {
      return {
        ok: false,
        status: 0,
        url: url.toString(),
        contentType: null,
        blocked: err instanceof Error ? err.message : String(err),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    ok: false,
    status: 0,
    url: current,
    contentType: null,
    blocked: `More than ${MAX_REDIRECTS} redirects.`,
  };
}

/** Reads at most MAX_BYTES so a hostile endpoint cannot exhaust memory. */
async function readCapped(res: Response): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      chunks.push(value);
      total += value.byteLength;
      if (total >= MAX_BYTES) break;
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      // Cancelling a finished stream is not an error worth surfacing.
    }
  }
  const merged = new Uint8Array(Math.min(total, MAX_BYTES));
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= merged.length) break;
    const take = Math.min(chunk.byteLength, merged.length - offset);
    merged.set(chunk.subarray(0, take), offset);
    offset += take;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}