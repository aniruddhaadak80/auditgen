import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfigFile } from "../src/config.js";
import {
  isPrivateAddress,
  assertFetchableUrl,
  assertPublicHost,
  safeFetch,
  BlockedUrlError,
} from "../src/util/fetchSafe.js";
import { parseSecurityTxt, candidateBaseUrls } from "../src/collectors/web.js";

/**
 * auditgen runs in CI, often on a cloud runner holding instance credentials,
 * and it is pointed at URLs taken from repository metadata that an attacker can
 * set. These tests are the difference between a tool that reports on trust and
 * the weakest link in the trust chain.
 */

describe("isPrivateAddress", () => {
  const blocked = [
    // Loopback
    "127.0.0.1",
    "127.1.2.3",
    // Private ranges
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    // Cloud instance metadata. This is the one that actually matters.
    "169.254.169.254",
    "169.254.170.2",
    // "this network"
    "0.0.0.0",
    // Carrier-grade NAT
    "100.64.0.1",
    // Benchmarking and protocol assignments
    "198.18.0.1",
    "192.0.0.1",
    // Multicast and broadcast
    "224.0.0.1",
    "255.255.255.255",
    // IPv6
    "::1",
    "::",
    "fe80::1",
    "fd00::1",
    "fc00::1",
    "ff02::1",
    // IPv4-mapped forms that could smuggle a v4 target past a v6 check
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "64:ff9b::1",
    "2002::1",
  ];

  for (const ip of blocked) {
    it(`blocks ${ip}`, () => {
      assert.equal(isPrivateAddress(ip), true);
    });
  }

  const allowed = [
    "1.1.1.1",
    "8.8.8.8",
    "140.82.121.4",
    "172.32.0.1",
    "192.169.0.1",
    "2606:4700::1111",
  ];

  for (const ip of allowed) {
    it(`allows ${ip}`, () => {
      assert.equal(isPrivateAddress(ip), false);
    });
  }

  it("blocks anything that is not a valid IP literal", () => {
    // Fail closed: an unrecognised form must not be treated as public.
    assert.equal(isPrivateAddress("not-an-ip"), true);
    assert.equal(isPrivateAddress("999.999.999.999"), true);
  });
});

describe("assertFetchableUrl", () => {
  it("allows http and https", () => {
    assert.equal(assertFetchableUrl("https://example.test/").protocol, "https:");
    assert.equal(assertFetchableUrl("http://example.test/").protocol, "http:");
  });

  it("blocks non-http schemes", () => {
    for (const url of [
      "file:///etc/passwd",
      "ftp://example.test/x",
      "gopher://example.test/",
      "data:text/html,<script>alert(1)</script>",
      "javascript:alert(1)",
    ]) {
      assert.throws(() => assertFetchableUrl(url), BlockedUrlError, url);
    }
  });

  it("blocks a literal private address without resolving anything", () => {
    assert.throws(
      () => assertFetchableUrl("http://169.254.169.254/latest/meta-data/"),
      /literal address/,
    );
    assert.throws(
      () => assertFetchableUrl("http://127.0.0.1:8080/admin"),
      /literal address/,
    );
  });

  it("blocks an IPv6 literal loopback", () => {
    assert.throws(() => assertFetchableUrl("http://[::1]/"), /literal address/);
  });

  it("blocks credentials embedded in the authority", () => {
    assert.throws(
      () => assertFetchableUrl("https://user:pass@example.test/"),
      /credentials/,
    );
  });

  it("rejects malformed input", () => {
    assert.throws(() => assertFetchableUrl("not a url"), /valid URL/);
  });
});

describe("assertPublicHost", () => {
  it("rejects a host that resolves to loopback", async () => {
    // localhost resolves to 127.0.0.1 without needing DNS.
    await assert.rejects(
      () => assertPublicHost(new URL("http://localhost/")),
      /private address/,
    );
  });

  it("rejects a host that cannot be resolved", async () => {
    await assert.rejects(
      () => assertPublicHost(new URL("https://this-host-does-not-exist.invalid/")),
      /Could not resolve|no addresses/,
    );
  });

  it("accepts an already-validated literal without a lookup", async () => {
    await assert.doesNotReject(() =>
      assertPublicHost(new URL("https://1.1.1.1/")),
    );
  });
});

describe("safeFetch", () => {
  it("refuses to fetch a cloud metadata URL", async () => {
    const res = await safeFetch("http://169.254.169.254/latest/meta-data/iam/");
    assert.equal(res.ok, false);
    assert.match(res.blocked ?? "", /private address|literal address/);
    assert.equal(res.body, undefined, "must not return metadata content");
  });

  it("refuses a file URL", async () => {
    const res = await safeFetch("file:///C:/Windows/win.ini");
    assert.equal(res.ok, false);
    assert.match(res.blocked ?? "", /scheme/);
  });

  it("returns a blocked result rather than throwing", async () => {
    // Callers treat this as data, so an unthrowable failure mode matters.
    const res = await safeFetch("http://127.0.0.1/");
    assert.equal(res.ok, false);
    assert.ok(res.blocked);
  });
});

describe("parseSecurityTxt", () => {
  const sample = `# Comment line
Contact: mailto:security@example.test
Contact: https://example.test/report
Expires: 2027-01-15T00:00:00.000Z
Encryption: https://example.test/pgp-key.txt
Preferred-Languages: en
Acknowledgments: https://example.test/hall-of-fame
Canonical: https://example.test/.well-known/security.txt
`;

  it("reads single fields", () => {
    const fields = parseSecurityTxt(sample);
    assert.equal(fields["encryption"], "https://example.test/pgp-key.txt");
    assert.equal(fields["canonical"], "https://example.test/.well-known/security.txt");
  });

  it("lowercases keys and joins repeated fields", () => {
    const fields = parseSecurityTxt(sample);
    assert.match(fields["contact"] ?? "", /security@example\.test/);
    assert.match(fields["contact"] ?? "", /example\.test\/report/);
  });

  it("tolerates CRLF line endings", () => {
    const fields = parseSecurityTxt(sample.replace(/\n/g, "\r\n"));
    assert.equal(fields["expires"], "2027-01-15T00:00:00.000Z");
  });

  it("ignores comments and blank lines", () => {
    const fields = parseSecurityTxt("# only a comment\n\n   \n");
    assert.deepEqual(fields, {});
  });

  it("ignores lines with no colon", () => {
    const fields = parseSecurityTxt("garbage\nContact: a@b.test");
    assert.equal(Object.keys(fields).length, 1);
  });

  it("does not read a claim about a certification", () => {
    // Explicitly documents the boundary: parseSecurityTxt exists to read
    // RFC 9116 fields, never to conclude anything from prose in the file.
    const fields = parseSecurityTxt("SOC2: Type II certified\nContact: a@b.test");
    assert.equal(fields["soc2"], "Type II certified");
    assert.equal(fields["contact"], "a@b.test");
  });
});

describe("loadConfigFile", () => {
  const dir = mkdtempSync(join(tmpdir(), "auditgen-cfg-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("reads a plain config", () => {
    const p = join(dir, "plain.json");
    writeFileSync(p, '{"organizationName":"Acme"}', "utf8");
    assert.equal(loadConfigFile(p).organizationName, "Acme");
  });

  it("tolerates a UTF-8 BOM", () => {
    // Windows PowerShell 5.1 writes a BOM for Set-Content -Encoding utf8, and
    // JSON.parse rejects U+FEFF. Without this, every config authored from the
    // default Windows shell fails to load.
    const p = join(dir, "bom.json");
    writeFileSync(p, '\uFEFF{"websiteUrls":["https://acme.test"]}', "utf8");
    assert.deepEqual(loadConfigFile(p).websiteUrls, ["https://acme.test"]);
  });

  it("reports the file path on a parse error", () => {
    const p = join(dir, "bad.json");
    writeFileSync(p, "{not json", "utf8");
    assert.throws(() => loadConfigFile(p), /bad\.json: invalid JSON/);
  });

  it("rejects a non-object document", () => {
    const p = join(dir, "array.json");
    writeFileSync(p, "[1,2]", "utf8");
    assert.throws(() => loadConfigFile(p), /expected a JSON object/);
  });

  it("strips line and block comments in a jsonc file", () => {
    const p = join(dir, "c.jsonc");
    writeFileSync(
      p,
      '// leading\n{\n /* block */ "organizationName": "Acme" // trailing\n}',
      "utf8",
    );
    assert.equal(loadConfigFile(p).organizationName, "Acme");
  });

  it("does not treat a URL as a comment", () => {
    const p = join(dir, "u.jsonc");
    writeFileSync(
      p,
      '{ "websiteUrls": ["https://acme.test//docs"] } // real comment',
      "utf8",
    );
    assert.deepEqual(loadConfigFile(p).websiteUrls, [
      "https://acme.test//docs",
    ]);
  });

  it("does not treat an escaped quote as a string end", () => {
    const p = join(dir, "e.jsonc");
    writeFileSync(
      p,
      '{ "systemDescription": "say \\"hi\\" // not a comment" }',
      "utf8",
    );
    assert.equal(
      loadConfigFile(p).systemDescription,
      'say "hi" // not a comment',
    );
  });
});

describe("candidateBaseUrls", () => {
  it("lists candidates in priority order, declared first", () => {
    // The caller probes in order and falls through, so a dead repository
    // homepage cannot mask a declared URL that is live.
    assert.deepEqual(
      candidateBaseUrls(["https://acme.test"], "https://github.test", "acme"),
      ["https://acme.test", "https://github.test"],
    );
  });

  it("falls back to the repository homepage when nothing is declared", () => {
    assert.deepEqual(
      candidateBaseUrls([], "https://acme.test/", "acme"),
      ["https://acme.test"],
    );
  });

  it("assumes a scheme when one is missing", () => {
    assert.deepEqual(candidateBaseUrls(["acme.test"], undefined, "acme"), [
      "https://acme.test",
    ]);
  });

  it("falls back to the owner's github pages", () => {
    assert.deepEqual(candidateBaseUrls([], undefined, "acme"), [
      "https://acme.github.io",
    ]);
  });

  it("deduplicates", () => {
    assert.deepEqual(
      candidateBaseUrls(["https://a.test", "https://a.test/"], undefined, "x"),
      ["https://a.test"],
    );
  });
});