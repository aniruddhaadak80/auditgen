import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reconcileLocalPath } from "../src/audit.js";

/**
 * This guard exists because the alternative is the worst failure this tool could
 * have: telling someone their repository has no committed secrets when it never
 * looked at their repository.
 */

function makeRepo(remote?: string): string {
  const dir = mkdtempSync(join(tmpdir(), "auditgen-test-"));
  execFileSync("git", ["init", "-b", "main"], { cwd: dir, windowsHide: true });
  if (remote) {
    execFileSync("git", ["remote", "add", "origin", remote], {
      cwd: dir,
      windowsHide: true,
    });
  }
  return dir;
}

const created: string[] = [];
after(() => {
  for (const dir of created) rmSync(dir, { recursive: true, force: true });
});

describe("reconcileLocalPath", () => {
  it("passes through when no local path was supplied", () => {
    const res = reconcileLocalPath({ owner: "acme", repo: "widget" });
    assert.deepEqual(res, {});
  });

  it("keeps a local path whose origin matches the target", () => {
    const dir = makeRepo("git@github.com:acme/widget.git");
    created.push(dir);
    const res = reconcileLocalPath({
      owner: "acme",
      repo: "widget",
      localPath: dir,
    });
    assert.equal(res.localPath, dir);
    assert.equal(res.mismatch, undefined);
  });

  it("matches case-insensitively", () => {
    const dir = makeRepo("https://github.com/Acme/Widget.git");
    created.push(dir);
    const res = reconcileLocalPath({
      owner: "acme",
      repo: "widget",
      localPath: dir,
    });
    assert.equal(res.localPath, dir);
  });

  it("discards a local path belonging to a different repository", () => {
    const dir = makeRepo("git@github.com:someone/else.git");
    created.push(dir);
    const res = reconcileLocalPath({
      owner: "acme",
      repo: "widget",
      localPath: dir,
    });
    assert.equal(res.localPath, undefined);
    assert.match(res.mismatch ?? "", /someone\/else/);
    assert.match(res.mismatch ?? "", /acme\/widget/);
    assert.match(res.mismatch ?? "", /wrong repository/);
  });

  it("discards a local path when the owner differs but the repo name matches", () => {
    const dir = makeRepo("https://github.com/attacker/widget.git");
    created.push(dir);
    const res = reconcileLocalPath({
      owner: "acme",
      repo: "widget",
      localPath: dir,
    });
    assert.equal(res.localPath, undefined);
    assert.match(res.mismatch ?? "", /wrong repository/);
  });

  it("discards a local path with a non-GitHub remote", () => {
    const dir = makeRepo("https://gitlab.com/acme/widget.git");
    created.push(dir);
    const res = reconcileLocalPath({
      owner: "acme",
      repo: "widget",
      localPath: dir,
    });
    assert.equal(res.localPath, undefined);
    assert.match(res.mismatch ?? "", /not a GitHub remote/);
  });

  it("discards a local path with no origin at all", () => {
    const dir = makeRepo();
    created.push(dir);
    const res = reconcileLocalPath({
      owner: "acme",
      repo: "widget",
      localPath: dir,
    });
    assert.equal(res.localPath, undefined);
    assert.match(res.mismatch ?? "", /no origin remote/);
  });
});