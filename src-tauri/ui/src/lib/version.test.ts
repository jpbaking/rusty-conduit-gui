import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { releaseNotesUrl, releaseStage, resolveAppVersion } from "./version.ts";

describe("resolveAppVersion", () => {
  test("uses the tag's release version", () => {
    assert.equal(resolveAppVersion("0.2.0", "0.2.0-beta.6"), "0.2.0-beta.6");
    assert.equal(resolveAppVersion("0.2.0", "0.2.0"), "0.2.0");
  });

  test("marks any other build as a development build", () => {
    assert.equal(resolveAppVersion("0.2.0", undefined), "0.2.0-dev");
    assert.equal(resolveAppVersion("0.2.0", ""), "0.2.0-dev");
  });

  test("rejects a release version for another X.Y.Z", () => {
    let message = "";
    try {
      resolveAppVersion("0.2.0", "0.3.0-beta.1");
    } catch (error) {
      message = (error as Error).message;
    }
    assert.match(message, /does not match package\.json version 0\.2\.0/);
    assert.notEqual(resolveAppVersion("0.2.0", "0.2.0-rc.1"), "0.2.0");
  });

  test("does not accept a longer version that only shares a prefix", () => {
    let threw = false;
    try {
      resolveAppVersion("0.2.0", "0.2.01");
    } catch {
      threw = true;
    }
    assert.ok(threw);
  });
});

describe("releaseStage", () => {
  test("names the pre-release label", () => {
    assert.equal(releaseStage("0.2.0-beta.6"), "beta");
    assert.equal(releaseStage("1.0.0-rc.1"), "rc");
    assert.equal(releaseStage("0.2.0-dev"), "dev");
    assert.equal(releaseStage("0.2.0-dev.abc1234"), "dev");
  });

  test("is null for a final release", () => {
    assert.equal(releaseStage("1.0.0"), null);
  });
});

describe("releaseNotesUrl", () => {
  const repo = "https://github.com/jpbaking/rusty-conduit-gui";

  test("links a release build to its own tag", () => {
    assert.equal(releaseNotesUrl(repo, "0.2.0-beta.6"), `${repo}/releases/tag/v0.2.0-beta.6`);
    assert.equal(releaseNotesUrl(repo, "1.0.0"), `${repo}/releases/tag/v1.0.0`);
  });

  test("links a development build to the releases list", () => {
    assert.equal(releaseNotesUrl(repo, "0.2.0-dev"), `${repo}/releases`);
  });
});
