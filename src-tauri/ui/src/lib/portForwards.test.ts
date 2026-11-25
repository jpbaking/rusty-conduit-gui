import { describe, test } from "node:test";
import assert from "node:assert/strict";

import {
  findForwardFlags,
  forwardFlag,
  forwardFromPreset,
  newForward,
  parseForwardFlags,
  parseForwardSpec,
  presetFromForward,
  presetSummary,
} from "./portForwards.ts";
import { presetErrors } from "./validate.ts";

type Parsed = ReturnType<typeof parseForwardSpec>;

function parsed(result: Parsed) {
  if (!("forward" in result)) throw new Error(result.error);
  return result.forward;
}

function failed(result: Parsed): string {
  if (!("error" in result)) throw new Error("expected an error");
  return result.error;
}

describe("port forward specs", () => {
  test("formats the ssh flag, bracketing IPv6", () => {
    const local = newForward("local", { port: 15432, dest_host: "db.internal", dest_port: 5432 });
    assert.equal(forwardFlag(local), "-L 127.0.0.1:15432:db.internal:5432");
    const remote = newForward("remote", { bind: "::1", port: 9000, dest_host: "fe80::1", dest_port: 22 });
    assert.equal(forwardFlag(remote), "-R [::1]:9000:[fe80::1]:22");
  });

  test("reads the three- and four-part forms", () => {
    const short = parsed(parseForwardSpec("local", "8080:db:5432"));
    assert.equal(short.bind, "127.0.0.1");
    assert.equal(short.port, 8080);
    assert.equal(short.dest_host, "db");
    assert.equal(short.dest_port, 5432);

    const full = parsed(parseForwardSpec("remote", "[::]:9000:[::1]:3000"));
    assert.equal(full.bind, "::");
    assert.equal(full.dest_host, "::1");

    assert.equal(parsed(parseForwardSpec("remote", "*:9000:localhost:3000")).bind, "0.0.0.0");
  });

  test("explains what it cannot read", () => {
    const cases: [Parameters<typeof parseForwardSpec>, RegExp][] = [
      [["local", "/tmp/sock:db:5432"], /Unix socket/],
      [["remote", "1080"], /expected/],
      [["remote", "0.0.0.0:1080"], /Proxy tab/],
      [["local", "8080:db:99999"], /destination port/],
      [["local", "box:8080:db:22"], /bind address/],
    ];
    for (const [args, expected] of cases) {
      assert.match(failed(parseForwardSpec(...args)), expected);
    }
  });

  test("finds flags in pasted text and argument lists", () => {
    const { forwards, errors } = parseForwardFlags("ssh -N -L 8080:db:5432 -R9000:localhost:3000 -L bad host");
    assert.deepEqual(
      forwards.map((f) => [f.direction, f.port]),
      [
        ["local", 8080],
        ["remote", 9000],
      ],
    );
    assert.equal(errors.length, 1);

    const found = findForwardFlags(["-v", "-L", "1:a:2", "-Rx", "-o", "Compression=yes"]);
    assert.deepEqual(
      found.map((f) => f.indices),
      [[1, 2], [3]],
    );
  });
});

describe("forward presets", () => {
  test("round-trip between a forward and a preset", () => {
    const forward = newForward("local", { name: " DB ", port: 15432, dest_host: "db", dest_port: 5432 });
    const preset = presetFromForward(forward);
    assert.equal(preset.name, "DB");
    assert.equal(preset.bind, null, "loopback is stored as the default");
    assert.equal(presetSummary(preset), "-L 15432 → db:5432");

    const added = forwardFromPreset(preset);
    assert.notEqual(added.id, forward.id);
    assert.equal(added.bind, "127.0.0.1");
    assert.equal(forwardFlag(added), forwardFlag({ ...forward, name: "DB" }));
  });

  test("an unnamed forward gets a name, and an empty host shows as chosen later", () => {
    const preset = presetFromForward(newForward("remote", { port: 9000, dest_host: "", dest_port: 3000 }));
    assert.equal(preset.name, "Remote 9000");
    assert.equal(presetSummary(preset), "-R 9000 → …:3000");
  });

  test("checks presets, allowing an empty host", () => {
    const preset = presetFromForward(newForward("local", { port: 1, dest_host: "", dest_port: 2 }));
    assert.deepEqual(presetErrors(preset), {});
    const errors = presetErrors({ ...preset, name: " ", bind: "box", port: 0, dest_host: "a b" });
    assert.deepEqual(Object.keys(errors).sort(), ["bind", "dest_host", "name", "port"]);
  });
});
