import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { PASSWORD_RULES, isStrongPassword } from "./password.ts";

const unmet = (password: string) => PASSWORD_RULES.filter((r) => !r.met(password)).map((r) => r.label);

describe("password rules", () => {
  test("match the backend's cases", () => {
    assert.ok(isStrongPassword("Str0ng!pw"));
    assert.ok(isStrongPassword("Ünï cødé 9"), "Unicode letters and a space count");
    assert.deepEqual(unmet("Ab1!xyz"), ["8 or more characters"]);
    assert.deepEqual(unmet("abcdefg1!"), ["An uppercase letter"]);
    assert.deepEqual(unmet("ABCDEFG1!"), ["A lowercase letter"]);
    assert.deepEqual(unmet("Abcdefgh!"), ["A number"]);
    assert.deepEqual(unmet("Abcdefgh1"), ["A special character"]);
    assert.equal(unmet("").length, 5);
  });

  test("count characters, not UTF-16 units", () => {
    // Seven characters, but the emoji is two UTF-16 units.
    assert.ok(!isStrongPassword("Ab1!xy😀"));
    assert.ok(isStrongPassword("Ab1!xyz😀"));
  });
});
