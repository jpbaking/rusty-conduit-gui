import { describe, test } from "node:test";
import assert from "node:assert/strict";

import type { OpenSshBinaryInfo, SessionState } from "./types.ts";
import {
  checkStatus,
  formatBytes,
  formatUptime,
  isActive,
  logLevel,
  passesLevel,
  proxyUrls,
  stateReason,
  statusOf,
} from "./format.ts";

const awaitingHostKey: SessionState = {
  state: "awaiting_host_key",
  hop_index: 0,
  hop_id: "hop-1",
  host: "example.com",
  port: 22,
  algorithm: "ssh-ed25519",
  sha256: "SHA256:abc",
  public_key_openssh: null,
};

const states: Record<SessionState["state"], SessionState> = {
  stopped: { state: "stopped" },
  starting: { state: "starting" },
  connected: { state: "connected" },
  reconnecting: { state: "reconnecting", attempt: 3, next_retry_secs: 5 },
  waiting_for_network: { state: "waiting_for_network" },
  locked: { state: "locked" },
  awaiting_host_key: awaitingHostKey,
  needs_attention: { state: "needs_attention", reason: "Host key changed" },
  failed: { state: "failed", reason: "Auth failed" },
};

describe("statusOf", () => {
  test("maps every state to a glyph, label, and tone", () => {
    assert.deepEqual(statusOf(states.connected), { glyph: "●", label: "Connected", tone: "ok" });
    assert.deepEqual(statusOf(states.starting), { glyph: "◐", label: "Starting", tone: "busy" });
    assert.deepEqual(statusOf(states.reconnecting), {
      glyph: "◐",
      label: "Reconnecting (try 3)",
      tone: "busy",
    });
    assert.deepEqual(statusOf(states.waiting_for_network), {
      glyph: "◐",
      label: "Waiting for network",
      tone: "busy",
    });
    assert.deepEqual(statusOf(states.locked), { glyph: "!", label: "Vault locked", tone: "alert" });
    assert.deepEqual(statusOf(states.awaiting_host_key), {
      glyph: "!",
      label: "Host key needs approval",
      tone: "alert",
    });
    assert.deepEqual(statusOf(states.needs_attention), {
      glyph: "!",
      label: "Needs attention",
      tone: "alert",
    });
    assert.deepEqual(statusOf(states.failed), { glyph: "!", label: "Failed", tone: "alert" });
    assert.deepEqual(statusOf(states.stopped), { glyph: "○", label: "Stopped", tone: "idle" });
  });
});

describe("isActive", () => {
  test("is true while a supervisor runs", () => {
    for (const name of ["starting", "connected", "reconnecting", "waiting_for_network", "awaiting_host_key"] as const) {
      assert.equal(isActive(states[name]), true, name);
    }
  });

  test("is false once the session has stopped or cannot run", () => {
    for (const name of ["stopped", "locked", "needs_attention", "failed"] as const) {
      assert.equal(isActive(states[name]), false, name);
    }
  });
});

describe("stateReason", () => {
  test("returns the reason only for needs_attention and failed", () => {
    assert.equal(stateReason(states.needs_attention), "Host key changed");
    assert.equal(stateReason(states.failed), "Auth failed");
    assert.equal(stateReason(states.connected), null);
    assert.equal(stateReason(states.stopped), null);
  });
});

describe("proxyUrls", () => {
  test("maps each listener role to client URLs", () => {
    assert.deepEqual(proxyUrls({ role: "HTTP/HTTPS", addr: "127.0.0.1:3128" }), [
      { label: "HTTP", url: "http://127.0.0.1:3128" },
    ]);
    assert.deepEqual(proxyUrls({ role: "SOCKS4/4a/5", addr: "127.0.0.1:1080" }), [
      { label: "SOCKS", url: "socks5h://127.0.0.1:1080" },
    ]);
    assert.deepEqual(proxyUrls({ role: "multiplexed HTTP/HTTPS + SOCKS4/4a/5", addr: "127.0.0.1:8080" }), [
      { label: "HTTP", url: "http://127.0.0.1:8080" },
      { label: "SOCKS", url: "socks5h://127.0.0.1:8080" },
    ]);
  });

  test("points wildcard binds at loopback", () => {
    assert.equal(proxyUrls({ role: "HTTP/HTTPS", addr: "0.0.0.0:3128" })[0]?.url, "http://127.0.0.1:3128");
    assert.equal(proxyUrls({ role: "SOCKS4/4a/5", addr: "[::]:1080" })[0]?.url, "socks5h://[::1]:1080");
  });
});

describe("formatBytes", () => {
  test("shows whole bytes below 1 KB", () => {
    assert.equal(formatBytes(0), "0 B");
    assert.equal(formatBytes(1023), "1023 B");
  });

  test("scales by 1024 with one decimal", () => {
    assert.equal(formatBytes(1024), "1.0 KB");
    assert.equal(formatBytes(1536), "1.5 KB");
    assert.equal(formatBytes(1024 ** 2), "1.0 MB");
    assert.equal(formatBytes(5.25 * 1024 ** 3), "5.3 GB");
    assert.equal(formatBytes(1024 ** 4), "1.0 TB");
  });

  test("stops at PB", () => {
    assert.equal(formatBytes(1024 ** 5), "1.0 PB");
    assert.equal(formatBytes(1024 ** 6), "1024.0 PB");
  });
});

describe("formatUptime", () => {
  test("shows seconds, minutes, or hours", () => {
    assert.equal(formatUptime(0), "0s");
    assert.equal(formatUptime(59), "59s");
    assert.equal(formatUptime(60), "1m 0s");
    assert.equal(formatUptime(3599), "59m 59s");
    assert.equal(formatUptime(3600), "1h 0m");
    assert.equal(formatUptime(3725), "1h 2m");
    assert.equal(formatUptime(90000), "25h 0m");
  });
});

describe("logLevel", () => {
  test("reads upper-case level words", () => {
    assert.equal(logLevel("2026-11-24 ERROR connection lost"), "error");
    assert.equal(logLevel("FATAL cannot bind"), "error");
    assert.equal(logLevel("WARN retrying"), "warn");
    assert.equal(logLevel("WARNING retrying"), "warn");
    assert.equal(logLevel("INFO started"), "info");
    assert.equal(logLevel("DEBUG frame"), "debug");
    assert.equal(logLevel("TRACE frame"), "debug");
    assert.equal(logLevel("VERBOSE frame"), "debug");
  });

  test("reads a JSON level field", () => {
    assert.equal(logLevel('{"level":"error","msg":"x"}'), "error");
    assert.equal(logLevel('{"level": "warn"}'), "warn");
    assert.equal(logLevel('{"level":"debug"}'), "debug");
  });

  test("treats unmarked lines as info", () => {
    assert.equal(logLevel("plain text"), "info");
    assert.equal(logLevel("an error in lower case"), "info");
    assert.equal(logLevel("TERRORIST"), "info");
  });
});

describe("passesLevel", () => {
  test("keeps lines at or above the filter level", () => {
    assert.equal(passesLevel("error", "warn"), true);
    assert.equal(passesLevel("warn", "warn"), true);
    assert.equal(passesLevel("info", "warn"), false);
    assert.equal(passesLevel("debug", "info"), false);
    assert.equal(passesLevel("debug", "debug"), true);
  });

  test("keeps everything for all", () => {
    for (const level of ["error", "warn", "info", "debug"] as const) {
      assert.equal(passesLevel(level, "all"), true, level);
    }
  });
});

describe("checkStatus", () => {
  const info = (patch: Partial<OpenSshBinaryInfo>): OpenSshBinaryInfo => ({
    requested: "ssh",
    resolved_path: "/usr/bin/ssh",
    version_raw: "OpenSSH_10.5p1",
    major: 10,
    minor: 5,
    supported: true,
    message: "OpenSSH 10.5 is supported.",
    note: null,
    ...patch,
  });

  test("reads each kind of result", () => {
    assert.deepEqual(checkStatus(info({})), { tone: "ok", label: "Supported" });
    assert.deepEqual(checkStatus(info({ note: "prompts" })), { tone: "busy", label: "Supported" });
    assert.deepEqual(checkStatus(info({ supported: false, major: 7, minor: 2 })), {
      tone: "busy",
      label: "Version too old",
    });
    assert.deepEqual(checkStatus(info({ supported: false, major: null, minor: null })), {
      tone: "alert",
      label: "Not usable",
    });
    assert.deepEqual(
      checkStatus(info({ supported: false, resolved_path: null, major: null, minor: null })),
      { tone: "alert", label: "Not found" },
    );
  });
});
