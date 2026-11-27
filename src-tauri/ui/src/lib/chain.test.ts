import { describe, test } from "node:test";
import assert from "node:assert/strict";

import type { AuthMethod, HopEntry, HopTestResult, SessionProfile } from "./types.ts";
import { authRefs, blankHost, hopBadge, hopRole, hopTitle, moved, profileRefs } from "./chain.ts";

function hop(name: string, host: string, auth: AuthMethod[] = []): HopEntry {
  return {
    hop_id: `hop-${name || host}`,
    name,
    host: { ...blankHost(), host, user: "me", auth },
  };
}

function result(status: HopTestResult["status"], error: string | null, elapsed_ms = 0): HopTestResult {
  return { hop_index: 0, hop_id: "hop-1", host: "example.com", port: 22, status, error, elapsed_ms, host_key: null };
}

function profile(hops: HopEntry[], ca: string | null): SessionProfile {
  return {
    id: "00000000-0000-0000-0000-000000000001",
    name: "Work",
    autostart: false,
    enabled: true,
    engine: "Russh",
    hops,
    forward: {
      enabled: true,
      bind: "127.0.0.1",
      http_port: 8080,
      socks_port: 0,
      max_connections: 0,
      allow: [],
      block: [],
    },
    reverse: {
      enabled: false,
      reverse_bind: "127.0.0.1",
      reverse_http_port: 0,
      reverse_socks_port: 0,
      reverse_max_connections: null,
      reverse_allow: [],
      reverse_block: [],
    },
    port_forwards: [],
    mitm:
      ca === null
        ? null
        : {
            ca,
            cert_ttl: 3600,
            cert_cache_max_entries: 0,
            socks_block_web: false,
            upstream_tls_mode: "strict",
            insecure_hosts: [],
          },
    tunnel: {
      ip_version: "auto",
      server_alive_interval: 30,
      server_alive_count_max: 3,
      tcp_keepalive: 60,
      tcp_keepalive_interval: 10,
      tcp_keepalive_retries: 5,
      no_reconnect: false,
      reconnect_initial_delay: 1,
      reconnect_max_delay: 60,
      startup_timeout: 30,
    },
    logging: { level: "INFO", format: "text", http_access_log: null, socks_log: null },
    openssh: { ssh_bin: "ssh", ssh_socks_bind: "127.0.0.1", ssh_socks_port: 0, extra_args: [] },
  };
}

describe("moved", () => {
  test("moves an item forward and back without changing the input", () => {
    const items = ["a", "b", "c"] as const;
    assert.deepEqual(moved(items, 0, 2), ["b", "c", "a"]);
    assert.deepEqual(moved(items, 2, 0), ["c", "a", "b"]);
    assert.deepEqual(moved(items, 1, 1), ["a", "b", "c"]);
    assert.deepEqual(items, ["a", "b", "c"]);
  });
});

describe("hopRole", () => {
  test("names jumps by position and the last hop as the target", () => {
    assert.equal(hopRole(0, 3), "Jump 1");
    assert.equal(hopRole(1, 3), "Jump 2");
    assert.equal(hopRole(2, 3), "Target");
    assert.equal(hopRole(0, 1), "Target");
  });
});

describe("hopTitle", () => {
  test("prefers the trimmed name, then the host, then a placeholder", () => {
    assert.equal(hopTitle(hop("  Bastion ", "bastion.example")), "Bastion");
    assert.equal(hopTitle(hop("", " db.example ")), "db.example");
    assert.equal(hopTitle(hop("  ", "  ")), "New hop");
  });
});

describe("hopBadge", () => {
  test("shows the elapsed time when connected", () => {
    assert.deepEqual(hopBadge(result("connected", null, 42)), {
      glyph: "✓",
      label: "Connected in 42 ms",
      tone: "ok",
    });
  });

  test("shows the error, or a fallback, when failed", () => {
    assert.deepEqual(hopBadge(result("failed", "Connection refused")), {
      glyph: "!",
      label: "Connection refused",
      tone: "alert",
    });
    assert.equal(hopBadge(result("failed", null)).label, "Failed");
  });

  test("flags a host key that is not trusted yet", () => {
    assert.deepEqual(hopBadge(result("host_key_unknown", "unknown host key")), {
      glyph: "!",
      label: "Host key not trusted yet",
      tone: "alert",
    });
  });

  test("marks hops that were never tried", () => {
    assert.deepEqual(hopBadge(result("not_attempted", null)), {
      glyph: "–",
      label: "Not attempted",
      tone: "idle",
    });
  });
});

describe("authRefs", () => {
  test("returns only password secret references, in order", () => {
    const auth: AuthMethod[] = [
      { Key: { key: "key-1" } },
      { Password: { secret: "secret-1" } },
      "SystemAgentOptIn",
      { KeyboardInteractive: { prompts: ["Code:"] } },
      { Password: { secret: "secret-2" } },
    ];
    assert.deepEqual(authRefs(auth), ["secret-1", "secret-2"]);
    assert.deepEqual(authRefs([]), []);
  });
});

describe("profileRefs", () => {
  const hops = [
    hop("jump", "jump.example", [{ Password: { secret: "secret-1" } }]),
    hop("target", "target.example", [{ Key: { key: "key-1" } }, { Password: { secret: "secret-2" } }]),
  ];

  test("collects every hop's secrets but not the MITM CA, which the vault lists itself", () => {
    assert.deepEqual(profileRefs(profile(hops, "ca-1")), ["secret-1", "secret-2"]);
  });

  test("handles a session without MITM", () => {
    assert.deepEqual(profileRefs(profile(hops, null)), ["secret-1", "secret-2"]);
    assert.deepEqual(profileRefs(profile([], null)), []);
  });
});
