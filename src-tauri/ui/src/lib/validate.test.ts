import { describe, test } from "node:test";
import assert from "node:assert/strict";

import type { Proxy, SessionProfile, Tunnel } from "./types.ts";
import {
  denylistedFlag,
  filterRuleError,
  isIpAddress,
  isLoopback,
  isPort,
  redactArgs,
  sessionErrors,
  configLineArgs,
  portSpecError,
  proxyErrors,
  tunnelErrors,
} from "./validate.ts";

function validProfile(): SessionProfile {
  return {
    id: "00000000-0000-0000-0000-000000000001",
    name: "Work",
    autostart: false,
    enabled: true,
    engine: "Russh",
    hops: [
      {
        hop_id: "hop-1",
        name: "",
        host: {
          id: "00000000-0000-0000-0000-000000000000",
          name: "",
          host: "example.com",
          port: 22,
          user: "me",
          auth: [],
          host_key_pin: null,
        },
      },
    ],
    forward: {
      enabled: true,
      bind: "127.0.0.1",
      http_port: 8080,
      socks_port: 1080,
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
    mitm: null,
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

describe("isPort", () => {
  test("accepts 1 to 65535", () => {
    assert.equal(isPort(1), true);
    assert.equal(isPort(22), true);
    assert.equal(isPort(65535), true);
  });

  test("rejects zero unless allowed", () => {
    assert.equal(isPort(0), false);
    assert.equal(isPort(0, true), true);
  });

  test("rejects out-of-range and fractional values", () => {
    assert.equal(isPort(65536), false);
    assert.equal(isPort(-1), false);
    assert.equal(isPort(1.5), false);
    assert.equal(isPort(Number.NaN), false);
  });
});

describe("isIpAddress", () => {
  test("accepts IPv4", () => {
    assert.equal(isIpAddress("127.0.0.1"), true);
    assert.equal(isIpAddress("0.0.0.0"), true);
    assert.equal(isIpAddress("255.255.255.255"), true);
  });

  test("rejects bad IPv4", () => {
    assert.equal(isIpAddress("256.0.0.1"), false);
    assert.equal(isIpAddress("01.2.3.4"), false);
    assert.equal(isIpAddress("1.2.3"), false);
    assert.equal(isIpAddress("1.2.3.4.5"), false);
  });

  test("accepts full and compressed IPv6", () => {
    assert.equal(isIpAddress("fe80:0:0:0:0:0:0:1"), true);
    assert.equal(isIpAddress("2001:db8::1"), true);
    assert.equal(isIpAddress("::1"), true);
    assert.equal(isIpAddress("::"), true);
  });

  test("accepts an embedded IPv4 tail", () => {
    assert.equal(isIpAddress("::ffff:192.0.2.1"), true);
    assert.equal(isIpAddress("0:0:0:0:0:ffff:192.0.2.1"), true);
    assert.equal(isIpAddress("::ffff:192.0.2.256"), false);
    assert.equal(isIpAddress("::192.0.2.1:1"), false);
  });

  test("rejects bad IPv6 and non-addresses", () => {
    assert.equal(isIpAddress("1:2:3:4:5:6:7:8:9"), false);
    assert.equal(isIpAddress("1:2:3:4:5:6:7"), false);
    assert.equal(isIpAddress("1::2::3"), false);
    assert.equal(isIpAddress("gggg::1"), false);
    assert.equal(isIpAddress("[::1]"), false);
    assert.equal(isIpAddress("fe80::1%eth0"), false);
    assert.equal(isIpAddress("example.com"), false);
    assert.equal(isIpAddress("127.0.0.1:22"), false);
    assert.equal(isIpAddress(""), false);
  });
});

describe("isLoopback", () => {
  test("matches 127.0.0.0/8 and ::1", () => {
    assert.equal(isLoopback("127.0.0.1"), true);
    assert.equal(isLoopback("127.1.2.3"), true);
    assert.equal(isLoopback("::1"), true);
  });

  test("rejects other addresses and names", () => {
    assert.equal(isLoopback("10.0.0.1"), false);
    assert.equal(isLoopback("0.0.0.0"), false);
    assert.equal(isLoopback("localhost"), false);
    assert.equal(isLoopback("127.0.0"), false);
  });
});

describe("filterRuleError", () => {
  test("accepts IPv4 and IPv6 CIDRs", () => {
    assert.equal(filterRuleError("10.0.0.0/8"), null);
    assert.equal(filterRuleError("10.0.0.0/32"), null);
    assert.equal(filterRuleError("2001:db8::/32"), null);
    assert.equal(filterRuleError("[2001:db8::]/128"), null);
    // Rust's u8 parser takes a leading `+` and leading zeros.
    assert.equal(filterRuleError("10.0.0.0/+08"), null);
  });

  test("rejects bad CIDR prefixes and addresses", () => {
    assert.equal(filterRuleError("10.0.0.0/33"), 'CIDR prefix exceeds /32 in "10.0.0.0/33".');
    assert.equal(filterRuleError("::/129"), 'CIDR prefix exceeds /128 in "::/129".');
    assert.equal(filterRuleError("10.0.0.0/256"), 'Invalid CIDR prefix in "10.0.0.0/256".');
    assert.equal(filterRuleError("10.0.0.0/abc"), 'Invalid CIDR prefix in "10.0.0.0/abc".');
    assert.equal(filterRuleError("10.0.0.0/"), 'Invalid CIDR prefix in "10.0.0.0/".');
    assert.equal(filterRuleError("example.com/8"), 'Invalid CIDR address in "example.com/8".');
  });

  test("rejects empty rules", () => {
    assert.equal(filterRuleError(""), "A rule cannot be empty.");
    assert.equal(filterRuleError("   "), "A rule cannot be empty.");
  });

  test("accepts plain IPs, bracketed IPv6, and domains", () => {
    assert.equal(filterRuleError("192.168.1.1"), null);
    assert.equal(filterRuleError("[::1]"), null);
    assert.equal(filterRuleError("example.com"), null);
    assert.equal(filterRuleError("Example.COM"), null);
    assert.equal(filterRuleError("example.com."), null);
    assert.equal(filterRuleError("my_host-1"), null);
  });

  test("accepts a leading *. wildcard only", () => {
    assert.equal(filterRuleError("*.example.com"), null);
    assert.equal(
      filterRuleError("foo.*.com"),
      'Only a leading "*." wildcard is supported in "foo.*.com".',
    );
    assert.equal(filterRuleError("*"), 'Only a leading "*." wildcard is supported in "*".');
    assert.equal(filterRuleError("*.*.com"), 'Invalid character in "*.*.com".');
  });

  test("rejects bad brackets and bad domains", () => {
    assert.equal(filterRuleError("[example.com]"), 'Invalid IP address in "[example.com]".');
    assert.equal(filterRuleError("[::1"), 'Invalid IP address in "[::1".');
    assert.equal(filterRuleError("bad domain"), 'Invalid character in "bad domain".');
    assert.equal(filterRuleError("a..b"), 'Invalid domain label in "a..b".');
    assert.equal(filterRuleError(`${"a".repeat(64)}.com`), `Invalid domain label in "${"a".repeat(64)}.com".`);
  });
});

describe("denylistedFlag", () => {
  test("catches denied short flags", () => {
    assert.equal(denylistedFlag("-F"), "F");
    assert.equal(denylistedFlag("-J"), "J");
    assert.equal(denylistedFlag("-i"), "i");
    assert.equal(denylistedFlag("-A"), "A");
  });

  test("walks bundled short flags", () => {
    assert.equal(denylistedFlag("-vF"), "F");
    assert.equal(denylistedFlag("-vvA"), "A");
    // `-p` takes the rest of the token as its value, so the F is not a flag.
    assert.equal(denylistedFlag("-pF"), null);
  });

  test("catches denied -o options in every form", () => {
    assert.equal(denylistedFlag("-oProxyCommand=foo"), "ProxyCommand");
    assert.equal(denylistedFlag("-voProxyJump=bastion"), "ProxyJump");
    assert.equal(denylistedFlag("ProxyCommand=foo"), "ProxyCommand");
    assert.equal(denylistedFlag("--IdentityFile=~/.ssh/id"), "IdentityFile");
    assert.equal(denylistedFlag("StrictHostKeyChecking no"), "StrictHostKeyChecking");
  });

  test("matches option names without regard to ASCII case", () => {
    assert.equal(denylistedFlag("proxycommand=foo"), "ProxyCommand");
    assert.equal(denylistedFlag("-oPROXYJUMP=x"), "ProxyJump");
    // The Kelvin sign is not ASCII, so it does not fold to k.
    assert.equal(denylistedFlag("-oUpdateHostKeys=yes"), null);
  });

  test("allows harmless flags and options", () => {
    assert.equal(denylistedFlag("-C"), null);
    assert.equal(denylistedFlag("-v"), null);
    assert.equal(denylistedFlag("-vvv"), null);
    assert.equal(denylistedFlag("-p2222"), null);
    assert.equal(denylistedFlag("-o"), null);
    assert.equal(denylistedFlag("-oCompression=yes"), null);
    assert.equal(denylistedFlag("Compression=yes"), null);
  });
});

describe("redactArgs", () => {
  test("keeps flag names and hides values", () => {
    assert.deepEqual(redactArgs(["-C", "-v", "--long"]), ["-C", "-v", "--long"]);
    assert.deepEqual(redactArgs(["-p2222"]), ["-p<redacted>"]);
  });

  test("hides the value after =", () => {
    assert.deepEqual(redactArgs(["-oUser=bob", "--opt=val"]), ["-oUser=<redacted>", "--opt=<redacted>"]);
  });

  test("keeps the option name after a separate -o", () => {
    assert.deepEqual(redactArgs(["-o", "User=bob"]), ["-o", "User=<redacted>"]);
  });

  test("hides positional arguments", () => {
    assert.deepEqual(redactArgs(["host", "x=y"]), ["<redacted>", "<redacted>"]);
    assert.deepEqual(redactArgs([]), []);
  });
});

describe("sessionErrors", () => {
  test("a valid profile has no errors", () => {
    assert.deepEqual(sessionErrors(validProfile()), {});
  });

  test("flags a missing name and missing hops", () => {
    const profile = validProfile();
    profile.name = "  ";
    profile.hops = [];
    const errors = sessionErrors(profile);
    assert.equal(errors.name, "Enter a session name.");
    assert.equal(errors.hops, "Add at least one hop. The last hop is the target.");
  });

  test("flags hop host fields by hop id", () => {
    const profile = validProfile();
    const hop = profile.hops[0];
    if (!hop) throw new Error("the fixture has one hop");
    hop.host.host = "";
    hop.host.port = 0;
    const errors = sessionErrors(profile);
    assert.equal(errors["hop:hop-1:host"], "Enter a host name or IP address.");
    assert.equal(errors["hop:hop-1:port"], "Use a port from 1 to 65535.");
  });

  test("checks connection caps; an empty reverse cap is allowed", () => {
    const profile = validProfile();
    profile.forward.max_connections = -1;
    profile.reverse.reverse_max_connections = 1.5;
    const errors = sessionErrors(profile);
    assert.equal(errors["forward.max_connections"], "Use a whole number. 0 means unlimited.");
    assert.equal(errors["reverse.max_connections"], "Use a whole number. 0 means unlimited.");
    profile.reverse.reverse_max_connections = null;
    assert.equal(sessionErrors(profile)["reverse.max_connections"], undefined);
  });

  test("requires a port on a proxy that is switched on", () => {
    const profile = validProfile();
    profile.forward.http_port = 0;
    profile.forward.socks_port = 0;
    let errors = sessionErrors(profile);
    assert.equal(errors["forward.ports"], "Set an HTTP or SOCKS port, or switch the forward proxy off.");
    assert.equal(errors.listeners, undefined);

    profile.reverse.enabled = true;
    errors = sessionErrors(profile);
    assert.equal(errors["reverse.ports"], "Set an HTTP or SOCKS port, or switch the reverse proxy off.");

    // Switched off, zero ports are fine; the reverse proxy with a port carries the session.
    profile.forward.enabled = false;
    profile.reverse.reverse_http_port = 8888;
    assert.deepEqual(sessionErrors(profile), {});
  });

  test("requires the forward or reverse proxy to be on", () => {
    const profile = validProfile();
    profile.forward.enabled = false;
    const errors = sessionErrors(profile);
    assert.equal(errors.listeners, "Turn on the forward or reverse proxy, or a port forward.");
    assert.equal(errors["forward.ports"], undefined);
  });

  test("a port forward alone is enough, and its fields are checked", () => {
    const profile = validProfile();
    profile.forward.enabled = false;
    const forward = {
      id: "f1",
      enabled: true,
      direction: "local" as const,
      name: "",
      bind: "127.0.0.1",
      port: 15432,
      dest_host: "db.internal",
      dest_port: 5432,
    };
    profile.port_forwards = [forward];
    assert.deepEqual(sessionErrors(profile), {});

    profile.port_forwards = [{ ...forward, port: 0, dest_host: "db:5432", dest_port: Number.NaN, bind: "x" }];
    const errors = sessionErrors(profile);
    assert.equal(errors["forwards:f1:port"], "Use a port from 1 to 65535.");
    assert.equal(errors["forwards:f1:dest_port"], "Use a port from 1 to 65535.");
    assert.equal(errors["forwards:f1:bind"], "Use an IP address, such as 127.0.0.1.");
    assert.ok(errors["forwards:f1:dest_host"]);
    assert.equal(errors.listeners, undefined);
  });

  test("port forwards must not collide with a proxy or each other", () => {
    const profile = validProfile();
    const base = {
      enabled: true,
      direction: "local" as const,
      name: "",
      bind: "0.0.0.0",
      dest_host: "db",
      dest_port: 1,
    };
    profile.port_forwards = [
      { ...base, id: "a", port: profile.forward.http_port },
      { ...base, id: "b", port: 9000 },
      { ...base, id: "c", port: 9000, bind: "127.0.0.1" },
      { ...base, id: "d", port: 9000, direction: "remote" },
      { ...base, id: "e", port: 9000, enabled: false },
    ];
    const errors = sessionErrors(profile);
    assert.equal(errors["forwards:a:port"], `Port ${profile.forward.http_port} is already used by the forward proxy.`);
    assert.equal(errors["forwards:b:port"], undefined);
    assert.equal(errors["forwards:c:port"], "Another forward already listens on port 9000.");
    assert.equal(errors["forwards:d:port"], undefined);
    assert.equal(errors["forwards:e:port"], undefined);
  });

  test("allows an allowlist and blocklist together and still checks each rule", () => {
    const profile = validProfile();
    profile.forward.allow = ["test.domain.net"];
    profile.forward.block = ["*.domain.net"];
    profile.reverse.reverse_allow = ["*.example.com"];
    profile.reverse.reverse_block = ["10.0.0.0/33"];
    const errors = sessionErrors(profile);
    assert.equal(errors["filters.forward.conflict"], undefined);
    assert.equal(errors["filters.reverse.conflict"], undefined);
    assert.equal(errors["filters.reverse.block:0"], 'CIDR prefix exceeds /32 in "10.0.0.0/33".');
  });

  test("requires a MITM certificate TTL of at least 10 seconds", () => {
    const profile = validProfile();
    profile.mitm = {
      ca: "ca-1",
      cert_ttl: 9,
      cert_cache_max_entries: 0,
      socks_block_web: false,
    };
    assert.equal(
      sessionErrors(profile)["mitm.cert_ttl"],
      "Use a whole number of at least 10 seconds.",
    );
    profile.mitm.cert_ttl = 10;
    assert.deepEqual(sessionErrors(profile), {});
  });

  test("requires a MITM CA to be chosen", () => {
    const profile = validProfile();
    profile.mitm = { ca: null, cert_ttl: 3600, cert_cache_max_entries: 0, socks_block_web: false };
    assert.equal(sessionErrors(profile)["mitm.ca"], "Choose a CA, or upload one.");
    profile.mitm.ca = "ca-1";
    assert.deepEqual(sessionErrors(profile), {});
  });

  test("rejects a reconnect initial delay above the maximum", () => {
    const profile = validProfile();
    profile.tunnel.reconnect_initial_delay = 120;
    profile.tunnel.reconnect_max_delay = 60;
    assert.equal(
      sessionErrors(profile)["tunnel.reconnect_initial_delay"],
      "The initial delay cannot exceed the maximum delay.",
    );
  });

  test("checks TCP keepalive ranges like the engine", () => {
    const profile = validProfile();
    profile.tunnel.tcp_keepalive = 32_768;
    profile.tunnel.tcp_keepalive_interval = 0;
    profile.tunnel.tcp_keepalive_retries = 128;
    const errors = sessionErrors(profile);
    assert.equal(errors["tunnel.tcp_keepalive"], "Use 0 (off) or a whole number from 1 to 32767.");
    assert.equal(errors["tunnel.tcp_keepalive_interval"], "Use a whole number from 1 to 32767.");
    assert.equal(errors["tunnel.tcp_keepalive_retries"], "Use a whole number from 1 to 127.");

    profile.tunnel.tcp_keepalive = 32_767;
    profile.tunnel.tcp_keepalive_interval = 32_767;
    profile.tunnel.tcp_keepalive_retries = 127;
    assert.deepEqual(sessionErrors(profile), {});

    // Off: interval and probes are not checked.
    profile.tunnel.tcp_keepalive = 0;
    profile.tunnel.tcp_keepalive_interval = Number.NaN;
    profile.tunnel.tcp_keepalive_retries = 0;
    assert.deepEqual(sessionErrors(profile), {});

    profile.tunnel.tcp_keepalive = 1.5;
    assert.equal(sessionErrors(profile)["tunnel.tcp_keepalive"], "Use 0 (off) or a whole number from 1 to 32767.");
  });

  test("applies the OpenSSH denylist for every engine", () => {
    const profile = validProfile();
    profile.openssh.extra_args = ["-C", "-oProxyCommand=nc %h %p"];
    const errors = sessionErrors(profile);
    assert.equal(errors["openssh.extra_args:0"], undefined);
    assert.equal(
      errors["openssh.extra_args:1"],
      '"-oProxyCommand=nc %h %p" uses the forbidden flag ProxyCommand.',
    );
  });
});

describe("configLineArgs", () => {
  test("finds ssh_config lines and offers the -o form", () => {
    assert.deepEqual(configLineArgs(["Compression yes", "-v", "ServerAliveInterval=30"]), [
      { index: 0, keyword: "Compression", fix: ["-o", "Compression=yes"] },
      { index: 2, keyword: "ServerAliveInterval", fix: ["-o", "ServerAliveInterval=30"] },
    ]);
  });

  test("leaves real command-line arguments alone", () => {
    assert.deepEqual(configLineArgs(["-o", "Compression=yes"]), []);
    assert.deepEqual(configLineArgs(["-o", "ServerAliveInterval 30"]), []);
    assert.deepEqual(configLineArgs(["-oCompression=yes", "-v", "-C", "-p", "2222"]), []);
    assert.deepEqual(configLineArgs(["-c", "aes256-gcm@openssh.com"]), []);
  });

  test("has no -o fix for Host and Match blocks", () => {
    assert.deepEqual(configLineArgs(["Host example"]), [{ index: 0, keyword: "Host", fix: null }]);
    assert.deepEqual(configLineArgs(["match all"]), [{ index: 0, keyword: "match", fix: null }]);
  });
});

// ---- v2: Tunnels and Proxies ----

const TUNNEL_ID = "a1111111-1111-4111-8111-111111111111";

function validTunnel(): Tunnel {
  const session = validProfile();
  return {
    id: TUNNEL_ID,
    name: "Bastion",
    enabled: true,
    start_mode: "linked",
    engine: session.engine,
    hops: session.hops,
    reverse: session.reverse,
    port_forwards: [],
    keepalive: session.tunnel,
    logging: session.logging,
    openssh: session.openssh,
  };
}

function validProxy(): Proxy {
  return {
    id: "b1111111-1111-4111-8111-111111111111",
    name: "Work",
    enabled: true,
    autostart: false,
    source: "managed",
    listeners: { bind: "127.0.0.1", http_port: 3128, socks_port: 1080, max_connections: 4096 },
    network: { connect_timeout: 10, tcp_keepalive: 60, tcp_keepalive_interval: 10, tcp_keepalive_retries: 5 },
    profiles: [
      { name: "corp", kind: { type: "http" }, host: "192.0.2.80", port: 8080, username: null, password: { vault: "00000000-0000-4000-8000-0000000000aa" }, bypass: [], color: null },
      { name: "ssh", kind: { type: "tunnel", tunnel_id: TUNNEL_ID }, host: null, port: null, username: null, password: null, bypass: [], color: null },
    ],
    routing: {
      default: "ssh",
      resolve_dns: false,
      rules: [{ host_wildcard: "*.corp.example", match_all: false, disabled: false, target: ["corp", "direct"] }],
    },
    filter: "off",
    socks_block_web: false,
    mitm: null,
    logging: { level: "INFO", format: "text", http_access_log: null, socks_log: null },
  };
}

describe("tunnelErrors", () => {
  test("accepts a tunnel without listeners", () => {
    assert.deepEqual(tunnelErrors(validTunnel()), {});
  });

  test("needs a hop with a target host", () => {
    const t = validTunnel();
    assert.ok(tunnelErrors({ ...t, hops: [] }).hops);
    const blank = { ...t, hops: [{ ...t.hops[0]!, host: { ...t.hops[0]!.host, host: " " } }] };
    assert.ok(tunnelErrors(blank)["hop:hop-1:host"]);
  });

  test("checks the denylist, reconnect order, and keepalive", () => {
    const t = validTunnel();
    assert.ok(tunnelErrors({ ...t, openssh: { ...t.openssh, extra_args: ["-oProxyCommand=nc"] } })["openssh.extra_args:0"]);
    const delays = { ...t.keepalive, reconnect_initial_delay: 100, reconnect_max_delay: 1 };
    assert.ok(tunnelErrors({ ...t, keepalive: delays })["keepalive.reconnect_initial_delay"]);
    assert.ok(tunnelErrors({ ...t, keepalive: { ...t.keepalive, tcp_keepalive_retries: 0 } })["keepalive.tcp_keepalive_retries"]);
    assert.ok(tunnelErrors({ ...t, keepalive: { ...t.keepalive, ip_version: "5" } })["keepalive.ip_version"]);
  });

  test("checks reverse filters", () => {
    const t = validTunnel();
    const both = { ...t.reverse, reverse_allow: ["test.domain.net"], reverse_block: ["*.domain.net"] };
    assert.deepEqual(tunnelErrors({ ...t, reverse: both }), {});
    const bad = { ...t.reverse, reverse_block: [""] };
    assert.ok(tunnelErrors({ ...t, reverse: bad })["filters.reverse.block:0"]);
  });

  test("local forwards may use any port; remote ones must not hit the reverse proxy", () => {
    const t = validTunnel();
    const reverse = { ...t.reverse, enabled: true, reverse_http_port: 9000, reverse_socks_port: 9001 };
    const fwd = (id: string, direction: "local" | "remote", port: number) => ({
      id, enabled: true, direction, name: "", bind: "127.0.0.1", port, dest_host: "db.internal", dest_port: 5432,
    });
    const local = { ...t, reverse, port_forwards: [fwd("l1", "local", 3128)] };
    assert.deepEqual(tunnelErrors(local), {});
    const clash = { ...local, port_forwards: [...local.port_forwards, fwd("r1", "remote", 9000)] };
    assert.ok(tunnelErrors(clash)["forwards:r1:port"]);
    const twice = { ...local, port_forwards: [...local.port_forwards, fwd("l2", "local", 3128)] };
    assert.ok(tunnelErrors(twice)["forwards:l2:port"]);
  });

  test("checks logging", () => {
    const t = validTunnel();
    assert.ok(tunnelErrors({ ...t, logging: { ...t.logging, level: "loud" } })["logging.level"]);
    assert.ok(tunnelErrors({ ...t, logging: { ...t.logging, format: "xml" } })["logging.format"]);
  });
});

describe("proxyErrors", () => {
  test("accepts a valid proxy", () => {
    assert.deepEqual(proxyErrors(validProxy(), [TUNNEL_ID]), {});
  });

  test("needs a listener", () => {
    const p = validProxy();
    const none = { ...p, listeners: { ...p.listeners, http_port: 0, socks_port: 0 } };
    assert.ok(proxyErrors(none, [TUNNEL_ID])["listeners.ports"]);
    assert.deepEqual(proxyErrors({ ...none, listeners: { ...none.listeners, socks_port: 1081 } }, [TUNNEL_ID]), {});
  });

  test("checks MITM, network, filter, and logging", () => {
    const p = validProxy();
    assert.ok(proxyErrors({ ...p, mitm: { ca: null, cert_ttl: 3600, cert_cache_max_entries: 0, socks_block_web: false } }, [TUNNEL_ID])["mitm.ca"]);
    assert.ok(proxyErrors({ ...p, mitm: { ca: "c", cert_ttl: 1, cert_cache_max_entries: 0, socks_block_web: false } }, [TUNNEL_ID])["mitm.cert_ttl"]);
    assert.ok(proxyErrors({ ...p, network: { ...p.network, connect_timeout: 0 } }, [TUNNEL_ID])["network.connect_timeout"]);
    assert.ok(proxyErrors({ ...p, network: { ...p.network, tcp_keepalive_interval: 0 } }, [TUNNEL_ID])["network.tcp_keepalive_interval"]);
    assert.deepEqual(proxyErrors({ ...p, network: { ...p.network, tcp_keepalive: 0, tcp_keepalive_retries: 0 } }, [TUNNEL_ID]), {});
    assert.ok(proxyErrors({ ...p, filter: { block: ["ok.example", "bad*.example"] } }, [TUNNEL_ID])["filter.block:1"]);
    assert.ok(proxyErrors({ ...p, logging: { ...p.logging, level: "loud" } }, [TUNNEL_ID])["logging.level"]);
  });

  test("checks profile names, tunnels, hosts, and ports", () => {
    const p = validProxy();
    const [corp, ssh] = p.profiles as [Proxy["profiles"][0], Proxy["profiles"][0]];
    assert.ok(proxyErrors({ ...p, profiles: [{ ...corp, name: "direct" }, ssh] }, [TUNNEL_ID])["profiles:0:name"]);
    assert.ok(proxyErrors({ ...p, profiles: [corp, { ...corp }, ssh] }, [TUNNEL_ID])["profiles:1:name"]);
    assert.ok(proxyErrors(p, [])["profiles:1:tunnel"]);
    assert.ok(proxyErrors({ ...p, profiles: [{ ...corp, host: "" }, ssh] }, [TUNNEL_ID])["profiles:0:host"]);
    assert.ok(proxyErrors({ ...p, profiles: [{ ...corp, port: 0 }, ssh] }, [TUNNEL_ID])["profiles:0:port"]);
  });

  test("flags a profile that points at the proxy's own listener", () => {
    const p = validProxy();
    const [corp, ssh] = p.profiles as [Proxy["profiles"][0], Proxy["profiles"][0]];
    const loop = { ...corp, host: "localhost", port: 3128 };
    assert.match(proxyErrors({ ...p, profiles: [loop, ssh] }, [TUNNEL_ID])["profiles:0:port"] ?? "", /loop/);
    const wild = { ...p, listeners: { ...p.listeners, bind: "0.0.0.0" }, profiles: [{ ...corp, host: "127.0.0.1", port: 1080 }, ssh] };
    assert.ok(proxyErrors(wild, [TUNNEL_ID])["profiles:0:port"]);
    const elsewhere = { ...p, profiles: [{ ...corp, host: "192.0.2.80", port: 3128 }, ssh] };
    assert.deepEqual(proxyErrors(elsewhere, [TUNNEL_ID]), {});
  });

  test("checks composite profiles", () => {
    const p = validProxy();
    const empty = { name: "split", kind: { type: "composite" as const, http: "", https: "", fallback: "" }, host: null, port: null, username: null, password: null, bypass: [], color: null };
    assert.ok(proxyErrors({ ...p, profiles: [...p.profiles, empty] }, [TUNNEL_ID])["profiles:2:composite"]);
    const unknown = { ...empty, kind: { ...empty.kind, http: "corp", fallback: "nope" } };
    assert.ok(proxyErrors({ ...p, profiles: [...p.profiles, unknown] }, [TUNNEL_ID])["profiles:2:composite.fallback"]);
    const good = { ...empty, kind: { ...empty.kind, http: "corp", https: "ssh", fallback: "direct" } };
    assert.deepEqual(proxyErrors({ ...p, profiles: [...p.profiles, good] }, [TUNNEL_ID]), {});
  });

  test("checks routing targets in every table", () => {
    const p = validProxy();
    assert.ok(proxyErrors({ ...p, routing: { ...p.routing, default: "missing" } }, [TUNNEL_ID])["routing.default"]);
    assert.ok(proxyErrors({ ...p, routing: { ...p.routing, default: [] } }, [TUNNEL_ID])["routing.default"]);
    const rule = { match_all: true, disabled: false, target: ["corp", "nope"] };
    assert.ok(proxyErrors({ ...p, routing: { ...p.routing, rules: [rule] } }, [TUNNEL_ID])["routing.rules:0:target"]);
    const socks = { ...p.routing, socks: { default: "block", inherit: true, rules: [{ ...rule, target: "x" }] } };
    const errors = proxyErrors({ ...p, routing: socks }, [TUNNEL_ID]);
    assert.equal(errors["routing.socks.default"], undefined);
    assert.ok(errors["routing.socks.rules:0:target"]);
    const http = { ...p.routing, http: { default: "gone", inherit: false, rules: [] } };
    assert.ok(proxyErrors({ ...p, routing: http }, [TUNNEL_ID])["routing.http.default"]);
  });

  test("checks rule conditions", () => {
    const p = validProxy();
    const withRule = (extra: object) => ({
      ...p,
      routing: { ...p.routing, rules: [{ match_all: false, disabled: false, target: "direct", ...extra }] },
    });
    assert.deepEqual(proxyErrors(withRule({ port: [443, "8000-8080"], cidr: "10.0.0.0/8", ip: "192.0.2.1" }), [TUNNEL_ID]), {});
    assert.ok(proxyErrors(withRule({ port: "9000-8000" }), [TUNNEL_ID])["routing.rules:0:port"]);
    assert.ok(proxyErrors(withRule({ cidr: "10.0.0.0" }), [TUNNEL_ID])["routing.rules:0:cidr"]);
    assert.ok(proxyErrors(withRule({ ip: "not-an-ip" }), [TUNNEL_ID])["routing.rules:0:ip"]);
    assert.ok(proxyErrors(withRule({ host_levels: { min: 3, max: 1 } }), [TUNNEL_ID])["routing.rules:0:host_levels"]);
  });
});

describe("portSpecError", () => {
  test("mirrors the engine's port spec parser", () => {
    assert.equal(portSpecError(443), null);
    assert.equal(portSpecError("443"), null);
    assert.equal(portSpecError("8000-8080"), null);
    assert.equal(portSpecError(" 80 - 81 "), null);
    assert.ok(portSpecError("8080-8000"));
    assert.ok(portSpecError("70000"));
    assert.ok(portSpecError("a-b"));
    assert.ok(portSpecError(1.5));
  });
});
