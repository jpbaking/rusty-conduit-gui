import { describe, test } from "node:test";
import assert from "node:assert/strict";

import {
  CONDITION_GROUPS,
  applySimpleCondition,
  buildProfileOptionGroups,
  classifyRule,
  formatTargetLabel,
  formatTimeRange,
  formatWeekdays,
  isKnownProfileOption,
  isUrlConditionKind,
  normalizeIpOrCidr,
  parseHostLevelsText,
  parseTimeRange,
  parseWeekdays,
  reorderList,
  ruleDetailText,
  type SimpleConditionKind,
  type TunnelLike,
  type UpstreamProfileLike,
} from "./routingRows.ts";
import type { RoutingRule } from "./types.ts";

const baseRule = (overrides: Partial<RoutingRule> = {}): RoutingRule => ({
  match_all: false,
  disabled: false,
  target: "direct",
  ...overrides,
});

describe("routingRows condition classification and round-trip", () => {
  test("CONDITION_GROUPS exposes Host, URL, and Special groups with placeholders", () => {
    assert.deepEqual(
      CONDITION_GROUPS.map((g) => g.label),
      ["Host", "URL", "Special"],
    );
    const allKinds = CONDITION_GROUPS.flatMap((g) => g.options.map((o) => o.value));
    assert.deepEqual(allKinds, [
      "host_wildcard",
      "host",
      "host_regex",
      "host_levels",
      "cidr",
      "url_wildcard",
      "url_regex",
      "keyword",
      "weekday",
      "time",
      "port",
      "match_all",
    ]);
    assert.equal(isUrlConditionKind("url_wildcard"), true);
    assert.equal(isUrlConditionKind("url_regex"), true);
    assert.equal(isUrlConditionKind("keyword"), true);
    assert.equal(isUrlConditionKind("host_wildcard"), false);
  });

  test("classifies every simple condition kind and round-trips through applySimpleCondition + ruleDetailText", () => {
    const cases: { kind: SimpleConditionKind; input: string; expectedText: string; check: (r: RoutingRule) => void }[] = [
      {
        kind: "host_wildcard",
        input: "*.example.com | *.foo.org",
        expectedText: "*.example.com | *.foo.org",
        check: (r) => assert.deepEqual(r.host_wildcard, ["*.example.com", "*.foo.org"]),
      },
      {
        kind: "host",
        input: "example.com",
        expectedText: "example.com",
        check: (r) => assert.equal(r.host, "example.com"),
      },
      {
        kind: "host_regex",
        input: "(^|\\.)example\\.com$",
        expectedText: "(^|\\.)example\\.com$",
        check: (r) => assert.equal(r.host_regex, "(^|\\.)example\\.com$"),
      },
      {
        kind: "host_levels",
        input: "2~4",
        expectedText: "2~4",
        check: (r) => assert.deepEqual(r.host_levels, { min: 2, max: 4 }),
      },
      {
        kind: "cidr",
        input: "10.0.0.0/8, 192.168.1.1, ::1",
        expectedText: "10.0.0.0/8, 192.168.1.1/32, ::1/128",
        check: (r) => assert.deepEqual(r.cidr, ["10.0.0.0/8", "192.168.1.1/32", "::1/128"]),
      },
      {
        kind: "url_wildcard",
        input: "http://*.example.com/api/*",
        expectedText: "http://*.example.com/api/*",
        check: (r) => assert.equal(r.url_wildcard, "http://*.example.com/api/*"),
      },
      {
        kind: "url_regex",
        input: "^http://example\\.com/(a|b)",
        expectedText: "^http://example\\.com/(a|b)",
        check: (r) => assert.equal(r.url_regex, "^http://example\\.com/(a|b)"),
      },
      {
        kind: "keyword",
        input: "example | staging",
        expectedText: "example | staging",
        check: (r) => assert.deepEqual(r.keyword, ["example", "staging"]),
      },
      {
        kind: "weekday",
        input: "mon-wed, fri",
        expectedText: "mon, tue, wed, fri",
        check: (r) => assert.deepEqual(r.weekday, ["mon", "tue", "wed", "fri"]),
      },
      {
        kind: "time",
        input: "09:00-17:30",
        expectedText: "09:00-17:30",
        check: (r) => assert.equal(r.time, "09:00-17:30"),
      },
      {
        kind: "port",
        input: "443, 8000-8999",
        expectedText: "443, 8000-8999",
        check: (r) => assert.deepEqual(r.port, [443, "8000-8999"]),
      },
      {
        kind: "match_all",
        input: "",
        expectedText: "",
        check: (r) => assert.equal(r.match_all, true),
      },
    ];

    for (const c of cases) {
      const updated = applySimpleCondition(baseRule({ name: "Keep", disabled: true, target: "block" }), c.kind, c.input);
      assert.equal(updated.name, "Keep");
      assert.equal(updated.disabled, true);
      assert.equal(updated.target, "block");
      c.check(updated);
      assert.equal(classifyRule(updated), c.kind);
      assert.equal(ruleDetailText(updated, c.kind), c.expectedText);
    }
  });

  test("classifies empty rule as host_wildcard and legacy ip-only rule as cidr", () => {
    assert.equal(classifyRule(baseRule()), "host_wildcard");
    const ipOnly = baseRule({ ip: "192.168.1.5" });
    assert.equal(classifyRule(ipOnly), "cidr");
    assert.equal(ruleDetailText(ipOnly, "cidr"), "192.168.1.5");
  });

  test("classifies multi-matcher, bypass, inbound, resolve_dns, failover, and multi-time rules as advanced", () => {
    assert.equal(classifyRule(baseRule({ host: "a.com", port: 443 })), "advanced");
    assert.equal(classifyRule(baseRule({ host: "a.com", bypass: "b.com" })), "advanced");
    assert.equal(classifyRule(baseRule({ host: "a.com", inbound: "http" })), "advanced");
    assert.equal(classifyRule(baseRule({ host: "a.com", resolve_dns: true })), "advanced");
    assert.equal(classifyRule(baseRule({ host: "a.com", target: ["corp", "direct"] })), "advanced");
    assert.equal(classifyRule(baseRule({ time: ["09:00-12:00", "13:00-17:00"] })), "advanced");
  });

  test("normalizes bare IPv4 and IPv6 addresses to CIDRs while leaving existing CIDRs and invalid text alone", () => {
    assert.equal(normalizeIpOrCidr("192.168.1.1"), "192.168.1.1/32");
    assert.equal(normalizeIpOrCidr("[::1]"), "::1/128");
    assert.equal(normalizeIpOrCidr("10.0.0.0/8"), "10.0.0.0/8");
    assert.equal(normalizeIpOrCidr("not-an-ip"), "not-an-ip");
  });

  test("parses and formats weekdays, time ranges, and host levels", () => {
    const days = parseWeekdays(["mon-fri"]);
    assert.deepEqual(days, {
      mon: true,
      tue: true,
      wed: true,
      thu: true,
      fri: true,
      sat: false,
      sun: false,
    });
    assert.deepEqual(formatWeekdays(days), ["mon", "tue", "wed", "thu", "fri"]);
    assert.equal(formatWeekdays({ ...days, mon: false, tue: false, wed: false, thu: false, fri: false }), undefined);

    assert.deepEqual(parseTimeRange("09:00-17:30"), { start: "09:00", end: "17:30" });
    assert.equal(formatTimeRange("09:00", "17:30"), "09:00-17:30");
    assert.equal(formatTimeRange("", ""), undefined);

    assert.deepEqual(parseHostLevelsText("2~"), { min: 2 });
    assert.deepEqual(parseHostLevelsText("~5"), { max: 5 });
    assert.equal(parseHostLevelsText(""), undefined);
  });
});

describe("routingRows reorderList", () => {
  test("reorders items without mutating the input", () => {
    const original = ["a", "b", "c", "d"];
    assert.deepEqual(reorderList(original, 0, 2), ["b", "c", "a", "d"]);
    assert.deepEqual(reorderList(original, 3, 1), ["a", "d", "b", "c"]);
    assert.deepEqual(reorderList(original, 1, 1), ["a", "b", "c", "d"]);
    assert.deepEqual(reorderList(original, -1, 2), ["a", "b", "c", "d"]);
    assert.deepEqual(reorderList(original, 0, 9), ["a", "b", "c", "d"]);
    assert.deepEqual(original, ["a", "b", "c", "d"]);
  });
});

describe("routingRows profile option groups and target labels", () => {
  const tunnels: TunnelLike[] = [
    {
      id: "t-1",
      name: "Work Bastion",
      port_forwards: [
        {
          id: "f-http",
          enabled: true,
          direction: "local",
          name: "Corp Squid",
          bind: "127.0.0.1",
          port: 3128,
          dest_host: "squid.internal",
          dest_port: 3128,
          proxy_protocol: "http",
        },
        {
          id: "f-socks",
          enabled: true,
          direction: "local",
          name: "",
          bind: "127.0.0.1",
          port: 1081,
          dest_host: "socks.internal",
          dest_port: 1080,
          proxy_protocol: "socks5",
        },
        {
          id: "f-plain",
          enabled: true,
          direction: "local",
          name: "DB",
          bind: "127.0.0.1",
          port: 5432,
          dest_host: "db.internal",
          dest_port: 5432,
          proxy_protocol: "none",
        },
        {
          id: "f-remote",
          enabled: true,
          direction: "remote",
          name: "Remote",
          bind: "127.0.0.1",
          port: 8080,
          dest_host: "127.0.0.1",
          dest_port: 8080,
          proxy_protocol: "http",
        },
      ],
    },
  ];
  const profiles: UpstreamProfileLike[] = [
    { name: "corp-http", color: "#3b82f6" },
  ];

  test("builds Built-in, Tunnels, Tunnel forwards, and Upstream servers groups", () => {
    const groups = buildProfileOptionGroups(tunnels, profiles);
    assert.deepEqual(
      groups.map((g) => g.label),
      ["Built-in", "Tunnels", "Tunnel forwards", "Upstream servers"],
    );
    assert.deepEqual(groups[0]!.options, [
      { value: "direct", label: "DIRECT" },
      { value: "block", label: "BLOCK" },
    ]);
    assert.deepEqual(groups[1]!.options, [{ value: "@tunnel:t-1", label: "Work Bastion" }]);
    assert.deepEqual(groups[2]!.options, [
      { value: "@forward:t-1:f-http", label: "Work Bastion › Corp Squid (HTTP)" },
      { value: "@forward:t-1:f-socks", label: "Work Bastion › 1081 (SOCKS5)" },
    ]);
    assert.deepEqual(groups[3]!.options, [{ value: "corp-http", label: "corp-http", color: "#3b82f6" }]);
    assert.equal(isKnownProfileOption("@forward:t-1:f-http", groups), true);
    assert.equal(isKnownProfileOption("@tunnel:missing", groups), false);
  });

  test("formats single targets, failover chains, and missing targets", () => {
    assert.equal(formatTargetLabel("direct", tunnels, profiles), "DIRECT");
    assert.equal(formatTargetLabel("block", tunnels, profiles), "BLOCK");
    assert.equal(formatTargetLabel("@tunnel:t-1", tunnels, profiles), "Work Bastion");
    assert.equal(
      formatTargetLabel("@forward:t-1:f-http", tunnels, profiles),
      "Work Bastion › Corp Squid (HTTP)",
    );
    assert.equal(
      formatTargetLabel(["@tunnel:t-1", "corp-http", "direct"], tunnels, profiles),
      "Work Bastion → corp-http → DIRECT",
    );
    assert.match(formatTargetLabel("@tunnel:gone", tunnels, profiles), /Unknown tunnel/);
    assert.match(formatTargetLabel("missing-prof", tunnels, profiles), /missing-prof/);
  });
});
