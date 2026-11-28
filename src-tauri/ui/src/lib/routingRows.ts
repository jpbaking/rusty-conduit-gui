// Pure helpers for the AirSwitch-style Proxy Routing table: condition classification,
// inline editing, drag-and-drop list reordering, and grouped profile pickers.

import type {
  RouteHostLevels,
  RouteOneOrMany,
  RoutePortSpec,
  RouteTarget,
  RoutingRule,
  Tunnel,
  UpstreamProfile,
} from "./types.ts";
import {
  FORWARD_TARGET_PREFIX,
  TUNNEL_TARGET_PREFIX,
  forwardTarget,
  isIpAddress,
  tunnelTarget,
} from "./validate.ts";

export type SimpleConditionKind =
  | "host_wildcard"
  | "host"
  | "host_regex"
  | "host_levels"
  | "cidr"
  | "url_wildcard"
  | "url_regex"
  | "keyword"
  | "weekday"
  | "time"
  | "port"
  | "match_all";

export type ConditionKind = SimpleConditionKind | "advanced";

export interface ConditionOption {
  value: ConditionKind;
  label: string;
  placeholder: string;
}

export interface ConditionGroup {
  label: string;
  options: readonly ConditionOption[];
}

export const CONDITION_GROUPS: readonly ConditionGroup[] = [
  {
    label: "Host",
    options: [
      { value: "host_wildcard", label: "Host wildcard", placeholder: "e.g. *.example.com" },
      { value: "host", label: "Host (exact)", placeholder: "e.g. example.com" },
      { value: "host_regex", label: "Host regex", placeholder: "e.g. (^|\\.)example\\.com$" },
      { value: "host_levels", label: "Host levels", placeholder: "min ~ max" },
      { value: "cidr", label: "IP / CIDR", placeholder: "e.g. 10.0.0.0/8 or 192.168.1.1" },
    ],
  },
  {
    label: "URL",
    options: [
      { value: "url_wildcard", label: "URL wildcard", placeholder: "e.g. http://*.example.com/api/*" },
      { value: "url_regex", label: "URL regex", placeholder: "e.g. ^http://example\\.com/api/" },
      { value: "keyword", label: "Keyword", placeholder: "e.g. example" },
    ],
  },
  {
    label: "Special",
    options: [
      { value: "weekday", label: "Weekday", placeholder: "Mon–Sun" },
      { value: "time", label: "Time", placeholder: "09:00–17:30" },
      { value: "port", label: "Port", placeholder: "e.g. 443 or 8000-8999" },
      { value: "match_all", label: "Always (match all)", placeholder: "" },
    ],
  },
];

export const WEEKDAYS = [
  { key: "mon", label: "Mon" },
  { key: "tue", label: "Tue" },
  { key: "wed", label: "Wed" },
  { key: "thu", label: "Thu" },
  { key: "fri", label: "Fri" },
  { key: "sat", label: "Sat" },
  { key: "sun", label: "Sun" },
] as const;

export type WeekdayKey = (typeof WEEKDAYS)[number]["key"];
export type WeekdaySelection = Record<WeekdayKey, boolean>;

const WEEKDAY_KEYS: readonly WeekdayKey[] = WEEKDAYS.map((d) => d.key);

export const isUrlConditionKind = (kind: ConditionKind): boolean =>
  kind === "url_wildcard" || kind === "url_regex" || kind === "keyword";

export function conditionPlaceholder(kind: ConditionKind): string {
  for (const group of CONDITION_GROUPS) {
    const found = group.options.find((opt) => opt.value === kind);
    if (found) return found.placeholder;
  }
  return "";
}

const asList = <T>(value: RouteOneOrMany<T> | undefined): T[] =>
  value === undefined ? [] : Array.isArray(value) ? value : [value];

function toOneOrMany(items: string[]): RouteOneOrMany<string> | undefined {
  if (items.length === 0) return undefined;
  return items.length === 1 ? items[0] : items;
}

const splitPipe = (text: string): string[] =>
  text
    .split(/[|\n]/)
    .map((s) => s.trim())
    .filter((s) => s !== "");

const splitPipeOrComma = (text: string): string[] =>
  text
    .split(/[|,\n]/)
    .map((s) => s.trim())
    .filter((s) => s !== "");

const splitLines = (text: string): string[] =>
  text
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");

const stripBrackets = (host: string): string =>
  host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

/** Normalizes a bare IP address to a single-host CIDR (`/32` for IPv4, `/128` for IPv6). */
export function normalizeIpOrCidr(token: string): string {
  const trimmed = token.trim();
  if (!trimmed || trimmed.includes("/")) return trimmed;
  const bare = stripBrackets(trimmed);
  if (!isIpAddress(bare)) return trimmed;
  return bare.includes(":") ? `${bare}/128` : `${bare}/32`;
}

/**
 * Classifies a `RoutingRule` into one of the inline simple condition kinds, or `"advanced"`
 * when it uses multiple matchers, `bypass`, `inbound`, `resolve_dns`, or a failover chain.
 */
export function classifyRule(rule: RoutingRule): ConditionKind {
  if (rule.inbound !== undefined) return "advanced";
  if (asList(rule.bypass).length > 0) return "advanced";
  if (rule.resolve_dns !== undefined) return "advanced";
  if (Array.isArray(rule.target) && rule.target.length > 1) return "advanced";

  const active: SimpleConditionKind[] = [];
  if (rule.match_all) active.push("match_all");
  if (asList(rule.host).length > 0) active.push("host");
  if (asList(rule.host_wildcard).length > 0) active.push("host_wildcard");
  if (asList(rule.host_regex).length > 0) active.push("host_regex");
  if (asList(rule.cidr).length > 0) active.push("cidr");
  if (asList(rule.ip).length > 0) active.push("cidr");
  if (asList(rule.port).length > 0) active.push("port");
  if (rule.host_levels !== undefined) active.push("host_levels");
  if (asList(rule.weekday).length > 0) active.push("weekday");
  if (asList(rule.time).length > 0) active.push("time");
  if (asList(rule.url_wildcard).length > 0) active.push("url_wildcard");
  if (asList(rule.url_regex).length > 0) active.push("url_regex");
  if (asList(rule.keyword).length > 0) active.push("keyword");

  if (active.length === 0) return "host_wildcard";
  if (active.length > 1) return "advanced";

  const kind = active[0]!;
  // A single inline time editor holds one start-end range.
  if (kind === "time" && asList(rule.time).length > 1) return "advanced";
  return kind;
}

/** Extracts the inline display text for a simple condition. */
export function ruleDetailText(rule: RoutingRule, kind: ConditionKind): string {
  switch (kind) {
    case "host_wildcard":
      return asList(rule.host_wildcard).join(" | ");
    case "host":
      return asList(rule.host).join(" | ");
    case "host_regex":
      return asList(rule.host_regex).join("\n");
    case "host_levels":
      return rule.host_levels
        ? `${rule.host_levels.min ?? ""}~${rule.host_levels.max ?? ""}`
        : "";
    case "cidr":
      return asList(rule.cidr ?? rule.ip).join(", ");
    case "url_wildcard":
      return asList(rule.url_wildcard).join(" | ");
    case "url_regex":
      return asList(rule.url_regex).join("\n");
    case "keyword":
      return asList(rule.keyword).join(" | ");
    case "weekday":
      return asList(rule.weekday).join(", ");
    case "time":
      return asList(rule.time).join(", ");
    case "port":
      return asList(rule.port).join(", ");
    case "match_all":
    case "advanced":
      return "";
  }
}

function emptyWeekdays(): WeekdaySelection {
  return { mon: false, tue: false, wed: false, thu: false, fri: false, sat: false, sun: false };
}

function normalizeWeekdayToken(token: string): WeekdayKey | null {
  const lowered = token.trim().toLowerCase().slice(0, 3);
  return (WEEKDAY_KEYS as readonly string[]).includes(lowered) ? (lowered as WeekdayKey) : null;
}

/** Parses `rule.weekday` (single tokens or ranges like `mon-fri`) into 7 booleans. */
export function parseWeekdays(value: RouteOneOrMany<string> | undefined): WeekdaySelection {
  const result = emptyWeekdays();
  const tokens = asList(value).flatMap(splitPipeOrComma);
  for (const token of tokens) {
    const dash = token.indexOf("-");
    if (dash >= 0) {
      const start = normalizeWeekdayToken(token.slice(0, dash));
      const end = normalizeWeekdayToken(token.slice(dash + 1));
      if (start && end) {
        const si = WEEKDAY_KEYS.indexOf(start);
        const ei = WEEKDAY_KEYS.indexOf(end);
        let i = si;
        for (let step = 0; step < 7; step += 1) {
          result[WEEKDAY_KEYS[i]!] = true;
          if (i === ei) break;
          i = (i + 1) % 7;
        }
      }
      continue;
    }
    const day = normalizeWeekdayToken(token);
    if (day) result[day] = true;
  }
  return result;
}

/** Converts 7 weekday booleans back to `RouteOneOrMany<string> | undefined`. */
export function formatWeekdays(selection: WeekdaySelection): RouteOneOrMany<string> | undefined {
  const selected = WEEKDAY_KEYS.filter((key) => selection[key]);
  return toOneOrMany(selected);
}

/** Parses `rule.time` (such as `"09:00-17:30"`) into `{ start, end }`. */
export function parseTimeRange(value: RouteOneOrMany<string> | undefined): { start: string; end: string } {
  const first = asList(value)[0]?.trim() ?? "";
  if (!first) return { start: "", end: "" };
  const dash = first.indexOf("-");
  if (dash < 0) return { start: first, end: "" };
  return { start: first.slice(0, dash).trim(), end: first.slice(dash + 1).trim() };
}

/** Formats `{ start, end }` back to `"HH:MM-HH:MM"`, or `undefined` when both are empty. */
export function formatTimeRange(start: string, end: string): string | undefined {
  const s = start.trim();
  const e = end.trim();
  if (!s && !e) return undefined;
  return `${s}-${e}`;
}

/** Parses `"min~max"` or `"min-max"` into `RouteHostLevels | undefined`. */
export function parseHostLevelsText(text: string): RouteHostLevels | undefined {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const sep = trimmed.includes("~") ? "~" : "-";
  const idx = trimmed.indexOf(sep);
  const rawMin = (idx >= 0 ? trimmed.slice(0, idx) : trimmed).trim();
  const rawMax = (idx >= 0 ? trimmed.slice(idx + 1) : "").trim();
  const levels: RouteHostLevels = {};
  if (rawMin !== "") levels.min = Number(rawMin);
  if (rawMax !== "") levels.max = Number(rawMax);
  return levels.min === undefined && levels.max === undefined ? undefined : levels;
}

function stripSimpleMatchers(rule: RoutingRule): RoutingRule {
  const next: RoutingRule = {
    match_all: false,
    disabled: rule.disabled,
    target: Array.isArray(rule.target) ? (rule.target[0] ?? "direct") : rule.target,
  };
  if (rule.name !== undefined) next.name = rule.name;
  if (rule.bypass_mitm) next.bypass_mitm = true;
  return next;
}

/**
 * Replaces the rule's condition with a single simple condition of `kind` and `value`.
 * Clears all other simple matchers and preserves `name`, `disabled`, `bypass_mitm` (cleared for
 * URL conditions, which require MITM), and primary `target`.
 */
export function applySimpleCondition(
  rule: RoutingRule,
  kind: SimpleConditionKind,
  value: string,
): RoutingRule {
  const next = stripSimpleMatchers(rule);
  if (isUrlConditionKind(kind)) delete next.bypass_mitm;
  switch (kind) {
    case "host_wildcard": {
      const v = toOneOrMany(splitPipe(value));
      if (v !== undefined) next.host_wildcard = v;
      return next;
    }
    case "host": {
      const v = toOneOrMany(splitPipeOrComma(value));
      if (v !== undefined) next.host = v;
      return next;
    }
    case "host_regex": {
      const v = toOneOrMany(splitLines(value));
      if (v !== undefined) next.host_regex = v;
      return next;
    }
    case "host_levels": {
      const levels = parseHostLevelsText(value);
      if (levels !== undefined) next.host_levels = levels;
      return next;
    }
    case "cidr": {
      const items = splitPipeOrComma(value).map(normalizeIpOrCidr);
      const v = toOneOrMany(items);
      if (v !== undefined) next.cidr = v;
      return next;
    }
    case "url_wildcard": {
      const v = toOneOrMany(splitPipe(value));
      if (v !== undefined) next.url_wildcard = v;
      return next;
    }
    case "url_regex": {
      const v = toOneOrMany(splitLines(value));
      if (v !== undefined) next.url_regex = v;
      return next;
    }
    case "keyword": {
      const v = toOneOrMany(splitPipeOrComma(value));
      if (v !== undefined) next.keyword = v;
      return next;
    }
    case "weekday": {
      const v = formatWeekdays(parseWeekdays(value));
      if (v !== undefined) next.weekday = v;
      return next;
    }
    case "time": {
      const trimmed = value.trim();
      if (trimmed) next.time = trimmed;
      return next;
    }
    case "port": {
      const items: RoutePortSpec[] = splitPipeOrComma(value).map((item) =>
        /^\d+$/.test(item) ? Number(item) : item,
      );
      if (items.length === 1) next.port = items[0]!;
      else if (items.length > 1) next.port = items;
      return next;
    }
    case "match_all":
      next.match_all = true;
      return next;
  }
}

/** Moves the item at `fromIndex` to `toIndex`, returning a new array. */
export function reorderList<T>(items: readonly T[], fromIndex: number, toIndex: number): T[] {
  const next = [...items];
  if (
    fromIndex === toIndex ||
    fromIndex < 0 ||
    toIndex < 0 ||
    fromIndex >= next.length ||
    toIndex >= next.length
  ) {
    return next;
  }
  const [moved] = next.splice(fromIndex, 1);
  if (moved !== undefined) next.splice(toIndex, 0, moved);
  return next;
}

export type TunnelLike = Pick<Tunnel, "id" | "name" | "port_forwards">;
export type UpstreamProfileLike = Pick<UpstreamProfile, "name" | "color">;

export interface ProfileOption {
  value: string;
  label: string;
  color?: string | null;
}

export interface ProfileOptionGroup {
  label: string;
  options: ProfileOption[];
}

function forwardProtocolLabel(protocol: "http" | "socks5"): string {
  return protocol === "http" ? "HTTP" : "SOCKS5";
}

/**
 * Builds the grouped `<select>` options for Proxy routing targets:
 * Built-in (DIRECT, BLOCK), Tunnels (`@tunnel:<id>`), tagged local Tunnel forwards
 * (`@forward:<tid>:<fid>`), and custom Upstream servers (`proxy.profiles`).
 */
export function buildProfileOptionGroups(
  tunnels: readonly TunnelLike[],
  proxyProfiles: readonly UpstreamProfileLike[],
): ProfileOptionGroup[] {
  const groups: ProfileOptionGroup[] = [
    {
      label: "Built-in",
      options: [
        { value: "direct", label: "DIRECT" },
        { value: "block", label: "BLOCK" },
      ],
    },
  ];

  if (tunnels.length > 0) {
    groups.push({
      label: "Tunnels",
      options: tunnels.map((t) => ({
        value: tunnelTarget(t.id),
        label: t.name.trim() || t.id,
      })),
    });
  }

  const forwardOptions: ProfileOption[] = [];
  for (const tunnel of tunnels) {
    const tunnelName = tunnel.name.trim() || tunnel.id;
    for (const fwd of tunnel.port_forwards) {
      if (fwd.direction !== "local" || fwd.proxy_protocol === "none") continue;
      const fwdLabel = fwd.name.trim() || String(fwd.port);
      forwardOptions.push({
        value: forwardTarget(tunnel.id, fwd.id),
        label: `${tunnelName} › ${fwdLabel} (${forwardProtocolLabel(fwd.proxy_protocol)})`,
      });
    }
  }
  if (forwardOptions.length > 0) {
    groups.push({ label: "Tunnel forwards", options: forwardOptions });
  }

  const upstreamOptions = proxyProfiles
    .filter((p) => p.name.trim() !== "")
    .map((p) => ({ value: p.name, label: p.name, color: p.color }));
  if (upstreamOptions.length > 0) {
    groups.push({ label: "Upstream servers", options: upstreamOptions });
  }

  return groups;
}

export function isKnownProfileOption(value: string, groups: readonly ProfileOptionGroup[]): boolean {
  return groups.some((group) => group.options.some((opt) => opt.value === value));
}

function formatSingleTarget(
  name: string,
  tunnels: readonly TunnelLike[],
  proxyProfiles: readonly UpstreamProfileLike[],
): string {
  if (name === "direct") return "DIRECT";
  if (name === "block") return "BLOCK";
  if (name.startsWith(TUNNEL_TARGET_PREFIX)) {
    const tid = name.slice(TUNNEL_TARGET_PREFIX.length);
    const tunnel = tunnels.find((t) => t.id === tid);
    return tunnel ? tunnel.name.trim() || tunnel.id : `Unknown tunnel (${tid})`;
  }
  if (name.startsWith(FORWARD_TARGET_PREFIX)) {
    const rest = name.slice(FORWARD_TARGET_PREFIX.length);
    const [tid, fid] = rest.split(":");
    const tunnel = tunnels.find((t) => t.id === tid);
    const fwd = tunnel?.port_forwards.find(
      (f) => f.id === fid && f.direction === "local" && f.proxy_protocol !== "none",
    );
    if (tunnel && fwd && fwd.proxy_protocol !== "none") {
      const tunnelName = tunnel.name.trim() || tunnel.id;
      const fwdLabel = fwd.name.trim() || String(fwd.port);
      return `${tunnelName} › ${fwdLabel} (${forwardProtocolLabel(fwd.proxy_protocol)})`;
    }
    return `Unknown forward (${name})`;
  }
  const upstream = proxyProfiles.find((p) => p.name === name);
  return upstream ? upstream.name : `${name} (unknown)`;
}

/** Formats a single target name or failover chain into a human-friendly label. */
export function formatTargetLabel(
  target: RouteTarget,
  tunnels: readonly TunnelLike[],
  proxyProfiles: readonly UpstreamProfileLike[],
): string {
  const names = Array.isArray(target) ? target : [target];
  return names.map((name) => formatSingleTarget(name, tunnels, proxyProfiles)).join(" → ");
}
