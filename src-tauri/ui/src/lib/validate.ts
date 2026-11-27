// Client-side checks that mirror the backend's rules, so problems show next to the field.

import type {
  HostProfile,
  LoggingConfig,
  ForwardPreset,
  MitmConfig,
  OpenSshOptions,
  PortForward,
  Proxy,
  ReverseConfig,
  RoutePortSpec,
  RouteTarget,
  RoutingRule,
  SessionProfile,
  SshEngine,
  Tunnel,
  TunnelConfig,
  TunnelId,
  Uuid,
} from "./types";

/** Field path, such as `forward.bind` or `hop:<id>:host`, mapped to its message. */
export type FieldErrors = Record<string, string>;

export const isPort = (value: number, allowZero = false): boolean =>
  Number.isInteger(value) && value >= (allowZero ? 0 : 1) && value <= 65535;

function isIpv4(text: string): boolean {
  const parts = text.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
  );
}

function isIpv6(text: string): boolean {
  const halves = text.split("::");
  if (halves.length > 2) return false;
  const groups = (half: string) => (half === "" ? [] : half.split(":"));
  const left = groups(halves[0] ?? "");
  const right = groups(halves[1] ?? "");
  const all = [...left, ...right];
  // An embedded IPv4 address may only be the final group, and counts as two groups.
  const last = all[all.length - 1];
  const hasV4 = last !== undefined && last.includes(".");
  if (hasV4 && !isIpv4(last)) return false;
  const hex = hasV4 ? all.slice(0, -1) : all;
  if (!hex.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) return false;
  const count = hex.length + (hasV4 ? 2 : 0);
  return halves.length === 2 ? count <= 7 : count === 8;
}

/** Matches what Rust's `IpAddr` accepts: no hostnames, ports, or zone ids. */
export const isIpAddress = (text: string): boolean => isIpv4(text) || isIpv6(text);

export function isLoopback(text: string): boolean {
  return text === "::1" || (isIpv4(text) && text.startsWith("127."));
}

export function hostErrors(host: HostProfile, prefix = ""): FieldErrors {
  const errors: FieldErrors = {};
  if (!host.host.trim()) errors[`${prefix}host`] = "Enter a host name or IP address.";
  if (!host.user.trim()) errors[`${prefix}user`] = "Enter a user name.";
  if (!isPort(host.port)) errors[`${prefix}port`] = "Use a port from 1 to 65535.";
  return errors;
}

export const LOG_LEVELS = ["QUIET", "FATAL", "ERROR", "INFO", "DEBUG", "VERBOSE"] as const;
export const LOG_FORMATS = ["text", "json"] as const;
export const MIN_CERT_TTL_SECS = 10;
const MAX_U32 = 4_294_967_295;
/** Upstream `MAX_TCP_KEEPALIVE_DURATION` / `MAX_TCP_KEEPALIVE_RETRIES` (Linux kernel caps). */
export const MAX_TCP_KEEPALIVE_SECS = 32_767;
export const MAX_TCP_KEEPALIVE_RETRIES = 127;

export const isWholeNumber = (value: number, max = Number.MAX_SAFE_INTEGER): boolean =>
  Number.isSafeInteger(value) && value >= 0 && value <= max;

function domainError(domain: string, raw: string): string | null {
  if (domain.length === 0 || domain.length > 253) return `Invalid domain in "${raw}".`;
  for (const label of domain.split(".")) {
    if (label.length === 0 || label.length > 63) return `Invalid domain label in "${raw}".`;
    if (!/^[a-z0-9_-]+$/.test(label)) return `Invalid character in "${raw}".`;
  }
  return null;
}

const stripBrackets = (host: string): string =>
  host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

/** Mirrors `FilterRule::from_str`. Returns the problem, or `null` for a valid rule. */
export function filterRuleError(raw: string): string | null {
  const text = raw.trim();
  if (!text) return "A rule cannot be empty.";

  const slash = text.indexOf("/");
  if (slash >= 0) {
    const address = stripBrackets(text.slice(0, slash));
    const prefix = text.slice(slash + 1);
    if (!isIpAddress(address)) return `Invalid CIDR address in "${raw}".`;
    // Rust's `u8` parser accepts a leading `+` and leading zeros.
    if (!/^\+?\d+$/.test(prefix) || Number(prefix) > 255) return `Invalid CIDR prefix in "${raw}".`;
    const max = isIpv4(address) ? 32 : 128;
    return Number(prefix) > max ? `CIDR prefix exceeds /${max} in "${raw}".` : null;
  }

  if (isIpAddress(stripBrackets(text))) return null;
  if (text.includes("[") || text.includes("]")) return `Invalid IP address in "${raw}".`;

  const lowered = text.replace(/[A-Z]/g, (c) => c.toLowerCase());
  const domain = lowered.endsWith(".") ? lowered.slice(0, -1) : lowered;
  if (domain.startsWith("*.")) return domainError(domain.slice(2), raw);
  if (domain.includes("*")) return `Only a leading "*." wildcard is supported in "${raw}".`;
  return domainError(domain, raw);
}

/** Same list as `DENIED_SHORT_FLAGS` in `conduit-core`. Case-sensitive. */
const DENIED_SHORT_FLAGS: readonly string[] = ["F", "J", "i", "O", "S", "A", "a", "W"];

/** Same list as `DENIED_OPTIONS` in `conduit-core`. Matched without regard to ASCII case. */
const DENIED_OPTIONS: readonly string[] = [
  "ProxyCommand",
  "ProxyJump",
  "IdentityAgent",
  "IdentityFile",
  "UserKnownHostsFile",
  "GlobalKnownHostsFile",
  "StrictHostKeyChecking",
  "ControlPath",
  "ControlMaster",
  "ControlPersist",
  "ForwardAgent",
  "Include",
  "LocalCommand",
  "PermitLocalCommand",
  "RemoteCommand",
  "KnownHostsCommand",
  "UpdateHostKeys",
  "Host",
  "Match",
];

/** Same as `VALUE_FLAGS` in `conduit-core`: short flags that take the rest of their token. */
const VALUE_FLAGS = "bceilmopBDEFIJLOPQRSwW";

// ASCII only, like Rust's `eq_ignore_ascii_case`. `toLowerCase` would fold the Kelvin sign to k.
const asciiLower = (text: string): string => text.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** Mirrors `denied_option`: reads a keyword the way `ssh_config` does. */
function deniedOption(text: string): string | null {
  const keyword = text.replace(/^[ \t\r\n"]+/, "").split(/[ \t\r\n="]/)[0] ?? "";
  const lowered = asciiLower(keyword);
  return DENIED_OPTIONS.find((option) => asciiLower(option) === lowered) ?? null;
}

/**
 * Mirrors `denylisted_flag`. Every token is checked as a possible option, so the value after a
 * separate `-o` is caught without tracking position. Short flags are walked like getopt.
 */
export function denylistedFlag(token: string): string | null {
  const undashed = token.startsWith("--")
    ? token.slice(2)
    : token.startsWith("-")
      ? token.slice(1)
      : token;
  const option = deniedOption(undashed);
  if (option) return option;
  const name = undashed.split("=")[0] ?? "";
  if (DENIED_SHORT_FLAGS.includes(name)) return name;
  if (!token.startsWith("-")) return null;

  const cluster = token.slice(1);
  let index = 0;
  for (const c of cluster) {
    if (DENIED_SHORT_FLAGS.includes(c)) return c;
    index += c.length;
    if (c === "o") return deniedOption(cluster.slice(index));
    if (VALUE_FLAGS.includes(c)) return null;
  }
  return null;
}

/** An extra argument written the way `ssh_config` is, which `ssh` would not read as an option. */
export interface ConfigLineArg {
  index: number;
  keyword: string;
  /** The arguments to put in its place, or `null` when `-o` cannot express it (Host, Match). */
  fix: [string, string] | null;
}

/**
 * Finds `Keyword value` or `Keyword=value` lines in the extra arguments. Each line is one
 * command-line argument, so these need `-o` in front. A value right after a flag that takes one
 * (`-o`, `-p`, ...) is left alone.
 */
export function configLineArgs(args: readonly string[]): ConfigLineArg[] {
  const found: ConfigLineArg[] = [];
  args.forEach((arg, index) => {
    if (arg.startsWith("-")) return;
    const previous = args[index - 1];
    if (previous && /^-[A-Za-z]$/.test(previous) && VALUE_FLAGS.includes(previous[1]!)) return;
    const match = /^([A-Za-z][A-Za-z0-9]*)(?:[ \t]*=[ \t]*|[ \t]+)(\S.*)$/.exec(arg.trim());
    if (!match) return;
    const [, keyword, value] = match as unknown as [string, string, string];
    const block = ["host", "match"].includes(asciiLower(keyword));
    found.push({ index, keyword, fix: block ? null : ["-o", `${keyword}=${value.trim()}`] });
  });
  return found;
}

const REDACTED = "<redacted>";

/** Keeps flag and option names so the shape is readable, and hides every value. */
export function redactArgs(args: readonly string[]): string[] {
  return args.map((arg, index) => {
    const equals = arg.indexOf("=");
    if (arg.startsWith("-")) {
      if (equals >= 0) return `${arg.slice(0, equals)}=${REDACTED}`;
      if (arg.startsWith("--") || arg.length <= 2) return arg;
      return `${arg.slice(0, 2)}${REDACTED}`;
    }
    // A bare `Name=value` is only known to be an option name right after `-o`.
    if (args[index - 1] === "-o" && equals > 0) return `${arg.slice(0, equals)}=${REDACTED}`;
    return REDACTED;
  });
}

function filterErrors(
  errors: FieldErrors,
  scope: "forward" | "reverse",
  allow: readonly string[],
  block: readonly string[],
): void {
  for (const [list, rules] of [["allow", allow], ["block", block]] as const) {
    rules.forEach((rule, index) => {
      const problem = filterRuleError(rule);
      if (problem) errors[`filters.${scope}.${list}:${index}`] = problem;
    });
  }
}

function mitmErrors(errors: FieldErrors, mitm: MitmConfig): void {
  if (!mitm.ca) errors["mitm.ca"] = "Choose a CA, or upload one.";
  if (!isWholeNumber(mitm.cert_ttl) || mitm.cert_ttl < MIN_CERT_TTL_SECS) {
    errors["mitm.cert_ttl"] = `Use a whole number of at least ${MIN_CERT_TTL_SECS} seconds.`;
  }
  if (!isWholeNumber(mitm.cert_cache_max_entries)) {
    errors["mitm.cert_cache_max_entries"] = "Use a whole number. 0 means unlimited.";
  }
  // Like the backend, every saved rule must parse, whichever mode is chosen.
  for (const rule of mitm.insecure_hosts) {
    const problem = filterRuleError(rule);
    if (problem) {
      errors["mitm.insecure_hosts"] = problem;
      break;
    }
  }
}

function keepaliveErrors(errors: FieldErrors, tunnel: TunnelConfig, prefix = "tunnel"): void {
  if (!["4", "6", "auto"].includes(tunnel.ip_version.trim().toLowerCase())) {
    errors[`${prefix}.ip_version`] = "Choose IPv4, IPv6, or Auto.";
  }
  const seconds = {
    [`${prefix}.server_alive_interval`]: tunnel.server_alive_interval,
    [`${prefix}.reconnect_initial_delay`]: tunnel.reconnect_initial_delay,
    [`${prefix}.reconnect_max_delay`]: tunnel.reconnect_max_delay,
    [`${prefix}.startup_timeout`]: tunnel.startup_timeout,
  };
  for (const [field, value] of Object.entries(seconds)) {
    if (!isWholeNumber(value)) errors[field] = "Use a whole number of seconds.";
  }
  if (!isWholeNumber(tunnel.server_alive_count_max, MAX_U32)) {
    errors[`${prefix}.server_alive_count_max`] = `Use a whole number up to ${MAX_U32}.`;
  }
  if (!isWholeNumber(tunnel.tcp_keepalive, MAX_TCP_KEEPALIVE_SECS)) {
    errors[`${prefix}.tcp_keepalive`] = `Use 0 (off) or a whole number from 1 to ${MAX_TCP_KEEPALIVE_SECS}.`;
  }
  // Interval and probe count only matter while TCP keepalive is on, as in the engine.
  if (tunnel.tcp_keepalive !== 0) {
    const interval = tunnel.tcp_keepalive_interval;
    if (!isWholeNumber(interval, MAX_TCP_KEEPALIVE_SECS) || interval < 1) {
      errors[`${prefix}.tcp_keepalive_interval`] = `Use a whole number from 1 to ${MAX_TCP_KEEPALIVE_SECS}.`;
    }
    const retries = tunnel.tcp_keepalive_retries;
    if (!isWholeNumber(retries, MAX_TCP_KEEPALIVE_RETRIES) || retries < 1) {
      errors[`${prefix}.tcp_keepalive_retries`] = `Use a whole number from 1 to ${MAX_TCP_KEEPALIVE_RETRIES}.`;
    }
  }
  if (
    !errors[`${prefix}.reconnect_initial_delay`] &&
    !errors[`${prefix}.reconnect_max_delay`] &&
    tunnel.reconnect_initial_delay > tunnel.reconnect_max_delay
  ) {
    errors[`${prefix}.reconnect_initial_delay`] = "The initial delay cannot exceed the maximum delay.";
  }
}

function loggingErrors(errors: FieldErrors, logging: LoggingConfig): void {
  if (!(LOG_LEVELS as readonly string[]).includes(logging.level.trim().toUpperCase())) {
    errors["logging.level"] = `Choose one of ${LOG_LEVELS.join(", ")}.`;
  }
  if (!(LOG_FORMATS as readonly string[]).includes(logging.format.trim().toLowerCase())) {
    errors["logging.format"] = "Choose text or json.";
  }
}

function opensshErrors(
  errors: FieldErrors,
  profile: { engine: SshEngine; openssh: OpenSshOptions },
): void {
  const { openssh } = profile;
  if (profile.engine === "OpenSsh" && !openssh.ssh_bin.trim()) {
    errors["openssh.ssh_bin"] = "Enter the ssh program to run.";
  }
  if (!isIpAddress(openssh.ssh_socks_bind)) {
    errors["openssh.ssh_socks_bind"] = "Use an IP address, such as 127.0.0.1.";
  }
  if (!isPort(openssh.ssh_socks_port, true)) {
    errors["openssh.ssh_socks_port"] = "Use a port from 0 to 65535. 0 picks a free port.";
  }
  // The backend applies this denylist for every engine, so it is checked for every engine.
  openssh.extra_args.forEach((arg, index) => {
    const flag = denylistedFlag(arg);
    if (flag) errors[`openssh.extra_args:${index}`] = `"${arg}" uses the forbidden flag ${flag}.`;
  });
}

const MAX_HOST_LEN = 253;

/** Mirrors `forward_host_problem`: an IP address (IPv6 may be in brackets) or a host name. */
export function forwardHostError(raw: string): string | null {
  const host = raw.trim();
  if (!host) return "Enter a host name or IP address.";
  if (isIpAddress(stripBrackets(host))) return null;
  const valid =
    host.length <= MAX_HOST_LEN &&
    host
      .split(".")
      .every((label) => label.length > 0 && label.length <= 63 && /^[A-Za-z0-9_][A-Za-z0-9_-]*$/.test(label));
  return valid ? null : "Use a host name or an IP address, with no port or spaces.";
}

const bindsOverlap = (a: string, b: string): boolean =>
  a === b || a === "0.0.0.0" || a === "::" || b === "0.0.0.0" || b === "::";

/** Field errors for each forward, keyed `forwards:<id>:<field>`. Mirrors `port_forward_problem`. */
function portForwardErrors(
  errors: FieldErrors,
  profile: {
    forward: SessionProfile["forward"] | null;
    reverse: ReverseConfig;
    port_forwards: PortForward[];
  },
): void {
  const { forward, reverse } = profile;
  profile.port_forwards.forEach((f: PortForward, index) => {
    const key = (field: string) => `forwards:${f.id}:${field}`;
    if (!isIpAddress(f.bind)) errors[key("bind")] = "Use an IP address, such as 127.0.0.1.";
    if (!isPort(f.port)) errors[key("port")] = "Use a port from 1 to 65535.";
    if (!isPort(f.dest_port)) errors[key("dest_port")] = "Use a port from 1 to 65535.";
    const hostError = forwardHostError(f.dest_host);
    if (hostError) errors[key("dest_host")] = hostError;
    if (f.direction === "remote" && f.proxy_protocol !== "none") {
      errors[key("proxy_protocol")] = "Proxy protocol is only supported on local (-L) port forwards.";
    }
    if (!f.enabled || errors[key("port")] || errors[key("bind")]) return;

    const [proxyBind, ports, side] =
      f.direction === "local"
        ? // A Tunnel has no forward proxy of its own, so a local forward may use any port.
          [forward?.bind ?? "", forward?.enabled ? [forward.http_port, forward.socks_port] : [], "forward"]
        : [
            reverse.reverse_bind,
            reverse.enabled ? [reverse.reverse_http_port, reverse.reverse_socks_port] : [],
            "reverse",
          ];
    if (bindsOverlap(f.bind, proxyBind) && ports.includes(f.port)) {
      errors[key("port")] = `Port ${f.port} is already used by the ${side} proxy.`;
      return;
    }
    const earlier = profile.port_forwards
      .slice(0, index)
      .some((o) => o.enabled && o.direction === f.direction && o.port === f.port && bindsOverlap(o.bind, f.bind));
    if (earlier) errors[key("port")] = `Another forward already listens on port ${f.port}.`;
  });
}

/** Mirrors `validate_forward_preset`. The destination host may be empty. */
export function presetErrors(preset: ForwardPreset): FieldErrors {
  const errors: FieldErrors = {};
  if (!preset.name.trim()) errors.name = "Enter a preset name.";
  if (preset.bind !== null && !isIpAddress(preset.bind)) errors.bind = "Use an IP address, or leave it empty.";
  if (!isPort(preset.port)) errors.port = "Use a port from 1 to 65535.";
  if (!isPort(preset.dest_port)) errors.dest_port = "Use a port from 1 to 65535.";
  const hostError = preset.dest_host.trim() ? forwardHostError(preset.dest_host) : null;
  if (hostError) errors.dest_host = hostError;
  return errors;
}

export function sessionErrors(profile: SessionProfile): FieldErrors {
  const errors: FieldErrors = {};
  if (!profile.name.trim()) errors.name = "Enter a session name.";
  if (profile.hops.length === 0) errors.hops = "Add at least one hop. The last hop is the target.";
  for (const hop of profile.hops) Object.assign(errors, hostErrors(hop.host, `hop:${hop.hop_id}:`));

  const { forward, reverse } = profile;
  if (!isIpAddress(forward.bind)) errors["forward.bind"] = "Use an IP address, such as 127.0.0.1.";
  if (!isIpAddress(reverse.reverse_bind)) {
    errors["reverse.bind"] = "Use an IP address, such as 127.0.0.1.";
  }
  const ports = {
    "forward.http": forward.http_port,
    "forward.socks": forward.socks_port,
    "reverse.http": reverse.reverse_http_port,
    "reverse.socks": reverse.reverse_socks_port,
  };
  for (const [field, port] of Object.entries(ports)) {
    if (!isPort(port, true)) errors[field] = "Use a port from 0 to 65535. 0 turns it off.";
  }
  if (!Number.isSafeInteger(forward.max_connections) || forward.max_connections < 0) {
    errors["forward.max_connections"] = "Use a whole number. 0 means unlimited.";
  }
  const reverseCap = reverse.reverse_max_connections;
  if (reverseCap !== null && (!Number.isSafeInteger(reverseCap) || reverseCap < 0)) {
    errors["reverse.max_connections"] = "Use a whole number. 0 means unlimited.";
  }
  // A proxy that is on needs a listener; switched off, its ports are kept but not used.
  if (forward.enabled && forward.http_port === 0 && forward.socks_port === 0) {
    errors["forward.ports"] = "Set an HTTP or SOCKS port, or switch the forward proxy off.";
  }
  if (reverse.enabled && reverse.reverse_http_port === 0 && reverse.reverse_socks_port === 0) {
    errors["reverse.ports"] = "Set an HTTP or SOCKS port, or switch the reverse proxy off.";
  }
  if (!forward.enabled && !reverse.enabled && !profile.port_forwards.some((f) => f.enabled)) {
    errors.listeners = "Turn on the forward or reverse proxy, or a port forward.";
  }
  portForwardErrors(errors, profile);

  filterErrors(errors, "forward", forward.allow, forward.block);
  filterErrors(errors, "reverse", reverse.reverse_allow, reverse.reverse_block);
  if (profile.mitm) mitmErrors(errors, profile.mitm);
  keepaliveErrors(errors, profile.tunnel);
  loggingErrors(errors, profile.logging);
  opensshErrors(errors, profile);
  return errors;
}

// ---------------------------------------------------------------------------------------------
// v2: Tunnels and Proxies. Mirror `validate_tunnel` and `validate_proxy` in `conduit-core`.
// ---------------------------------------------------------------------------------------------

/** Mirrors `validate_tunnel`. Unlike a v1 session, a Tunnel needs no listener of its own. */
export function tunnelErrors(tunnel: Tunnel): FieldErrors {
  const errors: FieldErrors = {};
  if (!tunnel.name.trim()) errors.name = "Enter a tunnel name.";
  if (tunnel.hops.length === 0) errors.hops = "Add at least one hop. The last hop is the target.";
  for (const hop of tunnel.hops) Object.assign(errors, hostErrors(hop.host, `hop:${hop.hop_id}:`));

  const { forward, reverse } = tunnel;
  if (forward.enabled) {
    if (!isIpAddress(forward.bind)) errors["forward.bind"] = "Use an IP address, such as 127.0.0.1.";
    if (!isPort(forward.http_port, true)) errors["forward.http"] = "Use a port from 0 to 65535. 0 turns it off.";
    if (!isPort(forward.socks_port, true)) errors["forward.socks"] = "Use a port from 0 to 65535. 0 turns it off.";
    if (!Number.isSafeInteger(forward.max_connections) || forward.max_connections < 0) {
      errors["forward.max_connections"] = "Use a whole number. 0 means unlimited.";
    }
    if (forward.http_port === 0 && forward.socks_port === 0) {
      errors["forward.ports"] = "Set an HTTP or SOCKS port, or switch the forward proxy off.";
    }
    if (tunnel.mitm) mitmErrors(errors, tunnel.mitm);
  }
  if (!isIpAddress(reverse.reverse_bind)) {
    errors["reverse.bind"] = "Use an IP address, such as 127.0.0.1.";
  }
  const ports = { "reverse.http": reverse.reverse_http_port, "reverse.socks": reverse.reverse_socks_port };
  for (const [field, port] of Object.entries(ports)) {
    if (!isPort(port, true)) errors[field] = "Use a port from 0 to 65535. 0 turns it off.";
  }
  const reverseCap = reverse.reverse_max_connections;
  if (reverseCap !== null && (!Number.isSafeInteger(reverseCap) || reverseCap < 0)) {
    errors["reverse.max_connections"] = "Use a whole number. 0 means unlimited.";
  }
  if (reverse.enabled && reverse.reverse_http_port === 0 && reverse.reverse_socks_port === 0) {
    errors["reverse.ports"] = "Set an HTTP or SOCKS port, or switch the reverse proxy off.";
  }
  portForwardErrors(errors, { forward, reverse, port_forwards: tunnel.port_forwards });
  filterErrors(errors, "forward", forward.allow, forward.block);
  filterErrors(errors, "reverse", reverse.reverse_allow, reverse.reverse_block);
  keepaliveErrors(errors, tunnel.keepalive, "keepalive");
  loggingErrors(errors, tunnel.logging);
  opensshErrors(errors, tunnel);
  return errors;
}

/** Built-in profile names a Proxy may route to without defining them. */
export const BUILTIN_PROFILES = ["direct", "block"] as const;

export const TUNNEL_TARGET_PREFIX = "@tunnel:";
export const FORWARD_TARGET_PREFIX = "@forward:";

export const tunnelTarget = (id: TunnelId): string => `${TUNNEL_TARGET_PREFIX}${id}`;
export const forwardTarget = (tid: TunnelId, fid: Uuid): string =>
  `${FORWARD_TARGET_PREFIX}${tid}:${fid}`;
export const isSyntheticTarget = (name: string): boolean =>
  name.startsWith(TUNNEL_TARGET_PREFIX) || name.startsWith(FORWARD_TARGET_PREFIX);

const MAX_U16 = 65_535;

/** Mirrors the engine's `parse_port_spec`: `443`, or `"8000-8080"` (a single `"443"` too). */
export function portSpecError(spec: RoutePortSpec): string | null {
  if (typeof spec === "number") {
    return Number.isInteger(spec) && spec >= 0 && spec <= MAX_U16 ? null : `Invalid port ${spec}.`;
  }
  const dash = spec.indexOf("-");
  const [a, b] = dash >= 0 ? [spec.slice(0, dash).trim(), spec.slice(dash + 1).trim()] : [spec.trim(), spec.trim()];
  const parse = (text: string) => (/^\+?\d+$/.test(text) && Number(text) <= MAX_U16 ? Number(text) : null);
  const low = parse(a);
  const high = parse(b);
  if (low === null || high === null || low > high) {
    return `Invalid port or range "${spec}" (use 443 or "8000-8080").`;
  }
  return null;
}

/** Mirrors the engine's `host_targets_listener` for IP literals and `localhost`. */
function hostTargetsListener(rawHost: string, bind: string): boolean {
  let host = stripBrackets(rawHost.trim().replace(/\.+$/, ""));
  if (asciiLower(host) === "localhost") host = "127.0.0.1";
  if (host.toLowerCase().startsWith("::ffff:") && isIpv4(host.slice(7))) host = host.slice(7);
  if (!isIpAddress(host)) return false;
  if (host === bind) return true;
  const unspecified = (ip: string) => ip === "0.0.0.0" || ip === "::";
  return unspecified(bind) && (isLoopback(host) || unspecified(host));
}

const targetNames = (target: RouteTarget): string[] => (Array.isArray(target) ? target : [target]);
const asList = <T>(value: T | T[] | undefined): T[] =>
  value === undefined ? [] : Array.isArray(value) ? value : [value];

/**
 * Field errors for a Proxy, keyed by field path (`listeners.http_port`,
 * `profiles:<index>:host`, `routing.rules:<index>:target`, `routing.http.default`, ...).
 * Mirrors `validate_proxy_with_tunnels` and the engine checks it runs on profiles, targets, and self-loops.
 */
export function proxyErrors(
  proxy: Proxy,
  knownTunnels: readonly (TunnelId | Pick<Tunnel, "id" | "port_forwards">)[],
): FieldErrors {
  const knownTunnelIds = new Set<TunnelId>();
  const tunnelsById = new Map<TunnelId, Pick<Tunnel, "id" | "port_forwards">>();
  for (const item of knownTunnels) {
    if (typeof item === "string") {
      knownTunnelIds.add(item);
    } else {
      knownTunnelIds.add(item.id);
      tunnelsById.set(item.id, item);
    }
  }
  const errors: FieldErrors = {};
  if (!proxy.name.trim()) errors.name = "Enter a proxy name.";

  const { listeners, network } = proxy;
  if (!isIpAddress(listeners.bind)) errors["listeners.bind"] = "Use an IP address, such as 127.0.0.1.";
  if (!isPort(listeners.http_port, true)) errors["listeners.http_port"] = "Use a port from 0 to 65535. 0 turns it off.";
  if (!isPort(listeners.socks_port, true)) errors["listeners.socks_port"] = "Use a port from 0 to 65535. 0 turns it off.";
  if (listeners.http_port === 0 && listeners.socks_port === 0) {
    errors["listeners.ports"] = "Set a non-zero HTTP or SOCKS port.";
  }
  if (!isWholeNumber(listeners.max_connections)) {
    errors["listeners.max_connections"] = "Use a whole number. 0 means unlimited.";
  }

  if (proxy.mitm) mitmErrors(errors, proxy.mitm);

  if (!isWholeNumber(network.connect_timeout) || network.connect_timeout === 0) {
    errors["network.connect_timeout"] = "Use a whole number of seconds greater than 0.";
  }
  keepaliveErrors(
    errors,
    {
      ip_version: "auto",
      server_alive_interval: 0,
      server_alive_count_max: 0,
      tcp_keepalive: network.tcp_keepalive,
      tcp_keepalive_interval: network.tcp_keepalive_interval,
      tcp_keepalive_retries: network.tcp_keepalive_retries,
      no_reconnect: false,
      reconnect_initial_delay: 0,
      reconnect_max_delay: 0,
      startup_timeout: 0,
    },
    "network",
  );

  if (proxy.filter !== "off") {
    const pairs: [string, readonly string[]][] =
      "allow" in proxy.filter
        ? [["allow", proxy.filter.allow]]
        : "block" in proxy.filter
          ? [["block", proxy.filter.block]]
          : [
              ["block", proxy.filter.block_except.block],
              ["allow", proxy.filter.block_except.allow],
            ];
    for (const [list, rules] of pairs) {
      rules.forEach((rule, index) => {
        const problem = filterRuleError(rule);
        if (problem) errors[`filter.${list}:${index}`] = problem;
      });
    }
  }

  loggingErrors(errors, proxy.logging);

  // Upstream profiles.
  const defined = new Set<string>(BUILTIN_PROFILES);
  const seen = new Set<string>();
  const ownListeners = [listeners.http_port, listeners.socks_port].filter((port) => port !== 0);
  proxy.profiles.forEach((profile, index) => {
    const key = (field: string) => `profiles:${index}:${field}`;
    const name = profile.name;
    defined.add(name);
    if (!name) errors[key("name")] = "Enter a profile name.";
    else if ((BUILTIN_PROFILES as readonly string[]).includes(name)) {
      errors[key("name")] = `"${name}" is a built-in profile name.`;
    } else if (name.startsWith("@")) {
      errors[key("name")] = 'Profile names cannot start with "@".';
    } else if (seen.has(name)) {
      errors[key("name")] = `Another profile is already named "${name}".`;
    }
    seen.add(name);

    const { kind } = profile;
    if (kind.type === "tunnel") {
      if (!knownTunnelIds.has(kind.tunnel_id)) errors[key("tunnel")] = "Choose a tunnel that exists.";
      return;
    }
    if (kind.type === "composite") {
      if (![kind.http, kind.https, kind.fallback].some((sub) => sub.trim())) {
        errors[key("composite")] = "Choose at least one of the HTTP, HTTPS, or fallback profiles.";
      }
      return;
    }
    const host = profile.host?.trim() ?? "";
    if (!host) errors[key("host")] = "Enter the upstream proxy's host.";
    if (profile.port === null || profile.port === 0 || !isPort(profile.port)) {
      errors[key("port")] = "Use a port from 1 to 65535.";
    } else if (host && ownListeners.includes(profile.port) && hostTargetsListener(host, listeners.bind)) {
      errors[key("port")] = `This points at the proxy's own listener ${listeners.bind}:${profile.port} (a loop).`;
    }
  });

  const singleTargetError = (name: string): string | null => {
    if (name.startsWith(TUNNEL_TARGET_PREFIX)) {
      const tid = name.slice(TUNNEL_TARGET_PREFIX.length);
      return tid && knownTunnelIds.has(tid) ? null : `Unknown tunnel "${tid}".`;
    }
    if (name.startsWith(FORWARD_TARGET_PREFIX)) {
      const rest = name.slice(FORWARD_TARGET_PREFIX.length);
      const parts = rest.split(":");
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return `Invalid tunnel forward target "${name}".`;
      }
      const [tid, fid] = parts as [string, string];
      if (!knownTunnelIds.has(tid)) return `Unknown tunnel "${tid}".`;
      const tunnel = tunnelsById.get(tid);
      if (tunnel) {
        const ok = tunnel.port_forwards.some(
          (f) => f.id === fid && f.direction === "local" && f.proxy_protocol !== "none",
        );
        if (!ok) return `Unknown or non-proxy local forward "${fid}".`;
      }
      return null;
    }
    return defined.has(name) ? null : `Unknown profile "${name}".`;
  };

  // Composite sub-profiles must exist; checked after every name is known.
  proxy.profiles.forEach((profile, index) => {
    if (profile.kind.type !== "composite") return;
    for (const field of ["http", "https", "fallback"] as const) {
      const sub = profile.kind[field].trim();
      if (sub) {
        const problem = singleTargetError(sub);
        if (problem) errors[`profiles:${index}:composite.${field}`] = problem;
      }
    }
  });

  // Routing targets and rule conditions.
  const targetError = (target: RouteTarget): string | null => {
    const names = targetNames(target);
    if (names.length === 0) return "Choose at least one profile.";
    for (const name of names) {
      const problem = singleTargetError(name);
      if (problem) return problem;
    }
    return null;
  };
  const ruleErrors = (prefix: string, rules: RoutingRule[]) => {
    rules.forEach((rule, index) => {
      const key = (field: string) => `${prefix}:${index}:${field}`;
      const problem = targetError(rule.target);
      if (problem) errors[key("target")] = problem;
      const badPort = asList(rule.port).map(portSpecError).find((e) => e !== null);
      if (badPort) errors[key("port")] = badPort;
      asList(rule.cidr).forEach((cidr) => {
        if (!cidr.includes("/") || filterRuleError(cidr) !== null) {
          errors[key("cidr")] = `Invalid CIDR "${cidr}".`;
        }
      });
      asList(rule.ip).forEach((ip) => {
        const text = stripBrackets(ip.trim());
        if (!isIpAddress(text) && !(text.includes("/") && filterRuleError(text) === null)) {
          errors[key("ip")] = `Invalid IP address "${ip}".`;
        }
      });
      const levels = rule.host_levels;
      if (levels) {
        const min = levels.min ?? 0;
        const max = levels.max ?? Number.MAX_SAFE_INTEGER;
        if (!isWholeNumber(min, MAX_U32) || !isWholeNumber(max)) {
          errors[key("host_levels")] = "Use whole numbers.";
        } else if (min > max) {
          errors[key("host_levels")] = `The minimum (${min}) is greater than the maximum (${max}).`;
        }
      }
    });
  };

  const { routing } = proxy;
  const defaultProblem = targetError(routing.default);
  if (defaultProblem) errors["routing.default"] = defaultProblem;
  ruleErrors("routing.rules", routing.rules);
  for (const inbound of ["http", "socks"] as const) {
    const table = routing[inbound];
    if (!table) continue;
    if (table.default !== undefined) {
      const problem = targetError(table.default);
      if (problem) errors[`routing.${inbound}.default`] = problem;
    }
    ruleErrors(`routing.${inbound}.rules`, table.rules);
  }
  return errors;
}
