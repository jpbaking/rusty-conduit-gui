// Client-side checks that mirror the backend's rules, so problems show next to the field.

import type { HostProfile, LoggingConfig, MitmConfig, SessionProfile, TunnelConfig } from "./types";

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
  if (allow.length > 0 && block.length > 0) {
    errors[`filters.${scope}.conflict`] = "Use an allowlist or a blocklist, not both.";
  }
  for (const [list, rules] of [["allow", allow], ["block", block]] as const) {
    rules.forEach((rule, index) => {
      const problem = filterRuleError(rule);
      if (problem) errors[`filters.${scope}.${list}:${index}`] = problem;
    });
  }
}

function mitmErrors(errors: FieldErrors, mitm: MitmConfig): void {
  if ("Pem" in mitm.ca_mode) {
    if (!mitm.ca_mode.Pem.cert.trim()) errors["mitm.cert"] = "Enter the CA certificate path.";
    if (!mitm.ca_mode.Pem.key.trim()) errors["mitm.key"] = "Enter the CA private key path.";
  } else if (!mitm.ca_mode.Pkcs12.path.trim()) {
    errors["mitm.path"] = "Enter the PKCS#12 bundle path.";
  }
  if (mitm.passphrase !== null && mitm.ca_passphrase_file !== null) {
    errors["mitm.passphrase"] = "Use a saved passphrase or a passphrase file, not both.";
  }
  if (!isWholeNumber(mitm.cert_ttl) || mitm.cert_ttl < MIN_CERT_TTL_SECS) {
    errors["mitm.cert_ttl"] = `Use a whole number of at least ${MIN_CERT_TTL_SECS} seconds.`;
  }
  if (!isWholeNumber(mitm.cert_cache_max_entries)) {
    errors["mitm.cert_cache_max_entries"] = "Use a whole number. 0 means unlimited.";
  }
}

function tunnelErrors(errors: FieldErrors, tunnel: TunnelConfig): void {
  if (!["4", "6", "auto"].includes(tunnel.ip_version.trim().toLowerCase())) {
    errors["tunnel.ip_version"] = "Choose IPv4, IPv6, or Auto.";
  }
  const seconds = {
    "tunnel.server_alive_interval": tunnel.server_alive_interval,
    "tunnel.reconnect_initial_delay": tunnel.reconnect_initial_delay,
    "tunnel.reconnect_max_delay": tunnel.reconnect_max_delay,
    "tunnel.startup_timeout": tunnel.startup_timeout,
  };
  for (const [field, value] of Object.entries(seconds)) {
    if (!isWholeNumber(value)) errors[field] = "Use a whole number of seconds.";
  }
  if (!isWholeNumber(tunnel.server_alive_count_max, MAX_U32)) {
    errors["tunnel.server_alive_count_max"] = `Use a whole number up to ${MAX_U32}.`;
  }
  if (!isWholeNumber(tunnel.tcp_keepalive, MAX_TCP_KEEPALIVE_SECS)) {
    errors["tunnel.tcp_keepalive"] = `Use 0 (off) or a whole number from 1 to ${MAX_TCP_KEEPALIVE_SECS}.`;
  }
  // Interval and probe count only matter while TCP keepalive is on, as in the engine.
  if (tunnel.tcp_keepalive !== 0) {
    const interval = tunnel.tcp_keepalive_interval;
    if (!isWholeNumber(interval, MAX_TCP_KEEPALIVE_SECS) || interval < 1) {
      errors["tunnel.tcp_keepalive_interval"] = `Use a whole number from 1 to ${MAX_TCP_KEEPALIVE_SECS}.`;
    }
    const retries = tunnel.tcp_keepalive_retries;
    if (!isWholeNumber(retries, MAX_TCP_KEEPALIVE_RETRIES) || retries < 1) {
      errors["tunnel.tcp_keepalive_retries"] = `Use a whole number from 1 to ${MAX_TCP_KEEPALIVE_RETRIES}.`;
    }
  }
  if (
    !errors["tunnel.reconnect_initial_delay"] &&
    !errors["tunnel.reconnect_max_delay"] &&
    tunnel.reconnect_initial_delay > tunnel.reconnect_max_delay
  ) {
    errors["tunnel.reconnect_initial_delay"] = "The initial delay cannot exceed the maximum delay.";
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

function opensshErrors(errors: FieldErrors, profile: SessionProfile): void {
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
  if (!forward.enabled && !reverse.enabled) {
    errors.listeners = "Turn on the forward or reverse proxy.";
  }

  filterErrors(errors, "forward", forward.allow, forward.block);
  filterErrors(errors, "reverse", reverse.reverse_allow, reverse.reverse_block);
  if (profile.mitm) mitmErrors(errors, profile.mitm);
  tunnelErrors(errors, profile.tunnel);
  loggingErrors(errors, profile.logging);
  opensshErrors(errors, profile);
  return errors;
}
