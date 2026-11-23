// Client-side checks that mirror the backend's rules, so problems show next to the field.

import type { HostProfile, SessionProfile } from "./types";

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
  if (Object.values(ports).every((port) => port === 0)) {
    errors.listeners = "Enable at least one forward or reverse port.";
  }
  return errors;
}
