// Port forwards (`ssh -L` / `ssh -R`): formatting, presets, and reading `ssh` flags.

import type { ForwardDirection, PortForward } from "./types";
import { isIpAddress } from "./validate.ts";

export const FLAG: Record<ForwardDirection, string> = { local: "-L", remote: "-R" };

const unbracket = (host: string): string =>
  host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

/** `host:port`, with an IPv6 address in brackets, as `ssh` and URLs write it. */
export function hostPort(host: string, port: number): string {
  const bare = unbracket(host.trim());
  return bare.includes(":") ? `[${bare}]:${port}` : `${bare}:${port}`;
}

/** The `ssh` argument value, such as `127.0.0.1:8080:db.internal:5432`. */
export function forwardSpec(forward: PortForward): string {
  return `${hostPort(forward.bind, forward.port)}:${hostPort(forward.dest_host, forward.dest_port)}`;
}

/** The whole `ssh` flag, such as `-L 127.0.0.1:8080:db.internal:5432`. */
export function forwardFlag(forward: PortForward): string {
  return `${FLAG[forward.direction]} ${forwardSpec(forward)}`;
}

export function newForward(direction: ForwardDirection, patch: Partial<PortForward> = {}): PortForward {
  return {
    id: crypto.randomUUID(),
    enabled: true,
    direction,
    name: "",
    bind: "127.0.0.1",
    port: Number.NaN,
    dest_host: direction === "local" ? "" : "localhost",
    dest_port: Number.NaN,
    ...patch,
  };
}

export interface ForwardPreset {
  label: string;
  direction: ForwardDirection;
  name: string;
  /** Local listen port. A high port, so no elevated rights are needed. */
  port: number;
  dest_host: string;
  dest_port: number;
}

export const PRESETS: readonly ForwardPreset[] = [
  { label: "PostgreSQL", direction: "local", name: "PostgreSQL", port: 15432, dest_host: "", dest_port: 5432 },
  { label: "MySQL", direction: "local", name: "MySQL", port: 13306, dest_host: "", dest_port: 3306 },
  { label: "Redis", direction: "local", name: "Redis", port: 16379, dest_host: "", dest_port: 6379 },
  { label: "Remote Desktop", direction: "local", name: "Remote Desktop", port: 13389, dest_host: "", dest_port: 3389 },
  { label: "Web UI (HTTPS)", direction: "local", name: "Web UI", port: 18443, dest_host: "", dest_port: 443 },
  {
    label: "Share a local dev server",
    direction: "remote",
    name: "Dev server",
    port: 8000,
    dest_host: "localhost",
    dest_port: 3000,
  },
];

/** Splits `ssh` forward syntax on `:`, keeping `[IPv6]` parts whole. */
function splitSpec(spec: string): string[] | null {
  const parts: string[] = [];
  let rest = spec;
  while (rest.length > 0) {
    if (rest.startsWith("[")) {
      const end = rest.indexOf("]");
      if (end < 0) return null;
      parts.push(rest.slice(1, end));
      rest = rest.slice(end + 1);
      if (rest.length > 0 && !rest.startsWith(":")) return null;
      rest = rest.slice(1);
    } else {
      const colon = rest.indexOf(":");
      parts.push(colon < 0 ? rest : rest.slice(0, colon));
      rest = colon < 0 ? "" : rest.slice(colon + 1);
    }
  }
  return parts;
}

const parsePort = (text: string): number | null =>
  /^\d{1,5}$/.test(text) && Number(text) >= 1 && Number(text) <= 65535 ? Number(text) : null;

/** `ssh` reads these bind addresses as names, and they mean the same as an IP here. */
function bindAddress(text: string): string | null {
  if (text === "" || text === "*") return "0.0.0.0";
  if (text === "localhost") return "127.0.0.1";
  return isIpAddress(text) ? text : null;
}

/** Reads one `-L` / `-R` value, or explains why it cannot be used. */
export function parseForwardSpec(
  direction: ForwardDirection,
  spec: string,
): { forward: PortForward } | { error: string } {
  const flag = FLAG[direction];
  if (spec.includes("/")) return { error: `${flag} ${spec}: Unix socket forwards are not supported.` };
  const parts = splitSpec(spec.trim());
  if (!parts || (parts.length !== 3 && parts.length !== 4)) {
    if (direction === "remote" && parts?.length === 2) {
      return { error: `${flag} ${spec}: a remote SOCKS proxy is set up in the Proxy tab.` };
    }
    return { error: `${flag} ${spec}: expected [bind:]port:host:hostport.` };
  }
  const [bindText, portText, host, destText] = parts.length === 4 ? parts : ["localhost", ...parts];
  const bind = bindAddress(bindText ?? "");
  const port = parsePort(portText ?? "");
  const destPort = parsePort(destText ?? "");
  if (bind === null) return { error: `${flag} ${spec}: the bind address must be an IP address.` };
  if (port === null) return { error: `${flag} ${spec}: the listen port must be 1 to 65535.` };
  if (destPort === null) return { error: `${flag} ${spec}: the destination port must be 1 to 65535.` };
  if (!host) return { error: `${flag} ${spec}: the destination host is missing.` };
  return { forward: newForward(direction, { bind, port, dest_host: host, dest_port: destPort }) };
}

/** Splits pasted text into arguments on whitespace. */
const words = (text: string): string[] => text.split(/\s+/).filter((w) => w.length > 0);

export interface FlagMatch {
  /** Indices of the arguments this flag used: the flag, and its value when separate. */
  indices: number[];
  result: ReturnType<typeof parseForwardSpec>;
}

/** Finds every `-L` / `-R` flag in a list of arguments, as `-L spec` or `-Lspec`. */
export function findForwardFlags(args: readonly string[]): FlagMatch[] {
  const found: FlagMatch[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    const match = /^-([LR])(.*)$/.exec(arg);
    if (!match) continue;
    const direction: ForwardDirection = match[1] === "L" ? "local" : "remote";
    if (match[2]) {
      found.push({ indices: [index], result: parseForwardSpec(direction, match[2]) });
    } else if (index + 1 < args.length) {
      found.push({ indices: [index, index + 1], result: parseForwardSpec(direction, args[index + 1]!) });
      index += 1;
    }
  }
  return found;
}

/**
 * Reads pasted `ssh` flags, such as `-L 8080:db:5432 -R 9000:localhost:3000`. Other text is
 * ignored, so a whole `ssh` command line can be pasted.
 */
export function parseForwardFlags(text: string): { forwards: PortForward[]; errors: string[] } {
  const forwards: PortForward[] = [];
  const errors: string[] = [];
  for (const { result } of findForwardFlags(words(text))) {
    if ("forward" in result) forwards.push(result.forward);
    else errors.push(result.error);
  }
  return { forwards, errors };
}
