// Port forwards (`ssh -L` / `ssh -R`): formatting, presets, and reading `ssh` flags.

import type { ForwardDirection, ForwardPreset, PortForward } from "./types";
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

const NIL = "00000000-0000-0000-0000-000000000000";
const LOOPBACK = "127.0.0.1";

/** A new forward with a preset's values. The preset is copied, not linked. */
export function forwardFromPreset(preset: ForwardPreset): PortForward {
  return newForward(preset.direction, {
    name: preset.name,
    bind: preset.bind ?? LOOPBACK,
    port: preset.port,
    dest_host: preset.dest_host,
    dest_port: preset.dest_port,
  });
}

/** A new preset from a forward. The backend gives it an id. */
export function presetFromForward(forward: PortForward): ForwardPreset {
  const name = forward.name.trim() || `${forward.direction === "local" ? "Local" : "Remote"} ${forward.port}`;
  return {
    id: NIL,
    name,
    direction: forward.direction,
    bind: forward.bind === LOOPBACK ? null : forward.bind,
    port: forward.port,
    dest_host: forward.dest_host.trim(),
    dest_port: forward.dest_port,
  };
}

export function blankPreset(direction: ForwardDirection = "local"): ForwardPreset {
  return {
    id: NIL,
    name: "",
    direction,
    bind: null,
    port: Number.NaN,
    dest_host: direction === "remote" ? "localhost" : "",
    dest_port: Number.NaN,
  };
}

/** A short description, such as `-L 15432 → db:5432`, with `…` for a host chosen per session. */
export function presetSummary(preset: ForwardPreset): string {
  const listen = preset.bind ? hostPort(preset.bind, preset.port) : String(preset.port);
  const host = preset.dest_host.trim() || "…";
  return `${FLAG[preset.direction]} ${listen} → ${host === "…" ? `…:${preset.dest_port}` : hostPort(host, preset.dest_port)}`;
}

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
