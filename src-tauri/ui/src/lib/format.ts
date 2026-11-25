// Pure display helpers shared by the shell components.

import type { ListenerInfo, OpenSshBinaryInfo, SessionState } from "./types";

export type StatusTone = "ok" | "busy" | "alert" | "idle";

export interface StatusDisplay {
  glyph: "●" | "◐" | "!" | "○";
  label: string;
  tone: StatusTone;
}

export function statusOf(state: SessionState): StatusDisplay {
  switch (state.state) {
    case "connected":
      return { glyph: "●", label: "Connected", tone: "ok" };
    case "starting":
      return { glyph: "◐", label: "Starting", tone: "busy" };
    case "reconnecting":
      return { glyph: "◐", label: `Reconnecting (try ${state.attempt})`, tone: "busy" };
    case "waiting_for_network":
      return { glyph: "◐", label: "Waiting for network", tone: "busy" };
    case "locked":
      return { glyph: "!", label: "Vault locked", tone: "alert" };
    case "awaiting_host_key":
      return { glyph: "!", label: "Host key needs approval", tone: "alert" };
    case "needs_attention":
      return { glyph: "!", label: "Needs attention", tone: "alert" };
    case "failed":
      return { glyph: "!", label: "Failed", tone: "alert" };
    case "stopped":
      return { glyph: "○", label: "Stopped", tone: "idle" };
  }
}

/** True while a supervisor is running, so the session can be stopped. */
export function isActive(state: SessionState): boolean {
  return !["stopped", "locked", "needs_attention", "failed"].includes(state.state);
}

export interface ProxyUrl {
  label: "HTTP" | "SOCKS";
  url: string;
}

// A wildcard bind address is not something a client can connect to.
function clientAddr(addr: string): string {
  if (addr.startsWith("0.0.0.0:")) return `127.0.0.1:${addr.slice("0.0.0.0:".length)}`;
  if (addr.startsWith("[::]:")) return `[::1]:${addr.slice("[::]:".length)}`;
  return addr;
}

/** Proxy URLs a client can use for a listener, matching the tray. SOCKS is `socks5h://` so DNS stays remote. */
export function proxyUrls(listener: ListenerInfo): ProxyUrl[] {
  const addr = clientAddr(listener.addr);
  const role = listener.role.toLowerCase();
  const urls: ProxyUrl[] = [];
  if (role.includes("http")) urls.push({ label: "HTTP", url: `http://${addr}` });
  if (role.includes("socks")) urls.push({ label: "SOCKS", url: `socks5h://${addr}` });
  return urls;
}

export function stateReason(state: SessionState): string | null {
  return state.state === "needs_attention" || state.state === "failed" ? state.reason : null;
}

export function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}

export function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function formatTime(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleTimeString([], { hour12: false });
}

export function formatDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleDateString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export type LogLevel = "error" | "warn" | "info" | "debug";
export type LogFilter = "all" | LogLevel;

const LEVEL_RANK: Record<LogLevel, number> = { error: 0, warn: 1, info: 2, debug: 3 };
const LEVEL_RE = /\b(ERROR|FATAL|WARN(?:ING)?|INFO|DEBUG|TRACE|VERBOSE)\b|"level"\s*:\s*"(\w+)"/;

/** Log lines have no level field, so it is read from the text. Unmarked lines count as info. */
export function logLevel(text: string): LogLevel {
  const match = LEVEL_RE.exec(text);
  const word = (match?.[1] ?? match?.[2] ?? "").toUpperCase();
  if (word === "ERROR" || word === "FATAL") return "error";
  if (word.startsWith("WARN")) return "warn";
  if (word === "DEBUG" || word === "TRACE" || word === "VERBOSE") return "debug";
  return "info";
}

export function passesLevel(level: LogLevel, filter: LogFilter): boolean {
  return filter === "all" || LEVEL_RANK[level] <= LEVEL_RANK[filter];
}

export interface CheckStatus {
  tone: "ok" | "busy" | "alert";
  label: string;
}

/** How an `ssh` program check reads at a glance. A supported version with a limit is amber. */
export function checkStatus(info: OpenSshBinaryInfo): CheckStatus {
  if (info.supported) return { tone: info.note ? "busy" : "ok", label: "Supported" };
  if (info.major !== null) return { tone: "busy", label: "Version too old" };
  if (info.resolved_path !== null) return { tone: "alert", label: "Not usable" };
  return { tone: "alert", label: "Not found" };
}

/** CAs that expire within this many days are flagged. */
export const CA_EXPIRY_WARNING_DAYS = 30;

export interface CaExpiry {
  tone: StatusTone;
  label: string;
}

/** How soon a CA expires, as of `nowSeconds`. Sessions using an expired CA will not start. */
export function caExpiry(notAfter: number, nowSeconds = Date.now() / 1000): CaExpiry {
  const days = Math.floor((notAfter - nowSeconds) / 86_400);
  if (notAfter <= nowSeconds) return { tone: "alert", label: "Expired" };
  if (days < 1) return { tone: "busy", label: "Expires today" };
  if (days <= CA_EXPIRY_WARNING_DAYS) {
    return { tone: "busy", label: `Expires in ${days} ${days === 1 ? "day" : "days"}` };
  }
  return { tone: "ok", label: `Expires ${formatDate(notAfter)}` };
}
