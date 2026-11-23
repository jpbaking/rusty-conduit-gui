// Pure display helpers shared by the shell components.

import type { SessionState } from "./types";

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
