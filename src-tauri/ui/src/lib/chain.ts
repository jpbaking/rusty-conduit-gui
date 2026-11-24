// Pure helpers for editing a session's hop chain.

import type { AuthMethod, HopEntry, HopTestResult, HostProfile, SessionProfile, Uuid } from "./types";

export const NIL_UUID: Uuid = "00000000-0000-0000-0000-000000000000";

export function blankHost(): HostProfile {
  return { id: NIL_UUID, name: "", host: "", port: 22, user: "", auth: [], host_key_pin: null };
}

/** `hop_id` keys the host-key pin, so each hop gets its own and keeps it when moved. */
export function newHop(): HopEntry {
  return {
    hop_id: crypto.randomUUID(),
    name: "",
    host: blankHost(),
    agent_forward: false,
    agent_forward_keys: [],
    agent_forward_command: null,
  };
}

export function moved<T>(items: readonly T[], from: number, to: number): T[] {
  const next = [...items];
  next.splice(to, 0, ...next.splice(from, 1));
  return next;
}

export function hopRole(index: number, count: number): string {
  return index === count - 1 ? "Target" : `Jump ${index + 1}`;
}

export function hopTitle(hop: HopEntry): string {
  return hop.name.trim() || hop.host.host.trim() || "New hop";
}

export interface HopBadge {
  glyph: "✓" | "!" | "–";
  label: string;
  tone: "ok" | "alert" | "idle";
}

export function hopBadge(result: HopTestResult): HopBadge {
  switch (result.status) {
    case "connected":
      return { glyph: "✓", label: `Connected in ${result.elapsed_ms} ms`, tone: "ok" };
    case "failed":
      return { glyph: "!", label: result.error ?? "Failed", tone: "alert" };
    case "host_key_unknown":
      return { glyph: "!", label: "Host key not trusted yet", tone: "alert" };
    case "not_attempted":
      return { glyph: "–", label: "Not attempted", tone: "idle" };
  }
}

export function authRefs(auth: readonly AuthMethod[]): string[] {
  return auth.flatMap((method) =>
    typeof method === "object" && "Password" in method ? [method.Password.secret] : [],
  );
}

export const profileRefs = (profile: SessionProfile): string[] => [
  ...profile.hops.flatMap((hop) => authRefs(hop.host.auth)),
  ...(profile.mitm?.passphrase ? [profile.mitm.passphrase] : []),
];
