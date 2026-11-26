// Typed client for every `src-tauri` command and event. Secret arguments are write-only: they
// are passed straight to Rust, never stored here, and never included in an error.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AccessRecordView,
  AppErrorCode,
  AutostartStatus,
  ChainTestResult,
  ClipboardFallbackPayload,
  CloseChoice,
  DeleteResult,
  ExportSummary,
  FilterMode,
  FilterTestResult,
  GenerateAlgorithm,
  HostKeyEntry,
  ForwardPreset,
  HostProfile,
  ImportSummary,
  KeyId,
  KeySource,
  KeyView,
  LogLine,
  CaView,
  MitmCaId,
  MitmCaUpload,
  VaultCaMeta,
  OpenSshBinaryInfo,
  PortConflictReport,
  RuntimeEvent,
  SecretMeta,
  SecretRef,
  SessionProfile,
  SessionView,
  ShellEventHandlers,
  ShellSnapshot,
  StateSummary,
  TrayStatusPayload,
  Uuid,
  VaultKeyMeta,
  VaultStatus,
  ViewLogsPayload,
  Proxy,
  ProxyEvent,
  ProxyId,
  ProxySaveResult,
  ProxySnapshot,
  ProxyView,
  RouteInbound,
  RouteTestResult,
  Tunnel,
  TunnelChainTestResult,
  TunnelEvent,
  TunnelId,
  TunnelView,
  UpstreamProbeResult,
  UpstreamProfile,
  V2EventHandlers,
} from "./types";

/** A failed command. `no_backend` means the page is running outside the desktop app. */
export class ApiError extends Error {
  readonly code: AppErrorCode | "no_backend" | "unknown";

  constructor(code: ApiError["code"], message: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
  }
}

function toApiError(raw: unknown): ApiError {
  if (raw instanceof ApiError) return raw;
  if (typeof raw === "object" && raw !== null && "code" in raw && "message" in raw) {
    const { code, message } = raw as { code: unknown; message: unknown };
    if (typeof code === "string" && typeof message === "string") {
      return new ApiError(code as AppErrorCode, message);
    }
  }
  return new ApiError("unknown", typeof raw === "string" ? raw : "The command failed.");
}

export function errorMessage(error: unknown): string {
  return toApiError(error).message;
}

/** True inside the Tauri webview. */
export const hasBackend = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    if (hasBackend()) return await invoke<T>(command, args);
    // The preview data is compiled out of production bundles.
    if (import.meta.env.DEV) {
      const { mockInvoke } = await import("./mock");
      return mockInvoke<T>(command, args);
    }
    throw new ApiError("no_backend", "This page must run inside the desktop app.");
  } catch (error) {
    throw toApiError(error);
  }
}

export const api = {
  // Vault lifecycle.
  vaultStatus: () => call<VaultStatus>("vault_status"),
  createVault: (password: string, useKeyring: boolean) =>
    call<VaultStatus>("create_vault", { password, useKeyring }),
  unlockVault: (password: string) => call<VaultStatus>("unlock_vault", { password }),
  unlockVaultKeyring: () => call<VaultStatus>("unlock_vault_keyring"),
  setVaultKeyring: (enabled: boolean) => call<VaultStatus>("set_vault_keyring", { enabled }),
  /** Checks `current` against the vault file, so the vault need not be unlocked. */
  changeMasterPassword: (current: string, next: string) =>
    call<VaultStatus>("change_master_password", { current, new: next }),

  // Keys and write-only secrets.
  importKeyPem: (name: string, pem: string, passphrase: string | null, source: KeySource) =>
    call<VaultKeyMeta>("import_key_pem", { name, pem, passphrase, source }),
  generateKey: (name: string, algorithm?: GenerateAlgorithm) =>
    call<VaultKeyMeta>("generate_key", { name, algorithm: algorithm ?? null }),
  renameKey: (id: KeyId, name: string) => call<VaultKeyMeta>("rename_key", { id, name }),
  deleteKey: (id: KeyId, force = false) => call<DeleteResult>("delete_key", { id, force }),
  listKeys: () => call<KeyView[]>("list_keys"),
  setPasswordSecret: (password: string, existing: SecretRef | null = null) =>
    call<SecretMeta>("set_password_secret", { existing, password }),
  deleteSecret: (secret: SecretRef, force = false) =>
    call<DeleteResult>("delete_secret", { secret, force }),

  // MITM CAs.
  importMitmCa: (name: string, upload: MitmCaUpload, passphrase: string | null) =>
    call<VaultCaMeta>("import_mitm_ca", { name, upload, passphrase }),
  renameMitmCa: (id: MitmCaId, name: string) => call<VaultCaMeta>("rename_mitm_ca", { id, name }),
  deleteMitmCa: (id: MitmCaId, force = false) => call<DeleteResult>("delete_mitm_ca", { id, force }),
  listMitmCas: () => call<CaView[]>("list_mitm_cas"),

  // Sessions and hosts.
  getStateSummary: () => call<StateSummary>("get_state_summary"),
  listSessions: () => call<SessionView[]>("list_sessions"),
  upsertSession: (profile: SessionProfile) => call<SessionProfile>("upsert_session", { profile }),
  deleteSession: (id: Uuid) => call<void>("delete_session", { id }),
  duplicateSession: (id: Uuid) => call<SessionProfile>("duplicate_session", { id }),
  listHosts: () => call<HostProfile[]>("list_hosts"),
  upsertHost: (host: HostProfile) => call<HostProfile>("upsert_host", { host }),
  deleteHost: (id: Uuid) => call<void>("delete_host", { id }),
  listForwardPresets: () => call<ForwardPreset[]>("list_forward_presets"),
  upsertForwardPreset: (preset: ForwardPreset) =>
    call<ForwardPreset>("upsert_forward_preset", { preset }),
  deleteForwardPreset: (id: Uuid) => call<void>("delete_forward_preset", { id }),
  restoreForwardPresets: () => call<ForwardPreset[]>("restore_forward_presets"),
  promoteHopToHost: (sessionId: Uuid, hopId: string, name: string | null = null) =>
    call<HostProfile>("promote_hop_to_host", { sessionId, hopId, name }),

  // Runtime.
  startSession: (id: Uuid) => call<void>("start_session", { id }),
  stopSession: (id: Uuid) => call<void>("stop_session", { id }),
  restartSession: (id: Uuid) => call<void>("restart_session", { id }),
  startAll: () => call<void>("start_all"),
  stopAll: () => call<void>("stop_all"),
  getSessionLogs: (id: Uuid, limit: number | null = null) =>
    call<LogLine[]>("get_session_logs", { id, limit }),
  clearSessionLogs: (id: Uuid) => call<void>("clear_session_logs", { id }),

  // Host keys and diagnostics.
  approveHostKey: (id: Uuid, sha256: string) => call<void>("approve_host_key", { id, sha256 }),
  rejectHostKey: (id: Uuid) => call<void>("reject_host_key", { id }),
  trustTestedHostKey: (id: Uuid, sha256: string) =>
    call<HostKeyEntry>("trust_tested_host_key", { id, sha256 }),
  listHostKeyPins: () => call<HostKeyEntry[]>("list_host_key_pins"),
  resetHostKey: (hopId: string, host: string, port: number) =>
    call<boolean>("reset_host_key", { hopId, host, port }),
  /** Pins a hop's key from a `known_hosts` file at `path`, which the user must type. */
  importKnownHost: (hopId: string, host: string, port: number, path: string) =>
    call<HostKeyEntry>("import_known_host", { hopId, host, port, path }),
  testChain: (id: Uuid) => call<ChainTestResult>("test_chain", { id }),

  // Session-editor helpers.
  checkPortConflicts: (sessionId: Uuid | null, bind: string, httpPort: number, socksPort: number) =>
    call<PortConflictReport>("check_port_conflicts", { sessionId, bind, httpPort, socksPort }),
  testFilterRules: (mode: FilterMode, rules: string[], target: string) =>
    call<FilterTestResult>("test_filter_rules", { mode, rules, target }),
  checkOpensshBinary: (sshBin?: string) =>
    call<OpenSshBinaryInfo>("check_openssh_binary", { sshBin: sshBin ?? null }),

  // Config export and import.
  exportConfig: (path: string, includeSecrets = false, passphrase: string | null = null) =>
    call<ExportSummary>("export_config", { path, includeSecrets, passphrase }),
  importConfig: (path: string, passphrase: string | null = null, replaceExisting = false) =>
    call<ImportSummary>("import_config", { path, passphrase, replaceExisting }),

  // Proxies (v2).
  listProxies: () => call<ProxyView[]>("list_proxies"),
  upsertProxy: (profile: Proxy) => call<ProxySaveResult>("upsert_proxy", { profile }),
  deleteProxy: (id: ProxyId) => call<void>("delete_proxy", { id }),
  duplicateProxy: (id: ProxyId) => call<ProxySaveResult>("duplicate_proxy", { id }),
  startProxy: (id: ProxyId) => call<void>("start_proxy", { id }),
  stopProxy: (id: ProxyId) => call<void>("stop_proxy", { id }),
  restartProxy: (id: ProxyId) => call<void>("restart_proxy", { id }),
  /** A profile name (`direct` included), or `null` for Auto Switch. */
  setProxyOverride: (id: ProxyId, overrideProfile: string | null) =>
    call<ProxySnapshot>("set_proxy_override", { id, overrideProfile }),
  getProxyLogs: (id: ProxyId, limit: number | null = null) =>
    call<LogLine[]>("get_proxy_logs", { id, limit }),
  clearProxyLogs: (id: ProxyId) => call<void>("clear_proxy_logs", { id }),
  getProxyAccessRecords: (id: ProxyId, limit: number | null = null) =>
    call<AccessRecordView[]>("get_proxy_access_records", { id, limit }),
  /** Route Tester: evaluates `rawTarget` against the draft `proxy`. Needs no vault. */
  testRoute: (proxy: Proxy, rawTarget: string, inbound: RouteInbound) =>
    call<RouteTestResult>("test_route", { proxy, rawTarget, inbound }),
  /** Test Upstream: dials `host:port` through one of the draft `proxy`'s profiles. */
  testUpstream: (proxy: Proxy, profileName: string, host: string, port: number, timeoutMs: number) =>
    call<UpstreamProbeResult>("test_upstream", { proxy, profileName, host, port, timeoutMs }),
  checkProxyPortConflicts: (
    proxyId: ProxyId | null,
    bind: string,
    httpPort: number,
    socksPort: number,
  ) => call<PortConflictReport>("check_proxy_port_conflicts", { proxyId, bind, httpPort, socksPort }),

  // Profile Library (v2).
  listProfileLibrary: () => call<UpstreamProfile[]>("list_profile_library"),
  upsertLibraryProfile: (profile: UpstreamProfile) =>
    call<UpstreamProfile>("upsert_library_profile", { profile }),
  deleteLibraryProfile: (name: string) => call<void>("delete_library_profile", { name }),
  /** Stores an upstream proxy password, or rotates `existing` to a new record. */
  setUpstreamPassword: (value: string, existing: SecretRef | null = null) =>
    call<SecretMeta>("set_upstream_password", { existing, value }),

  // Tunnels (v2).
  listTunnels: () => call<TunnelView[]>("list_tunnels"),
  upsertTunnel: (profile: Tunnel) => call<Tunnel>("upsert_tunnel", { profile }),
  /** Refuses without `force` while Proxies route through the Tunnel, listing them. */
  deleteTunnel: (id: TunnelId, force = false) => call<DeleteResult>("delete_tunnel", { id, force }),
  duplicateTunnel: (id: TunnelId) => call<Tunnel>("duplicate_tunnel", { id }),
  startTunnel: (id: TunnelId) => call<void>("start_tunnel", { id }),
  stopTunnel: (id: TunnelId) => call<void>("stop_tunnel", { id }),
  restartTunnel: (id: TunnelId) => call<void>("restart_tunnel", { id }),
  getTunnelLogs: (id: TunnelId, limit: number | null = null) =>
    call<LogLine[]>("get_tunnel_logs", { id, limit }),
  clearTunnelLogs: (id: TunnelId) => call<void>("clear_tunnel_logs", { id }),
  approveTunnelHostKey: (id: TunnelId, sha256: string) =>
    call<void>("approve_tunnel_host_key", { id, sha256 }),
  rejectTunnelHostKey: (id: TunnelId) => call<void>("reject_tunnel_host_key", { id }),
  /** An unknown key it stops at can be pinned with `trustTestedHostKey` and the Tunnel's id. */
  testTunnelChain: (id: TunnelId) => call<TunnelChainTestResult>("test_tunnel_chain", { id }),
  startAllV2: () => call<void>("start_all_v2"),
  stopAllV2: () => call<void>("stop_all_v2"),

  // Desktop shell.
  getAutostart: () => call<AutostartStatus>("get_autostart"),
  setAutostart: (enabled: boolean) => call<AutostartStatus>("set_autostart", { enabled }),
  shellReady: () => call<ShellSnapshot>("shell_ready"),
  resolveClose: (choice: CloseChoice) => call<void>("resolve_close", { choice }),
};

/**
 * Attaches every shell listener and resolves once all are live, so the caller can then safely
 * call `shellReady`. If any listener fails, the ones already attached are removed.
 */
export async function subscribeShellEvents(handlers: ShellEventHandlers): Promise<UnlistenFn> {
  if (!hasBackend()) return () => {};

  const results = await Promise.allSettled([
    listen<TrayStatusPayload>("tray-status", (e) => handlers.onTrayStatus(e.payload)),
    listen<RuntimeEvent>("runtime-event", (e) => handlers.onRuntimeEvent(e.payload)),
    listen<null>("runtime-lagged", () => handlers.onRuntimeLagged()),
    listen<ClipboardFallbackPayload>("clipboard-fallback", (e) =>
      handlers.onUiEvent({ event: "clipboard-fallback", payload: e.payload }),
    ),
    listen<ViewLogsPayload>("view-logs", (e) =>
      handlers.onUiEvent({ event: "view-logs", payload: e.payload }),
    ),
    listen<null>("unlock-vault", () => handlers.onUiEvent({ event: "unlock-vault" })),
    listen<null>("close-confirm", () => handlers.onUiEvent({ event: "close-confirm" })),
    listen<null>("quit-confirm", () => handlers.onUiEvent({ event: "quit-confirm" })),
    listen<{ message: string; is_warning: boolean }>("migration-notice", (e) =>
      handlers.onUiEvent({ event: "migration-notice", payload: e.payload }),
    ),
  ]);

  const attached: UnlistenFn[] = [];
  let failure: unknown;
  for (const result of results) {
    if (result.status === "fulfilled") attached.push(result.value);
    else failure ??= result.reason;
  }
  const unlistenAll = () => attached.forEach((unlisten) => unlisten());
  if (failure !== undefined) {
    unlistenAll();
    throw toApiError(failure);
  }
  return unlistenAll;
}

/** Attaches the v2 Proxy and Tunnel event listeners, with the same contract as above. */
export async function subscribeV2Events(handlers: V2EventHandlers): Promise<UnlistenFn> {
  if (!hasBackend()) return () => {};

  const onProxy = (e: { payload: ProxyEvent }) => handlers.onProxyEvent(e.payload);
  const results = await Promise.allSettled([
    listen<ProxyEvent>("proxy-state-changed", onProxy),
    listen<ProxyEvent>("proxy-reloaded", onProxy),
    listen<ProxyEvent>("proxy-override-changed", onProxy),
    listen<TunnelEvent>("tunnel-state-changed", (e) => handlers.onTunnelEvent(e.payload)),
  ]);

  const attached: UnlistenFn[] = [];
  let failure: unknown;
  for (const result of results) {
    if (result.status === "fulfilled") attached.push(result.value);
    else failure ??= result.reason;
  }
  const unlistenAll = () => attached.forEach((unlisten) => unlisten());
  if (failure !== undefined) {
    unlistenAll();
    throw toApiError(failure);
  }
  return unlistenAll;
}
