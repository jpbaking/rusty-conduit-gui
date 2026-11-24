// Typed client for every `src-tauri` command and event. Secret arguments are write-only: they
// are passed straight to Rust, never stored here, and never included in an error.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppErrorCode,
  AutostartStatus,
  BackupSummary,
  ChainTestResult,
  ClipboardFallbackPayload,
  CloseChoice,
  DeleteResult,
  ExportSummary,
  FilterMode,
  FilterTestResult,
  GenerateAlgorithm,
  HostKeyEntry,
  HostProfile,
  ImportBackupResult,
  ImportSummary,
  KeyId,
  KeySource,
  KeyView,
  LogLine,
  MitmCaInfo,
  MitmCaMode,
  MitmPassphraseSource,
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
  lockVault: () => call<VaultStatus>("lock_vault"),

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
  setMitmPassphrase: (sessionId: Uuid, passphrase: string) =>
    call<SecretMeta>("set_mitm_passphrase", { sessionId, passphrase }),
  deleteSecret: (secret: SecretRef, force = false) =>
    call<DeleteResult>("delete_secret", { secret, force }),
  exportBackup: (path: string, passphrase: string) =>
    call<BackupSummary>("export_backup", { path, passphrase }),
  importBackup: (path: string, passphrase: string) =>
    call<ImportBackupResult>("import_backup", { path, passphrase }),

  // Sessions and hosts.
  getStateSummary: () => call<StateSummary>("get_state_summary"),
  listSessions: () => call<SessionView[]>("list_sessions"),
  upsertSession: (profile: SessionProfile) => call<SessionProfile>("upsert_session", { profile }),
  deleteSession: (id: Uuid) => call<void>("delete_session", { id }),
  listHosts: () => call<HostProfile[]>("list_hosts"),
  upsertHost: (host: HostProfile) => call<HostProfile>("upsert_host", { host }),
  deleteHost: (id: Uuid) => call<void>("delete_host", { id }),
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
  listHostKeyPins: () => call<HostKeyEntry[]>("list_host_key_pins"),
  resetHostKey: (hopId: string, host: string, port: number) =>
    call<boolean>("reset_host_key", { hopId, host, port }),
  testChain: (id: Uuid) => call<ChainTestResult>("test_chain", { id }),

  // Session-editor helpers.
  checkPortConflicts: (sessionId: Uuid | null, bind: string, httpPort: number, socksPort: number) =>
    call<PortConflictReport>("check_port_conflicts", { sessionId, bind, httpPort, socksPort }),
  testFilterRules: (mode: FilterMode, rules: string[], target: string) =>
    call<FilterTestResult>("test_filter_rules", { mode, rules, target }),
  inspectMitmCa: (caMode: MitmCaMode, source: MitmPassphraseSource = {}) =>
    call<MitmCaInfo>("inspect_mitm_ca", {
      caMode,
      passphrase: source.passphrase ?? null,
      passphraseRef: source.passphraseRef ?? null,
      passphraseFile: source.passphraseFile ?? null,
    }),

  // Config export and import.
  exportConfig: (path: string, includeSecrets = false, passphrase: string | null = null) =>
    call<ExportSummary>("export_config", { path, includeSecrets, passphrase }),
  importConfig: (path: string, passphrase: string | null = null, replaceExisting = false) =>
    call<ImportSummary>("import_config", { path, passphrase, replaceExisting }),

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
