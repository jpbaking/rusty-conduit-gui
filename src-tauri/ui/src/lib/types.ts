// Wire types for the `src-tauri` IPC surface. Field names match the serialized Rust structs.
// No type here carries a secret: secrets are plain `string` command arguments that only go in.

export type Uuid = string;
export type KeyId = Uuid;
export type SecretRef = Uuid;
/** Unix epoch seconds. */
export type Timestamp = number;

// Errors.

export type AppErrorCode =
  | "vault_locked"
  | "unlock_failed"
  | "vault"
  | "storage"
  | "validation"
  | "runtime"
  | "vault_not_initialized"
  | "vault_exists"
  | "not_found"
  | "duplicate_key"
  | "invalid"
  | "io"
  | "task";

export interface AppErrorPayload {
  code: AppErrorCode;
  message: string;
}

// Vault and keys.

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
}

export interface SecretMeta {
  secret_ref: SecretRef;
  has_secret: boolean;
}

export type KeySource = "Uploaded" | "Pasted" | "Generated";
export type GenerateAlgorithm = "ed25519" | "ecdsa-p256";

export interface VaultKeyMeta {
  id: KeyId;
  name: string;
  algorithm: string;
  fingerprint_sha256: string;
  public_key_openssh: string;
  source: KeySource;
  created_at: Timestamp;
}

export interface UsageRef {
  id: Uuid;
  name: string;
}

export interface Usage {
  hosts: UsageRef[];
  sessions: UsageRef[];
}

export interface KeyView extends VaultKeyMeta {
  used_by: number;
  usage: Usage;
}

export interface DeleteResult {
  deleted: boolean;
  used_by: number;
  usage: Usage;
}

export interface BackupSummary {
  path: string;
  key_count: number;
}

export interface ImportBackupResult {
  imported: VaultKeyMeta[];
  skipped: number;
}

// Hosts.

export interface HostKeyPin {
  algorithm: string;
  fingerprint_sha256: string;
  first_seen: Timestamp;
  approved: boolean;
}

/** The key a pin is stored under. Pins belong to a session hop, not to a host profile. */
export interface HostKeyLookup {
  hop_id: string;
  host: string;
  port: number;
}

export interface HostKeyRecord {
  algorithm: string;
  fingerprint_sha256: string;
  first_seen: Timestamp;
  approved: boolean;
}

export interface HostKeyEntry {
  key: HostKeyLookup;
  record: HostKeyRecord;
}

export type AuthMethod =
  | { Key: { key: KeyId } }
  | { Password: { secret: SecretRef } }
  | { KeyboardInteractive: { prompts: string[] } }
  | "SystemAgentOptIn";

export interface HostProfile {
  id: Uuid;
  name: string;
  host: string;
  port: number;
  user: string;
  auth: AuthMethod[];
  host_key_pin: HostKeyPin | null;
}

// Session profiles.

export type SshEngine = "Russh" | "OpenSsh";

export interface HopEntry {
  hop_id: string;
  name: string;
  host: HostProfile;
  agent_forward: boolean;
  /** Vault keys exposed to this hop while `agent_forward` is on. Nothing else is exposed. */
  agent_forward_keys: KeyId[];
  /** Optional command run on this hop's agent-forwarding session channel. */
  agent_forward_command: string | null;
}

export interface ForwardConfig {
  bind: string;
  http_port: number;
  socks_port: number;
  max_connections: number;
  allow: string[];
  block: string[];
}

export interface ReverseConfig {
  reverse_bind: string;
  reverse_http_port: number;
  reverse_socks_port: number;
  reverse_allow: string[];
  reverse_block: string[];
}

export type MitmCaMode = { Pem: { cert: string; key: string } } | { Pkcs12: { path: string } };

export interface MitmConfig {
  ca_mode: MitmCaMode;
  passphrase: SecretRef | null;
  ca_passphrase_file: string | null;
  /** Seconds. */
  cert_ttl: number;
  cert_cache_max_entries: number;
  socks_block_web: boolean;
}

export interface TunnelConfig {
  ip_version: string;
  /** Seconds. */
  server_alive_interval: number;
  server_alive_count_max: number;
  no_reconnect: boolean;
  /** Seconds. */
  reconnect_initial_delay: number;
  /** Seconds. */
  reconnect_max_delay: number;
  /** Seconds. */
  startup_timeout: number;
}

export interface LoggingConfig {
  level: string;
  format: string;
  http_access_log: string | null;
  socks_log: string | null;
}

export interface OpenSshOptions {
  ssh_bin: string;
  ssh_socks_bind: string;
  ssh_socks_port: number;
  extra_args: string[];
}

export interface SessionProfile {
  id: Uuid;
  name: string;
  autostart: boolean;
  engine: SshEngine;
  hops: HopEntry[];
  forward: ForwardConfig;
  reverse: ReverseConfig;
  mitm: MitmConfig | null;
  tunnel: TunnelConfig;
  logging: LoggingConfig;
  openssh: OpenSshOptions;
}

// Runtime.

export interface HostKeyPrompt {
  hop_index: number;
  hop_id: string;
  host: string;
  port: number;
  algorithm: string;
  /** `SHA256:<base64>`, matching `ssh-keygen -l`. */
  sha256: string;
}

export type SessionState =
  | { state: "stopped" }
  | { state: "starting" }
  | { state: "connected" }
  | { state: "reconnecting"; attempt: number; next_retry_secs: number }
  | { state: "waiting_for_network" }
  | { state: "locked" }
  | ({ state: "awaiting_host_key" } & HostKeyPrompt)
  | { state: "needs_attention"; reason: string }
  | { state: "failed"; reason: string };

export interface ListenerInfo {
  role: string;
  addr: string;
}

export interface SessionStatsSnapshot {
  active_connections: number;
  total_connections: number;
  bytes_sent: number;
  bytes_received: number;
  uptime_secs: number;
}

export interface SessionSnapshot {
  id: Uuid;
  name: string;
  state: SessionState;
  stats: SessionStatsSnapshot;
  listeners: ListenerInfo[];
}

export interface SessionView {
  profile: SessionProfile;
  runtime: SessionSnapshot;
}

export interface StateSummary {
  vault: VaultStatus;
  session_count: number;
  host_count: number;
  key_count: number;
  sessions: SessionSnapshot[];
}

export interface LogLine {
  seq: number;
  timestamp: Timestamp;
  text: string;
}

export type HopTestStatus = "connected" | "failed" | "not_attempted";

export interface HopTestResult {
  hop_index: number;
  hop_id: string;
  host: string;
  port: number;
  status: HopTestStatus;
  error: string | null;
  elapsed_ms: number;
}

export interface ChainTestResult {
  session_id: Uuid;
  all_connected: boolean;
  hops: HopTestResult[];
}

// Session-editor helpers.

export type PortConflictKind = "session" | "os_socket";

export interface PortConflict {
  port: number;
  kind: PortConflictKind;
  detail: string;
}

export interface PortConflictReport {
  conflicts: PortConflict[];
}

export type FilterMode = "allow" | "block";

export interface RuleError {
  index: number;
  rule: string;
  message: string;
}

export interface FilterTestResult {
  /** Every rule parsed and the target is non-empty. */
  valid: boolean;
  /** `null` when the input is not valid. */
  allowed: boolean | null;
  reason: string;
  rule_errors: RuleError[];
}

/** Public facts about a MITM CA. Never carries key material or a passphrase. */
export interface MitmCaInfo {
  subject: string;
  /** RFC 3339. */
  not_after: string;
  expired: boolean;
  /** Whole days until expiry. Negative once expired. */
  days_remaining: number;
}

/** At most one source may be set. */
export interface MitmPassphraseSource {
  passphrase?: string | null;
  passphraseRef?: SecretRef | null;
  passphraseFile?: string | null;
}

// Config export and import. Summaries hold counts only.

export interface ExportSummary {
  path: string;
  encrypted: boolean;
  session_count: number;
  host_count: number;
  key_count: number;
  /** Vault records sealed into the bundle. Always 0 for a plain export. */
  secret_count: number;
  /** References whose vault record no longer exists. */
  missing_secrets: number;
}

export interface ImportSummary {
  encrypted: boolean;
  sessions_added: number;
  sessions_updated: number;
  sessions_skipped: number;
  hosts_added: number;
  hosts_updated: number;
  hosts_skipped: number;
  keys_added: number;
  secrets_added: number;
  known_hosts_added: number;
  known_hosts_updated: number;
  /** Credential references dropped because they could not be trusted or resolved. */
  credentials_removed: number;
}

// Desktop shell.

export interface AutostartStatus {
  enabled: boolean;
  executable: string;
  args: string[];
}

export type CloseChoice = "keep_running" | "quit" | "cancel";

export type UiEvent =
  | { event: "clipboard-fallback"; payload: ClipboardFallbackPayload }
  | { event: "view-logs"; payload: ViewLogsPayload }
  | { event: "unlock-vault" }
  | { event: "close-confirm" }
  | { event: "quit-confirm" };

export interface ShellSnapshot {
  tray_available: boolean;
  pending: UiEvent[];
}

// Event payloads.

export interface TrayStatusPayload {
  tray_available: boolean;
}

export interface ClipboardFallbackPayload {
  url: string;
}

export interface ViewLogsPayload {
  session_id: Uuid;
}

export type RuntimeEvent =
  | { event: "state_changed"; session_id: Uuid; state: SessionState }
  | { event: "known_hosts_changed"; session_id: Uuid; hop_id: string; host: string; port: number };

export interface ShellEventHandlers {
  onTrayStatus(payload: TrayStatusPayload): void;
  onRuntimeEvent(event: RuntimeEvent): void;
  onRuntimeLagged(): void;
  onUiEvent(event: UiEvent): void;
}
