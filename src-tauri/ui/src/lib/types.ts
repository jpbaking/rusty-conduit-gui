// Wire types for the `src-tauri` IPC surface. Field names match the serialized Rust structs.
// No type here carries a secret: secrets are plain `string` command arguments that only go in.

export type Uuid = string;
export type KeyId = Uuid;
export type SecretRef = Uuid;
export type MitmCaId = Uuid;
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
  | "duplicate_ca"
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
  /** The vault's key is also in the OS keyring, so it can be unlocked without the password. */
  keyring: boolean;
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
  // The backend always sends the v2 fields below. Optional so v1 callers that build a `Usage`
  // by hand still type-check until the v2 components replace them.
  tunnels?: UsageRef[];
  proxies?: UsageRef[];
  /** Names of Profile Library entries. */
  library_profiles?: string[];
}

export interface KeyView extends VaultKeyMeta {
  used_by: number;
  usage: Usage;
}

/** A MITM CA held in the vault. Its certificate and key never leave the backend. */
export interface VaultCaMeta {
  id: MitmCaId;
  name: string;
  /** The signing certificate's subject. */
  subject: string;
  /** When the signing certificate expires. */
  not_after: Timestamp;
  fingerprint_sha256: string;
  created_at: Timestamp;
}

export interface CaView extends VaultCaMeta {
  used_by: number;
  usage: Usage;
}

/** A CA's file contents for upload. Never a path: the backend keeps its own copy. */
export type MitmCaUpload =
  | { format: "pem"; cert: string; key: string }
  /** `data` is the PKCS#12 file, base64-encoded. */
  | { format: "pkcs12"; data: string };

export interface DeleteResult {
  deleted: boolean;
  used_by: number;
  usage: Usage;
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
  /** `<algorithm> <base64>`. Absent on pins recorded before this field existed. */
  public_key_openssh?: string | null;
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
}

export interface ForwardConfig {
  /** Whether the forward proxy runs. Off keeps the ports; the engine then listens on none. */
  enabled: boolean;
  bind: string;
  http_port: number;
  socks_port: number;
  max_connections: number;
  allow: string[];
  block: string[];
}

export interface ReverseConfig {
  /** Whether the reverse proxy runs. Off keeps the ports; nothing is opened on the target. */
  enabled: boolean;
  reverse_bind: string;
  reverse_http_port: number;
  reverse_socks_port: number;
  /** Concurrent reverse proxy clients, 0 = unlimited. `null` uses the forward cap. */
  reverse_max_connections: number | null;
  reverse_allow: string[];
  reverse_block: string[];
}

/** `local` is `ssh -L` (listens here), `remote` is `ssh -R` (listens on the target). */
export type ForwardDirection = "local" | "remote";

export interface PortForward {
  id: Uuid;
  /** Off keeps the forward saved without running it. */
  enabled: boolean;
  direction: ForwardDirection;
  name: string;
  /** Listen address: on this computer for `local`, on the target for `remote`. */
  bind: string;
  port: number;
  /** Resolved by the target for `local`, by this computer for `remote`. */
  dest_host: string;
  dest_port: number;
}

/** An app-wide template for a port forward. An empty `dest_host` is filled in per session. */
export interface ForwardPreset {
  id: Uuid;
  name: string;
  direction: ForwardDirection;
  /** Listen address. `null` uses 127.0.0.1. */
  bind: string | null;
  port: number;
  dest_host: string;
  dest_port: number;
}

export interface MitmConfig {
  /** A CA in the vault. `null` until one is chosen; the session cannot start without it. */
  ca: MitmCaId | null;
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
  /** Seconds of idle before TCP keepalive probes start on proxy sockets, 0 = off. */
  tcp_keepalive: number;
  /** Seconds between unanswered TCP keepalive probes. */
  tcp_keepalive_interval: number;
  /** Unanswered TCP keepalive probes before the OS closes the connection. */
  tcp_keepalive_retries: number;
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
  /** `false` leaves the session out of Start All and autostart. It can still be started alone. */
  enabled: boolean;
  engine: SshEngine;
  hops: HopEntry[];
  forward: ForwardConfig;
  reverse: ReverseConfig;
  port_forwards: PortForward[];
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
  /** `<algorithm> <base64>`, stored with the pin on approval. */
  public_key_openssh: string | null;
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
  enabled: boolean;
  state: SessionState;
  stats: SessionStatsSnapshot;
  /** Proxy listeners bound on this computer. */
  listeners: ListenerInfo[];
  /** Reverse proxy (-R) listeners bound on the target host, while connected. */
  remote_listeners: ListenerInfo[];
  /** Port forwards: local ones once bound, remote ones while connected. */
  port_forwards: ForwardStatus[];
}

/** A port forward that is running, or failed to start. One that is not listed is not running. */
export interface ForwardStatus {
  id: Uuid;
  direction: ForwardDirection;
  listen: string;
  destination: string;
  /** Why it is not listening, or `null` while it is. */
  error: string | null;
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

export type HopTestStatus = "connected" | "failed" | "host_key_unknown" | "not_attempted";

export interface HopTestResult {
  hop_index: number;
  hop_id: string;
  host: string;
  port: number;
  status: HopTestStatus;
  error: string | null;
  elapsed_ms: number;
  /** The key the hop presented when it is not trusted yet. Trusting it pins exactly this key. */
  host_key: HostKeyPrompt | null;
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

/** The result of checking a configured `ssh` program. */
export interface OpenSshBinaryInfo {
  requested: string;
  /** `null` when the program was not found. */
  resolved_path: string | null;
  /** The program's `-V` output. */
  version_raw: string | null;
  major: number | null;
  minor: number | null;
  supported: boolean;
  /** Guidance to show the user. */
  message: string;
  /** A limit of a supported version, such as when password prompts may not reach the app. */
  note: string | null;
}

// Config export and import. Summaries hold counts only.

export interface ExportSummary {
  path: string;
  encrypted: boolean;
  /** Vault secrets were included. Always encrypted when so. */
  with_secrets: boolean;
  session_count: number;
  host_count: number;
  key_count: number;
  ca_count: number;
  /** Vault records sealed into the bundle. Always 0 for a plain export. */
  secret_count: number;
  /** References whose vault record no longer exists. */
  missing_secrets: number;
}

export interface ImportSummary {
  encrypted: boolean;
  /** The file carried vault secrets, which were restored into the vault. */
  with_secrets: boolean;
  /** The file was an older key-only backup: only `keys_added` and `keys_skipped` apply. */
  key_only_backup: boolean;
  sessions_added: number;
  sessions_updated: number;
  sessions_skipped: number;
  hosts_added: number;
  hosts_updated: number;
  hosts_skipped: number;
  presets_added: number;
  presets_updated: number;
  presets_skipped: number;
  keys_added: number;
  /** Keys from a key-only backup that the vault already holds. */
  keys_skipped: number;
  cas_added: number;
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
  | { event: "quit-confirm" }
  | { event: "migration-notice"; payload: MigrationNoticePayload };

export interface ShellSnapshot {
  tray_available: boolean;
  pending: UiEvent[];
}

// Event payloads.

export interface MigrationNoticePayload {
  message: string;
  is_warning: boolean;
}

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


// ---------------------------------------------------------------------------------------------
// v2 model: Tunnels and Proxies. Mirrors `conduit-core/src/v2_model.rs` and the runtime managers.
// ---------------------------------------------------------------------------------------------

export type TunnelId = Uuid;
export type ProxyId = Uuid;

/** `linked`: runs while a Proxy uses it. `manual`: started and stopped by hand. */
export type TunnelStartMode = "linked" | { manual: { autostart: boolean } };

/** The SSH half of a v1 session. */
export interface Tunnel {
  id: TunnelId;
  name: string;
  enabled: boolean;
  start_mode: TunnelStartMode;
  engine: SshEngine;
  hops: HopEntry[];
  reverse: ReverseConfig;
  port_forwards: PortForward[];
  keepalive: TunnelConfig;
  logging: LoggingConfig;
  openssh: OpenSshOptions;
}

/** `managed`: edited in the app. `external_toml`: read from a TOML file and watched. */
export type SourceMode = "managed" | { external_toml: { path: string; debounce_ms: number } };

export interface ListenerConfig {
  bind: string;
  /** 0 turns the listener off. */
  http_port: number;
  /** 0 turns the listener off. */
  socks_port: number;
  max_connections: number;
}

export interface NetworkConfig {
  /** Seconds. */
  connect_timeout: number;
  /** Seconds, 0 = off. */
  tcp_keepalive: number;
  /** Seconds. */
  tcp_keepalive_interval: number;
  tcp_keepalive_retries: number;
}

export type GlobalFilterConfig = "off" | { allow: string[] } | { block: string[] };

/** Where an upstream password comes from. Never the password itself. */
export type UpstreamPasswordSource = { vault: SecretRef } | { env: string } | { file: string };

export type UpstreamKind =
  | { type: "http" }
  | { type: "https"; tls_insecure_skip_verify: boolean }
  | { type: "socks5" }
  | { type: "socks4a" }
  | { type: "composite"; http: string; https: string; fallback: string }
  | { type: "tunnel"; tunnel_id: TunnelId };

export type UpstreamKindName = UpstreamKind["type"];

export interface UpstreamProfile {
  name: string;
  kind: UpstreamKind;
  host: string | null;
  port: number | null;
  username: string | null;
  password: UpstreamPasswordSource | null;
  bypass: string[];
  color: string | null;
}

export type RouteInbound = "http" | "socks";

/** Serde `untagged`: a single value or a list. */
export type RouteOneOrMany<T> = T | T[];

/** A profile name (`direct` and `block` included), or a failover chain of them. */
export type RouteTarget = RouteOneOrMany<string>;

/** A single port, or a `"low-high"` range. */
export type RoutePortSpec = number | string;

export interface RouteHostLevels {
  min?: number;
  max?: number;
}

/** Unset matchers are left out of the wire shape. */
export interface RoutingRule {
  name?: string;
  inbound?: RouteInbound;
  host?: RouteOneOrMany<string>;
  host_wildcard?: RouteOneOrMany<string>;
  host_regex?: RouteOneOrMany<string>;
  cidr?: RouteOneOrMany<string>;
  ip?: RouteOneOrMany<string>;
  port?: RouteOneOrMany<RoutePortSpec>;
  host_levels?: RouteHostLevels;
  bypass?: RouteOneOrMany<string>;
  weekday?: RouteOneOrMany<string>;
  time?: RouteOneOrMany<string>;
  url_wildcard?: RouteOneOrMany<string>;
  url_regex?: RouteOneOrMany<string>;
  keyword?: RouteOneOrMany<string>;
  match_all: boolean;
  disabled: boolean;
  resolve_dns?: boolean;
  target: RouteTarget;
}

/** A per-inbound table (`[routing.http]` / `[routing.socks]`). */
export interface RoutingTable {
  default?: RouteTarget;
  inherit: boolean;
  rules: RoutingRule[];
}

export interface RoutingTablesConfig {
  default: RouteTarget;
  resolve_dns: boolean;
  rules: RoutingRule[];
  http?: RoutingTable;
  socks?: RoutingTable;
}

/** The proxy half of a v1 session. */
export interface Proxy {
  id: ProxyId;
  name: string;
  enabled: boolean;
  autostart: boolean;
  source: SourceMode;
  listeners: ListenerConfig;
  network: NetworkConfig;
  profiles: UpstreamProfile[];
  routing: RoutingTablesConfig;
  filter: GlobalFilterConfig;
  mitm: MitmConfig | null;
  logging: LoggingConfig;
}

// v2 runtime.

export type ProxyState =
  | { state: "stopped" }
  | { state: "starting" }
  | {
      state: "running";
      /** The tray override, `null` = Auto Switch. */
      override_profile: string | null;
      config_generation: number;
      restart_required: boolean;
    }
  | { state: "reloading" }
  | { state: "locked" }
  | { state: "needs_attention"; reason: string }
  | { state: "stopping" };

export interface ProxyTrafficSnapshot {
  active: number;
  bytes_in: number;
  bytes_out: number;
  hits: number;
}

export interface ProxySnapshot {
  id: ProxyId;
  name: string;
  enabled: boolean;
  state: ProxyState;
  /** Bound listeners, while running. */
  listeners: ListenerInfo[];
  config_generation: number;
  override_profile: string | null;
  /** The saved config changed something that only a restart applies. */
  restart_required: boolean;
  /** Traffic by serving profile, while running. */
  profile_counters: Record<string, ProxyTrafficSnapshot>;
  /** Traffic by rule label, while running. */
  rule_counters: Record<string, ProxyTrafficSnapshot>;
  referenced_tunnels: TunnelId[];
}

export interface ProxyView {
  profile: Proxy;
  snapshot: ProxySnapshot;
}

export interface ProxySaveResult {
  profile: Proxy;
  snapshot: ProxySnapshot;
  /** A running Proxy took the new routing without a restart. */
  reloaded: boolean;
  /** A running Proxy rejected the new routing and kept the old one; the save still stands. */
  reload_error: string | null;
}

/** A structured access record for the log drawer. `upstream` is always redacted. */
export interface AccessRecordView {
  kind: "http" | "socks";
  /** Unix time in milliseconds. */
  ts_ms: number;
  direction: "forward" | "reverse" | null;
  client: string;
  proto: string;
  /** HTTP method, or SOCKS command. */
  method: string;
  target: string;
  rule: string;
  profile: string;
  upstream: string;
  /** HTTP status code, or the SOCKS status label. */
  status: string;
  mitm: boolean;
  bytes_in: number;
  bytes_out: number;
  duration_ms: number;
}

/** One element of a Route Tester failover chain. */
export interface RouteTestTarget {
  /** The name as written in the rule or default. */
  name: string;
  /** The concrete profile dialed, after composite resolution and bypass. */
  profile: string;
  redacted_upstream: string;
  /** A profile `bypass` list sent the target `direct`. */
  bypassed: boolean;
}

export interface RouteTestResult {
  /** `[routing]`, `[routing.http]`, or `[routing.socks]`; `null` when the filter denied it. */
  table: string | null;
  /** The matched rule's label; `null` = the table default (or denied). */
  matched_rule: string | null;
  blocked_by_filter: boolean;
  filter_reason: string | null;
  /** The failover chain, in order. */
  targets: RouteTestTarget[];
}

export interface UpstreamProbeResult {
  ok: boolean;
  elapsed_ms: number;
  redacted_upstream: string;
  /** Redacted reason when `ok` is false. */
  error: string | null;
}

export interface TunnelSnapshot {
  id: TunnelId;
  name: string;
  enabled: boolean;
  start_mode: TunnelStartMode;
  engine: SshEngine;
  state: SessionState;
  stats: SessionStatsSnapshot;
  /** Reverse proxy (-R) listeners bound on the target host, while connected. */
  remote_listeners: ListenerInfo[];
  /** Loopback listeners of the reverse proxy on this computer. */
  reverse_listeners: string[];
  /** Port forwards: local ones once bound, remote ones while connected. */
  port_forwards: ForwardStatus[];
  /** How many Proxies currently hold a Linked reference. */
  linked_holders: number;
}

export interface TunnelView {
  profile: Tunnel;
  snapshot: TunnelSnapshot;
  /** Proxies that route through this Tunnel. */
  used_by: UsageRef[];
}

export interface TunnelChainTestResult {
  tunnel_id: TunnelId;
  all_connected: boolean;
  hops: HopTestResult[];
}

/** Payloads of the `proxy-*` events. */
export type ProxyEvent =
  | { event: "state_changed"; proxy_id: ProxyId; state: ProxyState }
  | { event: "reloaded"; proxy_id: ProxyId; config_generation: number }
  | { event: "override_changed"; proxy_id: ProxyId; override_profile: string | null };

/** Payload of the `tunnel-state-changed` event. */
export type TunnelEvent = { event: "state_changed"; tunnel_id: TunnelId; state: SessionState };

export interface V2EventHandlers {
  onProxyEvent(event: ProxyEvent): void;
  onTunnelEvent(event: TunnelEvent): void;
}
