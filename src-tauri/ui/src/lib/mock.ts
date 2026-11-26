// Sample data for `npm run dev` in a plain browser. Only loaded in development builds. It ignores
// every secret argument and uses documentation-only addresses (RFC 5737).

import { ApiError } from "./api";
import type {
  AccessRecordView,
  AirSwitchCommitResult,
  AirSwitchPreview,
  CliTomlFormat,
  ImportedProfileSummary,
  TomlExportResult,
  TomlImportCommitResult,
  TomlImportPreview,
  CaView,
  Proxy,
  ProxySaveResult,
  ProxySnapshot,
  ProxyState,
  ProxyView,
  RouteTestResult,
  RouteTarget,
  Tunnel,
  TunnelChainTestResult,
  TunnelSnapshot,
  TunnelView,
  UpstreamProbeResult,
  UpstreamProfile,
  DeleteResult,
  ExportSummary,
  FilterTestResult,
  HostKeyEntry,
  HostKeyPrompt,
  ForwardPreset,
  HostProfile,
  ImportSummary,
  KeyView,
  LogLine,
  OpenSshBinaryInfo,
  PortConflict,
  PortConflictReport,
  SessionProfile,
  SessionSnapshot,
  SessionState,
  SessionView,
  ShellSnapshot,
  StateSummary,
  VaultStatus,
} from "./types";

const NIL = "00000000-0000-0000-0000-000000000000";

const IDLE_STATS = {
  active_connections: 0,
  total_connections: 0,
  bytes_sent: 0,
  bytes_received: 0,
  uptime_secs: 0,
};

function profile(id: string, name: string, host: string, httpPort: number): SessionProfile {
  const hostProfile: HostProfile = {
    id: "00000000-0000-0000-0000-000000000000",
    name,
    host,
    port: 22,
    user: "demo",
    auth: [],
    host_key_pin: null,
  };
  return {
    id,
    name,
    autostart: false,
    enabled: true,
    engine: "Russh",
    hops: [{ hop_id: `${id}-hop`, name, host: hostProfile }],
    forward: {
      enabled: true,
      bind: "127.0.0.1",
      http_port: httpPort,
      socks_port: httpPort + 1,
      max_connections: 4096,
      allow: [],
      block: [],
    },
    reverse: {
      enabled: false,
      reverse_bind: "127.0.0.1",
      reverse_http_port: 0,
      reverse_socks_port: 0,
      reverse_max_connections: null,
      reverse_allow: [],
      reverse_block: [],
    },
    port_forwards: [],
    mitm: null,
    tunnel: {
      ip_version: "4",
      server_alive_interval: 15,
      server_alive_count_max: 3,
      tcp_keepalive: 60,
      tcp_keepalive_interval: 10,
      tcp_keepalive_retries: 5,
      no_reconnect: false,
      reconnect_initial_delay: 1,
      reconnect_max_delay: 30,
      startup_timeout: 30,
    },
    logging: { level: "INFO", format: "text", http_access_log: null, socks_log: null },
    openssh: { ssh_bin: "ssh", ssh_socks_bind: "127.0.0.1", ssh_socks_port: 0, extra_args: [] },
  };
}

function withReverse(p: SessionProfile, httpPort: number): SessionProfile {
  return { ...p, reverse: { ...p.reverse, enabled: true, reverse_http_port: httpPort } };
}

function withForwards(p: SessionProfile): SessionProfile {
  const base = { enabled: true, bind: "127.0.0.1" };
  return {
    ...p,
    port_forwards: [
      { ...base, id: "f0000000-0000-4000-8000-000000000001", direction: "local", name: "Staging DB", port: 15432, dest_host: "db.staging.internal", dest_port: 5432 },
      { ...base, id: "f0000000-0000-4000-8000-000000000002", direction: "remote", name: "Webhook receiver", port: 9000, dest_host: "localhost", dest_port: 3000 },
    ],
  };
}

function forwardStatuses(p: SessionProfile): SessionSnapshot["port_forwards"] {
  return p.port_forwards
    .filter((f) => f.enabled)
    .map((f) => ({
      id: f.id,
      direction: f.direction,
      listen: `${f.bind}:${f.port}`,
      destination: `${f.dest_host}:${f.dest_port}`,
      error: null,
    }));
}

function view(p: SessionProfile, state: SessionState, active = 0): SessionView {
  const connected = state.state === "connected";
  const runtime: SessionSnapshot = {
    id: p.id,
    name: p.name,
    enabled: p.enabled,
    state,
    stats: connected
      ? {
          active_connections: active,
          total_connections: 42,
          bytes_sent: 1_482_113,
          bytes_received: 20_911_004,
          uptime_secs: 3_725,
        }
      : { ...IDLE_STATS },
    listeners: connected
      ? [
          { role: "HTTP/HTTPS", addr: `${p.forward.bind}:${p.forward.http_port}` },
          { role: "SOCKS4/4a/5", addr: `${p.forward.bind}:${p.forward.socks_port}` },
        ]
      : [],
    remote_listeners:
      connected && p.reverse.reverse_http_port
        ? [{ role: "HTTP/HTTPS", addr: `${p.reverse.reverse_bind}:${p.reverse.reverse_http_port}` }]
        : [],
    port_forwards: connected ? forwardStatuses(p) : [],
  };
  return { profile: p, runtime };
}

const sessions: SessionView[] = [
  view(
    withForwards(withReverse(profile("11111111-1111-4111-8111-111111111111", "Staging bastion", "192.0.2.10", 3128), 8080)),
    { state: "connected" },
    3,
  ),
  view(profile("22222222-2222-4222-8222-222222222222", "Lab gateway", "198.51.100.7", 3130), {
    state: "reconnecting",
    attempt: 2,
    next_retry_secs: 8,
  }),
  view(profile("33333333-3333-4333-8333-333333333333", "Edge target", "203.0.113.20", 3132), {
    state: "needs_attention",
    reason: "authentication failed",
  }),
  view(profile("44444444-4444-4444-8444-444444444444", "Archive", "192.0.2.44", 3134), { state: "stopped" }),
];

const vault: VaultStatus = { initialized: true, unlocked: true, keyring: false };
let keys: KeyView[] = [
  {
    id: "55555555-5555-4555-8555-555555555555",
    name: "Demo ed25519",
    algorithm: "ssh-ed25519",
    fingerprint_sha256: "SHA256:demoFingerprintForPreviewOnly",
    public_key_openssh: "ssh-ed25519 AAAApreview demo",
    source: "Generated",
    created_at: Math.floor(Date.now() / 1000),
    used_by: 0,
    usage: { hosts: [], sessions: [], tunnels: [], proxies: [], library_profiles: [] },
  },
];
let cas: CaView[] = [
  {
    id: "66666666-6666-4666-8666-666666666666",
    name: "Demo inspection CA",
    subject: "CN=Preview CA",
    not_after: Math.floor(Date.now() / 1000) + 20 * 86_400,
    fingerprint_sha256: "SHA256:demoCaFingerprintForPreviewOnly",
    created_at: Math.floor(Date.now() / 1000),
    used_by: 0,
    usage: { hosts: [], sessions: [], tunnels: [], proxies: [], library_profiles: [] },
  },
];
let autostart = false;
let hosts: HostProfile[] = [];
const BUILTIN_PRESETS: ForwardPreset[] = [
  { id: "5f0d0000-0000-4000-8000-000000000001", name: "PostgreSQL", direction: "local", bind: null, port: 15432, dest_host: "", dest_port: 5432 },
  { id: "5f0d0000-0000-4000-8000-000000000002", name: "MySQL", direction: "local", bind: null, port: 13306, dest_host: "", dest_port: 3306 },
  { id: "5f0d0000-0000-4000-8000-000000000003", name: "Redis", direction: "local", bind: null, port: 16379, dest_host: "", dest_port: 6379 },
  { id: "5f0d0000-0000-4000-8000-000000000004", name: "Remote Desktop", direction: "local", bind: null, port: 13389, dest_host: "", dest_port: 3389 },
  { id: "5f0d0000-0000-4000-8000-000000000005", name: "Web UI (HTTPS)", direction: "local", bind: null, port: 18443, dest_host: "", dest_port: 443 },
  { id: "5f0d0000-0000-4000-8000-000000000006", name: "Share a local dev server", direction: "remote", bind: null, port: 8000, dest_host: "localhost", dest_port: 3000 },
];
let presets: ForwardPreset[] = structuredClone(BUILTIN_PRESETS);
const testedKeys = new Map<string, HostKeyPrompt>();

let pins: HostKeyEntry[] = [
  {
    key: { hop_id: "11111111-1111-4111-8111-111111111111-hop", host: "192.0.2.10", port: 22 },
    record: {
      algorithm: "ssh-ed25519",
      fingerprint_sha256: "SHA256:demoPinnedHostKeyForPreviewOnly",
      first_seen: Math.floor(Date.now() / 1000),
      approved: true,
    },
  },
];
const now = Math.floor(Date.now() / 1000);
let logs: LogLine[] = Array.from({ length: 400 }, (_, seq) => ({
  seq,
  timestamp: now - 400 + seq,
  text: `${["INFO", "INFO", "DEBUG", "WARN", "ERROR"][seq % 5]} sample log line ${seq}`,
}));

function find(args?: Record<string, unknown>): SessionView {
  const session = sessions.find((s) => s.profile.id === args?.id);
  if (!session) throw new ApiError("not_found", "session not found");
  return session;
}

const WILDCARD_BINDS = new Set(["0.0.0.0", "::"]);
const bindsOverlap = (a: string, b: string) =>
  a === b || WILDCARD_BINDS.has(a) || WILDCARD_BINDS.has(b);

function mockPortConflicts(args?: Record<string, unknown>): PortConflictReport {
  const bind = String(args?.bind);
  const ports = new Set([Number(args?.httpPort), Number(args?.socksPort)].filter((p) => p !== 0));
  const conflicts: PortConflict[] = [];
  for (const port of ports) {
    for (const { profile: other } of sessions) {
      if (other.id === args?.sessionId || !bindsOverlap(bind, other.forward.bind)) continue;
      for (const [role, used] of [["HTTP", other.forward.http_port], ["SOCKS", other.forward.socks_port]] as const) {
        if (used === port) {
          conflicts.push({
            port,
            kind: "session",
            detail: `session "${other.name}" uses ${other.forward.bind}:${port} for ${role}`,
          });
        }
      }
    }
  }
  return { conflicts };
}

/** A rough stand-in for the engine: exact names and `*.domain` only, no CIDR matching. */
function mockFilterTest(args?: Record<string, unknown>): FilterTestResult {
  const rules = (args?.rules as string[] | undefined) ?? [];
  const target = String(args?.target ?? "").trim();
  const rule_errors = rules.flatMap((rule, index) =>
    rule.trim() === "" || /\s/.test(rule) ? [{ index, rule, message: "invalid rule" }] : [],
  );
  if (rule_errors.length > 0) {
    return { valid: false, allowed: null, reason: `${rule_errors.length} rule(s) could not be parsed`, rule_errors };
  }
  if (!target) {
    return { valid: false, allowed: null, reason: "enter an IP address or domain to test", rule_errors };
  }
  if (rules.length === 0) {
    return { valid: true, allowed: true, reason: "no rules are set, so every destination is allowed", rule_errors };
  }
  const matched = rules.some((rule) =>
    rule.startsWith("*.") ? target.endsWith(rule.slice(1)) : rule === target,
  );
  const allowed = args?.mode === "allow" ? matched : !matched;
  return { valid: true, allowed, reason: `preview: destination ${target} ${matched ? "matches" : "does not match"} the rules`, rule_errors };
}

/** Only a program named `ssh` exists in the preview. */
function mockOpensshCheck(args?: Record<string, unknown>): OpenSshBinaryInfo {
  const requested = String(args?.sshBin ?? "").trim() || "ssh";
  if (requested !== "ssh" && !requested.endsWith("/ssh")) {
    return {
      requested,
      resolved_path: null,
      version_raw: null,
      major: null,
      minor: null,
      supported: false,
      message: `OpenSSH binary "${requested}" was not found.`,
      note: null,
    };
  }
  return {
    requested,
    resolved_path: requested === "ssh" ? "/usr/bin/ssh" : requested,
    version_raw: "OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024",
    major: 9,
    minor: 6,
    supported: true,
    message: "OpenSSH 9.6 is supported.",
    note: null,
  };
}

// ---- v2: Tunnels, Proxies, and the Profile Library. ----

const NO_USAGE = { hosts: [], sessions: [], tunnels: [], proxies: [], library_profiles: [] };

function sampleTunnel(id: string, name: string, host: string): Tunnel {
  const base = profile(id, name, host, 0);
  return {
    id,
    name,
    enabled: true,
    start_mode: "linked",
    engine: base.engine,
    hops: base.hops,
    reverse: base.reverse,
    port_forwards: [],
    keepalive: base.tunnel,
    logging: base.logging,
    openssh: base.openssh,
  };
}

function tunnelSnapshot(t: Tunnel, state: TunnelSnapshot["state"], holders = 0): TunnelSnapshot {
  return {
    id: t.id,
    name: t.name,
    enabled: t.enabled,
    start_mode: t.start_mode,
    engine: t.engine,
    state,
    stats: state.state === "connected" ? { ...IDLE_STATS, total_connections: 12, uptime_secs: 900 } : { ...IDLE_STATS },
    remote_listeners: [],
    reverse_listeners: [],
    port_forwards: [],
    linked_holders: holders,
  };
}

const TUNNEL_A = "a1111111-1111-4111-8111-111111111111";
const TUNNEL_B = "a2222222-2222-4222-8222-222222222222";

let tunnels: TunnelView[] = [
  { profile: sampleTunnel(TUNNEL_A, "Staging bastion", "192.0.2.10"), snapshot: tunnelSnapshot(sampleTunnel(TUNNEL_A, "Staging bastion", "192.0.2.10"), { state: "connected" }, 1), used_by: [] },
  { profile: sampleTunnel(TUNNEL_B, "Lab gateway", "198.51.100.7"), snapshot: tunnelSnapshot(sampleTunnel(TUNNEL_B, "Lab gateway", "198.51.100.7"), { state: "stopped" }), used_by: [] },
];

function blankProxyFields(): Omit<Proxy, "id" | "name"> {
  return {
    enabled: true,
    autostart: false,
    source: "managed",
    listeners: { bind: "127.0.0.1", http_port: 3128, socks_port: 1080, max_connections: 4096 },
    network: { connect_timeout: 10, tcp_keepalive: 60, tcp_keepalive_interval: 10, tcp_keepalive_retries: 5 },
    profiles: [],
    routing: { default: "direct", resolve_dns: false, rules: [] },
    filter: "off",
    socks_block_web: false,
    mitm: null,
    logging: { level: "INFO", format: "text", http_access_log: null, socks_log: null },
  };
}

function upstream(name: string, kind: UpstreamProfile["kind"], host: string | null, port: number | null): UpstreamProfile {
  return { name, kind, host, port, username: null, password: null, bypass: [], color: null };
}

const PROXY_A = "b1111111-1111-4111-8111-111111111111";
const PROXY_B = "b2222222-2222-4222-8222-222222222222";

const proxyA: Proxy = {
  ...blankProxyFields(),
  id: PROXY_A,
  name: "Work",
  profiles: [
    upstream("corp", { type: "http" }, "192.0.2.80", 8080),
    upstream("staging", { type: "tunnel", tunnel_id: TUNNEL_A }, null, null),
  ],
  routing: {
    default: "direct",
    resolve_dns: false,
    rules: [
      { name: "intranet", host_wildcard: "*.corp.example", match_all: false, disabled: false, target: ["corp", "direct"] },
      { name: "staging", host_wildcard: "*.staging.example", match_all: false, disabled: false, target: "staging" },
    ],
  },
};
const proxyB: Proxy = {
  ...blankProxyFields(),
  id: PROXY_B,
  name: "Direct",
  listeners: { bind: "127.0.0.1", http_port: 3130, socks_port: 1082, max_connections: 4096 },
};

function proxySnapshot(p: Proxy, state: ProxyState, generation = 0): ProxySnapshot {
  const running = state.state === "running";
  return {
    id: p.id,
    name: p.name,
    enabled: p.enabled,
    state,
    listeners: running
      ? [
          { role: "HTTP/HTTPS", addr: `${p.listeners.bind}:${p.listeners.http_port}` },
          { role: "SOCKS4/4a/5", addr: `${p.listeners.bind}:${p.listeners.socks_port}` },
        ]
      : [],
    config_generation: generation,
    override_profile: running ? state.override_profile : null,
    restart_required: running ? state.restart_required : false,
    profile_counters: running ? { corp: { active: 1, bytes_in: 20_480, bytes_out: 4_096, hits: 7 } } : {},
    rule_counters: running ? { intranet: { active: 1, bytes_in: 20_480, bytes_out: 4_096, hits: 7 } } : {},
    referenced_tunnels: tunnelIdsOf(p),
  };
}

let proxies: ProxyView[] = [
  { profile: proxyA, snapshot: proxySnapshot(proxyA, { state: "running", override_profile: null, config_generation: 1, restart_required: false }, 1) },
  { profile: proxyB, snapshot: proxySnapshot(proxyB, { state: "stopped" }) },
];

let library: UpstreamProfile[] = [upstream("Corporate HTTP", { type: "http" }, "192.0.2.80", 8080)];

const v2Logs = (label: string): LogLine[] =>
  Array.from({ length: 40 }, (_, seq) => ({ seq, timestamp: now - 40 + seq, text: `INFO ${label} sample line ${seq}` }));

function tunnelIdsOf(p: Proxy): string[] {
  return p.profiles.flatMap((u) => (u.kind.type === "tunnel" ? [u.kind.tunnel_id] : []));
}

function refreshTunnelUsage(): void {
  tunnels = tunnels.map((t) => ({
    ...t,
    used_by: proxies
      .filter((p) => tunnelIdsOf(p.profile).includes(t.profile.id))
      .map((p) => ({ id: p.profile.id, name: p.profile.name })),
  }));
}
refreshTunnelUsage();

function findProxy(args?: Record<string, unknown>): ProxyView {
  const proxy = proxies.find((p) => p.profile.id === args?.id);
  if (!proxy) throw new ApiError("not_found", "proxy not found");
  return proxy;
}

function findTunnel(args?: Record<string, unknown>): TunnelView {
  const tunnel = tunnels.find((t) => t.profile.id === args?.id);
  if (!tunnel) throw new ApiError("not_found", "tunnel not found");
  return tunnel;
}

function saveProxy(p: Proxy, isNew: boolean): ProxySaveResult {
  const saved = structuredClone(p);
  if (isNew || saved.id === NIL) saved.id = crypto.randomUUID();
  const existing = proxies.find((v) => v.profile.id === saved.id);
  let state: ProxyState = existing?.snapshot.state ?? { state: "stopped" };
  const reloaded = state.state === "running";
  if (state.state === "running") state = { ...state, config_generation: state.config_generation + 1 };
  const snapshot = proxySnapshot(saved, state, state.state === "running" ? state.config_generation : 0);
  const viewed: ProxyView = { profile: saved, snapshot };
  proxies = existing ? proxies.map((v) => (v.profile.id === saved.id ? viewed : v)) : [...proxies, viewed];
  refreshTunnelUsage();
  return structuredClone({ profile: saved, snapshot, reloaded, reload_error: null });
}

const firstTarget = (target: RouteTarget): string[] => (Array.isArray(target) ? target : [target]);

/** A tiny stand-in for the engine: exact and `*.` wildcard host rules only. */
function mockRouteTest(args?: Record<string, unknown>): RouteTestResult {
  const proxy = args?.proxy as Proxy;
  const host = String(args?.rawTarget ?? "").replace(/^[a-z]+:\/\//, "").split(/[/:]/)[0] ?? "";
  const matches = (pattern: string) =>
    pattern.startsWith("*.") ? host.endsWith(pattern.slice(1)) : host === pattern;
  const asList = (value: string | string[] | undefined) => (value === undefined ? [] : Array.isArray(value) ? value : [value]);
  const rule = proxy.routing.rules.find(
    (r) => !r.disabled && (r.match_all || [...asList(r.host), ...asList(r.host_wildcard)].some(matches)),
  );
  const names = firstTarget(rule ? rule.target : proxy.routing.default);
  return {
    table: "[routing]",
    matched_rule: rule ? (rule.name ?? "rule") : null,
    blocked_by_filter: false,
    filter_reason: null,
    targets: names.map((name) => ({ name, profile: name, redacted_upstream: name === "direct" ? "direct" : `${name} (redacted)`, bypassed: false })),
  };
}

function mockAccessRecords(): AccessRecordView[] {
  return Array.from({ length: 5 }, (_, i) => ({
    kind: i % 2 === 0 ? "http" : "socks",
    ts_ms: Date.now() - (5 - i) * 1000,
    direction: "forward",
    client: "127.0.0.1:50000",
    proto: i % 2 === 0 ? "HTTP/1.1" : "SOCKS5",
    method: i % 2 === 0 ? "CONNECT" : "connect",
    target: `app${i}.corp.example:443`,
    rule: "intranet",
    profile: "corp",
    upstream: "http://192.0.2.80:8080",
    status: i % 2 === 0 ? "200" : "succeeded",
    mitm: false,
    bytes_in: 4096 * (i + 1),
    bytes_out: 1024 * (i + 1),
    duration_ms: 120 * (i + 1),
  }));
}

const NOT_HANDLED = Symbol("not handled");

// ---- U4: import / export samples. No secret is ever returned. ----

const SAMPLE_IMPORTED: ImportedProfileSummary[] = [
  { name: "office", kind: "http", host: "192.0.2.90", port: 3128, username: "alice", password_extracted: true, password_source: null },
  { name: "lab-socks", kind: "socks5", host: "198.51.100.20", port: 1080, username: null, password_extracted: false, password_source: null },
];

const fileStem = (path: unknown) =>
  String(path ?? "import").split(/[\\/]/).pop()?.replace(/\.[^.]+$/, "") || "import";

const isCliFormat = (value: unknown): value is CliTomlFormat =>
  value === "rusty-conduit" || value === "rusty-conduit-ssh" || value === "rusty-conduit-switch";

function mockTomlFormat(args?: Record<string, unknown>): { format: CliTomlFormat; detected: boolean } {
  if (isCliFormat(args?.format)) return { format: args.format, detected: false };
  return { format: /ssh/i.test(String(args?.path)) ? "rusty-conduit-ssh" : "rusty-conduit-switch", detected: true };
}

function importedProxy(name: string): Proxy {
  return {
    ...blankProxyFields(),
    id: NIL,
    name,
    listeners: { bind: "127.0.0.1", http_port: 3140, socks_port: 1090, max_connections: 4096 },
    profiles: [
      { ...upstream("office", { type: "http" }, "192.0.2.90", 8080), username: "alice", password: { vault: crypto.randomUUID() } },
      upstream("lab-socks", { type: "socks5" }, "198.51.100.20", 1080),
    ],
    routing: {
      default: "direct",
      resolve_dns: false,
      rules: [{ name: "office", host_wildcard: "*.office.example", match_all: false, disabled: false, target: "office" }],
    },
  };
}

function setProxySource(args: Record<string, unknown> | undefined, source: Proxy["source"]): ProxySaveResult {
  const view = findProxy({ id: args?.proxyId });
  return saveProxy({ ...view.profile, source }, false);
}

function dispatchU4(command: string, args?: Record<string, unknown>): unknown {
  switch (command) {
    case "preview_airswitch_import":
      return {
        suggested_name: fileStem(args?.path),
        profile_count: SAMPLE_IMPORTED.length,
        rule_count: 1,
        extracted_password_count: 1,
        warnings: ["Rule list \"PAC script\" is browser-only and was skipped."],
        profiles: SAMPLE_IMPORTED,
      } satisfies AirSwitchPreview;
    case "commit_airswitch_import": {
      if (!vault.unlocked) throw new ApiError("vault_locked", "Unlock the vault to store imported passwords.");
      const target = args?.targetProxyId ? findProxy({ id: args.targetProxyId }).profile : null;
      const name = String(args?.proxyName ?? "").trim();
      const fresh = importedProxy(name || fileStem(args?.path));
      // Into a target: its profiles and routing are replaced; everything else stays.
      const merged = target
        ? { ...target, name: name || target.name, profiles: fresh.profiles, routing: fresh.routing }
        : fresh;
      const saved = saveProxy(merged, !target);
      return {
        proxy: saved.profile,
        warnings: ["Rule list \"PAC script\" is browser-only and was skipped."],
        stored_passwords: 1,
      } satisfies AirSwitchCommitResult;
    }
    case "preview_toml_import": {
      const { format, detected } = mockTomlFormat(args);
      const ssh = format === "rusty-conduit-ssh";
      return {
        format,
        detected,
        proxy_name: `${format} import`,
        tunnel_name: ssh ? `${format} import` : null,
        profile_count: format === "rusty-conduit" ? 0 : SAMPLE_IMPORTED.length,
        rule_count: format === "rusty-conduit-switch" ? 1 : 0,
        extracted_password_count: format === "rusty-conduit-switch" ? 1 : 0,
        warnings: [],
        notes: ssh ? ["Pick an SSH key for the Tunnel's hop before starting it."] : [],
        profiles: format === "rusty-conduit" ? [] : SAMPLE_IMPORTED,
      } satisfies TomlImportPreview;
    }
    case "commit_toml_import": {
      const { format } = mockTomlFormat(args);
      const name = String(args?.name ?? "").trim() || `${format} import`;
      if (format === "rusty-conduit-switch" && !vault.unlocked) {
        throw new ApiError("vault_locked", "Unlock the vault to store imported passwords.");
      }
      let tunnel: Tunnel | null = null;
      if (format === "rusty-conduit-ssh") {
        tunnel = sampleTunnel(crypto.randomUUID(), name, "203.0.113.5");
        tunnels = [...tunnels, { profile: tunnel, snapshot: tunnelSnapshot(tunnel, { state: "stopped" }), used_by: [] }];
      }
      const proxy = format === "rusty-conduit" ? { ...blankProxyFields(), id: NIL, name } : importedProxy(name);
      const saved = saveProxy(proxy, true);
      return {
        format,
        proxy: saved.profile,
        tunnel,
        warnings: [],
        notes: tunnel ? ["Pick an SSH key for the Tunnel's hop before starting it."] : [],
        stored_passwords: format === "rusty-conduit-switch" ? 1 : 0,
      } satisfies TomlImportCommitResult;
    }
    case "export_proxy_toml": {
      const view = findProxy({ id: args?.proxyId });
      const format = isCliFormat(args?.format) ? args.format : "rusty-conduit-switch";
      const p = view.profile;
      if (format === "rusty-conduit-ssh" && tunnelIdsOf(p).length === 0) {
        throw new ApiError("invalid", "rusty-conduit-ssh needs a Proxy that routes through one Tunnel.");
      }
      const toml = [
        `# ${p.name}, exported for ${format}`,
        "[listen]",
        `bind = "${p.listeners.bind}"`,
        `http_port = ${p.listeners.http_port}`,
        `socks_port = ${p.listeners.socks_port}`,
        ...p.profiles.flatMap((u) => [
          "",
          `[profiles.${JSON.stringify(u.name)}]`,
          `type = "${u.kind.type}"`,
          ...(u.password ? [`password_env = "RUSTY_CONDUIT_${u.name.toUpperCase().replace(/\W/g, "_")}_PASSWORD"`] : []),
        ]),
      ].join("\n");
      const notes = p.profiles.some((u) => u.password)
        ? ["Set the password_env variables before starting the CLI."]
        : [];
      return { format, toml, notes, path: (args?.path as string | null) ?? null } satisfies TomlExportResult;
    }
    case "link_proxy_external_toml":
      return setProxySource(args, {
        external_toml: { path: String(args?.path), debounce_ms: Math.min(Math.max(Number(args?.debounceMs) || 500, 250), 10_000) },
      });
    case "unlink_proxy_external_toml":
      return setProxySource(args, "managed");
    case "reload_proxy_external_toml": {
      const view = findProxy({ id: args?.proxyId });
      if (view.profile.source === "managed") throw new ApiError("invalid", "This Proxy is not linked to a TOML file.");
      return saveProxy(view.profile, false);
    }
    default:
      return NOT_HANDLED;
  }
}

function dispatchV2(command: string, args?: Record<string, unknown>): unknown {
  switch (command) {
    case "list_proxies":
      return structuredClone(proxies);
    case "upsert_proxy":
      return saveProxy(args?.profile as Proxy, false);
    case "duplicate_proxy": {
      const source = findProxy(args).profile;
      return saveProxy({ ...source, name: `${source.name} (copy)`, autostart: false }, true);
    }
    case "delete_proxy":
      findProxy(args);
      proxies = proxies.filter((p) => p.profile.id !== args?.id);
      refreshTunnelUsage();
      return null;
    case "start_proxy":
    case "restart_proxy": {
      const p = findProxy(args);
      p.snapshot = proxySnapshot(p.profile, { state: "running", override_profile: null, config_generation: p.snapshot.config_generation + 1, restart_required: false }, p.snapshot.config_generation + 1);
      return null;
    }
    case "stop_proxy": {
      const p = findProxy(args);
      p.snapshot = proxySnapshot(p.profile, { state: "stopped" });
      return null;
    }
    case "set_proxy_override": {
      const p = findProxy(args);
      if (p.snapshot.state.state !== "running") throw new ApiError("runtime", "proxy is not running");
      const override = (args?.overrideProfile as string | null) ?? null;
      p.snapshot = proxySnapshot(p.profile, { ...p.snapshot.state, override_profile: override }, p.snapshot.config_generation);
      return structuredClone(p.snapshot);
    }
    case "get_proxy_logs":
      return v2Logs(findProxy(args).profile.name);
    case "clear_proxy_logs":
    case "clear_tunnel_logs":
      return null;
    case "get_proxy_access_records":
      findProxy(args);
      return mockAccessRecords();
    case "test_route":
      return mockRouteTest(args);
    case "test_upstream": {
      const proxy = args?.proxy as Proxy;
      const name = String(args?.profileName);
      const known = name === "direct" || proxy.profiles.some((u) => u.name === name);
      return (known
        ? { ok: true, elapsed_ms: 42, redacted_upstream: name, error: null }
        : { ok: false, elapsed_ms: 0, redacted_upstream: name, error: `unknown upstream profile \`${name}\`` }) satisfies UpstreamProbeResult;
    }
    case "check_proxy_port_conflicts": {
      const bind = String(args?.bind);
      const ports = new Set([Number(args?.httpPort), Number(args?.socksPort)].filter((p) => p !== 0));
      const conflicts: PortConflict[] = [];
      for (const other of proxies) {
        if (other.profile.id === args?.proxyId || !bindsOverlap(bind, other.profile.listeners.bind)) continue;
        for (const port of [other.profile.listeners.http_port, other.profile.listeners.socks_port]) {
          if (ports.has(port)) conflicts.push({ port, kind: "session", detail: `Used by proxy "${other.profile.name}".` });
        }
      }
      return { conflicts } satisfies PortConflictReport;
    }
    case "list_profile_library":
      return structuredClone(library);
    case "upsert_library_profile": {
      const saved = structuredClone(args?.profile) as UpstreamProfile;
      library = [...library.filter((u) => u.name !== saved.name), saved];
      return structuredClone(saved);
    }
    case "delete_library_profile":
      library = library.filter((u) => u.name !== args?.name);
      return null;
    case "set_upstream_password":
      return { secret_ref: crypto.randomUUID(), has_secret: true };
    case "list_tunnels":
      return structuredClone(tunnels);
    case "upsert_tunnel": {
      const saved = structuredClone(args?.profile) as Tunnel;
      if (saved.id === NIL) saved.id = crypto.randomUUID();
      const existing = tunnels.find((t) => t.profile.id === saved.id);
      const snapshot = tunnelSnapshot(saved, existing?.snapshot.state ?? { state: "stopped" }, existing?.snapshot.linked_holders ?? 0);
      const viewed: TunnelView = { profile: saved, snapshot, used_by: existing?.used_by ?? [] };
      tunnels = existing ? tunnels.map((t) => (t.profile.id === saved.id ? viewed : t)) : [...tunnels, viewed];
      return structuredClone(saved);
    }
    case "duplicate_tunnel": {
      const source = findTunnel(args).profile;
      const copy: Tunnel = { ...structuredClone(source), id: crypto.randomUUID(), name: `${source.name} (copy)` };
      tunnels = [...tunnels, { profile: copy, snapshot: tunnelSnapshot(copy, { state: "stopped" }), used_by: [] }];
      return structuredClone(copy);
    }
    case "delete_tunnel": {
      const t = findTunnel(args);
      if (t.used_by.length > 0 && !args?.force) {
        return { deleted: false, used_by: t.used_by.length, usage: { ...NO_USAGE, proxies: t.used_by } } satisfies DeleteResult;
      }
      tunnels = tunnels.filter((v) => v.profile.id !== args?.id);
      return { deleted: true, used_by: t.used_by.length, usage: { ...NO_USAGE, proxies: t.used_by } } satisfies DeleteResult;
    }
    case "start_tunnel":
    case "restart_tunnel":
    case "approve_tunnel_host_key": {
      const t = findTunnel(args);
      t.snapshot = tunnelSnapshot(t.profile, { state: "connected" }, t.snapshot.linked_holders);
      return null;
    }
    case "stop_tunnel": {
      const t = findTunnel(args);
      t.snapshot = tunnelSnapshot(t.profile, { state: "stopped" }, t.snapshot.linked_holders);
      return null;
    }
    case "reject_tunnel_host_key": {
      const t = findTunnel(args);
      t.snapshot = tunnelSnapshot(t.profile, { state: "needs_attention", reason: "host key rejected" }, t.snapshot.linked_holders);
      return null;
    }
    case "get_tunnel_logs":
      return v2Logs(findTunnel(args).profile.name);
    case "test_tunnel_chain": {
      const t = findTunnel(args);
      return {
        tunnel_id: t.profile.id,
        all_connected: true,
        hops: t.profile.hops.map((hop, hop_index) => ({
          hop_index,
          hop_id: hop.hop_id,
          host: hop.host.host,
          port: hop.host.port,
          status: "connected",
          error: null,
          elapsed_ms: 35,
          host_key: null,
        })),
      } satisfies TunnelChainTestResult;
    }
    case "start_all_v2":
      proxies.filter((p) => p.profile.enabled).forEach((p) => dispatchV2("start_proxy", { id: p.profile.id }));
      return null;
    case "stop_all_v2":
      proxies.forEach((p) => dispatchV2("stop_proxy", { id: p.profile.id }));
      tunnels.forEach((t) => dispatchV2("stop_tunnel", { id: t.profile.id }));
      return null;
    default:
      return NOT_HANDLED;
  }
}

function dispatch(command: string, args?: Record<string, unknown>): unknown {
  switch (command) {
    case "shell_ready":
      return { tray_available: true, pending: [] } satisfies ShellSnapshot;
    case "vault_status":
      return { ...vault };
    case "list_sessions":
      return structuredClone(sessions);
    case "list_hosts":
      return [...hosts];
    case "list_forward_presets":
      return structuredClone(presets);
    case "upsert_forward_preset": {
      const saved = structuredClone(args?.preset) as ForwardPreset;
      if (!saved.id || saved.id === NIL) saved.id = crypto.randomUUID();
      presets = presets.some((p) => p.id === saved.id)
        ? presets.map((p) => (p.id === saved.id ? saved : p))
        : [...presets, saved];
      return saved;
    }
    case "delete_forward_preset":
      presets = presets.filter((p) => p.id !== args?.id);
      return null;
    case "restore_forward_presets":
      presets = [...presets, ...BUILTIN_PRESETS.filter((b) => !presets.some((p) => p.id === b.id))];
      return structuredClone(presets);
    case "list_keys":
      return [...keys];
    case "get_state_summary":
      return {
        vault: { ...vault },
        session_count: sessions.length,
        host_count: hosts.length,
        key_count: keys.length,
        sessions: sessions.map((s) => structuredClone(s.runtime)),
      } satisfies StateSummary;
    case "get_session_logs":
      return [...logs];
    case "clear_session_logs":
      logs = [];
      return null;
    case "start_session": {
      const session = find(args);
      session.runtime.state = { state: "connected" };
      session.runtime.port_forwards = forwardStatuses(session.profile);
      return null;
    }
    case "stop_session": {
      const session = find(args);
      session.runtime.state = { state: "stopped" };
      session.runtime.stats = { ...IDLE_STATS };
      session.runtime.listeners = [];
      session.runtime.remote_listeners = [];
      session.runtime.port_forwards = [];
      return null;
    }
    case "upsert_session": {
      const saved = structuredClone(args?.profile) as SessionProfile;
      const existing = sessions.find((s) => s.profile.id === saved.id);
      if (existing) {
        existing.profile = saved;
        existing.runtime.name = saved.name;
      } else {
        saved.id = crypto.randomUUID();
        sessions.push(view(saved, { state: "stopped" }));
      }
      return saved;
    }
    case "duplicate_session": {
      const copy = structuredClone(find(args).profile);
      copy.id = crypto.randomUUID();
      copy.name = `${copy.name.trim()} (copy)`;
      copy.autostart = false;
      for (const hop of copy.hops) {
        const old = hop.hop_id;
        hop.hop_id = crypto.randomUUID();
        const pin = pins.find(({ key }) => key.hop_id === old && key.host === hop.host.host && key.port === hop.host.port);
        if (pin) pins = [...pins, { ...structuredClone(pin), key: { ...pin.key, hop_id: hop.hop_id } }];
      }
      sessions.push(view(copy, { state: "stopped" }));
      return structuredClone(copy);
    }
    case "delete_session": {
      const session = find(args);
      sessions.splice(sessions.indexOf(session), 1);
      const hopIds = new Set(session.profile.hops.map((hop) => hop.hop_id));
      pins = pins.filter(({ key }) => !hopIds.has(key.hop_id));
      return null;
    }
    case "test_chain": {
      // Stops at the first hop without a pin, like the real test, offering a demo key to trust.
      const session = find(args);
      let broken = false;
      const hops = session.profile.hops.map((hop, hop_index) => {
        const base = { hop_index, hop_id: hop.hop_id, host: hop.host.host, port: hop.host.port };
        if (broken) return { ...base, status: "not_attempted", error: null, elapsed_ms: 0, host_key: null };
        const pinned = pins.some(
          ({ key }) => key.hop_id === hop.hop_id && key.host === hop.host.host && key.port === hop.host.port,
        );
        if (pinned) return { ...base, status: "connected", error: null, elapsed_ms: 25, host_key: null };
        broken = true;
        const host_key = { ...base, algorithm: "ssh-ed25519", sha256: `SHA256:demoKey${hop_index}ForPreviewOnly`, public_key_openssh: null };
        testedKeys.set(session.profile.id, host_key);
        return { ...base, status: "host_key_unknown", error: "unknown host key", elapsed_ms: 20, host_key };
      });
      return { session_id: session.profile.id, all_connected: !broken, hops };
    }
    case "trust_tested_host_key": {
      const seen = testedKeys.get(String(args?.id));
      if (!seen) throw new ApiError("not_found", "tested host key not found");
      if (seen.sha256 !== args?.sha256) throw new ApiError("invalid", "the host key changed since it was shown");
      testedKeys.delete(String(args?.id));
      const entry: HostKeyEntry = {
        key: { hop_id: seen.hop_id, host: seen.host, port: seen.port },
        record: {
          algorithm: seen.algorithm,
          fingerprint_sha256: seen.sha256,
          first_seen: Math.floor(Date.now() / 1000),
          approved: true,
          public_key_openssh: null,
        },
      };
      pins = [...pins, entry];
      return structuredClone(entry);
    }
    case "list_host_key_pins":
      return structuredClone(pins);
    case "reset_host_key": {
      const before = pins.length;
      pins = pins.filter(
        ({ key }) => !(key.hop_id === args?.hopId && key.host === args?.host && key.port === args?.port),
      );
      return pins.length !== before;
    }
    case "import_known_host": {
      // The preview cannot read files; any non-empty path imports a demo key.
      if (!String(args?.path ?? "").trim()) throw new ApiError("io", "cannot read : no such file");
      const entry: HostKeyEntry = {
        key: { hop_id: String(args?.hopId), host: String(args?.host), port: Number(args?.port) },
        record: {
          algorithm: "ssh-ed25519",
          fingerprint_sha256: "SHA256:demoImportedHostKeyForPreviewOnly",
          first_seen: Math.floor(Date.now() / 1000),
          approved: true,
          public_key_openssh: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMAKvbC1OkNvrNiAjJ6wli5nNQS5707OnbcrowxpV2Q",
        },
      };
      pins = [
        ...pins.filter(
          ({ key }) =>
            !(key.hop_id === entry.key.hop_id && key.host === entry.key.host && key.port === entry.key.port),
        ),
        entry,
      ];
      return structuredClone(entry);
    }
    case "set_password_secret":
      return { secret_ref: crypto.randomUUID(), has_secret: true };
    case "list_mitm_cas":
      return cas.map((ca) => {
        const users = sessions.filter((s) => s.profile.mitm?.ca === ca.id);
        const refs = users.map((s) => ({ id: s.profile.id, name: s.profile.name }));
        return { ...ca, used_by: refs.length, usage: { hosts: [], sessions: refs, tunnels: [], proxies: [], library_profiles: [] } } satisfies CaView;
      });
    case "import_mitm_ca": {
      const now = Math.floor(Date.now() / 1000);
      const ca: CaView = {
        id: crypto.randomUUID(),
        name: String(args?.name),
        subject: "CN=Preview Upload CA",
        not_after: now + 365 * 86_400,
        fingerprint_sha256: `SHA256:preview${cas.length}`,
        created_at: now,
        used_by: 0,
        usage: { hosts: [], sessions: [], tunnels: [], proxies: [], library_profiles: [] },
      };
      cas = [...cas, ca];
      return ca;
    }
    case "rename_mitm_ca":
      cas = cas.map((c) => (c.id === args?.id ? { ...c, name: String(args?.name) } : c));
      return cas.find((c) => c.id === args?.id);
    case "delete_mitm_ca": {
      const ca = cas.find((c) => c.id === args?.id);
      if (!ca) throw new ApiError("not_found", "MITM CA not found");
      const users = sessions.filter((s) => s.profile.mitm?.ca === ca.id);
      const usage = { hosts: [], sessions: users.map((s) => ({ id: s.profile.id, name: s.profile.name })) };
      if (users.length > 0 && !args?.force) return { deleted: false, used_by: users.length, usage } satisfies DeleteResult;
      for (const s of users) {
        if (s.profile.mitm) s.profile.mitm.ca = null;
        s.runtime.state = { state: "stopped" };
      }
      cas = cas.filter((c) => c.id !== ca.id);
      return { deleted: true, used_by: users.length, usage } satisfies DeleteResult;
    }
    case "delete_secret":
      return { deleted: true, used_by: 0, usage: { hosts: [], sessions: [], tunnels: [], proxies: [], library_profiles: [] } } satisfies DeleteResult;
    case "upsert_host": {
      const saved = structuredClone(args?.host) as HostProfile;
      if (saved.id === NIL) saved.id = crypto.randomUUID();
      hosts = hosts.some((h) => h.id === saved.id)
        ? hosts.map((h) => (h.id === saved.id ? saved : h))
        : [...hosts, saved];
      for (const session of sessions) {
        for (const hop of session.profile.hops) if (hop.host.id === saved.id) hop.host = structuredClone(saved);
      }
      return saved;
    }
    case "delete_host":
      hosts = hosts.filter((h) => h.id !== args?.id);
      for (const session of sessions) {
        for (const hop of session.profile.hops) if (hop.host.id === args?.id) hop.host.id = NIL;
      }
      return null;
    case "promote_hop_to_host": {
      const hop = sessions
        .find((s) => s.profile.id === args?.sessionId)
        ?.profile.hops.find((h) => h.hop_id === args?.hopId);
      if (!hop) throw new ApiError("not_found", "hop not found");
      const host: HostProfile = {
        ...structuredClone(hop.host),
        id: crypto.randomUUID(),
        name: (args?.name as string | null) || hop.name,
      };
      hop.host.id = host.id;
      hop.host.name = host.name;
      hosts = [...hosts, host];
      return host;
    }
    case "resolve_close":
      return null;
    case "create_vault":
      vault.initialized = true;
      vault.unlocked = true;
      vault.keyring = Boolean(args?.useKeyring);
      return { ...vault };
    case "set_vault_keyring":
      vault.keyring = Boolean(args?.enabled);
      return { ...vault };
    case "unlock_vault":
    case "unlock_vault_keyring":
      vault.unlocked = true;
      return { ...vault };
    case "lock_vault":
      vault.unlocked = false;
      return { ...vault };
    case "change_master_password":
      if (!vault.initialized) throw new ApiError("vault_not_initialized", "vault has not been created");
      vault.unlocked = true;
      return { ...vault };
    case "generate_key":
    case "import_key_pem": {
      const generated = command === "generate_key";
      const algorithm = args?.algorithm === "ecdsa-p256" ? "ECDSA-P256" : "ssh-ed25519";
      const id = crypto.randomUUID();
      const key: KeyView = {
        id,
        name: String(args?.name),
        algorithm,
        fingerprint_sha256: `SHA256:preview${id.slice(0, 8)}`,
        public_key_openssh: `${algorithm} AAAApreview ${id.slice(0, 8)}`,
        source: generated ? "Generated" : (args?.source as KeyView["source"]),
        created_at: Math.floor(Date.now() / 1000),
        used_by: 0,
        usage: { hosts: [], sessions: [], tunnels: [], proxies: [], library_profiles: [] },
      };
      keys = [...keys, key];
      return key;
    }
    case "rename_key":
      keys = keys.map((k) => (k.id === args?.id ? { ...k, name: String(args?.name) } : k));
      return keys.find((k) => k.id === args?.id);
    case "delete_key": {
      const key = keys.find((k) => k.id === args?.id);
      if (!key) throw new ApiError("not_found", "key not found");
      if (key.used_by > 0 && !args?.force) {
        return { deleted: false, used_by: key.used_by, usage: key.usage } satisfies DeleteResult;
      }
      keys = keys.filter((k) => k.id !== key.id);
      return { deleted: true, used_by: key.used_by, usage: key.usage } satisfies DeleteResult;
    }
    case "get_autostart":
      return { enabled: autostart, executable: "/opt/preview/app", args: ["--tray"] };
    case "set_autostart":
      autostart = Boolean(args?.enabled);
      return { enabled: autostart, executable: "/opt/preview/app", args: ["--tray"] };
    case "check_port_conflicts":
      return mockPortConflicts(args);
    case "test_filter_rules":
      return mockFilterTest(args);
    case "check_openssh_binary":
      return mockOpensshCheck(args);
    case "export_config": {
      const withSecrets = Boolean(args?.includeSecrets);
      return {
        path: String(args?.path),
        encrypted: args?.passphrase != null,
        with_secrets: withSecrets,
        session_count: sessions.length,
        host_count: hosts.length,
        key_count: keys.length,
        ca_count: cas.length,
        proxy_count: proxies.length,
        tunnel_count: tunnels.length,
        library_profile_count: library.length,
        secret_count: withSecrets ? keys.length + cas.length : 0,
        missing_secrets: 0,
      } satisfies ExportSummary;
    }
    case "import_config":
      return {
        encrypted: args?.passphrase != null,
        with_secrets: false,
        sessions_added: 0,
        sessions_updated: 0,
        sessions_skipped: sessions.length,
        hosts_added: 0,
        presets_added: 0,
        presets_updated: 0,
        presets_skipped: 0,
        proxies_added: 0,
        proxies_updated: 0,
        proxies_skipped: proxies.length,
        tunnels_added: 0,
        tunnels_updated: 0,
        tunnels_skipped: tunnels.length,
        library_profiles_added: 0,
        library_profiles_updated: 0,
        library_profiles_skipped: library.length,
        hosts_updated: 0,
        hosts_skipped: hosts.length,
        keys_added: 0,
        keys_skipped: 0,
        key_only_backup: false,
        cas_added: 0,
        secrets_added: 0,
        known_hosts_added: 0,
        known_hosts_updated: 0,
        credentials_removed: 0,
      } satisfies ImportSummary;
    case "approve_host_key":
      find(args).runtime.state = { state: "connected" };
      return null;
    case "reject_host_key":
      find(args).runtime.state = { state: "needs_attention", reason: "host key rejected" };
      return null;
    default: {
      const handled = dispatchV2(command, args);
      if (handled !== NOT_HANDLED) return handled;
      const u4 = dispatchU4(command, args);
      if (u4 !== NOT_HANDLED) return u4;
      throw new ApiError("invalid", `"${command}" is not available in the browser preview.`);
    }
  }
}

export async function mockInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return dispatch(command, args) as T;
}
