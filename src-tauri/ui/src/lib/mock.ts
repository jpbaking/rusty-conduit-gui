// Sample data for `npm run dev` in a plain browser. Only loaded in development builds. It ignores
// every secret argument and uses documentation-only addresses (RFC 5737).

import { ApiError } from "./api";
import type {
  DeleteResult,
  ExportSummary,
  FilterTestResult,
  HostKeyEntry,
  HostKeyPrompt,
  HostProfile,
  ImportSummary,
  KeyView,
  LogLine,
  MitmCaInfo,
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
    hops: [{ hop_id: `${id}-hop`, name, host: hostProfile, agent_forward: false, agent_forward_keys: [], agent_forward_command: null }],
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
  };
  return { profile: p, runtime };
}

const sessions: SessionView[] = [
  view(withReverse(profile("11111111-1111-4111-8111-111111111111", "Staging bastion", "192.0.2.10", 3128), 8080), { state: "connected" }, 3),
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

const vault: VaultStatus = { initialized: true, unlocked: true };
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
    usage: { hosts: [], sessions: [] },
  },
];
let autostart = false;
let hosts: HostProfile[] = [];
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
  };
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
      return null;
    }
    case "stop_session": {
      const session = find(args);
      session.runtime.state = { state: "stopped" };
      session.runtime.stats = { ...IDLE_STATS };
      session.runtime.listeners = [];
      session.runtime.remote_listeners = [];
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
    case "set_mitm_passphrase": {
      const session = sessions.find((s) => s.profile.id === args?.sessionId);
      if (!session?.profile.mitm) throw new ApiError("invalid", "this session has no MITM configuration");
      const secret_ref = crypto.randomUUID();
      session.profile.mitm.passphrase = secret_ref;
      return { secret_ref, has_secret: true };
    }
    case "delete_secret":
      return { deleted: true, used_by: 0, usage: { hosts: [], sessions: [] } } satisfies DeleteResult;
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
      return { ...vault };
    case "unlock_vault":
    case "unlock_vault_keyring":
      vault.unlocked = true;
      return { ...vault };
    case "lock_vault":
      vault.unlocked = false;
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
        usage: { hosts: [], sessions: [] },
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
    case "export_backup":
      return { path: String(args?.path), key_count: keys.length };
    case "import_backup":
      return { imported: [], skipped: keys.length };
    case "check_port_conflicts":
      return mockPortConflicts(args);
    case "test_filter_rules":
      return mockFilterTest(args);
    case "inspect_mitm_ca":
      return {
        subject: "CN=Preview CA",
        not_after: new Date(Date.now() + 90 * 86_400_000).toISOString(),
        expired: false,
        days_remaining: 90,
      } satisfies MitmCaInfo;
    case "check_openssh_binary":
      return mockOpensshCheck(args);
    case "export_config": {
      const encrypted = Boolean(args?.includeSecrets);
      return {
        path: String(args?.path),
        encrypted,
        session_count: sessions.length,
        host_count: hosts.length,
        key_count: keys.length,
        secret_count: encrypted ? keys.length : 0,
        missing_secrets: 0,
      } satisfies ExportSummary;
    }
    case "import_config":
      return {
        encrypted: args?.passphrase != null,
        sessions_added: 0,
        sessions_updated: 0,
        sessions_skipped: sessions.length,
        hosts_added: 0,
        hosts_updated: 0,
        hosts_skipped: hosts.length,
        keys_added: 0,
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
    default:
      throw new ApiError("invalid", `"${command}" is not available in the browser preview.`);
  }
}

export async function mockInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return dispatch(command, args) as T;
}
