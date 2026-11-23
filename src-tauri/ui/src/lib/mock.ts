// Sample data for `npm run dev` in a plain browser. Only loaded in development builds. It ignores
// every secret argument and uses documentation-only addresses (RFC 5737).

import { ApiError } from "./api";
import type {
  DeleteResult,
  HostKeyEntry,
  HostProfile,
  KeyView,
  LogLine,
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
    engine: "Russh",
    hops: [{ hop_id: `${id}-hop`, name, host: hostProfile, agent_forward: false }],
    forward: {
      bind: "127.0.0.1",
      http_port: httpPort,
      socks_port: httpPort + 1,
      max_connections: 4096,
      allow: [],
      block: [],
    },
    reverse: {
      reverse_bind: "127.0.0.1",
      reverse_http_port: 0,
      reverse_socks_port: 0,
      reverse_allow: [],
      reverse_block: [],
    },
    mitm: null,
    tunnel: {
      ip_version: "4",
      server_alive_interval: 15,
      server_alive_count_max: 3,
      no_reconnect: false,
      reconnect_initial_delay: 1,
      reconnect_max_delay: 30,
      startup_timeout: 30,
    },
    logging: { level: "INFO", format: "text", http_access_log: null, socks_log: null },
    openssh: { ssh_bin: "ssh", ssh_socks_bind: "127.0.0.1", ssh_socks_port: 0, extra_args: [] },
  };
}

function view(p: SessionProfile, state: SessionState, active = 0): SessionView {
  const connected = state.state === "connected";
  const runtime: SessionSnapshot = {
    id: p.id,
    name: p.name,
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
      ? [{ role: "http", addr: `${p.forward.bind}:${p.forward.http_port}` }]
      : [],
  };
  return { profile: p, runtime };
}

const sessions: SessionView[] = [
  view(profile("11111111-1111-4111-8111-111111111111", "Staging bastion", "192.0.2.10", 3128), { state: "connected" }, 3),
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
    case "test_chain": {
      const session = find(args);
      return {
        session_id: session.profile.id,
        all_connected: true,
        hops: session.profile.hops.map((hop, hop_index) => ({
          hop_index,
          hop_id: hop.hop_id,
          host: hop.host.host,
          port: hop.host.port,
          status: "connected",
          error: null,
          elapsed_ms: 25,
        })),
      };
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
    case "set_password_secret":
      return { secret_ref: crypto.randomUUID(), has_secret: true };
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
