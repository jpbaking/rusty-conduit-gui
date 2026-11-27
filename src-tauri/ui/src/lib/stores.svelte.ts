// Reactive application state. Holds metadata only: no secret ever enters this store.

import { api, errorMessage, subscribeShellEvents, subscribeV2Events } from "./api";
import { authRefs, blankHost, profileRefs } from "./chain";
import { isActive } from "./format";
import { hostErrors, proxyErrors, sessionErrors, tunnelErrors, type FieldErrors } from "./validate";
import type {
  AuthMethod,
  CaView,
  ChainTestResult,
  CloseChoice,
  HopEntry,
  HostKeyEntry,
  HostKeyPrompt,
  ForwardPreset,
  HostProfile,
  KeyId,
  KeyView,
  MigrationNoticePayload,
  MitmCaId,
  Proxy,
  ProxyEvent,
  ProxyId,
  ProxySaveResult,
  ProxySnapshot,
  ProxyView,
  RouteInbound,
  RouteTestResult,
  RuntimeEvent,
  Tunnel,
  TunnelChainTestResult,
  TunnelEvent,
  TunnelId,
  TunnelSnapshot,
  TunnelView,
  UpstreamProbeResult,
  UpstreamProfile,
  SessionProfile,
  SessionSnapshot,
  SessionView,
  UiEvent,
  Usage,
  Uuid,
  VaultStatus,
} from "./types";

/**
 * The sidebar's active section. `proxy`, `tunnel`, `profileLibrary`, and `vault` are the v2
 * sections; `sessions` and `keys` stay until the v2 components replace the v1 ones.
 */
export type NavView =
  | "proxy"
  | "tunnel"
  | "hosts"
  | "profileLibrary"
  | "vault"
  | "settings"
  | "sessions"
  | "keys";

/** A starting point offered by the New Proxy wizard. */
export type ProxyPreset = "direct" | "tunnel" | "switch";

/** What the log drawer shows. Proxy, Tunnel, and session ids never collide (all UUIDs). */
export type LogTarget =
  | { kind: "proxy"; id: ProxyId }
  | { kind: "tunnel"; id: TunnelId }
  | { kind: "session"; id: Uuid };

/** The outcome of the latest Proxy save, for the `gen #N · hot-reloaded` header. */
export interface ProxySaveNote {
  proxyId: ProxyId;
  configGeneration: number;
  reloaded: boolean;
  reloadError: string | null;
}
/**
 * A Log drawer quick action handed to the Proxy editor: open the Route Tester with `host`, or
 * open the Routing Rules tab with a new draft rule for `host`. `nonce` makes repeats distinct.
 */
export interface ProxyQuickAction {
  kind: "test_route" | "create_rule";
  proxyId: ProxyId;
  host: string;
  inbound: RouteInbound;
  nonce: number;
}
export type ClosePrompt = "close" | "quit";

export interface PendingHostKey {
  sessionId: Uuid;
  sessionName: string;
  prompt: HostKeyPrompt;
  /** `session`: a running session waits for the answer. `test`: Test Chain stopped at the key. */
  source: "session" | "test";
}

/** The id of a session that has not been saved yet. The backend assigns a real one. */
export const NEW_SESSION_ID: Uuid = "00000000-0000-0000-0000-000000000000";

const NIL_HOST_ID: Uuid = NEW_SESSION_ID;
const POLL_INTERVAL_MS = 2_000;

type StateChangedEvent = Extract<RuntimeEvent, { event: "state_changed" }>;
type V2Event = { kind: "proxy"; event: ProxyEvent } | { kind: "tunnel"; event: TunnelEvent };

const DEFAULT_LOGGING = { level: "INFO", format: "text", http_access_log: null, socks_log: null };

function blankTunnel(): Tunnel {
  const session = blankProfile();
  return {
    id: NEW_SESSION_ID,
    name: "New tunnel",
    enabled: true,
    start_mode: "linked",
    engine: session.engine,
    hops: [],
    forward: { ...session.forward, enabled: false, http_port: 0, socks_port: 0 },
    reverse: session.reverse,
    port_forwards: [],
    mitm: null,
    socks_block_web: false,
    keepalive: session.tunnel,
    logging: { ...DEFAULT_LOGGING },
    openssh: session.openssh,
  };
}

function blankProxy(name: string, httpPort: number, socksPort: number): Proxy {
  return {
    id: NEW_SESSION_ID,
    name,
    enabled: true,
    autostart: false,
    source: "managed",
    listeners: { bind: "127.0.0.1", http_port: httpPort, socks_port: socksPort, max_connections: 4096 },
    network: { connect_timeout: 10, tcp_keepalive: 60, tcp_keepalive_interval: 10, tcp_keepalive_retries: 5 },
    profiles: [],
    routing: { default: "direct", resolve_dns: false, rules: [] },
    filter: "off",
    socks_block_web: false,
    mitm: null,
    logging: { ...DEFAULT_LOGGING },
  };
}

/** A profile name derived from a Tunnel's name: lower case, words joined by `-`. */
export function tunnelProfileName(tunnelName: string): string {
  const slug = tunnelName.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return slug && slug !== "direct" && slug !== "block" ? slug : "tunnel";
}

/** Vault records an upstream profile's password points at. */
export const proxySecretRefs = (proxy: Proxy): string[] =>
  proxy.profiles.flatMap((p) => (p.password && "vault" in p.password ? [p.password.vault] : []));

const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** Applies a Proxy event to its snapshot. Returns the snapshot unchanged if nothing applies. */
export function applyProxyEvent(snapshot: ProxySnapshot, event: ProxyEvent): ProxySnapshot {
  switch (event.event) {
    case "state_changed": {
      const { state } = event;
      return state.state === "running"
        ? {
            ...snapshot,
            state,
            override_profile: state.override_profile,
            config_generation: state.config_generation,
            restart_required: state.restart_required,
          }
        : { ...snapshot, state };
    }
    case "reloaded": {
      const state =
        snapshot.state.state === "running"
          ? { ...snapshot.state, config_generation: event.config_generation }
          : snapshot.state;
      return { ...snapshot, state, config_generation: event.config_generation };
    }
    case "override_changed": {
      const state =
        snapshot.state.state === "running"
          ? { ...snapshot.state, override_profile: event.override_profile }
          : snapshot.state;
      return { ...snapshot, state, override_profile: event.override_profile };
    }
  }
}

function blankProfile(): SessionProfile {
  return {
    id: NEW_SESSION_ID,
    name: "New session",
    autostart: false,
    enabled: true,
    engine: "Russh",
    hops: [],
    forward: {
      enabled: true,
      bind: "127.0.0.1",
      http_port: 3128,
      socks_port: 1080,
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

const sameProfile = (a: SessionProfile, b: SessionProfile) =>
  JSON.stringify(a) === JSON.stringify(b);

const usesKey = (auth: AuthMethod[], id: KeyId) =>
  auth.some((method) => typeof method === "object" && "Key" in method && method.Key.key === id);

const withoutKey = (auth: AuthMethod[], id: KeyId) =>
  auth.filter((method) => !(typeof method === "object" && "Key" in method && method.Key.key === id));

const hopUsesKey = (hop: HopEntry, id: KeyId) => usesKey(hop.host.auth, id);

class AppStore {
  // Backend data. Replaced whole, so `$state.raw` avoids deep proxies and IPC clone problems.
  sessions = $state.raw<SessionView[]>([]);
  hosts = $state.raw<HostProfile[]>([]);
  presets = $state.raw<ForwardPreset[]>([]);
  keys = $state.raw<KeyView[]>([]);
  cas = $state.raw<CaView[]>([]);
  pins = $state.raw<HostKeyEntry[]>([]);
  proxies = $state.raw<ProxyView[]>([]);
  tunnels = $state.raw<TunnelView[]>([]);
  profileLibrary = $state.raw<UpstreamProfile[]>([]);
  vault = $state.raw<VaultStatus>({ initialized: false, unlocked: false, keyring: false });
  /** False until the backend has reported the vault, so a failed load never offers "create". */
  vaultKnown = $state(false);

  // Navigation and selection.
  view = $state<NavView>("sessions");
  selectedId = $state<Uuid | null>(null);
  search = $state("");
  /** Unsaved edits by session id, so switching sessions does not lose them. */
  drafts = $state.raw<Record<Uuid, SessionProfile>>({});
  selectedHopId = $state<string | null>(null);
  /** The host profile being created or edited. */
  hostDraft = $state.raw<HostProfile | null>(null);
  savingHost = $state(false);

  // v2 selection and drafts. A new Proxy or Tunnel is keyed by `NEW_SESSION_ID` until saved.
  selectedProxyId = $state<ProxyId | null>(null);
  selectedTunnelId = $state<TunnelId | null>(null);
  proxyDrafts = $state.raw<Record<ProxyId, Proxy>>({});
  tunnelDrafts = $state.raw<Record<TunnelId, Tunnel>>({});
  savingProxy = $state(false);
  savingTunnel = $state(false);
  proxySaveNote = $state.raw<ProxySaveNote | null>(null);
  routeTest = $state.raw<RouteTestResult | null>(null);
  upstreamTest = $state.raw<UpstreamProbeResult | null>(null);
  tunnelChainResult = $state.raw<TunnelChainTestResult | null>(null);
  /** A Log drawer quick action the Proxy editor has not picked up yet. */
  proxyQuickAction = $state.raw<ProxyQuickAction | null>(null);
  #quickActionNonce = 0;
  /** What the log drawer shows while `logsOpen`. */
  logTarget = $state.raw<LogTarget | null>(null);

  // Shell.
  loaded = $state(false);
  trayAvailable = $state(true);
  trayBannerDismissed = $state(false);
  clipboardUrl = $state<string | null>(null);
  closePrompt = $state<ClosePrompt | null>(null);
  unlockRequested = $state(false);
  /** Waits for the vault to open; see `runUnlocked`. */
  #afterUnlock: (() => void) | null = null;
  logsOpen = $state(false);
  notice = $state<string | null>(null);
  migrationNotice = $state<MigrationNoticePayload | null>(null);

  // Header actions.
  saving = $state(false);
  toggling = $state(false);
  testing = $state(false);
  chainResult = $state.raw<ChainTestResult | null>(null);

  filteredSessions = $derived.by(() => {
    const query = this.search.trim().toLowerCase();
    if (!query) return this.sessions;
    return this.sessions.filter(({ profile }) =>
      [profile.name, ...profile.hops.map((hop) => hop.host.host)].some((text) =>
        text.toLowerCase().includes(query),
      ),
    );
  });

  selected = $derived(this.sessions.find((s) => s.profile.id === this.selectedId) ?? null);

  /** The profile being edited: unsaved changes if there are any, otherwise the saved one. */
  draft = $derived.by<SessionProfile | null>(() => {
    if (this.selectedId === null) return null;
    return this.drafts[this.selectedId] ?? this.selected?.profile ?? null;
  });

  /** The hop open in the editor. Falls back to the first hop if the choice no longer exists. */
  selectedHop = $derived.by<HopEntry | null>(() => {
    const hops = this.draft?.hops ?? [];
    return hops.find((hop) => hop.hop_id === this.selectedHopId) ?? hops[0] ?? null;
  });

  draftErrors = $derived<FieldErrors>(this.draft ? sessionErrors(this.draft) : {});
  draftValid = $derived(Object.keys(this.draftErrors).length === 0);

  hostDraftErrors = $derived.by<FieldErrors>(() => {
    if (!this.hostDraft) return {};
    const errors = hostErrors(this.hostDraft);
    if (!this.hostDraft.name.trim()) errors.name = "Enter a profile name.";
    return errors;
  });

  selectedProxy = $derived(this.proxies.find((p) => p.profile.id === this.selectedProxyId) ?? null);
  selectedTunnel = $derived(
    this.tunnels.find((t) => t.profile.id === this.selectedTunnelId) ?? null,
  );

  /** The Proxy being edited: unsaved changes if there are any, otherwise the saved one. */
  proxyDraft = $derived.by<Proxy | null>(() => {
    if (this.selectedProxyId === null) return null;
    return this.proxyDrafts[this.selectedProxyId] ?? this.selectedProxy?.profile ?? null;
  });

  tunnelDraft = $derived.by<Tunnel | null>(() => {
    if (this.selectedTunnelId === null) return null;
    return this.tunnelDrafts[this.selectedTunnelId] ?? this.selectedTunnel?.profile ?? null;
  });

  proxyDirty = $derived(this.selectedProxyId !== null && this.selectedProxyId in this.proxyDrafts);
  tunnelDirty = $derived(
    this.selectedTunnelId !== null && this.selectedTunnelId in this.tunnelDrafts,
  );
  knownTunnelIds = $derived(this.tunnels.map((t) => t.profile.id));
  proxyDraftErrors = $derived<FieldErrors>(
    this.proxyDraft ? proxyErrors(this.proxyDraft, this.tunnels.map((t) => t.profile)) : {},
  );
  proxyDraftValid = $derived(Object.keys(this.proxyDraftErrors).length === 0);
  tunnelDraftErrors = $derived<FieldErrors>(this.tunnelDraft ? tunnelErrors(this.tunnelDraft) : {});
  tunnelDraftValid = $derived(Object.keys(this.tunnelDraftErrors).length === 0);

  showUnlock = $derived(
    this.loaded && this.vaultKnown && this.unlockRequested && !this.vault.unlocked,
  );

  isNew = $derived(this.selectedId === NEW_SESSION_ID);
  dirty = $derived(this.selectedId !== null && this.selectedId in this.drafts);
  selectedActive = $derived(this.selected ? isActive(this.selected.runtime.state) : false);

  /** The selected session's host-key prompt if it has one, otherwise the first waiting. */
  pendingHostKey = $derived.by<PendingHostKey | null>(() => {
    const waiting = this.sessions.filter((s) => s.runtime.state.state === "awaiting_host_key");
    const session = waiting.find((s) => s.profile.id === this.selectedId) ?? waiting[0];
    if (!session || session.runtime.state.state !== "awaiting_host_key") return null;
    const { state: _state, ...prompt } = session.runtime.state;
    return { sessionId: session.profile.id, sessionName: session.profile.name, prompt, source: "session" };
  });

  /** An unknown key the latest Test Chain run stopped at, until the user trusts or rejects it. */
  testHostKey = $state.raw<PendingHostKey | null>(null);

  #unlisten: (() => void) | null = null;
  #pollTimer: ReturnType<typeof setInterval> | null = null;
  #started = false;
  #snapshotsInFlight = 0;
  /** Events received while a snapshot was loading. They may be newer than that snapshot. */
  #eventsDuringSnapshot: StateChangedEvent[] = [];
  #v2EventsDuringSnapshot: V2Event[] = [];
  /** Password records no longer used by an edit. Deleted once nothing saved refers to them. */
  #orphanedSecrets = new Set<string>();

  /** Attaches listeners first, then tells the backend it may flush queued events. */
  async start(): Promise<void> {
    if (this.#started) return;
    this.#started = true;
    try {
      const unlisten = await subscribeStore(this);
      if (!this.#started) {
        unlisten();
        return;
      }
      this.#unlisten = unlisten;
      const shell = await api.shellReady();
      this.trayAvailable = shell.tray_available;
      shell.pending.forEach((event) => this.handleUiEvent(event));
    } catch (error) {
      this.notice = errorMessage(error);
    }
    if (!this.#started) return;
    const refreshed = await this.refresh();
    if (refreshed && !this.vault.unlocked) this.unlockRequested = true;
    this.loaded = true;
    this.#pollTimer = setInterval(() => void this.pollRuntime(), POLL_INTERVAL_MS);
  }

  stop(): void {
    this.#started = false;
    this.#unlisten?.();
    this.#unlisten = null;
    if (this.#pollTimer !== null) clearInterval(this.#pollTimer);
    this.#pollTimer = null;
  }

  /** Reloads everything from the backend. Returns whether the load succeeded. */
  async refresh(): Promise<boolean> {
    this.#snapshotsInFlight += 1;
    try {
      const [sessions, hosts, presets, keys, cas, vault, pins, proxies, tunnels, library] =
        await Promise.all([
          api.listSessions(),
          api.listHosts(),
          api.listForwardPresets(),
          api.listKeys(),
          api.listMitmCas(),
          api.vaultStatus(),
          api.listHostKeyPins(),
          api.listProxies(),
          api.listTunnels(),
          api.listProfileLibrary(),
        ]);
      this.proxies = proxies;
      this.tunnels = tunnels;
      this.profileLibrary = library;
      this.#reconcileV2Selection();
      this.sessions = sessions;
      this.hosts = hosts;
      this.presets = presets;
      this.keys = keys;
      this.cas = cas;
      this.setVault(vault);
      this.pins = pins;
      this.#reconcileSelection();
      return true;
    } catch (error) {
      this.notice = errorMessage(error);
      return false;
    } finally {
      this.#finishSnapshot();
    }
  }

  setVault(status: VaultStatus): void {
    this.vault = status;
    this.vaultKnown = true;
    if (status.unlocked) {
      this.unlockRequested = false;
      const pending = this.#afterUnlock;
      this.#afterUnlock = null;
      if (pending) queueMicrotask(pending);
    }
  }

  requestUnlock(): void {
    this.unlockRequested = true;
  }

  dismissUnlock(): void {
    this.unlockRequested = false;
    this.#afterUnlock = null;
  }

  /**
   * Runs `action` now if the vault is unlocked. Otherwise asks to unlock, then runs it once the
   * vault opens; dismissing the prompt drops it.
   */
  runUnlocked(action: () => void): void {
    if (this.vault.unlocked) {
      action();
      return;
    }
    this.#afterUnlock = action;
    this.requestUnlock();
  }

  /** Names of unsaved edits that would lose this key if it is deleted. */
  draftsUsingKey(id: KeyId): string[] {
    const names = Object.values(this.drafts)
      .filter((profile) => profile.hops.some((hop) => hopUsesKey(hop, id)))
      .map((profile) => profile.name);
    if (this.hostDraft && usesKey(this.hostDraft.auth, id)) names.push(this.hostDraft.name);
    return names;
  }

  /**
   * Deletes a key the user confirmed. Forces only past references they were shown: if anything
   * new refers to the key, nothing is deleted and the fresh usage is returned to confirm again.
   */
  async deleteKey(id: KeyId, confirmed: Usage): Promise<Usage | null> {
    const first = await api.deleteKey(id);
    if (!first.deleted) {
      const seen = new Set([...confirmed.hosts, ...confirmed.sessions].map((ref) => ref.id));
      const current = [...first.usage.hosts, ...first.usage.sessions];
      if (current.some((ref) => !seen.has(ref.id))) return first.usage;
      const forced = await api.deleteKey(id, true);
      if (!forced.deleted) return forced.usage;
    }
    this.#mapDraftHops((hop) =>
      hopUsesKey(hop, id)
        ? {
            ...hop,
            host: { ...hop.host, auth: withoutKey(hop.host.auth, id) },
          }
        : hop,
    );
    if (this.hostDraft && usesKey(this.hostDraft.auth, id)) {
      this.hostDraft = { ...this.hostDraft, auth: withoutKey(this.hostDraft.auth, id) };
    }
    await this.refresh();
    return null;
  }

  /** Names of unsaved edits whose MITM uses this CA. */
  draftsUsingCa(id: MitmCaId): string[] {
    return Object.values(this.drafts)
      .filter((profile) => profile.mitm?.ca === id)
      .map((profile) => profile.name);
  }

  /**
   * Deletes a CA the user confirmed, with the same contract as {@link deleteKey}. Sessions that
   * used it keep MITM on with no CA, so they cannot start until another is chosen.
   */
  async deleteMitmCa(id: MitmCaId, confirmed: Usage): Promise<Usage | null> {
    const first = await api.deleteMitmCa(id);
    if (!first.deleted) {
      const seen = new Set(confirmed.sessions.map((ref) => ref.id));
      if (first.usage.sessions.some((ref) => !seen.has(ref.id))) return first.usage;
      const forced = await api.deleteMitmCa(id, true);
      if (!forced.deleted) return forced.usage;
    }
    const drafts = Object.entries(this.drafts).map(([key, profile]) => [
      key,
      profile.mitm?.ca === id ? { ...profile, mitm: { ...profile.mitm, ca: null } } : profile,
    ]);
    this.drafts = Object.fromEntries(drafts);
    await this.refresh();
    return null;
  }

  /** Stats and vault state have no events, so they are polled while the page is visible. */
  async pollRuntime(): Promise<void> {
    if (document.hidden || this.#snapshotsInFlight > 0) return;
    this.#snapshotsInFlight += 1;
    let needsReload = false;
    try {
      const summary = await api.getStateSummary();
      this.setVault(summary.vault);
      needsReload =
        summary.session_count !== this.sessions.length ||
        summary.host_count !== this.hosts.length ||
        summary.key_count !== this.keys.length;
      this.#mergeRuntime(summary.sessions);
      const [proxies, tunnels] = await Promise.all([api.listProxies(), api.listTunnels()]);
      needsReload ||=
        proxies.length !== this.proxies.length || tunnels.length !== this.tunnels.length;
      this.#mergeV2Runtime(proxies, tunnels);
    } catch {
      // A missed poll is harmless. The next one retries.
    } finally {
      this.#finishSnapshot();
    }
    if (needsReload) await this.refresh();
  }

  handleRuntimeEvent(event: RuntimeEvent): void {
    if (event.event === "known_hosts_changed") {
      void this.refresh();
      return;
    }
    if (this.#snapshotsInFlight > 0) this.#eventsDuringSnapshot.push(event);
    this.#applyStateChange(event);
  }

  handleUiEvent(event: UiEvent): void {
    switch (event.event) {
      case "clipboard-fallback":
        this.clipboardUrl = event.payload.url;
        break;
      case "view-logs":
        this.openLogsFor(event.payload.session_id);
        break;
      case "unlock-vault":
        this.view = "keys";
        this.unlockRequested = !(this.vaultKnown && this.vault.unlocked);
        break;
      case "close-confirm":
        this.closePrompt = "close";
        break;
      case "quit-confirm":
        this.closePrompt = "quit";
        break;
      case "migration-notice":
        this.migrationNotice = event.payload;
        break;
    }
  }

  async resolveClose(choice: CloseChoice): Promise<void> {
    this.closePrompt = null;
    try {
      await api.resolveClose(choice);
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  navigate(view: NavView): void {
    this.view = view;
  }

  /** Opens Settings at the port forward presets. */
  openForwardPresets(): void {
    this.view = "settings";
    // After Settings has rendered.
    setTimeout(() => document.getElementById("settings-presets")?.scrollIntoView({ block: "start" }));
  }

  selectSession(id: Uuid): void {
    this.selectedId = id;
    this.view = "sessions";
    this.chainResult = null;
  }

  newSession(): void {
    if (!(NEW_SESSION_ID in this.drafts)) {
      this.drafts = { ...this.drafts, [NEW_SESSION_ID]: blankProfile() };
    }
    this.selectSession(NEW_SESSION_ID);
  }

  /** Saves a copy of a saved session and opens it. Unsaved edits to the original are not copied. */
  async duplicateSession(id: Uuid): Promise<void> {
    try {
      const copy = await api.duplicateSession(id);
      await this.refresh();
      this.selectSession(copy.id);
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /** Stops and deletes a saved session, then frees the saved passwords nothing else uses. */
  async deleteSession(id: Uuid): Promise<void> {
    const session = this.sessions.find((s) => s.profile.id === id);
    if (!session) return;
    try {
      await api.deleteSession(id);
      const draft = this.drafts[id];
      this.#dropDraft(id);
      [...profileRefs(session.profile), ...(draft ? profileRefs(draft) : [])].forEach((ref) =>
        this.#orphanedSecrets.add(ref),
      );
      if (this.selectedId === id) this.chainResult = null;
      await this.refresh();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /**
   * Includes or leaves out a saved session from Start All and autostart. Saved right away, and
   * carried into any unsaved edits so saving them later does not undo it.
   */
  async setSessionEnabled(id: Uuid, enabled: boolean): Promise<void> {
    const session = this.sessions.find((s) => s.profile.id === id);
    if (!session) return;
    try {
      await api.upsertSession({ ...session.profile, enabled });
      const draft = this.drafts[id];
      if (draft) this.drafts = { ...this.drafts, [id]: { ...draft, enabled } };
      await this.refresh();
      const latest = this.drafts[id];
      const saved = this.sessions.find((s) => s.profile.id === id)?.profile;
      if (latest && saved && sameProfile(saved, latest)) this.#dropDraft(id);
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /** Throws away the unsaved new session. */
  async discardNewSession(): Promise<void> {
    const draft = this.drafts[NEW_SESSION_ID];
    if (!draft) return;
    this.#dropDraft(NEW_SESSION_ID);
    profileRefs(draft).forEach((ref) => this.#orphanedSecrets.add(ref));
    if (this.selectedId === NEW_SESSION_ID) this.selectedId = this.sessions[0]?.profile.id ?? null;
    await this.#deleteOrphanedSecrets();
  }

  /** Applies an edit to the selected session. Undoing every change clears the draft. */
  updateDraft(edit: (profile: SessionProfile) => SessionProfile): void {
    const id = this.selectedId;
    const current = this.draft;
    if (id === null || !current) return;
    const next = edit(current);
    if (next.hops !== current.hops) this.chainResult = null;
    this.#noteDroppedSecrets(profileRefs(current), profileRefs(next));
    const saved = this.selected?.profile;
    if (saved && sameProfile(saved, next)) {
      this.#dropDraft(id);
    } else {
      this.drafts = { ...this.drafts, [id]: next };
    }
  }

  async save(): Promise<void> {
    const id = this.selectedId;
    const profile = this.draft;
    if (id === null || !profile || !this.dirty || this.saving || !this.draftValid) return;
    this.saving = true;
    try {
      const saved = await api.upsertSession(profile);
      // Edits typed while the save was running stay as a draft under the saved id.
      const latest = this.drafts[id];
      this.#dropDraft(id);
      if (latest && latest !== profile) {
        this.drafts = { ...this.drafts, [saved.id]: { ...latest, id: saved.id } };
      }
      if (this.selectedId === id) this.selectedId = saved.id;
      this.sessions = this.sessions.map((s) =>
        s.profile.id === saved.id ? { ...s, profile: saved } : s,
      );
      await this.refresh();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    } finally {
      this.saving = false;
    }
  }

  pinFor(hop: HopEntry): HostKeyEntry | null {
    return (
      this.pins.find(
        ({ key }) =>
          key.hop_id === hop.hop_id && key.host === hop.host.host && key.port === hop.host.port,
      ) ?? null
    );
  }

  async resetPin(hop: HopEntry): Promise<void> {
    try {
      await api.resetHostKey(hop.hop_id, hop.host.host, hop.host.port);
      await this.refresh();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /**
   * Pins the hop's key from a `known_hosts` file at a path the user typed. Returns an error
   * message, or `null` on success.
   */
  async importKnownHost(hop: HopEntry, path: string): Promise<string | null> {
    try {
      await api.importKnownHost(hop.hop_id, hop.host.host, hop.host.port, path);
      await this.refresh();
      return null;
    } catch (error) {
      return errorMessage(error);
    }
  }

  /** Saves a hop of the saved session as a reusable host and links the hop to it. */
  /** Saves a forward preset. Returns the saved preset, or `null` after showing the error. */
  async saveForwardPreset(preset: ForwardPreset): Promise<ForwardPreset | null> {
    try {
      const saved = await api.upsertForwardPreset(preset);
      this.presets = await api.listForwardPresets();
      return saved;
    } catch (error) {
      this.notice = errorMessage(error);
      return null;
    }
  }

  async deleteForwardPreset(id: string): Promise<void> {
    try {
      await api.deleteForwardPreset(id);
      this.presets = await api.listForwardPresets();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  async restoreForwardPresets(): Promise<void> {
    try {
      this.presets = await api.restoreForwardPresets();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  async promoteHop(hopId: string, name: string): Promise<boolean> {
    const session = this.selected;
    if (!session || this.dirty) return false;
    try {
      await api.promoteHopToHost(session.profile.id, hopId, name);
      await this.refresh();
      return true;
    } catch (error) {
      this.notice = errorMessage(error);
      return false;
    }
  }

  newHost(): void {
    this.cancelHost();
    this.hostDraft = blankHost();
  }

  editHost(host: HostProfile): void {
    this.cancelHost();
    this.hostDraft = host;
  }

  updateHostDraft(edit: (host: HostProfile) => HostProfile): void {
    if (!this.hostDraft) return;
    const next = edit(this.hostDraft);
    this.#noteDroppedSecrets(authRefs(this.hostDraft.auth), authRefs(next.auth));
    this.hostDraft = next;
  }

  /** Discards the host edit, including any password saved only for that edit. */
  cancelHost(): void {
    if (!this.hostDraft) return;
    authRefs(this.hostDraft.auth).forEach((ref) => this.#orphanedSecrets.add(ref));
    this.hostDraft = null;
    void this.#deleteOrphanedSecrets();
  }

  async saveHost(): Promise<void> {
    const draft = this.hostDraft;
    if (!draft || this.savingHost || Object.keys(this.hostDraftErrors).length > 0) return;
    this.savingHost = true;
    try {
      const saved = await api.upsertHost(draft);
      this.#mapDraftHops((hop) =>
        hop.host.id === saved.id ? { ...hop, host: saved } : hop,
      );
      if (this.hostDraft === draft) this.hostDraft = null;
      await this.refresh();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    } finally {
      this.savingHost = false;
    }
  }

  /** Linked hops keep working from their own copy and become inline. */
  async deleteHost(host: HostProfile): Promise<void> {
    try {
      await api.deleteHost(host.id);
      this.#mapDraftHops((hop) =>
        hop.host.id === host.id ? { ...hop, host: { ...hop.host, id: NIL_HOST_ID } } : hop,
      );
      if (this.hostDraft?.id === host.id) this.cancelHost();
      authRefs(host.auth).forEach((ref) => this.#orphanedSecrets.add(ref));
      await this.refresh();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  #mapDraftHops(edit: (hop: HopEntry) => HopEntry): void {
    this.drafts = Object.fromEntries(
      Object.entries(this.drafts).map(([id, profile]) => [
        id,
        { ...profile, hops: profile.hops.map(edit) },
      ]),
    );
  }

  #noteDroppedSecrets(before: string[], after: string[]): void {
    const kept = new Set(after);
    before.filter((ref) => !kept.has(ref)).forEach((ref) => this.#orphanedSecrets.add(ref));
  }

  /** Never forces: the backend refuses to delete a secret that saved config still uses. */
  async #deleteOrphanedSecrets(): Promise<void> {
    const inDrafts = new Set([
      ...Object.values(this.drafts).flatMap(profileRefs),
      ...authRefs(this.hostDraft?.auth ?? []),
      ...Object.values(this.proxyDrafts).flatMap(proxySecretRefs),
      ...Object.values(this.tunnelDrafts).flatMap((t) => t.hops.flatMap((hop) => authRefs(hop.host.auth))),
    ]);
    for (const ref of [...this.#orphanedSecrets]) {
      if (inDrafts.has(ref)) continue;
      this.#orphanedSecrets.delete(ref);
      try {
        await api.deleteSecret(ref);
      } catch {
        // A locked vault or an already-removed record leaves nothing the user can act on.
      }
    }
  }

  async toggleSelected(): Promise<void> {
    const session = this.selected;
    if (!session || this.toggling) return;
    const id = session.profile.id;
    const stopping = isActive(session.runtime.state);
    this.toggling = true;
    try {
      await (stopping ? api.stopSession(id) : api.startSession(id));
      await this.pollRuntime();
    } catch (error) {
      this.notice = errorMessage(error);
    } finally {
      this.toggling = false;
    }
  }

  async testSelected(): Promise<void> {
    const session = this.selected;
    if (!session || this.testing) return;
    const id = session.profile.id;
    this.testing = true;
    this.chainResult = null;
    this.testHostKey = null;
    try {
      const result = await api.testChain(id);
      if (this.selectedId !== id) return;
      this.chainResult = result;
      const prompt = result.hops.find((hop) => hop.host_key)?.host_key;
      if (prompt) {
        this.testHostKey = { sessionId: id, sessionName: session.profile.name, prompt, source: "test" };
      }
    } catch (error) {
      this.notice = errorMessage(error);
    } finally {
      this.testing = false;
    }
  }

  /** Pins the key Test Chain stopped at, then tests again so the next hop gets checked. */
  async trustTestedHostKey(sha256: string): Promise<void> {
    const pending = this.testHostKey;
    if (!pending) return;
    await api.trustTestedHostKey(pending.sessionId, sha256);
    this.testHostKey = null;
    await this.refresh();
    if (this.selectedId === pending.sessionId) await this.testSelected();
  }

  /** Leaves the key untrusted. The hop stays marked in the test result. */
  rejectTestedHostKey(): void {
    this.testHostKey = null;
  }

  // -------------------------------------------------------------------------------------------
  // v2: Proxies, Tunnels, and the Profile Library.
  // -------------------------------------------------------------------------------------------

  /** Opens the log drawer for a Proxy, Tunnel, or legacy session id, whichever matches. */
  openLogsFor(id: Uuid): void {
    if (this.proxies.some((p) => p.profile.id === id)) {
      this.selectProxy(id);
      this.logTarget = { kind: "proxy", id };
    } else if (this.tunnels.some((t) => t.profile.id === id)) {
      this.selectTunnel(id);
      this.logTarget = { kind: "tunnel", id };
    } else if (this.sessions.some((s) => s.profile.id === id)) {
      this.selectSession(id);
      this.logTarget = { kind: "session", id };
    } else {
      return;
    }
    this.logsOpen = true;
  }

  /** Hands a Log drawer quick action to the Proxy editor, selecting the Proxy first. */
  requestProxyQuickAction(kind: ProxyQuickAction["kind"], proxyId: ProxyId, host: string, inbound: RouteInbound): void {
    if (!this.proxies.some((p) => p.profile.id === proxyId)) return;
    this.selectProxy(proxyId);
    this.#quickActionNonce += 1;
    this.proxyQuickAction = { kind, proxyId, host, inbound, nonce: this.#quickActionNonce };
  }

  /** Takes the pending quick action for `proxyId`, if any, so it runs once. */
  takeProxyQuickAction(proxyId: ProxyId | null): ProxyQuickAction | null {
    const action = this.proxyQuickAction;
    if (!action || action.proxyId !== proxyId) return null;
    this.proxyQuickAction = null;
    return action;
  }

  handleProxyEvent(event: ProxyEvent): void {
    if (this.#snapshotsInFlight > 0) this.#v2EventsDuringSnapshot.push({ kind: "proxy", event });
    this.#applyProxyEvent(event);
  }

  handleTunnelEvent(event: TunnelEvent): void {
    if (this.#snapshotsInFlight > 0) this.#v2EventsDuringSnapshot.push({ kind: "tunnel", event });
    this.#applyTunnelEvent(event);
  }

  /** Reloads only the v2 lists. */
  async refreshV2(): Promise<boolean> {
    this.#snapshotsInFlight += 1;
    try {
      const [proxies, tunnels, library] = await Promise.all([
        api.listProxies(),
        api.listTunnels(),
        api.listProfileLibrary(),
      ]);
      this.proxies = proxies;
      this.tunnels = tunnels;
      this.profileLibrary = library;
      this.#reconcileV2Selection();
      return true;
    } catch (error) {
      this.notice = errorMessage(error);
      return false;
    } finally {
      this.#finishSnapshot();
    }
  }

  /**
   * After a `.bak` or `config.toml` import: reloads the v2 lists and opens what was imported,
   * the Proxy first, else the Tunnel.
   */
  async openImported(proxy: Proxy | null, tunnel: Tunnel | null = null): Promise<void> {
    await this.refreshV2();
    if (proxy) {
      // An import into an existing Proxy replaces it, so any unsaved edits to it are stale.
      if (proxy.id in this.proxyDrafts) {
        const { [proxy.id]: _dropped, ...rest } = this.proxyDrafts;
        this.proxyDrafts = rest;
      }
      this.selectProxy(proxy.id);
    } else if (tunnel) {
      this.selectTunnel(tunnel.id);
    }
  }

  /**
   * Applies what an External TOML link, unlink, or reload saved: the Proxy's draft is dropped,
   * since the file (or the switch back) replaced it, and the v2 lists are reloaded.
   */
  async applyProxySourceChange(result: ProxySaveResult): Promise<void> {
    const id = result.profile.id;
    if (id in this.proxyDrafts) {
      const { [id]: _dropped, ...rest } = this.proxyDrafts;
      this.proxyDrafts = rest;
    }
    this.proxySaveNote = {
      proxyId: id,
      configGeneration: result.snapshot.config_generation,
      reloaded: result.reloaded,
      reloadError: result.reload_error,
    };
    const viewed: ProxyView = { profile: result.profile, snapshot: result.snapshot };
    this.proxies = this.proxies.map((p) => (p.profile.id === id ? viewed : p));
    await this.refreshV2();
  }

  selectProxy(id: ProxyId): void {
    if (this.selectedProxyId !== id) {
      this.routeTest = null;
      this.upstreamTest = null;
    }
    this.selectedProxyId = id;
    this.view = "proxy";
  }

  selectTunnel(id: TunnelId): void {
    if (this.selectedTunnelId !== id) this.tunnelChainResult = null;
    this.selectedTunnelId = id;
    this.view = "tunnel";
  }

  /** The first HTTP and SOCKS ports from the defaults up that no saved Proxy uses on 127.0.0.1. */
  #freeProxyPorts(): [number, number] {
    const used = new Set(
      this.proxies.flatMap(({ profile }) => [profile.listeners.http_port, profile.listeners.socks_port]),
    );
    const next = (port: number, taken: Set<number>) => {
      while (used.has(port) || taken.has(port)) port += 1;
      return port;
    };
    const http = next(3128, new Set());
    return [http, next(1080, new Set([http]))];
  }

  /**
   * Starts a new Proxy draft from a New Proxy wizard preset and opens it.
   * - `direct`: no upstream profiles, everything goes `direct` (plain `rusty-conduit`).
   * - `tunnel`: one `tunnel` profile, used as the default target (`rusty-conduit-ssh`).
   * - `switch`: Auto Switch (`rusty-conduit-switch`): default `direct`, rules to be added, and
   *   the Tunnel as a profile when one is given or exists.
   * `tunnelId` defaults to the first Tunnel. With no Tunnel at all the `tunnel` preset keeps a
   * nil Tunnel id, which validation flags until one is chosen.
   */
  newProxyFromPreset(preset: ProxyPreset, tunnelId: TunnelId | null = null): Proxy {
    const [httpPort, socksPort] = this.#freeProxyPorts();
    const names: Record<ProxyPreset, string> = {
      direct: "New proxy",
      tunnel: "New tunnel proxy",
      switch: "New Auto Switch proxy",
    };
    const proxy = blankProxy(names[preset], httpPort, socksPort);
    const tunnel =
      this.tunnels.find((t) => t.profile.id === tunnelId)?.profile ?? this.tunnels[0]?.profile ?? null;
    if (preset !== "direct" && (preset === "tunnel" || tunnel)) {
      const name = tunnel ? tunnelProfileName(tunnel.name) : "tunnel";
      proxy.profiles = [
        {
          name,
          kind: { type: "tunnel", tunnel_id: tunnel?.id ?? tunnelId ?? NEW_SESSION_ID },
          host: null,
          port: null,
          username: null,
          password: null,
          bypass: [],
          color: null,
        },
      ];
      if (preset === "tunnel") proxy.routing = { ...proxy.routing, default: name };
    }
    this.proxyDrafts = { ...this.proxyDrafts, [NEW_SESSION_ID]: proxy };
    this.selectProxy(NEW_SESSION_ID);
    return proxy;
  }

  newTunnel(): Tunnel {
    const tunnel = this.tunnelDrafts[NEW_SESSION_ID] ?? blankTunnel();
    this.tunnelDrafts = { ...this.tunnelDrafts, [NEW_SESSION_ID]: tunnel };
    this.selectTunnel(NEW_SESSION_ID);
    return tunnel;
  }

  /** Applies an edit to the selected Proxy. Undoing every change clears the draft. */
  updateProxyDraft(edit: (proxy: Proxy) => Proxy): void {
    const id = this.selectedProxyId;
    const current = this.proxyDraft;
    if (id === null || !current) return;
    const next = edit(current);
    if (next.routing !== current.routing || next.profiles !== current.profiles) this.routeTest = null;
    this.#noteDroppedSecrets(proxySecretRefs(current), proxySecretRefs(next));
    const saved = this.selectedProxy?.profile;
    if (saved && sameJson(saved, next)) {
      const { [id]: _dropped, ...rest } = this.proxyDrafts;
      this.proxyDrafts = rest;
    } else {
      this.proxyDrafts = { ...this.proxyDrafts, [id]: next };
    }
  }

  updateTunnelDraft(edit: (tunnel: Tunnel) => Tunnel): void {
    const id = this.selectedTunnelId;
    const current = this.tunnelDraft;
    if (id === null || !current) return;
    const next = edit(current);
    if (next.hops !== current.hops) this.tunnelChainResult = null;
    this.#noteDroppedSecrets(
      current.hops.flatMap((hop) => authRefs(hop.host.auth)),
      next.hops.flatMap((hop) => authRefs(hop.host.auth)),
    );
    const saved = this.selectedTunnel?.profile;
    if (saved && sameJson(saved, next)) {
      const { [id]: _dropped, ...rest } = this.tunnelDrafts;
      this.tunnelDrafts = rest;
    } else {
      this.tunnelDrafts = { ...this.tunnelDrafts, [id]: next };
    }
  }

  /** Throws away the selected Proxy's unsaved edits (or the unsaved new Proxy). */
  async discardProxyDraft(): Promise<void> {
    const id = this.selectedProxyId;
    const draft = id === null ? undefined : this.proxyDrafts[id];
    if (id === null || !draft) return;
    const { [id]: _dropped, ...rest } = this.proxyDrafts;
    this.proxyDrafts = rest;
    proxySecretRefs(draft).forEach((ref) => this.#orphanedSecrets.add(ref));
    if (id === NEW_SESSION_ID) this.selectedProxyId = this.proxies[0]?.profile.id ?? null;
    await this.#deleteOrphanedSecrets();
  }

  async discardTunnelDraft(): Promise<void> {
    const id = this.selectedTunnelId;
    const draft = id === null ? undefined : this.tunnelDrafts[id];
    if (id === null || !draft) return;
    const { [id]: _dropped, ...rest } = this.tunnelDrafts;
    this.tunnelDrafts = rest;
    draft.hops.flatMap((hop) => authRefs(hop.host.auth)).forEach((ref) => this.#orphanedSecrets.add(ref));
    if (id === NEW_SESSION_ID) this.selectedTunnelId = this.tunnels[0]?.profile.id ?? null;
    await this.#deleteOrphanedSecrets();
  }

  /**
   * Saves the selected Proxy. A running Proxy hot-reloads; the outcome is kept in
   * `proxySaveNote` for the `gen #N · hot-reloaded` / `Restart to Apply` header.
   */
  async saveProxy(restart = false): Promise<void> {
    const id = this.selectedProxyId;
    const proxy = this.proxyDraft;
    if (id === null || !proxy || !this.proxyDirty || this.savingProxy || !this.proxyDraftValid) return;
    this.savingProxy = true;
    try {
      const result = await api.upsertProxy(proxy);
      const savedId = result.profile.id;
      const latest = this.proxyDrafts[id];
      const { [id]: _dropped, ...rest } = this.proxyDrafts;
      this.proxyDrafts = latest && latest !== proxy ? { ...rest, [savedId]: { ...latest, id: savedId } } : rest;
      if (this.selectedProxyId === id) this.selectedProxyId = savedId;
      this.proxySaveNote = {
        proxyId: savedId,
        configGeneration: result.snapshot.config_generation,
        reloaded: result.reloaded,
        reloadError: result.reload_error,
      };
      const viewed: ProxyView = { profile: result.profile, snapshot: result.snapshot };
      this.proxies = this.proxies.some((p) => p.profile.id === savedId)
        ? this.proxies.map((p) => (p.profile.id === savedId ? viewed : p))
        : [...this.proxies, viewed];
      if (restart) {
        await api.restartProxy(savedId);
        this.proxySaveNote = null;
      }
      await this.refreshV2();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    } finally {
      this.savingProxy = false;
    }
  }

  async saveTunnel(restart = false): Promise<void> {
    const id = this.selectedTunnelId;
    const tunnel = this.tunnelDraft;
    if (id === null || !tunnel || !this.tunnelDirty || this.savingTunnel || !this.tunnelDraftValid) return;
    this.savingTunnel = true;
    try {
      const saved = await api.upsertTunnel(tunnel);
      const latest = this.tunnelDrafts[id];
      const { [id]: _dropped, ...rest } = this.tunnelDrafts;
      this.tunnelDrafts =
        latest && latest !== tunnel ? { ...rest, [saved.id]: { ...latest, id: saved.id } } : rest;
      if (this.selectedTunnelId === id) this.selectedTunnelId = saved.id;
      if (restart) {
        await api.restartTunnel(saved.id);
      }
      await this.refreshV2();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    } finally {
      this.savingTunnel = false;
    }
  }

  async duplicateProxy(id: ProxyId): Promise<void> {
    try {
      const copy = await api.duplicateProxy(id);
      await this.refreshV2();
      this.selectProxy(copy.profile.id);
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  async duplicateTunnel(id: TunnelId): Promise<void> {
    try {
      const copy = await api.duplicateTunnel(id);
      await this.refreshV2();
      this.selectTunnel(copy.id);
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  async deleteProxy(id: ProxyId): Promise<void> {
    const proxy = this.proxies.find((p) => p.profile.id === id);
    if (!proxy) return;
    try {
      await api.deleteProxy(id);
      const draft = this.proxyDrafts[id];
      const { [id]: _dropped, ...rest } = this.proxyDrafts;
      this.proxyDrafts = rest;
      [...proxySecretRefs(proxy.profile), ...(draft ? proxySecretRefs(draft) : [])].forEach((ref) =>
        this.#orphanedSecrets.add(ref),
      );
      if (this.proxySaveNote?.proxyId === id) this.proxySaveNote = null;
      await this.refreshV2();
      await this.#deleteOrphanedSecrets();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /**
   * Deletes a Tunnel the user confirmed, with the same contract as {@link deleteKey}: forces
   * only past the Proxies the user was shown, otherwise returns the fresh usage.
   */
  async deleteTunnel(id: TunnelId, confirmed: Usage | null = null): Promise<Usage | null> {
    const tunnel = this.tunnels.find((t) => t.profile.id === id);
    if (!tunnel) return null;
    try {
      const first = await api.deleteTunnel(id);
      if (!first.deleted) {
        const seen = new Set((confirmed?.proxies ?? []).map((ref) => ref.id));
        if (!confirmed || (first.usage.proxies ?? []).some((ref) => !seen.has(ref.id))) return first.usage;
        const forced = await api.deleteTunnel(id, true);
        if (!forced.deleted) return forced.usage;
      }
      const draft = this.tunnelDrafts[id];
      const { [id]: _dropped, ...rest } = this.tunnelDrafts;
      this.tunnelDrafts = rest;
      [...tunnel.profile.hops, ...(draft?.hops ?? [])]
        .flatMap((hop) => authRefs(hop.host.auth))
        .forEach((ref) => this.#orphanedSecrets.add(ref));
      await this.refreshV2();
      await this.#deleteOrphanedSecrets();
      return null;
    } catch (error) {
      this.notice = errorMessage(error);
      return null;
    }
  }

  /** Includes or leaves out a saved Proxy from Start All and autostart. Saved right away. */
  async setProxyEnabled(id: ProxyId, enabled: boolean): Promise<void> {
    const proxy = this.proxies.find((p) => p.profile.id === id);
    if (!proxy) return;
    try {
      await api.upsertProxy({ ...proxy.profile, enabled });
      const draft = this.proxyDrafts[id];
      if (draft) this.proxyDrafts = { ...this.proxyDrafts, [id]: { ...draft, enabled } };
      await this.refreshV2();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  async setTunnelEnabled(id: TunnelId, enabled: boolean): Promise<void> {
    const tunnel = this.tunnels.find((t) => t.profile.id === id);
    if (!tunnel) return;
    try {
      await api.upsertTunnel({ ...tunnel.profile, enabled });
      const draft = this.tunnelDrafts[id];
      if (draft) this.tunnelDrafts = { ...this.tunnelDrafts, [id]: { ...draft, enabled } };
      await this.refreshV2();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  async #runV2(action: () => Promise<unknown>): Promise<void> {
    try {
      await action();
      await this.refreshV2();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  startProxy = (id: ProxyId) => this.#runV2(() => api.startProxy(id));
  stopProxy = (id: ProxyId) => this.#runV2(() => api.stopProxy(id));
  restartProxy = (id: ProxyId) => this.#runV2(() => api.restartProxy(id));
  startTunnel = (id: TunnelId) => this.#runV2(() => api.startTunnel(id));
  stopTunnel = (id: TunnelId) => this.#runV2(() => api.stopTunnel(id));
  restartTunnel = (id: TunnelId) => this.#runV2(() => api.restartTunnel(id));
  approveTunnelHostKey = (id: TunnelId, sha256: string) =>
    this.#runV2(() => api.approveTunnelHostKey(id, sha256));
  rejectTunnelHostKey = (id: TunnelId) => this.#runV2(() => api.rejectTunnelHostKey(id));
  startAllV2 = () => this.#runV2(() => api.startAllV2());
  stopAllV2 = () => this.#runV2(() => api.stopAllV2());

  /** Tray-style override: a profile name (`direct` included), or `null` for Auto Switch. */
  async setProxyOverride(id: ProxyId, profile: string | null): Promise<void> {
    try {
      const snapshot = await api.setProxyOverride(id, profile);
      this.#setProxySnapshot(id, snapshot);
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /** Route Tester against the selected Proxy's draft. */
  async testRoute(rawTarget: string, inbound: RouteInbound): Promise<RouteTestResult | null> {
    const proxy = this.proxyDraft;
    if (!proxy) return null;
    try {
      const result = await api.testRoute(proxy, rawTarget, inbound);
      if (this.proxyDraft === proxy) this.routeTest = result;
      return result;
    } catch (error) {
      this.notice = errorMessage(error);
      return null;
    }
  }

  /** Test Upstream: dials `host:port` through one profile of the selected Proxy's draft. */
  async testUpstream(
    profileName: string,
    host: string,
    port: number,
    timeoutMs = 5_000,
  ): Promise<UpstreamProbeResult | null> {
    const proxy = this.proxyDraft;
    if (!proxy) return null;
    try {
      const result = await api.testUpstream(proxy, profileName, host, port, timeoutMs);
      this.upstreamTest = result;
      return result;
    } catch (error) {
      this.notice = errorMessage(error);
      return null;
    }
  }

  async testTunnelChain(id: TunnelId): Promise<TunnelChainTestResult | null> {
    this.tunnelChainResult = null;
    try {
      const result = await api.testTunnelChain(id);
      if (this.selectedTunnelId === id) this.tunnelChainResult = result;
      return result;
    } catch (error) {
      this.notice = errorMessage(error);
      return null;
    }
  }

  async saveLibraryProfile(profile: UpstreamProfile): Promise<UpstreamProfile | null> {
    try {
      const saved = await api.upsertLibraryProfile(profile);
      this.profileLibrary = await api.listProfileLibrary();
      return saved;
    } catch (error) {
      this.notice = errorMessage(error);
      return null;
    }
  }

  async deleteLibraryProfile(name: string): Promise<void> {
    try {
      await api.deleteLibraryProfile(name);
      this.profileLibrary = await api.listProfileLibrary();
    } catch (error) {
      this.notice = errorMessage(error);
    }
  }

  /** Copies a Profile Library entry into the selected Proxy's draft. Returns false on a clash. */
  addLibraryProfileToDraft(name: string): boolean {
    const entry = this.profileLibrary.find((p) => p.name === name);
    const proxy = this.proxyDraft;
    if (!entry || !proxy || proxy.profiles.some((p) => p.name === name)) return false;
    this.updateProxyDraft((p) => ({ ...p, profiles: [...p.profiles, structuredClone(entry)] }));
    return true;
  }

  #setProxySnapshot(id: ProxyId, snapshot: ProxySnapshot): void {
    this.proxies = this.proxies.map((p) => (p.profile.id === id ? { ...p, snapshot } : p));
  }

  #applyProxyEvent(event: ProxyEvent): void {
    const proxy = this.proxies.find((p) => p.profile.id === event.proxy_id);
    if (!proxy) return;
    this.#setProxySnapshot(event.proxy_id, applyProxyEvent(proxy.snapshot, event));
  }

  #applyTunnelEvent(event: TunnelEvent): void {
    if (!this.tunnels.some((t) => t.profile.id === event.tunnel_id)) return;
    this.tunnels = this.tunnels.map((t) =>
      t.profile.id === event.tunnel_id ? { ...t, snapshot: { ...t.snapshot, state: event.state } } : t,
    );
  }

  #mergeV2Runtime(proxies: ProxyView[], tunnels: TunnelView[]): void {
    const proxyById = new Map<ProxyId, ProxySnapshot>(proxies.map((p) => [p.profile.id, p.snapshot]));
    const tunnelById = new Map<TunnelId, TunnelSnapshot>(tunnels.map((t) => [t.profile.id, t.snapshot]));
    this.proxies = this.proxies.map((p) => {
      const snapshot = proxyById.get(p.profile.id);
      return snapshot ? { ...p, snapshot } : p;
    });
    this.tunnels = this.tunnels.map((t) => {
      const snapshot = tunnelById.get(t.profile.id);
      return snapshot ? { ...t, snapshot } : t;
    });
  }

  #reconcileV2Selection(): void {
    const proxyIds = new Set(this.proxies.map((p) => p.profile.id));
    const tunnelIds = new Set(this.tunnels.map((t) => t.profile.id));
    const keep = <T>(drafts: Record<Uuid, T>, ids: Set<Uuid>) => {
      const kept = Object.entries(drafts).filter(([id]) => id === NEW_SESSION_ID || ids.has(id));
      return kept.length === Object.keys(drafts).length ? drafts : Object.fromEntries(kept);
    };
    this.proxyDrafts = keep(this.proxyDrafts, proxyIds);
    this.tunnelDrafts = keep(this.tunnelDrafts, tunnelIds);
    const proxyNew = this.selectedProxyId === NEW_SESSION_ID && NEW_SESSION_ID in this.proxyDrafts;
    if (!proxyNew && (this.selectedProxyId === null || !proxyIds.has(this.selectedProxyId))) {
      this.selectedProxyId = this.proxies[0]?.profile.id ?? null;
    }
    const tunnelNew = this.selectedTunnelId === NEW_SESSION_ID && NEW_SESSION_ID in this.tunnelDrafts;
    if (!tunnelNew && (this.selectedTunnelId === null || !tunnelIds.has(this.selectedTunnelId))) {
      this.selectedTunnelId = this.tunnels[0]?.profile.id ?? null;
    }
  }

  #dropDraft(id: Uuid): void {
    const { [id]: _dropped, ...rest } = this.drafts;
    this.drafts = rest;
  }

  #finishSnapshot(): void {
    this.#snapshotsInFlight -= 1;
    // Replay so a snapshot read before these events cannot leave an older state on screen.
    this.#eventsDuringSnapshot.forEach((event) => this.#applyStateChange(event));
    this.#v2EventsDuringSnapshot.forEach((item) =>
      item.kind === "proxy" ? this.#applyProxyEvent(item.event) : this.#applyTunnelEvent(item.event),
    );
    if (this.#snapshotsInFlight === 0) {
      this.#eventsDuringSnapshot = [];
      this.#v2EventsDuringSnapshot = [];
    }
  }

  #applyStateChange(event: StateChangedEvent): void {
    if (!this.sessions.some((s) => s.profile.id === event.session_id)) return;
    this.sessions = this.sessions.map((s) =>
      s.profile.id === event.session_id
        ? { ...s, runtime: { ...s.runtime, state: event.state } }
        : s,
    );
  }

  #mergeRuntime(snapshots: SessionSnapshot[]): void {
    const byId = new Map(snapshots.map((snapshot) => [snapshot.id, snapshot]));
    this.sessions = this.sessions.map((s) => {
      const runtime = byId.get(s.profile.id);
      return runtime ? { ...s, runtime } : s;
    });
  }

  #reconcileSelection(): void {
    const ids = new Set(this.sessions.map((s) => s.profile.id));
    const kept = Object.entries(this.drafts).filter(
      ([id]) => id === NEW_SESSION_ID || ids.has(id),
    );
    if (kept.length !== Object.keys(this.drafts).length) {
      this.drafts = Object.fromEntries(kept);
    }
    if (this.selectedId === NEW_SESSION_ID && NEW_SESSION_ID in this.drafts) return;
    if (this.selectedId === null || !ids.has(this.selectedId)) {
      this.selectedId = this.sessions[0]?.profile.id ?? null;
    }
  }
}

async function subscribeStore(store: AppStore): Promise<() => void> {
  const unlistenShell = await subscribeShellListeners(store);
  try {
    const unlistenV2 = await subscribeV2Events({
      onProxyEvent: (event) => store.handleProxyEvent(event),
      onTunnelEvent: (event) => store.handleTunnelEvent(event),
    });
    return () => {
      unlistenShell();
      unlistenV2();
    };
  } catch (error) {
    unlistenShell();
    throw error;
  }
}

function subscribeShellListeners(store: AppStore) {
  return subscribeShellEvents({
    onTrayStatus: ({ tray_available }) => {
      store.trayAvailable = tray_available;
      if (tray_available) store.trayBannerDismissed = false;
    },
    onRuntimeEvent: (event) => store.handleRuntimeEvent(event),
    onRuntimeLagged: () => void store.refresh(),
    onUiEvent: (event) => store.handleUiEvent(event),
  });
}

export const store = new AppStore();
