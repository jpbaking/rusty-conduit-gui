// Reactive application state. Holds metadata only: no secret ever enters this store.

import { api, errorMessage, subscribeShellEvents } from "./api";
import { authRefs, blankHost, profileRefs } from "./chain";
import { isActive } from "./format";
import { hostErrors, sessionErrors, type FieldErrors } from "./validate";
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
  MitmCaId,
  RuntimeEvent,
  SessionProfile,
  SessionSnapshot,
  SessionView,
  UiEvent,
  Usage,
  Uuid,
  VaultStatus,
} from "./types";

export type NavView = "sessions" | "hosts" | "keys" | "settings";
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
      const [sessions, hosts, presets, keys, cas, vault, pins] = await Promise.all([
        api.listSessions(),
        api.listHosts(),
        api.listForwardPresets(),
        api.listKeys(),
        api.listMitmCas(),
        api.vaultStatus(),
        api.listHostKeyPins(),
      ]);
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
        this.selectSession(event.payload.session_id);
        this.logsOpen = true;
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

  #dropDraft(id: Uuid): void {
    const { [id]: _dropped, ...rest } = this.drafts;
    this.drafts = rest;
  }

  #finishSnapshot(): void {
    this.#snapshotsInFlight -= 1;
    // Replay so a snapshot read before these events cannot leave an older state on screen.
    this.#eventsDuringSnapshot.forEach((event) => this.#applyStateChange(event));
    if (this.#snapshotsInFlight === 0) this.#eventsDuringSnapshot = [];
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

function subscribeStore(store: AppStore) {
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
