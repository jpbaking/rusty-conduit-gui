<script lang="ts" module>
  import type {
    SessionProfile,
    SessionView,
    Tunnel,
    TunnelView,
  } from "../types";
  import type { FieldErrors } from "../validate";

  /** Shows a Tunnel in the session shape the shared SSH tabs edit. */
  export function tunnelAsSession(tunnel: Tunnel): SessionProfile {
    return {
      id: tunnel.id,
      name: tunnel.name,
      autostart: typeof tunnel.start_mode === "object" && tunnel.start_mode.manual.autostart,
      enabled: tunnel.enabled,
      engine: tunnel.engine,
      hops: tunnel.hops,
      forward: tunnel.forward,
      reverse: tunnel.reverse,
      port_forwards: tunnel.port_forwards,
      mitm: tunnel.mitm,
      tunnel: tunnel.keepalive,
      logging: tunnel.logging,
      openssh: tunnel.openssh,
    };
  }

  /** Writes the SSH fields of an edited session-shaped Tunnel back into the Tunnel. */
  export function sessionIntoTunnel(tunnel: Tunnel, edited: SessionProfile): Tunnel {
    return {
      ...tunnel,
      name: edited.name,
      enabled: edited.enabled,
      engine: edited.engine,
      hops: edited.hops,
      forward: edited.forward,
      reverse: edited.reverse,
      port_forwards: edited.port_forwards,
      mitm: edited.mitm,
      socks_block_web: edited.mitm ? edited.mitm.socks_block_web : tunnel.socks_block_web,
      keepalive: edited.tunnel,
      logging: edited.logging,
      openssh: edited.openssh,
    };
  }

  /** Tunnel validation names keepalive fields `keepalive.*`; the shared tabs read `tunnel.*`. */
  export function tunnelErrorsForTabs(errors: FieldErrors): FieldErrors {
    return Object.fromEntries(
      Object.entries(errors).map(([field, message]) => [
        field.startsWith("keepalive.") ? `tunnel.${field.slice("keepalive.".length)}` : field,
        message,
      ]),
    );
  }

  /** A saved Tunnel with its runtime, in the session view shape. */
  export function tunnelAsSessionView(view: TunnelView): SessionView {
    const { snapshot } = view;
    return {
      profile: tunnelAsSession(view.profile),
      runtime: {
        id: snapshot.id,
        name: snapshot.name,
        enabled: snapshot.enabled,
        state: snapshot.state,
        stats: snapshot.stats,
        listeners: snapshot.listeners,
        remote_listeners: snapshot.remote_listeners,
        port_forwards: snapshot.port_forwards,
      },
    };
  }
</script>

<script lang="ts">
  import { tick } from "svelte";
  import { NIL_UUID, hopTitle } from "../chain";
  import { formatBytes, formatUptime, isActive, stateReason, statusOf } from "../format";
  import { opensshCheck, type Fallback } from "../opensshCheck.svelte";
  import { NEW_SESSION_ID, store } from "../stores.svelte";
  import type { HopEntry, TunnelStartMode } from "../types";
  import EngineCheck from "./EngineCheck.svelte";
  import FiltersTab from "./FiltersTab.svelte";
  import ForwardProxyTab from "./ForwardProxyTab.svelte";
  import HopEditor from "./HopEditor.svelte";
  import JumpChainBuilder, { provideChainEditor, type ChainEditor } from "./JumpChainBuilder.svelte";
  import KeepaliveTab from "./KeepaliveTab.svelte";
  import LoggingAdvancedTab from "./LoggingAdvancedTab.svelte";
  import MitmTab from "./MitmTab.svelte";
  import OpensshFallbackDialog from "./OpensshFallbackDialog.svelte";
  import PortForwardsTab from "./PortForwardsTab.svelte";
  import ReverseProxyTab from "./ReverseProxyTab.svelte";

  type TabId = "connection" | "proxy" | "ports" | "filters" | "mitm" | "keepalive" | "advanced";

  const ALL_TABS: readonly { id: TabId; label: string; title: string }[] = [
    { id: "connection", label: "Connection", title: "Connection & jump chain" },
    { id: "proxy", label: "Proxy", title: "Forward & reverse (-R) proxy" },
    { id: "ports", label: "Ports", title: "Port forwards (-L / -R)" },
    { id: "filters", label: "Filters", title: "Destination filters" },
    { id: "mitm", label: "MITM", title: "HTTPS MITM (tunnel Forward listener only)" },
    { id: "keepalive", label: "Keepalive", title: "Keepalive, reconnect & start mode" },
    { id: "advanced", label: "Advanced", title: "Logging & advanced" },
  ];

  const uid = $props.id();
  const tunnel = $derived(store.tunnelDraft as Tunnel);
  const saved = $derived(store.selectedTunnel);
  const draft = $derived(tunnelAsSession(tunnel));
  const errors = $derived(tunnelErrorsForTabs(store.tunnelDraftErrors));
  const tabs = $derived(
    tunnel.forward.enabled ? ALL_TABS : ALL_TABS.filter((tab) => tab.id !== "mitm"),
  );

  /** The tab that shows a field's error, or `null` for the header (the name). */
  function tabForField(field: string): TabId | null {
    if (field === "hops" || field.startsWith("hop:") || field === "tunnel.ip_version") return "connection";
    if (field.startsWith("forward.") || field.startsWith("reverse.")) return "proxy";
    if (field === "listeners" || field.startsWith("forwards:")) return "ports";
    if (field.startsWith("filters.")) return "filters";
    if (field.startsWith("mitm.")) return tunnel.forward.enabled ? "mitm" : null;
    if (field.startsWith("tunnel.")) return "keepalive";
    if (field.startsWith("logging.") || field.startsWith("openssh.")) return "advanced";
    return null;
  }

  const errorCounts = $derived.by(() => {
    const counts: Partial<Record<TabId, number>> = {};
    for (const field of Object.keys(errors)) {
      const tab = tabForField(field);
      if (tab !== null) counts[tab] = (counts[tab] ?? 0) + 1;
    }
    return counts;
  });
  const savedView = $derived(saved ? tunnelAsSessionView(saved) : null);
  const runtime = $derived(saved?.snapshot ?? null);
  const status = $derived(runtime ? statusOf(runtime.state) : null);
  const active = $derived(runtime ? isActive(runtime.state) : false);
  const reason = $derived(runtime ? stateReason(runtime.state) : null);
  const isNew = $derived(store.selectedTunnelId === NEW_SESSION_ID);
  const canRun = $derived(!!saved && !store.tunnelDirty);
  const usedBy = $derived(saved?.used_by ?? []);

  let selectedHopId = $state<string | null>(null);
  let testing = $state(false);
  const selectedHop = $derived(
    draft.hops.find((hop) => hop.hop_id === selectedHopId) ?? draft.hops[0] ?? null,
  );
  const hop = $derived(selectedHop);
  const linkedHost = $derived(hop ? (store.hosts.find((h) => h.id === hop.host.id) ?? null) : null);

  async function testChain() {
    const id = saved?.profile.id;
    if (!id || testing) return;
    testing = true;
    try {
      await store.testTunnelChain(id);
    } finally {
      testing = false;
    }
  }

  const editor: ChainEditor = {
    get draft() {
      return draft;
    },
    get draftErrors() {
      return errors;
    },
    updateDraft(edit) {
      store.updateTunnelDraft((current) => sessionIntoTunnel(current, edit(tunnelAsSession(current))));
    },
    get selectedHop() {
      return selectedHop;
    },
    get selectedHopId() {
      return selectedHopId;
    },
    set selectedHopId(id) {
      selectedHopId = id;
    },
    get chainResult() {
      return store.tunnelChainResult;
    },
    testSelected: testChain,
    get selected() {
      return savedView;
    },
    get startMode() {
      return tunnel.start_mode;
    },
    setStartMode(start_mode: TunnelStartMode) {
      store.updateTunnelDraft((t) => ({ ...t, start_mode }));
    },
    isTunnel: true,
  };
  provideChainEditor(editor);

  const startModeLabel = $derived(
    tunnel.start_mode === "linked"
      ? "Linked"
      : tunnel.start_mode.manual.autostart
        ? "Auto-start"
        : "Manual",
  );

  let activeTab = $state<TabId>("connection");
  let tabButtons = $state<Partial<Record<TabId, HTMLButtonElement>>>({});
  const tabId = (id: TabId) => `${uid}-tab-${id}`;
  const panelId = (id: TabId) => `${uid}-panel-${id}`;

  $effect(() => {
    if (!tunnel.forward.enabled && activeTab === "mitm") {
      activeTab = "proxy";
    }
  });

  async function focusTab(id: TabId) {
    activeTab = id;
    await tick();
    tabButtons[id]?.focus();
  }

  function onTabKeydown(event: KeyboardEvent, index: number) {
    const last = tabs.length - 1;
    const targets: Record<string, number> = {
      ArrowRight: index === last ? 0 : index + 1,
      ArrowLeft: index === 0 ? last : index - 1,
      Home: 0,
      End: last,
    };
    const target = targets[event.key];
    if (target === undefined) return;
    event.preventDefault();
    const next = tabs[target];
    if (next) void focusTab(next.id);
  }

  let fallback = $state<Fallback | null>(null);

  function setEngine(engine: Tunnel["engine"]) {
    store.updateTunnelDraft((t) => ({ ...t, engine }));
  }

  /** OpenSSH is checked as soon as it is chosen; an unusable program falls back to Rust SSH. */
  async function chooseEngine(engine: Tunnel["engine"]) {
    setEngine(engine);
    if (engine !== "OpenSsh") return;
    const id = store.selectedTunnelId;
    const bin = tunnel.openssh.ssh_bin.trim();
    await opensshCheck.run(bin);
    if (store.selectedTunnelId !== id || tunnel.engine !== "OpenSsh" || opensshCheck.bin !== bin) return;
    if (opensshCheck.info?.supported) return;
    setEngine("Russh");
    fallback = { bin, info: opensshCheck.info, error: opensshCheck.error };
  }

  function useOpenssh(bin: string) {
    store.updateTunnelDraft((t) => ({ ...t, engine: "OpenSsh", openssh: { ...t.openssh, ssh_bin: bin } }));
    fallback = null;
  }

  function editHop(id: string, edit: (hop: HopEntry) => HopEntry) {
    store.updateTunnelDraft((t) => ({ ...t, hops: t.hops.map((h) => (h.hop_id === id ? edit(h) : h)) }));
  }

  /** Links the hop to a host profile, or keeps its values inline when none is chosen. */
  function applyHost(target: HopEntry, id: string) {
    const host = store.hosts.find((h) => h.id === id);
    editHop(target.hop_id, (h) =>
      host ? { ...h, name: host.name, host } : { ...h, host: { ...h.host, id: NIL_UUID } },
    );
  }
</script>

<header class="header-bar">
  <input
    class="title-input"
    aria-label="Tunnel name"
    placeholder="Tunnel name"
    value={tunnel.name}
    oninput={(e) => {
      const name = e.currentTarget.value;
      store.updateTunnelDraft((t) => ({ ...t, name }));
    }}
  />
  {#if status}
    <span class="pill {status.tone}" role="status">
      <span aria-hidden="true">{status.glyph}</span>
      {status.label}
    </span>
  {:else if isNew}
    <span class="pill idle">Not saved</span>
  {/if}
  {#if saved && !saved.profile.enabled}
    <span class="pill idle" title="Not included in Start All or autostart">Disabled</span>
  {/if}
  <span class="pill idle" title="Start mode">{startModeLabel}</span>

  <dl class="stats" aria-label="Live statistics">
    <div><dt>Conns</dt><dd>{runtime?.stats.active_connections ?? 0}</dd></div>
    <div><dt>In</dt><dd>{formatBytes(runtime?.stats.bytes_received ?? 0)}</dd></div>
    <div><dt>Out</dt><dd>{formatBytes(runtime?.stats.bytes_sent ?? 0)}</dd></div>
    <div><dt>Up</dt><dd>{formatUptime(runtime?.stats.uptime_secs ?? 0)}</dd></div>
  </dl>

  <div class="header-actions">
    <button
      disabled={!canRun || testing}
      title={store.tunnelDirty ? "Save your changes first" : undefined}
      onclick={testChain}
    >
      {testing ? "Testing…" : "Test Chain"}
    </button>
    {#if store.tunnelDirty}
      <button disabled={store.savingTunnel} onclick={() => store.discardTunnelDraft()}>Discard</button>
    {/if}
    <button
      disabled={!store.tunnelDirty || store.savingTunnel || !store.tunnelDraftValid}
      title={store.tunnelDirty && !store.tunnelDraftValid
        ? "Fix the highlighted fields first"
        : active
          ? "Saves and restarts the tunnel so all changes take effect immediately"
          : undefined}
      onclick={() => store.saveTunnel(active)}
    >
      {store.savingTunnel ? "Saving…" : active ? "Save & Restart" : "Save"}
    </button>
    {#if saved}
      <button onclick={() => store.openLogsFor(saved.profile.id)}>Logs</button>
      {#if active}
        <button onclick={() => store.restartTunnel(saved.profile.id)}>Restart</button>
        <button class="danger" onclick={() => store.stopTunnel(saved.profile.id)}>Stop</button>
      {:else}
        <button
          class="primary"
          disabled={!canRun}
          title={store.tunnelDirty ? "Save your changes first" : undefined}
          onclick={() => store.startTunnel(saved.profile.id)}
        >
          Start
        </button>
      {/if}
    {/if}
  </div>
</header>

<main class="content">
  <div class="session-editor">
    {#if reason}<p class="reason" role="alert">{reason}</p>{/if}
    {#if errors.name}<p class="field-error">{errors.name}</p>{/if}

    <section class="used-by" aria-labelledby={`${uid}-used-by`}>
      <h2 id={`${uid}-used-by`}>Used by</h2>
      {#if usedBy.length === 0}
        <p class="muted">
          No Proxy routes through this tunnel yet.
          {tunnel.start_mode === "linked" ? "A Linked tunnel only runs while a Proxy that uses it runs." : ""}
        </p>
      {:else}
        <ul class="plain-list used-by-list">
          {#each usedBy as ref (ref.id)}
            <li><button class="link-button" onclick={() => store.selectProxy(ref.id)}>{ref.name}</button></li>
          {/each}
        </ul>
        {#if runtime}
          <small class="muted">{runtime.linked_holders} running {runtime.linked_holders === 1 ? "Proxy holds" : "Proxies hold"} it open.</small>
        {/if}
      {/if}
    </section>

    <div class="tab-list" role="tablist" aria-label="Tunnel settings">
      {#each tabs as tab, index (tab.id)}
        {@const count = errorCounts[tab.id] ?? 0}
        <button
          bind:this={tabButtons[tab.id]}
          type="button"
          class="tab"
          class:active={activeTab === tab.id}
          role="tab"
          id={tabId(tab.id)}
          aria-selected={activeTab === tab.id}
          aria-controls={panelId(tab.id)}
          tabindex={activeTab === tab.id ? 0 : -1}
          onclick={() => (activeTab = tab.id)}
          onkeydown={(e) => onTabKeydown(e, index)}
          title={tab.title}
        >
          {tab.label}
          {#if count > 0}
            <span class="tab-badge" aria-hidden="true">{count}</span>
            <span class="sr-only">, {count} {count === 1 ? "error" : "errors"}</span>
          {/if}
        </button>
      {/each}
    </div>

    <div class="tab-panel" role="tabpanel" id={panelId("connection")} aria-labelledby={tabId("connection")} hidden={activeTab !== "connection"}>
      <div class="connection-layout">
        <aside class="route-column">
          <JumpChainBuilder />
          {#if errors.hops}<p class="field-error">{errors.hops}</p>{/if}

          <section class="route-settings" aria-labelledby={`${uid}-connection-heading`}>
            <h2 id={`${uid}-connection-heading`}>Connection</h2>
            <label class="field">
              IP version
              <select
                value={tunnel.keepalive.ip_version}
                onchange={(e) => {
                  const ip_version = e.currentTarget.value;
                  store.updateTunnelDraft((t) => ({ ...t, keepalive: { ...t.keepalive, ip_version } }));
                }}
              >
                <option value="4">IPv4</option>
                <option value="6">IPv6</option>
                <option value="auto">Auto</option>
              </select>
            </label>
            {#if errors["tunnel.ip_version"]}<p class="field-error">{errors["tunnel.ip_version"]}</p>{/if}
            <label class="field">
              Engine
              <select
                value={tunnel.engine}
                onchange={(e) => void chooseEngine(e.currentTarget.value as Tunnel["engine"])}
              >
                <option value="Russh">Built-in Rust SSH</option>
                <option value="OpenSsh">OpenSSH (system ssh)</option>
              </select>
            </label>
            {#if tunnel.engine === "OpenSsh"}
              <EngineCheck onChangeProgram={() => void focusTab("advanced")} />
            {/if}
          </section>
        </aside>

        <div class="hop-column">
          {#if hop}
            {#key hop.hop_id}
              <div class="hop-card">
                <div class="hop-head">
                  <div class="hop-head-title">
                    <h2>{hopTitle(hop)}</h2>
                  </div>
                  <label class="field-inline">
                    <span class="sr-only">Host profile for this hop</span>
                    <select value={linkedHost?.id ?? ""} onchange={(e) => applyHost(hop, e.currentTarget.value)}>
                      <option value="">Inline (no profile)</option>
                      {#each store.hosts as host (host.id)}
                        <option value={host.id}>{host.name} ({host.user}@{host.host}:{host.port})</option>
                      {/each}
                    </select>
                  </label>
                </div>
                <HopEditor
                  host={hop.host}
                  {hop}
                  locked={!!linkedHost}
                  {errors}
                  errorPrefix={`hop:${hop.hop_id}:`}
                  onHostChange={(edit) => editHop(hop.hop_id, (h) => ({ ...h, host: edit(h.host) }))}
                  onHopChange={(edit) => editHop(hop.hop_id, edit)}
                />
              </div>
            {/key}
          {:else}
            <div class="hop-card hop-empty">
              <p class="muted">Add a target to start building the route.</p>
            </div>
          {/if}
        </div>
      </div>
    </div>

    <div class="tab-panel" role="tabpanel" id={panelId("proxy")} aria-labelledby={tabId("proxy")} hidden={activeTab !== "proxy"}>
      {#key store.selectedTunnelId}
        <ForwardProxyTab />
      {/key}
      <ReverseProxyTab />
    </div>

    {#key store.selectedTunnelId}
      <div class="tab-panel" role="tabpanel" id={panelId("ports")} aria-labelledby={tabId("ports")} hidden={activeTab !== "ports"}>
        <PortForwardsTab />
      </div>

      <div class="tab-panel" role="tabpanel" id={panelId("filters")} aria-labelledby={tabId("filters")} hidden={activeTab !== "filters"}>
        <FiltersTab />
      </div>

      {#if tunnel.forward.enabled}
        <div class="tab-panel" role="tabpanel" id={panelId("mitm")} aria-labelledby={tabId("mitm")} hidden={activeTab !== "mitm"}>
          <p class="note">
            HTTPS MITM and SOCKS web blocking here apply only to this tunnel's own Forward listener, not to Proxies routing through this tunnel.
          </p>
          <MitmTab
            target={{
              mitm: tunnel.mitm,
              socksBlockWeb: tunnel.socks_block_web || (tunnel.mitm?.socks_block_web ?? false),
              errors,
              set: (mitm) => store.updateTunnelDraft((t) => ({ ...t, mitm })),
              setSocksBlockWeb: (socks_block_web) =>
                store.updateTunnelDraft((t) => ({
                  ...t,
                  socks_block_web,
                  mitm: t.mitm ? { ...t.mitm, socks_block_web } : null,
                })),
            }}
          />
        </div>
      {/if}

      <div class="tab-panel" role="tabpanel" id={panelId("keepalive")} aria-labelledby={tabId("keepalive")} hidden={activeTab !== "keepalive"}>
        <KeepaliveTab />
      </div>

      <div class="tab-panel" role="tabpanel" id={panelId("advanced")} aria-labelledby={tabId("advanced")} hidden={activeTab !== "advanced"}>
        <LoggingAdvancedTab />
      </div>
    {/key}
  </div>
</main>

{#if fallback}
  <OpensshFallbackDialog {fallback} onUse={useOpenssh} onClose={() => (fallback = null)} />
{/if}

<style>
  .used-by {
    margin-bottom: 0.75rem;
  }
  .used-by h2 {
    font-size: 0.95rem;
    margin: 0 0 0.25rem;
  }
  .used-by-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0;
  }
</style>
