<script lang="ts" module>
  import type { StatusDisplay } from "../format";
  import type { ProxyState, ProxyView } from "../types";

  /** How a Proxy's state shows in the sidebar and header. */
  export function proxyStatusOf(state: ProxyState): StatusDisplay {
    switch (state.state) {
      case "running":
        return { glyph: "●", label: "Running", tone: "ok" };
      case "starting":
        return { glyph: "◐", label: "Starting", tone: "busy" };
      case "reloading":
        return { glyph: "◐", label: "Reloading", tone: "busy" };
      case "stopping":
        return { glyph: "◐", label: "Stopping", tone: "busy" };
      case "locked":
        return { glyph: "!", label: "Vault locked", tone: "alert" };
      case "needs_attention":
        return { glyph: "!", label: "Needs attention", tone: "alert" };
      case "stopped":
        return { glyph: "○", label: "Stopped", tone: "idle" };
    }
  }

  /** True while the Proxy has listeners or is getting them, so it can be stopped. */
  export function proxyActive(state: ProxyState): boolean {
    return !["stopped", "locked", "needs_attention"].includes(state.state);
  }

  export type ProxyModeLabel = "Direct" | "Tunnel" | "Upstream" | "Auto Switch" | "Override" | "Block";

  /**
   * The sidebar's mode pill: `Override` while the tray forces a profile, `Auto Switch` when
   * rules pick the route, otherwise what the default sends traffic to.
   */
  export function proxyMode(view: ProxyView): ProxyModeLabel {
    const { profile, snapshot } = view;
    if (snapshot.state.state === "running" && snapshot.override_profile !== null) return "Override";
    const routing = profile.routing;
    const rules = routing.rules.length + (routing.http?.rules.length ?? 0) + (routing.socks?.rules.length ?? 0);
    if (rules > 0) return "Auto Switch";
    const target = Array.isArray(routing.default) ? routing.default[0] : routing.default;
    if (target === undefined || target === "direct") return "Direct";
    if (target === "block") return "Block";
    const upstream = profile.profiles.find((p) => p.name === target);
    return upstream?.kind.type === "tunnel" ? "Tunnel" : "Upstream";
  }
</script>

<script lang="ts">
  import { tick } from "svelte";
  import { formatBytes } from "../format";
  import { NEW_SESSION_ID, store, type ProxyQuickAction } from "../stores.svelte";
  import type { GlobalFilterConfig, Proxy, ProxyTrafficSnapshot } from "../types";
  import FilterEditor from "./FilterEditor.svelte";
  import MitmTab from "./MitmTab.svelte";
  import ProxyImportExportTab from "./ProxyImportExportTab.svelte";
  import ProxyListenersTab from "./ProxyListenersTab.svelte";
  import ProxyLoggingTab from "./ProxyLoggingTab.svelte";
  import ProxyProfilesTab from "./ProxyProfilesTab.svelte";
  import ProxyRoutingTab from "./ProxyRoutingTab.svelte";

  const TABS = [
    { label: "Routing", title: "Routing rules & Route Tester" },
    { label: "Profiles", title: "Upstream profiles" },
    { label: "Listeners", title: "Listeners & network" },
    { label: "Filter", title: "Global filter" },
    { label: "MITM", title: "HTTPS MITM" },
    { label: "Import / Export", title: "Import / Export & TOML" },
    { label: "General", title: "Logging & general" },
  ] as const;
  const ROUTING_TAB = 0;
  const PROFILES_TAB = 1;
  const LISTENERS_TAB = 2;
  const FILTER_TAB = 3;
  const MITM_TAB = 4;
  const IMPORT_TAB = 5;
  const GENERAL_TAB = 6;

  /** The tab that shows a field's error. */
  function tabForField(field: string): number {
    if (field.startsWith("routing.")) return ROUTING_TAB;
    if (field.startsWith("profiles:")) return PROFILES_TAB;
    if (field.startsWith("listeners.") || field.startsWith("network.")) return LISTENERS_TAB;
    if (field.startsWith("filter.")) return FILTER_TAB;
    if (field.startsWith("mitm.")) return MITM_TAB;
    return GENERAL_TAB;
  }

  const uid = $props.id();
  const draft = $derived(store.proxyDraft);
  const saved = $derived(store.selectedProxy);
  const snapshot = $derived(saved?.snapshot ?? null);
  const status = $derived(snapshot ? proxyStatusOf(snapshot.state) : null);
  const active = $derived(snapshot ? proxyActive(snapshot.state) : false);
  const running = $derived(snapshot?.state.state === "running" ? snapshot.state : null);
  const isNew = $derived(store.selectedProxyId === NEW_SESSION_ID);
  const errors = $derived(store.proxyDraftErrors);
  const errorCounts = $derived.by(() => {
    const counts = TABS.map(() => 0);
    for (const field of Object.keys(errors)) {
      const tab = tabForField(field);
      counts[tab] = (counts[tab] ?? 0) + 1;
    }
    return counts;
  });
  const reason = $derived(snapshot?.state.state === "needs_attention" ? snapshot.state.reason : null);
  const saveNote = $derived(
    saved && store.proxySaveNote?.proxyId === saved.profile.id ? store.proxySaveNote : null,
  );
  const restartRequired = $derived(!!snapshot && (snapshot.restart_required || !!running?.restart_required));
  const overrideProfile = $derived(running?.override_profile ?? null);
  const profileCounters = $derived(Object.entries(snapshot?.profile_counters ?? {}));
  const totals = $derived(
    profileCounters.reduce<ProxyTrafficSnapshot>(
      (sum, [, c]) => ({
        active: sum.active + c.active,
        bytes_in: sum.bytes_in + c.bytes_in,
        bytes_out: sum.bytes_out + c.bytes_out,
        hits: sum.hits + c.hits,
      }),
      { active: 0, bytes_in: 0, bytes_out: 0, hits: 0 },
    ),
  );

  let activeTab = $state(ROUTING_TAB);
  let tabButtons = $state<HTMLButtonElement[]>([]);
  const tabId = (index: number) => `${uid}-tab-${index}`;
  const panelId = (index: number) => `${uid}-panel-${index}`;

  async function focusTab(index: number) {
    activeTab = index;
    await tick();
    tabButtons[index]?.focus();
  }

  function onTabKeydown(event: KeyboardEvent, index: number) {
    const last = TABS.length - 1;
    const targets: Record<string, number> = {
      ArrowRight: index === last ? 0 : index + 1,
      ArrowLeft: index === 0 ? last : index - 1,
      Home: 0,
      End: last,
    };
    const target = targets[event.key];
    if (target === undefined) return;
    event.preventDefault();
    void focusTab(target);
  }

  // Quick actions from the Log drawer, and the header's Test Route shortcut.
  let quickAction = $state.raw<ProxyQuickAction | null>(null);
  let localNonce = -1;

  $effect(() => {
    if (!store.proxyQuickAction) return;
    const taken = store.takeProxyQuickAction(store.selectedProxyId);
    if (!taken) return;
    activeTab = ROUTING_TAB;
    quickAction = taken;
  });

  function openRouteTester() {
    const id = store.selectedProxyId;
    if (id === null) return;
    activeTab = ROUTING_TAB;
    localNonce -= 1;
    quickAction = { kind: "test_route", proxyId: id, host: "", inbound: "http", nonce: localNonce };
  }

  function filterLists(filter: GlobalFilterConfig): { allow: string[]; block: string[] } {
    if (filter === "off") return { allow: [], block: [] };
    return "allow" in filter ? { allow: filter.allow, block: [] } : { allow: [], block: filter.block };
  }

  function setFilter(allow: string[], block: string[]) {
    const filter: GlobalFilterConfig = allow.length > 0 ? { allow } : block.length > 0 ? { block } : "off";
    store.updateProxyDraft((p) => ({ ...p, filter }));
  }
</script>

{#if draft}
  {@const proxy = draft as Proxy}
  {@const lists = filterLists(proxy.filter)}
  <header class="header-bar">
    <input
      class="title-input"
      aria-label="Proxy name"
      placeholder="Proxy name"
      value={proxy.name}
      oninput={(e) => {
        const name = e.currentTarget.value;
        store.updateProxyDraft((p) => ({ ...p, name }));
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
    {#if running}
      <span class="pill idle" title="Config generation running now">
        gen #{running.config_generation}{#if saveNote?.reloaded} · hot-reloaded{/if}
      </span>
    {/if}
    {#if overrideProfile !== null && saved}
      <span class="pill busy" title="Set from the tray; rules are bypassed">
        Override: {overrideProfile}
        <button
          type="button"
          class="link-button"
          aria-label="Clear the override and use Auto Switch"
          onclick={() => store.setProxyOverride(saved.profile.id, null)}
        >×</button>
      </span>
    {/if}
    {#if saved && !saved.profile.enabled}
      <span class="pill idle" title="Not included in Start All or autostart">Disabled</span>
    {/if}

    <dl class="stats" aria-label="Live counters">
      <div><dt>Active</dt><dd>{totals.active}</dd></div>
      <div><dt>Hits</dt><dd>{totals.hits}</dd></div>
      <div><dt>In</dt><dd>{formatBytes(totals.bytes_in)}</dd></div>
      <div><dt>Out</dt><dd>{formatBytes(totals.bytes_out)}</dd></div>
    </dl>

    <div class="header-actions">
      <button onclick={openRouteTester}>Test Route</button>
      {#if store.proxyDirty}
        <button disabled={store.savingProxy} onclick={() => store.discardProxyDraft()}>Discard</button>
      {/if}
      <button
        disabled={!store.proxyDirty || store.savingProxy || !store.proxyDraftValid}
        title={store.proxyDirty && !store.proxyDraftValid
          ? "Fix the highlighted fields first"
          : running
            ? "Saves and applies the new routing without dropping connections"
            : undefined}
        onclick={() => store.saveProxy()}
      >
        {store.savingProxy ? "Saving…" : running ? "Save (Hot-Reload)" : "Save"}
      </button>
      {#if saved}
        <button onclick={() => store.openLogsFor(saved.profile.id)}>Logs</button>
        {#if active}
          <button onclick={() => store.restartProxy(saved.profile.id)}>Restart</button>
          <button class="danger" onclick={() => store.stopProxy(saved.profile.id)}>Stop</button>
        {:else}
          <button
            class="primary"
            disabled={store.proxyDirty}
            title={store.proxyDirty ? "Save your changes first" : undefined}
            onclick={() => store.startProxy(saved.profile.id)}
          >
            Start
          </button>
        {/if}
      {/if}
    </div>
  </header>

  <main class="content">
    <div class="session-editor">
      {#if restartRequired && saved}
        <div class="banner warn" role="alert">
          <span>Some saved changes (such as listeners) only apply after a restart.</span>
          <button class="primary" onclick={() => store.restartProxy(saved.profile.id)}>Restart to Apply</button>
        </div>
      {/if}
      {#if saveNote?.reloadError}
        <p class="reason" role="alert">
          Saved, but the running Proxy kept its previous routing: {saveNote.reloadError}
        </p>
      {/if}
      {#if reason}<p class="reason" role="alert">{reason}</p>{/if}
      {#if errors.name}<p class="field-error">{errors.name}</p>{/if}

      {#if profileCounters.length > 0}
        <ul class="plain-list counter-list" aria-label="Traffic by profile">
          {#each profileCounters as [name, counter] (name)}
            <li>
              <strong>{name}</strong>
              <span class="muted">{counter.active} active · {counter.hits} hits · ↓{formatBytes(counter.bytes_in)} ↑{formatBytes(counter.bytes_out)}</span>
            </li>
          {/each}
        </ul>
      {/if}

      <div class="tab-list" role="tablist" aria-label="Proxy settings">
        {#each TABS as tab, index (tab.label)}
          {@const count = errorCounts[index] ?? 0}
          <button
            bind:this={tabButtons[index]}
            type="button"
            class="tab"
            class:active={activeTab === index}
            role="tab"
            id={tabId(index)}
            aria-selected={activeTab === index}
            aria-controls={panelId(index)}
            tabindex={activeTab === index ? 0 : -1}
            onclick={() => (activeTab = index)}
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

      <div class="tab-panel" role="tabpanel" id={panelId(ROUTING_TAB)} aria-labelledby={tabId(ROUTING_TAB)} hidden={activeTab !== ROUTING_TAB}>
        <ProxyRoutingTab {quickAction} />
      </div>
      <div class="tab-panel" role="tabpanel" id={panelId(PROFILES_TAB)} aria-labelledby={tabId(PROFILES_TAB)} hidden={activeTab !== PROFILES_TAB}>
        <ProxyProfilesTab />
      </div>
      <div class="tab-panel" role="tabpanel" id={panelId(LISTENERS_TAB)} aria-labelledby={tabId(LISTENERS_TAB)} hidden={activeTab !== LISTENERS_TAB}>
        <ProxyListenersTab />
      </div>
      <div class="tab-panel" role="tabpanel" id={panelId(FILTER_TAB)} aria-labelledby={tabId(FILTER_TAB)} hidden={activeTab !== FILTER_TAB}>
        <FilterEditor
          title="Global filter"
          scope="global"
          allow={lists.allow}
          block={lists.block}
          {errors}
          errorPrefix="filter."
          onChange={setFilter}
        />
      </div>
      <div class="tab-panel" role="tabpanel" id={panelId(MITM_TAB)} aria-labelledby={tabId(MITM_TAB)} hidden={activeTab !== MITM_TAB}>
        <MitmTab
          target={{
            mitm: proxy.mitm,
            errors,
            set: (mitm) => store.updateProxyDraft((p) => ({ ...p, mitm })),
          }}
        />
      </div>
      <div class="tab-panel" role="tabpanel" id={panelId(IMPORT_TAB)} aria-labelledby={tabId(IMPORT_TAB)} hidden={activeTab !== IMPORT_TAB}>
        <ProxyImportExportTab />
      </div>
      <div class="tab-panel" role="tabpanel" id={panelId(GENERAL_TAB)} aria-labelledby={tabId(GENERAL_TAB)} hidden={activeTab !== GENERAL_TAB}>
        <ProxyLoggingTab />
      </div>
    </div>
  </main>
{/if}

<style>
  .counter-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin: 0 0 0.5rem;
  }
</style>
