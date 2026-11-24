<script lang="ts">
  import { tick } from "svelte";
  import { stateReason } from "../format";
  import { store } from "../stores.svelte";
  import { opensshCheck, type Fallback } from "../opensshCheck.svelte";
  import type { HopEntry, SessionProfile } from "../types";
  import type { FieldErrors } from "../validate";
  import FiltersTab from "./FiltersTab.svelte";
  import HopEditor from "./HopEditor.svelte";
  import HopProfileBar from "./HopProfileBar.svelte";
  import JumpChainBuilder from "./JumpChainBuilder.svelte";
  import KeepaliveTab from "./KeepaliveTab.svelte";
  import ListenerStrip from "./ListenerStrip.svelte";
  import LoggingAdvancedTab from "./LoggingAdvancedTab.svelte";
  import EngineCheck from "./EngineCheck.svelte";
  import OpensshFallbackDialog from "./OpensshFallbackDialog.svelte";
  import MitmTab from "./MitmTab.svelte";
  import ProxyTab from "./ProxyTab.svelte";

  // Short labels keep the tab row on one line; the full name is the tooltip.
  const TABS = [
    { label: "Connection", title: "Connection & jump chain" },
    { label: "Proxy", title: "Forward & reverse (-R) proxy" },
    { label: "Filters", title: "Destination filters" },
    { label: "MITM", title: "HTTPS MITM" },
    { label: "Keepalive", title: "Keepalive & reconnect" },
    { label: "Advanced", title: "Logging & advanced" },
  ] as const;
  const CONNECTION_TAB = 0;
  const PROXY_TAB = 1;
  const FILTERS_TAB = 2;
  const MITM_TAB = 3;
  const KEEPALIVE_TAB = 4;
  const LOGGING_TAB = 5;

  /** The tabs that show a field's error. */
  function tabsForField(field: string): number[] {
    if (field === "hops" || field.startsWith("hop:") || field === "tunnel.ip_version") {
      return [CONNECTION_TAB];
    }
    if (field.startsWith("forward.") || field.startsWith("reverse.") || field === "listeners") {
      return [PROXY_TAB];
    }
    if (field.startsWith("filters.")) return [FILTERS_TAB];
    if (field.startsWith("mitm.")) return [MITM_TAB];
    if (field.startsWith("tunnel.")) return [KEEPALIVE_TAB];
    if (field.startsWith("logging.") || field.startsWith("openssh.")) return [LOGGING_TAB];
    return [];
  }

  function countByTab(errors: FieldErrors): number[] {
    const counts = TABS.map(() => 0);
    for (const field of Object.keys(errors)) {
      for (const tab of tabsForField(field)) counts[tab] = (counts[tab] ?? 0) + 1;
    }
    return counts;
  }

  const uid = $props.id();
  const draft = $derived(store.draft as SessionProfile);
  const hop = $derived(store.selectedHop);
  const errors = $derived(store.draftErrors);
  const errorCounts = $derived(countByTab(errors));
  const reason = $derived(store.selected ? stateReason(store.selected.runtime.state) : null);
  const locked = $derived(!!hop && store.hosts.some((h) => h.id === hop.host.id));
  let activeTab = $state(CONNECTION_TAB);
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

  /** Set while the "OpenSSH can't be used" dialog is open. */
  let fallback = $state<Fallback | null>(null);

  function setEngine(engine: SessionProfile["engine"]) {
    store.updateDraft((p) => ({ ...p, engine }));
  }

  /** OpenSSH is checked as soon as it is chosen; an unusable program falls back to Rust SSH. */
  async function chooseEngine(engine: SessionProfile["engine"]) {
    setEngine(engine);
    if (engine !== "OpenSsh") return;
    const session = store.selectedId;
    const bin = draft.openssh.ssh_bin.trim();
    await opensshCheck.run(bin);
    // Ignore a result that no longer applies: another session, or the choice changed meanwhile.
    if (store.selectedId !== session || draft.engine !== "OpenSsh" || opensshCheck.bin !== bin) return;
    if (opensshCheck.info?.supported) return;
    setEngine("Russh");
    fallback = { bin, info: opensshCheck.info, error: opensshCheck.error };
  }

  /** The dialog found a supported program: use it. */
  function useOpenssh(bin: string) {
    store.updateDraft((p) => ({ ...p, engine: "OpenSsh", openssh: { ...p.openssh, ssh_bin: bin } }));
    fallback = null;
  }

  function editHop(id: string, edit: (hop: HopEntry) => HopEntry) {
    store.updateDraft((profile) => ({
      ...profile,
      hops: profile.hops.map((h) => (h.hop_id === id ? edit(h) : h)),
    }));
  }
</script>

<div class="session-editor">
  {#if reason}<p class="reason" role="alert">{reason}</p>{/if}
  {#if errors.name}<p class="field-error">{errors.name}</p>{/if}
  <ListenerStrip />

  <div class="tab-list" role="tablist" aria-label="Session settings">
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

  <!-- Panels stay mounted so a half-typed value survives switching tabs. -->
  <div class="tab-panel" role="tabpanel" id={panelId(CONNECTION_TAB)} aria-labelledby={tabId(CONNECTION_TAB)} hidden={activeTab !== CONNECTION_TAB}>
    <div class="connection-layout">
      <aside class="route-column">
        <JumpChainBuilder />
        {#if errors.hops}<p class="field-error">{errors.hops}</p>{/if}

        <section class="route-settings" aria-labelledby={`${uid}-connection-heading`}>
          <h2 id={`${uid}-connection-heading`}>Connection</h2>
          <label class="field">
            IP version
            <select
              value={draft.tunnel.ip_version}
              onchange={(e) => {
                const ip_version = e.currentTarget.value;
                store.updateDraft((p) => ({ ...p, tunnel: { ...p.tunnel, ip_version } }));
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
              value={draft.engine}
              onchange={(e) => void chooseEngine(e.currentTarget.value as SessionProfile["engine"])}
            >
              <option value="Russh">Built-in Rust SSH</option>
              <option value="OpenSsh">OpenSSH (system ssh)</option>
            </select>
          </label>
          {#if draft.engine === "OpenSsh"}
            <EngineCheck onChangeProgram={() => void focusTab(LOGGING_TAB)} />
          {/if}
        </section>
      </aside>

      <div class="hop-column">
        {#if hop}
          {#key hop.hop_id}
            <div class="hop-card">
              <HopProfileBar {hop} />
              <HopEditor
                host={hop.host}
                {hop}
                {locked}
                {errors}
                errorPrefix={`hop:${hop.hop_id}:`}
                onHostChange={(edit) => editHop(hop.hop_id, (h) => ({ ...h, host: edit(h.host) }))}
                onHopChange={(edit) => editHop(hop.hop_id, edit)}
              />
            </div>
          {/key}
        {:else}
          <div class="hop-card hop-empty">
            <p class="muted">Add a target on the right to start building the route.</p>
          </div>
        {/if}
      </div>
    </div>
  </div>

  <div class="tab-panel" role="tabpanel" id={panelId(PROXY_TAB)} aria-labelledby={tabId(PROXY_TAB)} hidden={activeTab !== PROXY_TAB}>
    <ProxyTab />
  </div>

  <!-- Keyed so per-session editor state, such as a typed rule, never carries across sessions. -->
  {#key store.selectedId}
    <div class="tab-panel" role="tabpanel" id={panelId(FILTERS_TAB)} aria-labelledby={tabId(FILTERS_TAB)} hidden={activeTab !== FILTERS_TAB}>
      <FiltersTab />
    </div>

    <div class="tab-panel" role="tabpanel" id={panelId(MITM_TAB)} aria-labelledby={tabId(MITM_TAB)} hidden={activeTab !== MITM_TAB}>
      <MitmTab />
    </div>

    <div class="tab-panel" role="tabpanel" id={panelId(KEEPALIVE_TAB)} aria-labelledby={tabId(KEEPALIVE_TAB)} hidden={activeTab !== KEEPALIVE_TAB}>
      <KeepaliveTab />
    </div>

    <div class="tab-panel" role="tabpanel" id={panelId(LOGGING_TAB)} aria-labelledby={tabId(LOGGING_TAB)} hidden={activeTab !== LOGGING_TAB}>
      <LoggingAdvancedTab />
    </div>
  {/key}

</div>

{#if fallback}
  <OpensshFallbackDialog {fallback} onUse={useOpenssh} onClose={() => (fallback = null)} />
{/if}
