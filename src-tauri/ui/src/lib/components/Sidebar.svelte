<script lang="ts">
  import { tick } from "svelte";
  import { isActive, statusOf } from "../format";
  import { NEW_SESSION_ID, store, type NavView } from "../stores.svelte";
  import type { ProxyView, TunnelView, Usage } from "../types";
  import ContextMenu, { type MenuItem } from "./ContextMenu.svelte";
  import ModalDialog from "./ModalDialog.svelte";
  import { proxyActive, proxyMode, proxyStatusOf } from "./ProxyEditor.svelte";

  interface Props {
    /** Opens the New Proxy wizard (including importing a backup or CLI config). */
    onNewProxy: () => void;
  }

  let { onNewProxy }: Props = $props();

  const NAV: { view: NavView; label: string; also?: NavView[] }[] = [
    { view: "hosts", label: "Host Profiles" },
    { view: "profileLibrary", label: "Profile Library" },
    { view: "vault", label: "Vault", also: ["keys"] },
    { view: "settings", label: "Settings" },
  ];

  const query = $derived(store.search.trim().toLowerCase());
  const proxies = $derived(
    query ? store.proxies.filter((p) => p.profile.name.toLowerCase().includes(query)) : store.proxies,
  );
  const tunnels = $derived(
    query
      ? store.tunnels.filter(({ profile }) =>
          [profile.name, ...profile.hops.map((hop) => hop.host.host)].some((text) =>
            text.toLowerCase().includes(query),
          ),
        )
      : store.tunnels,
  );
  const unsavedProxy = $derived(store.proxyDrafts[NEW_SESSION_ID] ?? null);
  const unsavedTunnel = $derived(store.tunnelDrafts[NEW_SESSION_ID] ?? null);

  type Target =
    | { kind: "proxy"; view: ProxyView | null }
    | { kind: "tunnel"; view: TunnelView | null };

  interface OpenMenu {
    x: number;
    y: number;
    target: Target;
    trigger: HTMLElement;
  }

  let menu = $state<OpenMenu | null>(null);
  /** The item to delete, with the Proxies the user was shown for a Tunnel. */
  let confirming = $state<{ target: Target; usage: Usage | null } | null>(null);
  let deleting = $state(false);

  const hasDraft = (kind: Target["kind"], id: string) =>
    kind === "proxy" ? id in store.proxyDrafts : id in store.tunnelDrafts;

  const menuItems = $derived.by<MenuItem[]>(() => {
    const open = menu;
    if (!open) return [];
    const { target } = open;
    if (!target.view) {
      return [{ label: "Discard…", danger: true, onSelect: () => (confirming = { target, usage: null }) }];
    }
    const id = target.view.profile.id;
    const enabled = target.view.profile.enabled;
    const proxy = target.kind === "proxy";
    return [
      {
        label: "Duplicate",
        title: hasDraft(target.kind, id) ? "Copies the saved settings, not unsaved changes" : undefined,
        onSelect: () => void (proxy ? store.duplicateProxy(id) : store.duplicateTunnel(id)),
      },
      {
        label: enabled ? "Disable" : "Enable",
        title: enabled ? "Leave this out of Start All and autostart" : "Include this in Start All and autostart",
        onSelect: () => void (proxy ? store.setProxyEnabled(id, !enabled) : store.setTunnelEnabled(id, !enabled)),
      },
      { label: "Delete…", danger: true, onSelect: () => (confirming = { target, usage: null }) },
    ];
  });

  function openMenu(event: MouseEvent, target: Target) {
    event.preventDefault();
    const trigger = event.currentTarget as HTMLElement;
    // The keyboard (Shift+F10, Menu key) reports no pointer position, so open beside the row.
    const box = trigger.getBoundingClientRect();
    const fromKeyboard = event.clientX === 0 && event.clientY === 0;
    menu = {
      x: fromKeyboard ? box.left + 16 : event.clientX,
      y: fromKeyboard ? box.bottom : event.clientY,
      target,
      trigger,
    };
  }

  async function closeMenu(restoreFocus: boolean) {
    const trigger = menu?.trigger;
    menu = null;
    if (restoreFocus) {
      await tick();
      trigger?.focus();
    }
  }

  /** The Proxies a Tunnel delete affects: the fresh usage if the backend sent one. */
  function affectedProxies(view: TunnelView, usage: Usage | null) {
    return usage?.proxies ?? view.used_by;
  }

  async function confirmDelete() {
    const current = confirming;
    if (!current || deleting) return;
    deleting = true;
    const { target } = current;
    let again: Usage | null = null;
    if (target.kind === "proxy") {
      if (target.view) await store.deleteProxy(target.view.profile.id);
      else {
        store.selectProxy(NEW_SESSION_ID);
        await store.discardProxyDraft();
      }
    } else if (target.view) {
      const shown: Usage = { hosts: [], sessions: [], proxies: affectedProxies(target.view, current.usage) };
      again = await store.deleteTunnel(target.view.profile.id, shown);
    } else {
      store.selectTunnel(NEW_SESSION_ID);
      await store.discardTunnelDraft();
    }
    deleting = false;
    // Something new uses the Tunnel: show the fresh list and ask again.
    confirming = again ? { target, usage: again } : null;
  }

  const viewActive = (item: (typeof NAV)[number]) =>
    store.view === item.view || (item.also ?? []).includes(store.view);
</script>

<aside class="sidebar">
  <div class="brand">Rusty Conduit GUI</div>

  <div class="sidebar-tools">
    <input type="search" placeholder="Search" aria-label="Search proxies and tunnels" bind:value={store.search} />
  </div>

  <div class="sidebar-lists">
    <section aria-labelledby="sidebar-proxies">
      <div class="list-head">
        <h2 id="sidebar-proxies">Proxies</h2>
        <span class="list-actions">
          <button class="primary small" onclick={onNewProxy}>+ New Proxy</button>
        </span>
      </div>
      <ul class="session-list" aria-label="Proxies">
        {#if unsavedProxy}
          <li>
            <button
              class="session-row"
              class:active={store.selectedProxyId === NEW_SESSION_ID && store.view === "proxy"}
              aria-haspopup="menu"
              onclick={() => store.selectProxy(NEW_SESSION_ID)}
              oncontextmenu={(e) => openMenu(e, { kind: "proxy", view: null })}
            >
              <span class="glyph idle" aria-hidden="true">○</span>
              <span class="session-name">{unsavedProxy.name || "Untitled"}</span>
              <span class="session-tag">unsaved</span>
            </button>
          </li>
        {/if}
        {#each proxies as proxy (proxy.profile.id)}
          {@const status = proxyStatusOf(proxy.snapshot.state)}
          {@const mode = proxyMode(proxy)}
          <li>
            <button
              class="session-row"
              class:active={store.selectedProxyId === proxy.profile.id && store.view === "proxy"}
              class:disabled-session={!proxy.profile.enabled}
              title={proxy.profile.enabled ? status.label : `${status.label}. Disabled: not included in Start All.`}
              aria-haspopup="menu"
              onclick={() => store.selectProxy(proxy.profile.id)}
              oncontextmenu={(e) => openMenu(e, { kind: "proxy", view: proxy })}
            >
              <span class="glyph {status.tone}" aria-hidden="true">{status.glyph}</span>
              <span class="session-name">{proxy.profile.name}</span>
              <span
                class="mode-pill"
                class:override={mode === "Override"}
                title={mode === "Override" ? `Override: ${proxy.snapshot.override_profile}` : undefined}
              >{mode}</span>
              {#if !proxy.profile.enabled}<span class="session-tag">disabled</span>{/if}
              <span class="sr-only">{status.label}{proxy.profile.enabled ? "" : ", disabled"}</span>
            </button>
          </li>
        {:else}
          {#if !unsavedProxy}
            <li class="empty">{query ? "No matching proxies." : "No proxies yet."}</li>
          {/if}
        {/each}
      </ul>
    </section>

    <section aria-labelledby="sidebar-tunnels">
      <div class="list-head">
        <h2 id="sidebar-tunnels">Tunnels</h2>
        <button class="small" onclick={() => store.newTunnel()}>+ New Tunnel</button>
      </div>
      <ul class="session-list" aria-label="Tunnels">
        {#if unsavedTunnel}
          <li>
            <button
              class="session-row"
              class:active={store.selectedTunnelId === NEW_SESSION_ID && store.view === "tunnel"}
              aria-haspopup="menu"
              onclick={() => store.selectTunnel(NEW_SESSION_ID)}
              oncontextmenu={(e) => openMenu(e, { kind: "tunnel", view: null })}
            >
              <span class="glyph idle" aria-hidden="true">○</span>
              <span class="session-name">{unsavedTunnel.name || "Untitled"}</span>
              <span class="session-tag">unsaved</span>
            </button>
          </li>
        {/if}
        {#each tunnels as tunnel (tunnel.profile.id)}
          {@const status = statusOf(tunnel.snapshot.state)}
          {@const linked = tunnel.profile.start_mode === "linked"}
          <li>
            <button
              class="session-row"
              class:active={store.selectedTunnelId === tunnel.profile.id && store.view === "tunnel"}
              class:disabled-session={!tunnel.profile.enabled}
              title={tunnel.profile.enabled ? status.label : `${status.label}. Disabled: not included in Start All.`}
              aria-haspopup="menu"
              onclick={() => store.selectTunnel(tunnel.profile.id)}
              oncontextmenu={(e) => openMenu(e, { kind: "tunnel", view: tunnel })}
            >
              <span class="glyph {status.tone}" aria-hidden="true">{status.glyph}</span>
              <span class="session-name">{tunnel.profile.name}</span>
              <span class="mode-pill" title={linked ? "Runs while a Proxy uses it" : "Started by hand"}>
                {linked ? "Linked" : "Manual"}
              </span>
              {#if !tunnel.profile.enabled}<span class="session-tag">disabled</span>{/if}
              <span class="sr-only">{status.label}{tunnel.profile.enabled ? "" : ", disabled"}</span>
            </button>
          </li>
        {:else}
          {#if !unsavedTunnel}
            <li class="empty">{query ? "No matching tunnels." : "No tunnels yet."}</li>
          {/if}
        {/each}
      </ul>
    </section>
  </div>

  <nav aria-label="Main" class="bottom-nav">
    {#each NAV as item (item.view)}
      <button
        class="nav-item"
        class:active={viewActive(item)}
        aria-current={viewActive(item) ? "page" : undefined}
        onclick={() => store.navigate(item.view)}
      >
        {item.label}
      </button>
    {/each}
  </nav>
</aside>

{#if menu}
  <ContextMenu
    x={menu.x}
    y={menu.y}
    label={menu.target.view
      ? `${menu.target.view.profile.name} actions`
      : menu.target.kind === "proxy"
        ? "Unsaved proxy actions"
        : "Unsaved tunnel actions"}
    items={menuItems}
    onClose={closeMenu}
  />
{/if}

{#if confirming}
  {@const target = confirming.target}
  {@const noun = target.kind === "proxy" ? "proxy" : "tunnel"}
  <ModalDialog
    title={target.view ? `Delete ${noun}` : `Discard new ${noun}`}
    onDismiss={() => !deleting && (confirming = null)}
  >
    {#if target.view}
      {@const running =
        target.kind === "proxy" ? proxyActive(target.view.snapshot.state) : isActive(target.view.snapshot.state)}
      <p>Delete <strong>{target.view.profile.name}</strong>? This cannot be undone.</p>
      <ul class="plain-list muted">
        {#if running}<li>It is running and will be stopped first.</li>{/if}
        {#if hasDraft(target.kind, target.view.profile.id)}<li>Its unsaved changes are lost.</li>{/if}
        {#if target.kind === "tunnel"}
          <li>Host-key pins for its hops are removed.</li>
        {/if}
        <li>Saved passwords that nothing else uses are deleted from the vault.</li>
      </ul>
      {#if target.kind === "tunnel"}
        {@const affected = affectedProxies(target.view, confirming.usage)}
        {#if affected.length > 0}
          <p class="warning">
            {affected.length === 1 ? "This Proxy routes" : "These Proxies route"} through it and will
            fail to reach it until you choose another Tunnel:
          </p>
          <ul class="plain-list">
            {#each affected as ref (ref.id)}<li>{ref.name}</li>{/each}
          </ul>
        {/if}
      {/if}
    {:else}
      <p>Discard <strong>{(target.kind === "proxy" ? unsavedProxy?.name : unsavedTunnel?.name) || `the new ${noun}`}</strong>? It has not been saved.</p>
    {/if}
    {#snippet actions()}
      <button disabled={deleting} onclick={() => (confirming = null)}>Cancel</button>
      <button class="danger" disabled={deleting} onclick={confirmDelete}>
        {deleting ? "Deleting…" : target.view ? "Delete" : "Discard"}
      </button>
    {/snippet}
  </ModalDialog>
{/if}

<style>
  .sidebar-lists {
    display: flex;
    flex-direction: column;
    gap: 12px;
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }
  .list-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    margin-bottom: 4px;
  }
  .list-actions {
    display: flex;
    gap: 4px;
  }
  .list-head h2 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    margin: 0;
  }
  .small {
    font-size: 12px;
    padding: 2px 8px;
  }
  .mode-pill {
    margin-left: auto;
    padding: 0 6px;
    border: 1px solid var(--border);
    border-radius: 999px;
    font-size: 11px;
    color: var(--muted);
    white-space: nowrap;
  }
  .mode-pill.override {
    border-color: currentColor;
    color: var(--warn, inherit);
  }
  .bottom-nav {
    border-top: 1px solid var(--border);
    padding-top: 8px;
  }
</style>
