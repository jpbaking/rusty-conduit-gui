<script lang="ts">
  import { tick } from "svelte";
  import { isActive, statusOf } from "../format";
  import { NEW_SESSION_ID, store, type NavView } from "../stores.svelte";
  import type { SessionView } from "../types";
  import ContextMenu, { type MenuItem } from "./ContextMenu.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  const NAV: { view: NavView; label: string }[] = [
    { view: "sessions", label: "Sessions" },
    { view: "hosts", label: "Host Profiles" },
    { view: "keys", label: "Key Vault" },
    { view: "settings", label: "Settings" },
  ];

  const unsavedNew = $derived(store.drafts[NEW_SESSION_ID] ?? null);

  interface OpenMenu {
    x: number;
    y: number;
    /** A saved session, or null for the unsaved new one. */
    session: SessionView | null;
    trigger: HTMLElement;
  }

  let menu = $state<OpenMenu | null>(null);
  let confirming = $state<{ session: SessionView | null } | null>(null);
  let deleting = $state(false);

  const menuItems = $derived.by<MenuItem[]>(() => {
    const target = menu;
    if (!target) return [];
    if (!target.session) {
      return [{ label: "Discard…", danger: true, onSelect: () => (confirming = { session: null }) }];
    }
    const session = target.session;
    return [
      {
        label: "Duplicate",
        title: store.drafts[session.profile.id] ? "Copies the saved settings, not unsaved changes" : undefined,
        onSelect: () => void store.duplicateSession(session.profile.id),
      },
      session.profile.enabled
        ? {
            label: "Disable",
            title: "Leave this session out of Start All and autostart",
            onSelect: () => void store.setSessionEnabled(session.profile.id, false),
          }
        : {
            label: "Enable",
            title: "Include this session in Start All and autostart",
            onSelect: () => void store.setSessionEnabled(session.profile.id, true),
          },
      { label: "Delete…", danger: true, onSelect: () => (confirming = { session }) },
    ];
  });

  function openMenu(event: MouseEvent, session: SessionView | null) {
    event.preventDefault();
    const trigger = event.currentTarget as HTMLElement;
    // The keyboard (Shift+F10, Menu key) reports no pointer position, so open beside the row.
    const box = trigger.getBoundingClientRect();
    const fromKeyboard = event.clientX === 0 && event.clientY === 0;
    menu = {
      x: fromKeyboard ? box.left + 16 : event.clientX,
      y: fromKeyboard ? box.bottom : event.clientY,
      session,
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

  async function confirmDelete() {
    const target = confirming;
    if (!target || deleting) return;
    deleting = true;
    if (target.session) await store.deleteSession(target.session.profile.id);
    else await store.discardNewSession();
    deleting = false;
    confirming = null;
  }
</script>

<aside class="sidebar">
  <div class="brand">Rusty Conduit GUI</div>

  <nav aria-label="Main">
    {#each NAV as item (item.view)}
      <button
        class="nav-item"
        class:active={store.view === item.view}
        aria-current={store.view === item.view ? "page" : undefined}
        onclick={() => store.navigate(item.view)}
      >
        {item.label}
      </button>
    {/each}
  </nav>

  <div class="sidebar-tools">
    <input
      type="search"
      placeholder="Search sessions"
      aria-label="Search sessions"
      bind:value={store.search}
    />
    <button class="primary" onclick={() => store.newSession()}>+ New Session</button>
  </div>

  <ul class="session-list" aria-label="Sessions">
    {#if unsavedNew}
      <li>
        <button
          class="session-row"
          class:active={store.selectedId === NEW_SESSION_ID && store.view === "sessions"}
          aria-haspopup="menu"
          onclick={() => store.selectSession(NEW_SESSION_ID)}
          oncontextmenu={(e) => openMenu(e, null)}
        >
          <span class="glyph idle" aria-hidden="true">○</span>
          <span class="session-name">{unsavedNew.name || "Untitled"}</span>
          <span class="session-tag">unsaved</span>
        </button>
      </li>
    {/if}
    {#each store.filteredSessions as session (session.profile.id)}
      {@const status = statusOf(session.runtime.state)}
      <li>
        <button
          class="session-row"
          class:active={store.selectedId === session.profile.id && store.view === "sessions"}
          class:disabled-session={!session.profile.enabled}
          title={session.profile.enabled ? status.label : `${status.label}. Disabled: not included in Start All.`}
          aria-haspopup="menu"
          onclick={() => store.selectSession(session.profile.id)}
          oncontextmenu={(e) => openMenu(e, session)}
        >
          <span class="glyph {status.tone}" aria-hidden="true">{status.glyph}</span>
          <span class="session-name">{session.profile.name}</span>
          {#if !session.profile.enabled}<span class="session-tag">disabled</span>{/if}
          <span class="sr-only">{status.label}{session.profile.enabled ? "" : ", disabled"}</span>
        </button>
      </li>
    {:else}
      {#if !unsavedNew}
        <li class="empty">{store.search ? "No matching sessions." : "No sessions yet."}</li>
      {/if}
    {/each}
  </ul>
</aside>

{#if menu}
  <ContextMenu
    x={menu.x}
    y={menu.y}
    label={menu.session ? `${menu.session.profile.name} actions` : "Unsaved session actions"}
    items={menuItems}
    onClose={closeMenu}
  />
{/if}

{#if confirming}
  {@const session = confirming.session}
  <ModalDialog
    title={session ? "Delete session" : "Discard new session"}
    onDismiss={() => !deleting && (confirming = null)}
  >
    {#if session}
      <p>Delete <strong>{session.profile.name}</strong>? This cannot be undone.</p>
      <ul class="plain-list muted">
        {#if isActive(session.runtime.state)}<li>It is running and will be stopped first.</li>{/if}
        {#if store.drafts[session.profile.id]}<li>Its unsaved changes are lost.</li>{/if}
        <li>Host-key pins for its hops are removed.</li>
        <li>Saved passwords that no other session or host profile uses are deleted from the vault.</li>
      </ul>
    {:else}
      <p>Discard <strong>{unsavedNew?.name || "the new session"}</strong>? It has not been saved.</p>
    {/if}
    {#snippet actions()}
      <button disabled={deleting} onclick={() => (confirming = null)}>Cancel</button>
      <button class="danger" disabled={deleting} onclick={confirmDelete}>
        {deleting ? "Deleting…" : session ? "Delete" : "Discard"}
      </button>
    {/snippet}
  </ModalDialog>
{/if}
