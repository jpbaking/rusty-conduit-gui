<script lang="ts">
  import { statusOf } from "../format";
  import { NEW_SESSION_ID, store, type NavView } from "../stores.svelte";

  const NAV: { view: NavView; label: string }[] = [
    { view: "sessions", label: "Sessions" },
    { view: "hosts", label: "Host Profiles" },
    { view: "keys", label: "Key Vault" },
    { view: "settings", label: "Settings" },
  ];

  const unsavedNew = $derived(store.drafts[NEW_SESSION_ID] ?? null);
</script>

<aside class="sidebar">
  <div class="brand">Rusty Conduit SSH</div>

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
          onclick={() => store.selectSession(NEW_SESSION_ID)}
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
          title={status.label}
          onclick={() => store.selectSession(session.profile.id)}
        >
          <span class="glyph {status.tone}" aria-hidden="true">{status.glyph}</span>
          <span class="session-name">{session.profile.name}</span>
          <span class="sr-only">{status.label}</span>
        </button>
      </li>
    {:else}
      {#if !unsavedNew}
        <li class="empty">{store.search ? "No matching sessions." : "No sessions yet."}</li>
      {/if}
    {/each}
  </ul>
</aside>
