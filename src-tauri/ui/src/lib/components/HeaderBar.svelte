<script lang="ts">
  import { formatBytes, formatUptime, statusOf } from "../format";
  import { store } from "../stores.svelte";

  const runtime = $derived(store.selected?.runtime ?? null);
  const status = $derived(runtime ? statusOf(runtime.state) : null);
  const canStart = $derived(!!store.selected && !store.dirty);
</script>

<header class="header-bar">
  <input
    class="title-input"
    aria-label="Session name"
    value={store.draft?.name ?? ""}
    placeholder="Session name"
    disabled={!store.draft}
    oninput={(e) => {
      const name = e.currentTarget.value;
      store.updateDraft((profile) => ({ ...profile, name }));
    }}
  />

  {#if status}
    <span class="pill {status.tone}" role="status">
      <span aria-hidden="true">{status.glyph}</span>
      {status.label}
    </span>
  {:else if store.isNew}
    <span class="pill idle">Not saved</span>
  {/if}
  {#if store.selected && !store.selected.profile.enabled}
    <span class="pill idle" title="Not included in Start All or autostart">Disabled</span>
  {/if}

  <dl class="stats" aria-label="Live statistics">
    <div><dt>Conns</dt><dd>{runtime?.stats.active_connections ?? 0}</dd></div>
    <div><dt>In</dt><dd>{formatBytes(runtime?.stats.bytes_received ?? 0)}</dd></div>
    <div><dt>Out</dt><dd>{formatBytes(runtime?.stats.bytes_sent ?? 0)}</dd></div>
    <div><dt>Up</dt><dd>{formatUptime(runtime?.stats.uptime_secs ?? 0)}</dd></div>
  </dl>

  <div class="header-actions">
    <button
      disabled={!canStart || store.testing}
      title={store.dirty ? "Save your changes first" : undefined}
      onclick={() => store.testSelected()}
    >
      {store.testing ? "Testing…" : "Test Chain"}
    </button>
    <button
      disabled={!store.dirty || store.saving || !store.draftValid}
      title={store.dirty && !store.draftValid ? "Fix the highlighted fields first" : undefined}
      onclick={() => store.save()}
    >
      {store.saving ? "Saving…" : "Save"}
    </button>
    {#if store.selectedActive}
      <button class="danger" disabled={store.toggling} onclick={() => store.toggleSelected()}>
        Stop
      </button>
    {:else}
      <button
        class="primary"
        disabled={!canStart || store.toggling}
        title={store.dirty ? "Save your changes first" : undefined}
        onclick={() => store.toggleSelected()}
      >
        Start
      </button>
    {/if}
  </div>
</header>
