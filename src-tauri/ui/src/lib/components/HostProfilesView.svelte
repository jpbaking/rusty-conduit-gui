<script lang="ts">
  import { store } from "../stores.svelte";
  import type { HostProfile } from "../types";
  import HopEditor from "./HopEditor.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  const uid = $props.id();
  let deleting = $state<HostProfile | null>(null);

  const draft = $derived(store.hostDraft);
  const errors = $derived(store.hostDraftErrors);
  const isExisting = $derived(!!draft && store.hosts.some((h) => h.id === draft.id));

  function linkedSessions(id: string): string[] {
    return store.sessions
      .filter((s) => s.profile.hops.some((hop) => hop.host.id === id))
      .map((s) => s.profile.name);
  }

  async function confirmDelete() {
    const host = deleting;
    deleting = null;
    if (host) await store.deleteHost(host);
  }
</script>

<main class="content">
  <div class="view-header">
    <h1>Host Profiles</h1>
    <button class="primary" onclick={() => store.newHost()}>+ New Profile</button>
  </div>

  {#if store.hosts.length === 0 && !draft}
    <p class="muted">No host profiles yet. Create one, or use Save as Profile on a session hop.</p>
  {:else if store.hosts.length > 0}
    <ul class="host-list">
      {#each store.hosts as host (host.id)}
        {@const linked = linkedSessions(host.id)}
        <li class:active={draft?.id === host.id}>
          <span class="host-summary">
            <strong>{host.name}</strong>
            <code>{host.user}@{host.host}:{host.port}</code>
            <small class="muted">
              {host.auth.length} sign-in {host.auth.length === 1 ? "method" : "methods"},
              used by {linked.length} {linked.length === 1 ? "session" : "sessions"}
            </small>
          </span>
          <button onclick={() => store.editHost(host)}>Edit</button>
          <button class="danger" onclick={() => (deleting = host)}>Delete</button>
        </li>
      {/each}
    </ul>
  {/if}

  {#if draft}
    <section class="host-form" aria-labelledby="host-form-heading">
      <h2 id="host-form-heading">{isExisting ? `Edit ${draft.name || "profile"}` : "New profile"}</h2>
      <div class="field">
        <label class="field">
        Profile name
        <input
          value={draft.name}
          aria-invalid={!!errors.name}
          aria-describedby={errors.name ? `${uid}-errors-name` : undefined}
          oninput={(e) => {
            const name = e.currentTarget.value;
            store.updateHostDraft((host) => ({ ...host, name }));
          }}
        />
        </label>
        {#if errors.name}<span id={`${uid}-errors-name`} class="field-error">{errors.name}</span>{/if}
      </div>
      {#key draft.id}
        <HopEditor host={draft} {errors} onHostChange={(edit) => store.updateHostDraft(edit)} />
      {/key}
      {#if isExisting && linkedSessions(draft.id).length > 0}
        <p class="muted">Saving updates the linked hops. Running sessions use it on their next start.</p>
      {/if}
      <div class="form-actions">
        <button onclick={() => store.cancelHost()}>Cancel</button>
        <button
          class="primary"
          disabled={store.savingHost || Object.keys(errors).length > 0}
          onclick={() => store.saveHost()}
        >
          {store.savingHost ? "Saving…" : "Save Profile"}
        </button>
      </div>
    </section>
  {/if}
</main>

{#if deleting}
  {@const linked = linkedSessions(deleting.id)}
  <ModalDialog title="Delete host profile" onDismiss={() => (deleting = null)}>
    <p>Delete <strong>{deleting.name}</strong>?</p>
    {#if linked.length > 0}
      <p>These sessions keep working with their own copy of the details, but stop being linked:</p>
      <ul class="plain-list">
        {#each linked as name (name)}<li>{name}</li>{/each}
      </ul>
    {/if}
    {#snippet actions()}
      <button onclick={() => (deleting = null)}>Cancel</button>
      <button class="danger" onclick={confirmDelete}>Delete</button>
    {/snippet}
  </ModalDialog>
{/if}
