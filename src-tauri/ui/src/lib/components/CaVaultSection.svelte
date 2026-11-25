<script lang="ts">
  import { api, errorMessage } from "../api";
  import { caExpiry, formatDate, isActive } from "../format";
  import { store } from "../stores.svelte";
  import type { CaView, Usage } from "../types";
  import AddCaModal from "./AddCaModal.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  const uid = $props.id();
  const renameFormId = `${uid}-rename`;

  let adding = $state(false);
  let renaming = $state.raw<CaView | null>(null);
  let renameValue = $state("");
  let deleting = $state.raw<CaView | null>(null);
  let deleteUsage = $state.raw<Usage>({ hosts: [], sessions: [] });
  let usageChanged = $state(false);
  let busy = $state(false);
  let dialogError = $state<string | null>(null);

  const ready = $derived(store.vault.initialized && store.vault.unlocked);
  const unsavedUsers = $derived(deleting ? store.draftsUsingCa(deleting.id) : []);
  /** Sessions that hold the CA in memory right now, so deleting it stops them. */
  const runningIds = $derived(
    new Set(store.sessions.filter((s) => isActive(s.runtime.state)).map((s) => s.profile.id)),
  );

  const usageLabel = (count: number) => `Used by ${count} ${count === 1 ? "session" : "sessions"}`;
  const usageNames = (usage: Usage) => usage.sessions.map((ref) => ref.name).join(", ");

  function selectOnFocus(node: HTMLInputElement) {
    node.focus();
    node.select();
  }

  function startRename(ca: CaView) {
    renaming = ca;
    renameValue = ca.name;
    dialogError = null;
  }

  async function submitRename(event: SubmitEvent) {
    event.preventDefault();
    if (!renaming || busy || !renameValue.trim()) return;
    busy = true;
    dialogError = null;
    try {
      await api.renameMitmCa(renaming.id, renameValue);
      await store.refresh();
      renaming = null;
    } catch (error) {
      dialogError = errorMessage(error);
    } finally {
      busy = false;
    }
  }

  function startDelete(ca: CaView) {
    deleting = ca;
    deleteUsage = ca.usage;
    usageChanged = false;
    dialogError = null;
  }

  async function confirmDelete() {
    if (!deleting || busy) return;
    busy = true;
    dialogError = null;
    try {
      const fresh = await store.deleteMitmCa(deleting.id, deleteUsage);
      if (fresh) {
        deleteUsage = fresh;
        usageChanged = true;
      } else {
        deleting = null;
      }
    } catch (error) {
      dialogError = errorMessage(error);
    } finally {
      busy = false;
    }
  }
</script>

<section class="vault-section" aria-labelledby={`${uid}-heading`}>
  <div class="view-header">
    <h2 id={`${uid}-heading`}>MITM CAs <small class="muted">used to decrypt HTTPS</small></h2>
    <div class="vault-actions">
      <button class="primary" disabled={!ready} onclick={() => (adding = true)}>Upload CA</button>
    </div>
  </div>

  {#if store.cas.length === 0}
    <p class="muted">No CAs stored.</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Subject</th>
            <th scope="col">SHA-256 fingerprint</th>
            <th scope="col">Expiry</th>
            <th scope="col">Created</th>
            <th scope="col">Usage</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each store.cas as ca (ca.id)}
            {@const expiry = caExpiry(ca.not_after)}
            <tr>
              <td><strong>{ca.name}</strong></td>
              <td>{ca.subject}</td>
              <td><code>{ca.fingerprint_sha256}</code></td>
              <td><span class={`pill ${expiry.tone}`} title={formatDate(ca.not_after)}>{expiry.label}</span></td>
              <td>{formatDate(ca.created_at)}</td>
              <td>
                <span class="usage-badge" class:used={ca.used_by > 0} title={usageNames(ca.usage)}>
                  {usageLabel(ca.used_by)}
                </span>
              </td>
              <td>
                <div class="row-actions">
                  <button onclick={() => startRename(ca)}>Rename</button>
                  <button class="danger" disabled={!ready} onclick={() => startDelete(ca)}>Delete</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

{#if adding}
  <AddCaModal onClose={() => (adding = false)} />
{/if}

{#if renaming}
  <ModalDialog title="Rename CA" onDismiss={() => { if (!busy) renaming = null; }}>
    <form id={renameFormId} class="modal-form" onsubmit={submitRename}>
      <label class="field">
        Name
        <input bind:value={renameValue} required use:selectOnFocus />
      </label>
      {#if dialogError}<p class="reason" role="alert">{dialogError}</p>{/if}
    </form>
    {#snippet actions()}
      <button type="button" disabled={busy} onclick={() => (renaming = null)}>Cancel</button>
      <button type="submit" form={renameFormId} class="primary" disabled={busy || !renameValue.trim()}>Rename</button>
    {/snippet}
  </ModalDialog>
{/if}

{#if deleting}
  {@const affected = deleteUsage.sessions.length}
  <ModalDialog title="Delete CA" onDismiss={() => { if (!busy) deleting = null; }}>
    <p>Delete <strong>{deleting.name}</strong>? This cannot be undone.</p>
    {#if usageChanged}
      <p class="reason" role="alert">The list of affected sessions changed. Review it before deleting.</p>
    {/if}
    {#if affected > 0}
      <p>
        These sessions will have no CA. Running ones are stopped now, and none of them will start
        until you choose another CA or turn MITM off:
      </p>
      <ul class="plain-list">
        {#each deleteUsage.sessions as ref (ref.id)}
          <li>{ref.name}{#if runningIds.has(ref.id)} <span class="pill busy">running, will be stopped</span>{/if}</li>
        {/each}
      </ul>
    {/if}
    {#if unsavedUsers.length > 0}
      <p>It will also be removed from unsaved edits to: {unsavedUsers.join(", ")}.</p>
    {/if}
    {#if dialogError}<p class="reason" role="alert">{dialogError}</p>{/if}
    {#snippet actions()}
      <button disabled={busy} onclick={() => (deleting = null)}>Cancel</button>
      <button class="danger" disabled={busy} onclick={confirmDelete}>
        {affected > 0 ? `Delete and remove from ${affected}` : "Delete"}
      </button>
    {/snippet}
  </ModalDialog>
{/if}
