<script lang="ts">
  import { api, errorMessage } from "../api";
  import { formatDate } from "../format";
  import { store } from "../stores.svelte";
  import type { KeyView, Usage } from "../types";
  import AddKeyModal, { type AddKeyMode } from "./AddKeyModal.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  const uid = $props.id();
  const renameFormId = `${uid}-rename`;

  let adding = $state<AddKeyMode | null>(null);
  let renaming = $state.raw<KeyView | null>(null);
  let renameValue = $state("");
  let deleting = $state.raw<KeyView | null>(null);
  let deleteUsage = $state.raw<Usage>({ hosts: [], sessions: [] });
  let usageChanged = $state(false);
  let busy = $state(false);
  let dialogError = $state<string | null>(null);
  let copiedId = $state<string | null>(null);
  let copyFallback = $state.raw<KeyView | null>(null);
  let copiedTimer: ReturnType<typeof setTimeout> | undefined;

  const ready = $derived(store.vault.initialized && store.vault.unlocked);
  const unsavedUsers = $derived(deleting ? store.draftsUsingKey(deleting.id) : []);

  $effect(() => () => clearTimeout(copiedTimer));

  const usageLabel = (count: number) =>
    `Used by ${count} ${count === 1 ? "host/session" : "hosts/sessions"}`;

  const usageNames = (usage: Usage) =>
    [...usage.hosts, ...usage.sessions].map((ref) => ref.name).join(", ");

  async function copyPublicKey(key: KeyView) {
    try {
      await navigator.clipboard.writeText(key.public_key_openssh);
      copiedId = key.id;
      clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => (copiedId = null), 1500);
    } catch {
      copyFallback = key;
    }
  }

  function selectOnFocus(node: HTMLInputElement) {
    node.focus();
    node.select();
  }

  function startRename(key: KeyView) {
    renaming = key;
    renameValue = key.name;
    dialogError = null;
  }

  async function submitRename(event: SubmitEvent) {
    event.preventDefault();
    if (!renaming || busy || !renameValue.trim()) return;
    busy = true;
    dialogError = null;
    try {
      await api.renameKey(renaming.id, renameValue);
      await store.refresh();
      renaming = null;
    } catch (error) {
      dialogError = errorMessage(error);
    } finally {
      busy = false;
    }
  }

  function startDelete(key: KeyView) {
    deleting = key;
    deleteUsage = key.usage;
    usageChanged = false;
    dialogError = null;
  }

  async function confirmDelete() {
    if (!deleting || busy) return;
    busy = true;
    dialogError = null;
    try {
      const fresh = await store.deleteKey(deleting.id, deleteUsage);
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

<main class="content">
  <div class="view-header">
    <h1>Key Vault</h1>
    <div class="vault-actions">
      <button disabled={!ready} onclick={() => (adding = "upload")}>Upload File</button>
      <button disabled={!ready} onclick={() => (adding = "paste")}>Paste Private Key</button>
      <button class="primary" disabled={!ready} onclick={() => (adding = "generate")}>Generate New Key</button>
    </div>
  </div>

  {#if !ready}
    <p class="warning">
      {store.vault.initialized ? "The vault is locked." : "The vault has not been created yet."}
      <button onclick={() => store.requestUnlock()}>
        {store.vault.initialized ? "Unlock Vault" : "Create Vault"}
      </button>
    </p>
  {/if}

  {#if store.keys.length === 0}
    <p class="muted">No keys stored.</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Algorithm</th>
            <th scope="col">SHA-256 fingerprint</th>
            <th scope="col">Created</th>
            <th scope="col">Usage</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each store.keys as key (key.id)}
            <tr>
              <td><strong>{key.name}</strong></td>
              <td>{key.algorithm}</td>
              <td><code>{key.fingerprint_sha256}</code></td>
              <td>{formatDate(key.created_at)}</td>
              <td>
                <span class="usage-badge" class:used={key.used_by > 0} title={usageNames(key.usage)}>
                  {usageLabel(key.used_by)}
                </span>
              </td>
              <td>
                <div class="row-actions">
                  <button onclick={() => copyPublicKey(key)}>
                    {copiedId === key.id ? "Copied" : "Copy Public Key"}
                  </button>
                  <button onclick={() => startRename(key)}>Rename</button>
                  <button class="danger" disabled={!ready} onclick={() => startDelete(key)}>Delete</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</main>

{#if adding}
  <AddKeyModal mode={adding} onClose={() => (adding = null)} />
{/if}

{#if renaming}
  <ModalDialog title="Rename key" onDismiss={() => { if (!busy) renaming = null; }}>
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
  {@const affected = deleteUsage.hosts.length + deleteUsage.sessions.length}
  <ModalDialog title="Delete key" onDismiss={() => { if (!busy) deleting = null; }}>
    <p>Delete <strong>{deleting.name}</strong>? This cannot be undone.</p>
    {#if usageChanged}
      <p class="reason" role="alert">The list of affected items changed. Review it before deleting.</p>
    {/if}
    {#if affected > 0}
      <p>This key will be removed from:</p>
      <ul class="plain-list">
        {#each deleteUsage.hosts as ref (`host-${ref.id}`)}<li>Host: {ref.name}</li>{/each}
        {#each deleteUsage.sessions as ref (`session-${ref.id}`)}<li>Session: {ref.name}</li>{/each}
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

{#if copyFallback}
  <ModalDialog title="Copy public key" onDismiss={() => (copyFallback = null)}>
    <p>The clipboard is not available. Copy this public key instead.</p>
    <input class="url-field" readonly aria-label="Public key" value={copyFallback.public_key_openssh} use:selectOnFocus />
    {#snippet actions()}
      <button onclick={() => (copyFallback = null)}>Close</button>
    {/snippet}
  </ModalDialog>
{/if}
