<script lang="ts">
  import { api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { VaultStatus } from "../types";
  import ModalDialog from "./ModalDialog.svelte";

  const uid = $props.id();
  const formId = `${uid}-form`;

  // Held only until submit, then cleared before any request is awaited.
  let password = $state("");
  let confirmation = $state("");
  let useKeyring = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);

  const creating = $derived(!store.vault.initialized);
  const ready = $derived(!!password && (!creating || !!confirmation));

  async function run(action: () => Promise<VaultStatus>) {
    busy = true;
    error = null;
    try {
      store.setVault(await action());
      await store.refresh();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !ready) return;
    const master = password;
    const repeated = confirmation;
    password = "";
    confirmation = "";
    if (creating && master !== repeated) {
      error = "The passwords do not match. Enter them again.";
      return;
    }
    const keyring = useKeyring;
    await run(() => (creating ? api.createVault(master, keyring) : api.unlockVault(master)));
  }

  function dismiss() {
    if (!busy) store.dismissUnlock();
  }
</script>

<ModalDialog title={creating ? "Create vault" : "Unlock vault"} onDismiss={dismiss}>
  <form id={formId} class="modal-form" onsubmit={submit} autocomplete="off">
    {#if creating}
      <p>Choose a master password. Keys and passwords are always stored encrypted.</p>
    {:else}
      <p>Enter your master password to use saved keys and passwords.</p>
    {/if}
    <label class="field">
      Master password
      <input
        type="password"
        bind:value={password}
        autocomplete={creating ? "new-password" : "current-password"}
      />
    </label>
    {#if creating}
      <label class="field">
        Confirm master password
        <input type="password" bind:value={confirmation} autocomplete="new-password" />
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={useKeyring} />
        Also store the unlock key in the OS keyring
      </label>
    {/if}
    {#if error}<p class="reason" role="alert">{error}</p>{/if}
  </form>
  {#snippet actions()}
    <button type="button" disabled={busy} onclick={dismiss}>Not now</button>
    {#if !creating}
      <button type="button" disabled={busy} onclick={() => run(api.unlockVaultKeyring)}>Use OS Keyring</button>
    {/if}
    <button type="submit" form={formId} class="primary" disabled={busy || !ready}>
      {busy ? "Working…" : creating ? "Create Vault" : "Unlock"}
    </button>
  {/snippet}
</ModalDialog>
