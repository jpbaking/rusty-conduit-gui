<script lang="ts">
  import { api, errorMessage } from "../api";
  import { isStrongPassword } from "../password";
  import { store } from "../stores.svelte";
  import PasswordRules from "./PasswordRules.svelte";

  const uid = $props.id();

  let keyringBusy = $state(false);
  let keyringError = $state<string | null>(null);

  async function setKeyring(enabled: boolean) {
    keyringBusy = true;
    keyringError = null;
    try {
      store.setVault(await api.setVaultKeyring(enabled));
    } catch (error) {
      keyringError = errorMessage(error);
    } finally {
      keyringBusy = false;
    }
  }

  function toggleKeyring(event: Event & { currentTarget: HTMLInputElement }) {
    const enabled = event.currentTarget.checked;
    // Shown as it really is until the change is made.
    event.currentTarget.checked = store.vault.keyring;
    // Storing the key needs it in memory; turning it off does not.
    if (enabled) store.runUnlocked(() => void setKeyring(true));
    else void setKeyring(false);
  }

  // Held only until submit, then cleared before any request is awaited.
  let current = $state("");
  let next = $state("");
  let confirmation = $state("");
  let changing = $state(false);
  let changeError = $state<string | null>(null);
  let changeResult = $state<string | null>(null);
  const canChange = $derived(!!current && isStrongPassword(next) && !!confirmation && !changing);

  async function changePassword(event: SubmitEvent) {
    event.preventDefault();
    if (!canChange) return;
    const [oldPassword, newPassword, repeated] = [current, next, confirmation];
    current = "";
    next = "";
    confirmation = "";
    changeError = null;
    changeResult = null;
    if (newPassword !== repeated) {
      changeError = "The new passwords do not match. Enter them again.";
      return;
    }
    changing = true;
    try {
      const status = await api.changeMasterPassword(oldPassword, newPassword);
      store.setVault(status);
      changeResult = status.keyring
        ? "Master password changed. The OS keyring has the new key."
        : "Master password changed.";
      await store.refresh();
    } catch (error) {
      changeError = errorMessage(error);
      // A keyring that could not be updated was turned off; show that.
      store.setVault(await api.vaultStatus().catch(() => store.vault));
    } finally {
      changing = false;
    }
  }
</script>

<section aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>Vault</h2>
  {#if !store.vault.initialized}
    <p class="muted">No vault yet. It holds your SSH keys, MITM CAs, and saved passwords, encrypted.</p>
    <div>
      <button class="primary" onclick={() => store.requestUnlock()}>Create Vault</button>
    </div>
  {:else}
    <label class="check">
      <input type="checkbox" checked={store.vault.keyring} disabled={keyringBusy} onchange={toggleKeyring} />
      Unlock with the OS keyring
      <small class="muted">the master password keeps working</small>
    </label>
    {#if keyringError}<p class="reason" role="alert">{keyringError}</p>{/if}

    <form class="settings-subform" onsubmit={changePassword} autocomplete="off" aria-labelledby={`${uid}-change`}>
      <h3 id={`${uid}-change`}>Change master password</h3>
      <label class="field">
        Current master password
        <input type="password" bind:value={current} disabled={changing} autocomplete="current-password" />
      </label>
      <label class="field">
        New master password
        <input
          type="password"
          bind:value={next}
          disabled={changing}
          autocomplete="new-password"
          aria-describedby={`${uid}-rules`}
        />
      </label>
      <PasswordRules password={next} id={`${uid}-rules`} />
      <label class="field">
        Confirm new master password
        <input type="password" bind:value={confirmation} disabled={changing} autocomplete="new-password" />
      </label>
      <p class="muted">
        Saved keys and passwords are re-encrypted under a new key{store.vault.keyring
          ? ", and the OS keyring is updated"
          : ""}. Sessions keep running.
      </p>
      <div class="form-actions">
        <button type="submit" class="primary" disabled={!canChange}>
          {changing ? "Changing…" : "Change Password"}
        </button>
      </div>
      {#if changeError}<p class="reason" role="alert">{changeError}</p>{/if}
      {#if changeResult}<p class="ok-text" role="status">{changeResult}</p>{/if}
    </form>
  {/if}
</section>
