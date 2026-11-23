<script lang="ts">
  import { onMount } from "svelte";
  import { api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { AutostartStatus } from "../types";

  let autostart = $state.raw<AutostartStatus | null>(null);
  let autostartBusy = $state(false);
  let autostartError = $state<string | null>(null);

  let exportPath = $state("");
  let importPath = $state("");
  // Held only until submit, then cleared before any request is awaited.
  let exportPassphrase = $state("");
  let exportConfirmation = $state("");
  let importPassphrase = $state("");
  let backupBusy = $state(false);
  let backupError = $state<string | null>(null);
  let backupResult = $state<string | null>(null);

  const unlocked = $derived(store.vault.initialized && store.vault.unlocked);
  const vaultLabel = $derived(
    !store.vault.initialized ? "Not created" : store.vault.unlocked ? "Unlocked" : "Locked",
  );

  /** A relative path would land in the app's working directory, and `~` is not expanded. */
  const isAbsolutePath = (path: string) => /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(path);

  onMount(async () => {
    try {
      autostart = await api.getAutostart();
    } catch (error) {
      autostartError = errorMessage(error);
    }
  });

  async function toggleAutostart(event: Event & { currentTarget: HTMLInputElement }) {
    const input = event.currentTarget;
    const enabled = input.checked;
    autostartBusy = true;
    autostartError = null;
    try {
      autostart = await api.setAutostart(enabled);
    } catch (error) {
      autostartError = errorMessage(error);
    } finally {
      input.checked = autostart?.enabled ?? false;
      autostartBusy = false;
    }
  }

  async function runBackup(action: () => Promise<string>) {
    backupBusy = true;
    backupError = null;
    backupResult = null;
    try {
      backupResult = await action();
    } catch (error) {
      backupError = errorMessage(error);
    } finally {
      backupBusy = false;
    }
  }

  async function submitExport(event: SubmitEvent) {
    event.preventDefault();
    const passphrase = exportPassphrase;
    const repeated = exportConfirmation;
    exportPassphrase = "";
    exportConfirmation = "";
    if (backupBusy || !passphrase) return;
    const path = exportPath.trim();
    backupResult = null;
    if (!isAbsolutePath(path)) {
      backupError = "Enter a full file path.";
      return;
    }
    if (passphrase !== repeated) {
      backupError = "The passphrases do not match. Enter them again.";
      return;
    }
    await runBackup(async () => {
      const { key_count } = await api.exportBackup(path, passphrase);
      return `Exported ${key_count} ${key_count === 1 ? "key" : "keys"}.`;
    });
  }

  async function submitImport(event: SubmitEvent) {
    event.preventDefault();
    const passphrase = importPassphrase;
    importPassphrase = "";
    if (backupBusy || !passphrase) return;
    const path = importPath.trim();
    backupResult = null;
    if (!isAbsolutePath(path)) {
      backupError = "Enter a full file path.";
      return;
    }
    await runBackup(async () => {
      const { imported, skipped } = await api.importBackup(path, passphrase);
      await store.refresh();
      return `Imported ${imported.length}, skipped ${skipped} already in the vault.`;
    });
  }
</script>

<main class="content">
  <h1>Settings</h1>
  <div class="settings">
    <section aria-labelledby="settings-startup">
      <h2 id="settings-startup">Startup</h2>
      <label class="check">
        <input
          type="checkbox"
          checked={autostart?.enabled ?? false}
          disabled={!autostart || autostartBusy}
          onchange={toggleAutostart}
        />
        Start at login, in the tray
      </label>
      {#if autostartError}<p class="reason" role="alert">{autostartError}</p>{/if}
    </section>

    <section aria-labelledby="settings-vault">
      <h2 id="settings-vault">Vault</h2>
      <p>Status: <strong>{vaultLabel}</strong></p>
      <div>
        {#if unlocked}
          <button onclick={() => store.lockVault()}>Lock Vault</button>
        {:else}
          <button class="primary" onclick={() => store.requestUnlock()}>
            {store.vault.initialized ? "Unlock Vault" : "Create Vault"}
          </button>
        {/if}
      </div>
    </section>

    <section aria-labelledby="settings-backup">
      <h2 id="settings-backup">Encrypted key backup</h2>
      {#if !unlocked}<p class="muted">Unlock the vault to export or import a backup.</p>{/if}

      <form onsubmit={submitExport} autocomplete="off">
        <label class="field">
          Export to file (full path)
          <input bind:value={exportPath} disabled={!unlocked} spellcheck="false" />
        </label>
        <label class="field">
          Backup passphrase
          <input type="password" bind:value={exportPassphrase} disabled={!unlocked} autocomplete="new-password" />
        </label>
        <label class="field">
          Confirm backup passphrase
          <input type="password" bind:value={exportConfirmation} disabled={!unlocked} autocomplete="new-password" />
        </label>
        <p class="muted">An existing file at this path is replaced.</p>
        <div class="form-actions">
          <button
            type="submit"
            disabled={!unlocked || backupBusy || !exportPath.trim() || !exportPassphrase || !exportConfirmation}
          >
            Export Backup
          </button>
        </div>
      </form>

      <form onsubmit={submitImport} autocomplete="off">
        <label class="field">
          Import from file (full path)
          <input bind:value={importPath} disabled={!unlocked} spellcheck="false" />
        </label>
        <label class="field">
          Backup passphrase
          <input type="password" bind:value={importPassphrase} disabled={!unlocked} autocomplete="off" />
        </label>
        <div class="form-actions">
          <button type="submit" disabled={!unlocked || backupBusy || !importPath.trim() || !importPassphrase}>
            Import Backup
          </button>
        </div>
      </form>

      {#if backupError}<p class="reason" role="alert">{backupError}</p>{/if}
      {#if backupResult}<p class="ok-text" role="status">{backupResult}</p>{/if}
    </section>
  </div>
</main>
