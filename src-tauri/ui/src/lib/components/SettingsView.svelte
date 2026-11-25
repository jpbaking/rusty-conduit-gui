<script lang="ts">
  import { onMount } from "svelte";
  import { api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { AutostartStatus } from "../types";

  let keyringBusy = $state(false);
  let keyringError = $state<string | null>(null);

  async function toggleKeyring(event: Event & { currentTarget: HTMLInputElement }) {
    const enabled = event.currentTarget.checked;
    keyringBusy = true;
    keyringError = null;
    try {
      store.setVault(await api.setVaultKeyring(enabled));
    } catch (error) {
      keyringError = errorMessage(error);
      // Show the setting as it really is, not as clicked.
      event.currentTarget.checked = store.vault.keyring;
    } finally {
      keyringBusy = false;
    }
  }

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

  // Config passphrases stay in their DOM inputs and are never copied into component state.
  let configExportPath = $state("");
  let configImportPath = $state("");
  let includeSecrets = $state(false);
  let replaceExisting = $state(false);
  let configBusy = $state(false);
  let configError = $state<string | null>(null);
  let configResult = $state.raw<string[]>([]);
  let configWarning = $state<string | null>(null);

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

  /** Reads a password input and empties it in the same step. */
  function takeSecret(form: HTMLFormElement, name: string): string {
    const input = form.elements.namedItem(name);
    if (!(input instanceof HTMLInputElement)) return "";
    const value = input.value;
    input.value = "";
    return value;
  }

  const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

  function showConfigError(message: string) {
    configResult = [];
    configWarning = null;
    configError = message;
  }

  async function runConfig(action: () => Promise<void>) {
    configBusy = true;
    configError = null;
    configWarning = null;
    configResult = [];
    try {
      await action();
    } catch (error) {
      configError = errorMessage(error);
    } finally {
      configBusy = false;
    }
  }

  async function submitConfigExport(event: SubmitEvent) {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const passphrase = takeSecret(form, "config-export-passphrase");
    const repeated = takeSecret(form, "config-export-confirmation");
    if (configBusy) return;
    const path = configExportPath.trim();
    const withSecrets = includeSecrets;
    if (!isAbsolutePath(path)) return showConfigError("Enter a full file path.");
    if (withSecrets) {
      if (!unlocked) return showConfigError("Unlock the vault to include secrets.");
      if (!passphrase) return showConfigError("Enter a passphrase for the encrypted backup.");
      if (passphrase !== repeated) {
        return showConfigError("The passphrases do not match. Enter them again.");
      }
    }
    await runConfig(async () => {
      const summary = await api.exportConfig(path, withSecrets, withSecrets ? passphrase : null);
      configResult = [
        withSecrets ? "Exported an encrypted full backup." : "Exported config without secrets.",
        `${plural(summary.session_count, "session")}, ${plural(summary.host_count, "host")}, ${plural(summary.key_count, "key")}.`,
        ...(withSecrets ? [`${plural(summary.secret_count, "secret")} encrypted.`] : []),
      ];
      if (summary.missing_secrets > 0) {
        configWarning = `${plural(summary.missing_secrets, "saved secret")} could not be included because the vault no longer has them.`;
      }
    });
  }

  async function submitConfigImport(event: SubmitEvent) {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const passphrase = takeSecret(form, "config-import-passphrase");
    if (configBusy) return;
    const path = configImportPath.trim();
    if (!isAbsolutePath(path)) return showConfigError("Enter a full file path.");
    const replace = replaceExisting;
    await runConfig(async () => {
      const summary = await api.importConfig(path, passphrase || null, replace);
      configResult = [
        summary.encrypted ? "Imported an encrypted backup." : "Imported config.",
        `Sessions: ${summary.sessions_added} added, ${summary.sessions_updated} updated, ${summary.sessions_skipped} skipped.`,
        `Hosts: ${summary.hosts_added} added, ${summary.hosts_updated} updated, ${summary.hosts_skipped} skipped.`,
        ...(summary.encrypted
          ? [
              `Vault: ${plural(summary.keys_added, "key")} and ${plural(summary.secrets_added, "secret")} added.`,
              `Known hosts: ${summary.known_hosts_added} added, ${summary.known_hosts_updated} updated.`,
            ]
          : []),
      ];
      if (summary.credentials_removed > 0) {
        configWarning = `${plural(summary.credentials_removed, "credential link")} removed because the file could not vouch for them. Add them again where needed.`;
      }
      await store.refresh();
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
      {#if store.vault.initialized}
        <label class="check">
          <input
            type="checkbox"
            checked={store.vault.keyring}
            disabled={keyringBusy || (!unlocked && !store.vault.keyring)}
            onchange={toggleKeyring}
          />
          Unlock with the OS keyring
          <small class="muted">the master password keeps working</small>
        </label>
        {#if !unlocked && !store.vault.keyring}
          <p class="muted">Unlock the vault to store its key in the OS keyring.</p>
        {/if}
        {#if keyringError}<p class="reason" role="alert">{keyringError}</p>{/if}
      {/if}
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

    <section aria-labelledby="settings-config">
      <h2 id="settings-config">Config export and import</h2>

      <form onsubmit={submitConfigExport} autocomplete="off" aria-label="Export config">
        <label class="field">
          Export to file (full path)
          <input bind:value={configExportPath} spellcheck="false" />
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={includeSecrets} />
          Include secrets (encrypted full backup)
        </label>
        {#if includeSecrets}
          {#if !unlocked}<p class="muted">Unlock the vault to include secrets.</p>{/if}
          <label class="field">
            Backup passphrase
            <input name="config-export-passphrase" type="password" disabled={!unlocked} autocomplete="new-password" />
          </label>
          <label class="field">
            Confirm backup passphrase
            <input name="config-export-confirmation" type="password" disabled={!unlocked} autocomplete="new-password" />
          </label>
        {:else}
          <p class="muted">Passwords and private keys are left out.</p>
        {/if}
        <p class="muted">An existing file at this path is replaced.</p>
        <div class="form-actions">
          <button type="submit" disabled={configBusy || !configExportPath.trim() || (includeSecrets && !unlocked)}>
            Export Config
          </button>
        </div>
      </form>

      <form onsubmit={submitConfigImport} autocomplete="off" aria-label="Import config">
        <label class="field">
          Import from file (full path)
          <input bind:value={configImportPath} spellcheck="false" />
        </label>
        <label class="field">
          Backup passphrase (encrypted backups only)
          <input name="config-import-passphrase" type="password" autocomplete="off" />
        </label>
        <p class="muted">Encrypted backups need an unlocked vault.</p>
        <label class="check">
          <input type="checkbox" bind:checked={replaceExisting} />
          Replace existing
        </label>
        <p class="muted">
          {replaceExisting ? "Matching sessions and hosts are overwritten." : "Matching sessions and hosts are skipped."}
        </p>
        <div class="form-actions">
          <button type="submit" disabled={configBusy || !configImportPath.trim()}>Import Config</button>
        </div>
      </form>

      {#if configError}<p class="reason" role="alert">{configError}</p>{/if}
      {#if configResult.length}
        <div class="ok-text" role="status">
          {#each configResult as line}<p>{line}</p>{/each}
        </div>
      {/if}
      {#if configWarning}<p class="reason" role="alert">{configWarning}</p>{/if}
    </section>
  </div>
</main>
