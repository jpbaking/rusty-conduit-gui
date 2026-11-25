<script lang="ts">
  import { ApiError, api, errorMessage } from "../api";
  import { isStrongPassword } from "../password";
  import { store } from "../stores.svelte";
  import { today } from "../fileDialog";
  import type { ImportSummary } from "../types";
  import BrowseButton from "./BrowseButton.svelte";
  import PasswordRules from "./PasswordRules.svelte";

  const BACKUP_FILES = [{ name: "Rusty Conduit backup", extensions: ["json"] }];

  const uid = $props.id();

  /** A relative path would land in the app's working directory, and `~` is not expanded. */
  const isAbsolutePath = (path: string) => /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(path);
  const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

  let exportPath = $state("");
  let includeSecrets = $state(false);
  // Held only until submit, then cleared before any request is awaited.
  let exportPassword = $state("");
  let exportConfirmation = $state("");
  let importPath = $state("");
  let importPassword = $state("");
  let replaceExisting = $state(false);

  let busy = $state(false);
  let error = $state<string | null>(null);
  let result = $state.raw<string[]>([]);
  let warning = $state<string | null>(null);

  // A password is required with secrets and optional without; one that is given must be strong.
  const encrypting = $derived(includeSecrets || !!exportPassword);
  const canExport = $derived(
    !busy &&
      !!exportPath.trim() &&
      (!encrypting || (isStrongPassword(exportPassword) && !!exportConfirmation)),
  );

  function showError(message: string) {
    result = [];
    warning = null;
    error = message;
  }

  async function run(action: () => Promise<void>) {
    busy = true;
    error = null;
    warning = null;
    result = [];
    try {
      await action();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  function submitExport(event: SubmitEvent) {
    event.preventDefault();
    if (!canExport) return;
    const path = exportPath.trim();
    const withSecrets = includeSecrets;
    const password = exportPassword;
    const repeated = exportConfirmation;
    exportPassword = "";
    exportConfirmation = "";
    if (!isAbsolutePath(path)) return showError("Enter a full file path.");
    if (password && password !== repeated) {
      return showError("The backup passwords do not match. Enter them again.");
    }
    const exportNow = () =>
      void run(async () => {
        const summary = await api.exportConfig(path, withSecrets, password || null);
        result = [
          withSecrets
            ? "Backed up, with secrets, encrypted."
            : summary.encrypted
              ? "Backed up without secrets, encrypted."
              : "Backed up without secrets, not encrypted.",
          `${plural(summary.session_count, "session")}, ${plural(summary.host_count, "host")}, ${plural(summary.key_count, "key")}, ${plural(summary.ca_count, "CA")}.`,
          ...(withSecrets ? [`${plural(summary.secret_count, "secret")} encrypted.`] : []),
        ];
        if (summary.missing_secrets > 0) {
          warning = `${plural(summary.missing_secrets, "saved secret")} could not be included because the vault no longer has them.`;
        }
      });
    // Secrets are read from the vault, so it must be open.
    if (withSecrets) store.runUnlocked(exportNow);
    else exportNow();
  }

  function importLines(summary: ImportSummary): string[] {
    if (summary.key_only_backup) {
      return [
        "Restored an older key-only backup.",
        `${plural(summary.keys_added, "key")} added, ${summary.keys_skipped} already in the vault.`,
      ];
    }
    return [
      summary.with_secrets
        ? "Restored a backup with secrets."
        : `Restored a backup without secrets${summary.encrypted ? ", from an encrypted file" : ""}.`,
      `Sessions: ${summary.sessions_added} added, ${summary.sessions_updated} updated, ${summary.sessions_skipped} skipped.`,
      `Hosts: ${summary.hosts_added} added, ${summary.hosts_updated} updated, ${summary.hosts_skipped} skipped.`,
      `Port forward presets: ${summary.presets_added} added, ${summary.presets_updated} updated, ${summary.presets_skipped} skipped.`,
      ...(summary.with_secrets
        ? [
            `Vault: ${plural(summary.keys_added, "key")}, ${plural(summary.cas_added, "CA")}, and ${plural(summary.secrets_added, "secret")} added.`,
            `Known hosts: ${summary.known_hosts_added} added, ${summary.known_hosts_updated} updated.`,
          ]
        : []),
    ];
  }

  function submitImport(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !importPath.trim()) return;
    const path = importPath.trim();
    const password = importPassword;
    const replace = replaceExisting;
    importPassword = "";
    if (!isAbsolutePath(path)) return showError("Enter a full file path.");
    const importNow = () =>
      void run(async () => {
        try {
          const summary = await api.importConfig(path, password || null, replace);
          result = importLines(summary);
          if (summary.credentials_removed > 0) {
            warning = `${plural(summary.credentials_removed, "credential link")} removed because the file could not vouch for them. Add them again where needed.`;
          }
          await store.refresh();
        } catch (failure) {
          // A backup with secrets is restored into the vault, so open it and try again.
          if (failure instanceof ApiError && failure.code === "vault_locked") {
            store.runUnlocked(importNow);
            error = "Unlock the vault to restore this backup's secrets.";
            return;
          }
          throw failure;
        }
      });
    importNow();
  }
</script>

<section aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>Backup and restore</h2>

  <form class="settings-subform" onsubmit={submitExport} autocomplete="off" aria-labelledby={`${uid}-export`}>
    <h3 id={`${uid}-export`}>Back up</h3>
    <div class="field">
      <label for={`${uid}-export-path`}>Save to file</label>
      <div class="inline-form">
        <input id={`${uid}-export-path`} bind:value={exportPath} spellcheck="false" placeholder="Choose where to save" />
        <BrowseButton
          mode="save"
          title="Save backup"
          defaultPath={exportPath.trim() || `rusty-conduit-backup-${today()}.json`}
          filters={BACKUP_FILES}
          onPick={(path) => (exportPath = path)}
        />
      </div>
    </div>
    <p class="muted">
      Holds sessions, hosts, and port forward presets. An existing file at this path is replaced.
    </p>
    <label class="check">
      <input type="checkbox" bind:checked={includeSecrets} />
      Include secrets: SSH keys, MITM CAs, saved passwords, and pinned host keys
    </label>
    <label class="field">
      <span>
        Backup password
        <small class="muted">{includeSecrets ? "required with secrets" : "optional, encrypts the file"}</small>
      </span>
      <input
        type="password"
        bind:value={exportPassword}
        autocomplete="new-password"
        aria-required={includeSecrets}
        aria-describedby={encrypting ? `${uid}-rules` : undefined}
      />
    </label>
    {#if encrypting}
      <PasswordRules password={exportPassword} id={`${uid}-rules`} />
      <label class="field">
        Confirm backup password
        <input type="password" bind:value={exportConfirmation} autocomplete="new-password" />
      </label>
      <p class="muted">The file is encrypted with this password. Without it, the backup cannot be restored.</p>
    {:else}
      <p class="muted">Without a password, the file is saved unencrypted.</p>
    {/if}
    <div class="form-actions">
      <button type="submit" class="primary" disabled={!canExport}>Back Up</button>
    </div>
  </form>

  <form class="settings-subform" onsubmit={submitImport} autocomplete="off" aria-labelledby={`${uid}-import`}>
    <h3 id={`${uid}-import`}>Restore</h3>
    <div class="field">
      <label for={`${uid}-import-path`}>Restore from file</label>
      <div class="inline-form">
        <input id={`${uid}-import-path`} bind:value={importPath} spellcheck="false" placeholder="Choose a backup file" />
        <BrowseButton mode="open" title="Open backup" filters={BACKUP_FILES} onPick={(path) => (importPath = path)} />
      </div>
    </div>
    <label class="field">
      <span>Backup password <small class="muted">only for an encrypted backup</small></span>
      <input type="password" bind:value={importPassword} autocomplete="off" />
    </label>
    <label class="check">
      <input type="checkbox" bind:checked={replaceExisting} />
      Replace existing
    </label>
    <p class="muted">
      {replaceExisting
        ? "Matching sessions, hosts, and presets are overwritten."
        : "Matching sessions, hosts, and presets are skipped."}
      Older key-only backups can be restored here too.
    </p>
    <div class="form-actions">
      <button type="submit" disabled={busy || !importPath.trim()}>Restore</button>
    </div>
  </form>

  {#if error}<p class="reason" role="alert">{error}</p>{/if}
  {#if result.length}
    <div class="ok-text" role="status">
      {#each result as line}<p>{line}</p>{/each}
    </div>
  {/if}
  {#if warning}<p class="reason" role="alert">{warning}</p>{/if}
</section>
