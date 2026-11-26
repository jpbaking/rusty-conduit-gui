<script lang="ts">
  import { ApiError, api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { AirSwitchPreview, CliTomlFormat, ImportedProfileSummary, TomlImportPreview } from "../types";
  import BrowseButton from "./BrowseButton.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    onClose: () => void;
  }

  let { onClose }: Props = $props();

  const uid = $props.id();

  type Mode = "airswitch" | "toml";

  const BAK_FILES = [{ name: "AirSwitch / ZeroOmega / SwitchyOmega backup", extensions: ["bak", "json"] }];
  const TOML_FILES = [{ name: "CLI config", extensions: ["toml"] }];
  const FORMATS: { value: CliTomlFormat | "auto"; label: string }[] = [
    { value: "auto", label: "Auto-detect" },
    { value: "rusty-conduit", label: "rusty-conduit" },
    { value: "rusty-conduit-ssh", label: "rusty-conduit-ssh (Proxy + Tunnel)" },
    { value: "rusty-conduit-switch", label: "rusty-conduit-switch" },
  ];

  /** A relative path would land in the app's working directory, and `~` is not expanded. */
  const isAbsolutePath = (path: string) => /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(path);
  const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

  let mode = $state<Mode>("airswitch");
  let path = $state("");
  let format = $state<CliTomlFormat | "auto">("auto");
  let name = $state("");

  let busy = $state(false);
  let error = $state<string | null>(null);
  let bakPreview = $state.raw<AirSwitchPreview | null>(null);
  let tomlPreview = $state.raw<TomlImportPreview | null>(null);

  const preview = $derived(mode === "airswitch" ? bakPreview : tomlPreview);
  const passwordsToVault = $derived(preview?.extracted_password_count ?? 0);
  const canPreview = $derived(!busy && !!path.trim());
  const canImport = $derived(!busy && preview !== null);

  /** A preview belongs to one file, mode, and format: changing any of them drops it. */
  function resetPreview() {
    bakPreview = null;
    tomlPreview = null;
    error = null;
  }

  function setMode(next: Mode) {
    if (mode === next) return;
    mode = next;
    path = "";
    name = "";
    resetPreview();
  }

  const chosenFormat = () => (format === "auto" ? null : format);

  async function run(action: () => Promise<void>) {
    busy = true;
    error = null;
    try {
      await action();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  function loadPreview(event?: SubmitEvent) {
    event?.preventDefault();
    if (!canPreview) return;
    const file = path.trim();
    if (!isAbsolutePath(file)) {
      error = "Enter a full file path.";
      return;
    }
    resetPreview();
    void run(async () => {
      if (mode === "airswitch") {
        const result = await api.previewAirswitchImport(file);
        bakPreview = result;
        if (!name.trim()) name = result.suggested_name;
      } else {
        const result = await api.previewTomlImport(file, chosenFormat());
        tomlPreview = result;
        if (!name.trim()) name = result.proxy_name ?? result.tunnel_name ?? "";
      }
    });
  }

  function commit() {
    if (!canImport) return;
    const file = path.trim();
    const label = name.trim() || null;
    const importNow = () =>
      void run(async () => {
        try {
          if (mode === "airswitch") {
            const result = await api.commitAirswitchImport(file, label);
            await store.openImported(result.proxy);
            if (result.warnings.length) store.notice = `Imported with ${plural(result.warnings.length, "warning")}: ${result.warnings.join(" ")}`;
          } else {
            const result = await api.commitTomlImport(file, chosenFormat(), label);
            await store.openImported(result.proxy, result.tunnel);
            const extra = [...result.warnings, ...result.notes];
            if (extra.length) store.notice = `Imported. To finish by hand: ${extra.join(" ")}`;
          }
          onClose();
        } catch (failure) {
          // Imported passwords go straight into the vault, so open it and try again.
          if (failure instanceof ApiError && failure.code === "vault_locked") {
            store.runUnlocked(importNow);
            error = "Unlock the vault to store the imported passwords.";
            return;
          }
          throw failure;
        }
      });
    // Asking first avoids a failed round trip when passwords will be vaulted.
    if (passwordsToVault > 0) store.runUnlocked(importNow);
    else importNow();
  }

  function profileLine(p: ImportedProfileSummary): string {
    const where = p.host ? ` ${p.host}${p.port ? `:${p.port}` : ""}` : "";
    const user = p.username ? `, user ${p.username}` : "";
    const secret = p.password_extracted
      ? ", password → Vault"
      : p.password_source
        ? `, password from ${p.password_source}`
        : "";
    return `${p.name} (${p.kind}${where}${user}${secret})`;
  }
</script>

<ModalDialog title="Import" onDismiss={onClose}>
  <fieldset class="import-modes">
    <legend>What are you importing?</legend>
    <label class="wizard-option" class:selected={mode === "airswitch"}>
      <input type="radio" name={`${uid}-mode`} checked={mode === "airswitch"} onchange={() => setMode("airswitch")} />
      <span class="wizard-text">
        <strong>Browser extension backup</strong>
        <span>An AirSwitch, ZeroOmega, or SwitchyOmega <code>.bak</code> file. Becomes a new Proxy.</span>
      </span>
    </label>
    <label class="wizard-option" class:selected={mode === "toml"}>
      <input type="radio" name={`${uid}-mode`} checked={mode === "toml"} onchange={() => setMode("toml")} />
      <span class="wizard-text">
        <strong>CLI <code>config.toml</code></strong>
        <span>From <code>rusty-conduit</code>, <code>rusty-conduit-ssh</code>, or <code>rusty-conduit-switch</code>.</span>
      </span>
    </label>
  </fieldset>

  <form onsubmit={loadPreview} autocomplete="off">
    <div class="field">
      <label for={`${uid}-path`}>File</label>
      <div class="inline-form">
        <input
          id={`${uid}-path`}
          bind:value={path}
          oninput={resetPreview}
          spellcheck="false"
          placeholder={mode === "airswitch" ? "Choose a .bak file" : "Choose a config.toml"}
        />
        <BrowseButton
          mode="open"
          title={mode === "airswitch" ? "Open extension backup" : "Open CLI config"}
          filters={mode === "airswitch" ? BAK_FILES : TOML_FILES}
          onPick={(picked) => {
            path = picked;
            resetPreview();
          }}
        />
      </div>
    </div>
    {#if mode === "toml"}
      <label class="field">
        Format
        <select bind:value={format} onchange={resetPreview}>
          {#each FORMATS as option (option.value)}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </label>
    {/if}
    <div class="form-actions">
      <button type="submit" disabled={!canPreview}>Preview</button>
    </div>
  </form>

  {#if preview}
    <section class="import-preview" aria-labelledby={`${uid}-preview`}>
      <h3 id={`${uid}-preview`}>Preview</h3>
      {#if tomlPreview && mode === "toml"}
        <p>
          Format: <code>{tomlPreview.format}</code>
          <small class="muted">{tomlPreview.detected ? "detected from the file" : "as chosen"}</small>
        </p>
        {#if tomlPreview.tunnel_name}
          <p class="muted">Creates a Tunnel{tomlPreview.proxy_name ? " and a Proxy that uses it" : ""}.</p>
        {/if}
      {/if}
      <p>
        {plural(preview.profile_count, "upstream profile")}, {plural(preview.rule_count, "rule")}{passwordsToVault
          ? `, ${plural(passwordsToVault, "password")} to store in the Vault`
          : ""}.
      </p>
      {#if passwordsToVault && !store.vault.unlocked}
        <p class="warning">The vault is locked. You will be asked to unlock it so the passwords can be stored.</p>
      {/if}
      {#if preview.profiles.length}
        <ul class="import-profiles">
          {#each preview.profiles as p, i (i)}<li>{profileLine(p)}</li>{/each}
        </ul>
      {/if}
      {#if preview.warnings.length}
        <div class="warning" role="status">
          <strong>Not imported</strong>
          <ul>{#each preview.warnings as w}<li>{w}</li>{/each}</ul>
        </div>
      {/if}
      {#if tomlPreview && mode === "toml" && tomlPreview.notes.length}
        <div class="warning" role="status">
          <strong>To finish by hand</strong>
          <ul>{#each tomlPreview.notes as n}<li>{n}</li>{/each}</ul>
        </div>
      {/if}
      <label class="field">
        Name
        <input bind:value={name} spellcheck="false" placeholder="Name for what is imported" />
      </label>
    </section>
  {/if}

  {#if error}<p class="reason" role="alert">{error}</p>{/if}

  {#snippet actions()}
    <button onclick={onClose}>Cancel</button>
    <button class="primary" disabled={!canImport} onclick={commit}>Import</button>
  {/snippet}
</ModalDialog>

<style>
  .import-modes {
    border: none;
    margin: 0 0 0.75rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .import-modes legend {
    margin-bottom: 0.5rem;
  }
  .wizard-option {
    display: flex;
    gap: 0.6rem;
    align-items: flex-start;
    padding: 0.5rem 0.6rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
  }
  .wizard-option.selected {
    background: var(--surface-2);
  }
  .wizard-text {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .import-preview {
    margin-top: 0.75rem;
  }
  .import-profiles {
    margin: 0.25rem 0 0.5rem;
    padding-left: 1.2rem;
  }
</style>
