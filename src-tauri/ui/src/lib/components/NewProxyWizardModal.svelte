<script lang="ts">
  import { ApiError, api, errorMessage } from "../api";
  import { store, type ProxyPreset } from "../stores.svelte";
  import type { AirSwitchPreview, CliTomlFormat, ImportedProfileSummary, TomlImportPreview } from "../types";
  import BrowseButton from "./BrowseButton.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    onClose: () => void;
  }

  let { onClose }: Props = $props();

  const uid = $props.id();

  type WizardChoice = ProxyPreset | "import";

  const PRESETS: { choice: WizardChoice; title: string; binary: string; summary: string }[] = [
    {
      choice: "direct",
      title: "Direct",
      binary: "rusty-conduit",
      summary: "A local HTTP and SOCKS proxy that connects straight out. No upstreams, no rules.",
    },
    {
      choice: "tunnel",
      title: "Through a tunnel",
      binary: "rusty-conduit-ssh",
      summary: "Sends everything through an SSH Tunnel by default.",
    },
    {
      choice: "switch",
      title: "Auto Switch",
      binary: "rusty-conduit-switch",
      summary: "Starts direct; add rules that pick a tunnel or upstream per host, port, or time.",
    },
    {
      choice: "import",
      title: "Auto Switch — Import backup",
      binary: "rusty-conduit-switch",
      summary: "Browse for an AirSwitch / ZeroOmega / SwitchyOmega .bak backup (or CLI config.toml).",
    },
  ];

  const IMPORT_FILES = [
    { name: "AirSwitch / ZeroOmega / SwitchyOmega backup", extensions: ["bak", "json"] },
    { name: "CLI config", extensions: ["toml"] },
  ];
  const FORMATS: { value: CliTomlFormat | "auto"; label: string }[] = [
    { value: "auto", label: "Auto-detect" },
    { value: "rusty-conduit", label: "rusty-conduit" },
    { value: "rusty-conduit-ssh", label: "rusty-conduit-ssh (Proxy + Tunnel)" },
    { value: "rusty-conduit-switch", label: "rusty-conduit-switch" },
  ];

  const isAbsolutePath = (p: string) => /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(p);
  const isTomlPath = (p: string) => p.trim().toLowerCase().endsWith(".toml");
  const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

  let choice = $state<WizardChoice>("direct");
  let tunnelId = $state<string>(store.tunnels[0]?.profile.id ?? "");

  // Import state (when choice === "import")
  let importPath = $state("");
  let tomlFormat = $state<CliTomlFormat | "auto">("auto");
  let importName = $state("");
  let busy = $state(false);
  let importError = $state<string | null>(null);
  let bakPreview = $state.raw<AirSwitchPreview | null>(null);
  let tomlPreview = $state.raw<TomlImportPreview | null>(null);

  const isImport = $derived(choice === "import");
  const importIsToml = $derived(isTomlPath(importPath));
  const preview = $derived(importIsToml ? tomlPreview : bakPreview);
  const passwordsToVault = $derived(preview?.extracted_password_count ?? 0);
  const canPreview = $derived(!busy && !!importPath.trim());

  const needsTunnel = $derived(choice === "tunnel");
  const noTunnels = $derived(store.tunnels.length === 0);
  const canCreate = $derived(isImport ? !busy && preview !== null : !needsTunnel || tunnelId !== "");

  function resetPreview() {
    bakPreview = null;
    tomlPreview = null;
    importError = null;
  }

  const chosenFormat = () => (tomlFormat === "auto" ? null : tomlFormat);

  async function runImportAction(action: () => Promise<void>) {
    busy = true;
    importError = null;
    try {
      await action();
    } catch (failure) {
      importError = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  function loadPreview(event?: SubmitEvent) {
    event?.preventDefault();
    if (!canPreview) return;
    const file = importPath.trim();
    if (!isAbsolutePath(file)) {
      importError = "Enter a full file path.";
      return;
    }
    resetPreview();
    void runImportAction(async () => {
      if (isTomlPath(file)) {
        const result = await api.previewTomlImport(file, chosenFormat());
        tomlPreview = result;
        if (!importName.trim()) importName = result.proxy_name ?? result.tunnel_name ?? "";
      } else {
        const result = await api.previewAirswitchImport(file);
        bakPreview = result;
        if (!importName.trim()) importName = result.suggested_name;
      }
    });
  }

  function commitImport() {
    if (!preview || busy) return;
    const file = importPath.trim();
    const label = importName.trim() || null;
    const toml = isTomlPath(file);
    const importNow = () =>
      void runImportAction(async () => {
        try {
          if (toml) {
            const result = await api.commitTomlImport(file, chosenFormat(), label);
            await store.openImported(result.proxy, result.tunnel);
            const extra = [...result.warnings, ...result.notes];
            if (extra.length) store.notice = `Imported. To finish by hand: ${extra.join(" ")}`;
          } else {
            const result = await api.commitAirswitchImport(file, label);
            await store.openImported(result.proxy);
            if (result.warnings.length) {
              store.notice = `Imported with ${plural(result.warnings.length, "warning")}: ${result.warnings.join(" ")}`;
            }
          }
          onClose();
        } catch (failure) {
          if (failure instanceof ApiError && failure.code === "vault_locked") {
            store.runUnlocked(importNow);
            importError = "Unlock the vault to store the imported passwords.";
            return;
          }
          throw failure;
        }
      });
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

  function create() {
    if (!canCreate) return;
    if (choice === "import") {
      commitImport();
      return;
    }
    store.newProxyFromPreset(choice, choice === "direct" || tunnelId === "" ? null : tunnelId);
    onClose();
  }

  function createTunnelFirst() {
    store.newTunnel();
    onClose();
  }
</script>

<ModalDialog title="New Proxy" onDismiss={onClose}>
  <fieldset class="wizard-presets">
    <legend>How should this proxy reach the internet?</legend>
    {#each PRESETS as option (option.choice)}
      <label class="wizard-option" class:selected={choice === option.choice}>
        <input
          type="radio"
          name={`${uid}-preset`}
          value={option.choice}
          checked={choice === option.choice}
          onchange={() => (choice = option.choice)}
        />
        <span class="wizard-text">
          <strong>{option.title}</strong>
          <small class="muted"><code>{option.binary}</code></small>
          <span>{option.summary}</span>
        </span>
      </label>
    {/each}
  </fieldset>

  {#if choice === "import"}
    <form onsubmit={loadPreview} autocomplete="off">
      <div class="field">
        <label for={`${uid}-import-path`}>Backup or config file</label>
        <div class="inline-form">
          <input
            id={`${uid}-import-path`}
            bind:value={importPath}
            oninput={resetPreview}
            spellcheck="false"
            placeholder="Choose an AirSwitch .bak file (or config.toml)"
          />
          <BrowseButton
            mode="open"
            title="Open AirSwitch backup or CLI config"
            filters={IMPORT_FILES}
            onPick={(picked) => {
              importPath = picked;
              importName = "";
              resetPreview();
              loadPreview();
            }}
          />
        </div>
      </div>
      {#if importIsToml}
        <label class="field">
          Format
          <select bind:value={tomlFormat} onchange={() => loadPreview()}>
            {#each FORMATS as option (option.value)}
              <option value={option.value}>{option.label}</option>
            {/each}
          </select>
        </label>
      {/if}
      {#if !preview}
        <div class="form-actions">
          <button type="submit" disabled={!canPreview}>{busy ? "Reading…" : "Preview"}</button>
        </div>
      {/if}
    </form>

    {#if preview}
      <section class="import-preview" aria-labelledby={`${uid}-preview`}>
        <h3 id={`${uid}-preview`}>Preview</h3>
        {#if tomlPreview && importIsToml}
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
        {#if tomlPreview && importIsToml && tomlPreview.notes.length}
          <div class="warning" role="status">
            <strong>To finish by hand</strong>
            <ul>{#each tomlPreview.notes as n}<li>{n}</li>{/each}</ul>
          </div>
        {/if}
        <label class="field">
          Name
          <input bind:value={importName} spellcheck="false" placeholder="Name for this proxy" />
        </label>
      </section>
    {/if}

    {#if importError}<p class="reason" role="alert">{importError}</p>{/if}
  {:else if choice !== "direct"}
    {#if noTunnels}
      <p class={needsTunnel ? "warning" : "muted"}>
        {needsTunnel
          ? "There is no Tunnel yet. Create one first, then make this proxy."
          : "There is no Tunnel yet. Rules can still use direct, block, or an upstream you add."}
      </p>
      <button type="button" class="link-button" onclick={createTunnelFirst}>+ Create a Tunnel</button>
    {:else}
      <label class="field">
        Tunnel
        <select bind:value={tunnelId}>
          {#if !needsTunnel}<option value="">None for now</option>{/if}
          {#each store.tunnels as tunnel (tunnel.profile.id)}
            <option value={tunnel.profile.id}>{tunnel.profile.name}</option>
          {/each}
        </select>
      </label>
      <button type="button" class="link-button" onclick={createTunnelFirst}>Or create a new Tunnel first</button>
    {/if}
  {/if}

  {#snippet actions()}
    <button onclick={onClose}>Cancel</button>
    <button class="primary" disabled={!canCreate} onclick={create}>{isImport ? "Import" : "Create"}</button>
  {/snippet}
</ModalDialog>

<style>
  .wizard-presets {
    border: none;
    margin: 0 0 0.75rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .wizard-presets legend {
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
