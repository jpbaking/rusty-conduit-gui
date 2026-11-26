<script lang="ts">
  import { ApiError, api, errorMessage } from "../api";
  import { NEW_SESSION_ID, store } from "../stores.svelte";
  import type { AirSwitchPreview, CliTomlFormat, Proxy, TomlExportResult } from "../types";
  import BrowseButton from "./BrowseButton.svelte";

  const uid = $props.id();

  const TOML_FILES = [{ name: "CLI config", extensions: ["toml"] }];
  const BAK_FILES = [{ name: "AirSwitch / ZeroOmega / SwitchyOmega backup", extensions: ["bak", "json"] }];
  const FORMATS: { value: CliTomlFormat; label: string }[] = [
    { value: "rusty-conduit", label: "rusty-conduit (direct, no upstreams or rules)" },
    { value: "rusty-conduit-ssh", label: "rusty-conduit-ssh (through one Tunnel)" },
    { value: "rusty-conduit-switch", label: "rusty-conduit-switch (profiles and rules)" },
  ];
  // Matches the watcher's clamp in `conduit-runtime`.
  const MIN_DEBOUNCE_MS = 250;
  const MAX_DEBOUNCE_MS = 10_000;

  /** A relative path would land in the app's working directory, and `~` is not expanded. */
  const isAbsolutePath = (path: string) => /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(path);
  const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

  const draft = $derived(store.proxyDraft as Proxy);
  const source = $derived(draft.source);
  const proxyId = $derived(store.selectedProxyId);
  /** Only a saved Proxy can be linked, exported, or imported into. */
  const saved = $derived(proxyId !== null && proxyId !== NEW_SESSION_ID);
  /** These tools act on the saved Proxy, so unsaved edits would be lost or ignored. */
  const blockedReason = $derived(
    !saved
      ? "Save this Proxy first."
      : store.proxyDirty
        ? "Save or discard your unsaved changes first."
        : null,
  );

  // External TOML link.
  let linkPath = $state("");
  let debounceMs = $state(500);
  // Export.
  let exportFormat = $state<CliTomlFormat>("rusty-conduit-switch");
  let exportPath = $state("");
  let exported = $state.raw<TomlExportResult | null>(null);
  let copied = $state(false);
  // AirSwitch import into this Proxy.
  let bakPath = $state("");
  let bakPreview = $state.raw<AirSwitchPreview | null>(null);

  let busy = $state<"link" | "export" | "import" | null>(null);
  let errors = $state<{ link?: string; export?: string; import?: string }>({});
  let messages = $state<{ link?: string; export?: string; import?: string }>({});

  // Results belong to one Proxy: switching Proxies clears them.
  $effect(() => {
    void proxyId;
    exported = null;
    bakPreview = null;
    errors = {};
    messages = {};
  });

  async function run(area: "link" | "export" | "import", action: () => Promise<void>) {
    busy = area;
    errors = { ...errors, [area]: undefined };
    messages = { ...messages, [area]: undefined };
    try {
      await action();
    } catch (failure) {
      errors = { ...errors, [area]: errorMessage(failure) };
    } finally {
      busy = null;
    }
  }

  function reloadNote(reloaded: boolean, reloadError: string | null): string {
    if (reloadError) return ` The running Proxy kept its old routing: ${reloadError}`;
    return reloaded ? " The running Proxy picked it up." : "";
  }

  // ---- Config source & External TOML link ----

  function link(event: SubmitEvent) {
    event.preventDefault();
    if (blockedReason || busy || !proxyId) return;
    const file = linkPath.trim();
    if (!isAbsolutePath(file)) {
      errors = { ...errors, link: "Enter a full file path." };
      return;
    }
    const ms = Math.round(Number(debounceMs));
    if (!Number.isFinite(ms) || ms < MIN_DEBOUNCE_MS || ms > MAX_DEBOUNCE_MS) {
      errors = { ...errors, link: `Debounce must be ${MIN_DEBOUNCE_MS}–${MAX_DEBOUNCE_MS} ms.` };
      return;
    }
    const id = proxyId;
    void run("link", async () => {
      const result = await api.linkProxyExternalToml(id, file, ms);
      await store.applyProxySourceChange(result);
      messages = { ...messages, link: `Linked.${reloadNote(result.reloaded, result.reload_error)}` };
    });
  }

  function reloadNow() {
    if (blockedReason || busy || !proxyId) return;
    const id = proxyId;
    void run("link", async () => {
      const result = await api.reloadProxyExternalToml(id);
      await store.applyProxySourceChange(result);
      messages = { ...messages, link: `Reloaded from the file.${reloadNote(result.reloaded, result.reload_error)}` };
    });
  }

  function unlink() {
    if (blockedReason || busy || !proxyId) return;
    const id = proxyId;
    void run("link", async () => {
      const result = await api.unlinkProxyExternalToml(id);
      await store.applyProxySourceChange(result);
      messages = { ...messages, link: "Switched to Managed. The current settings are kept and edited in the app." };
    });
  }

  // ---- Export CLI config.toml ----

  function previewToml() {
    if (!saved || busy || !proxyId) return;
    const id = proxyId;
    const format = exportFormat;
    void run("export", async () => {
      exported = await api.exportProxyToml(id, format);
    });
  }

  function copyToml() {
    if (!saved || busy || !proxyId) return;
    const id = proxyId;
    const format = exportFormat;
    void run("export", async () => {
      const result = await api.exportProxyToml(id, format);
      exported = result;
      try {
        await navigator.clipboard.writeText(result.toml);
        copied = true;
        setTimeout(() => (copied = false), 1500);
      } catch {
        errors = { ...errors, export: "The clipboard is not available. Select the text below and copy it." };
      }
    });
  }

  function saveToml(event: SubmitEvent) {
    event.preventDefault();
    if (!saved || busy || !proxyId) return;
    const file = exportPath.trim();
    if (!isAbsolutePath(file)) {
      errors = { ...errors, export: "Enter a full file path." };
      return;
    }
    const id = proxyId;
    const format = exportFormat;
    void run("export", async () => {
      const result = await api.exportProxyToml(id, format, file);
      exported = result;
      messages = { ...messages, export: `Saved to ${result.path ?? file} (owner-only).` };
    });
  }

  // ---- Import AirSwitch .bak into this Proxy ----

  function previewBak(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    const file = bakPath.trim();
    if (!isAbsolutePath(file)) {
      errors = { ...errors, import: "Enter a full file path." };
      return;
    }
    bakPreview = null;
    void run("import", async () => {
      bakPreview = await api.previewAirswitchImport(file);
    });
  }

  function commitBak() {
    if (blockedReason || busy || !proxyId || !bakPreview) return;
    const id = proxyId;
    const file = bakPath.trim();
    const needsVault = bakPreview.extracted_password_count > 0;
    const importNow = () =>
      void run("import", async () => {
        try {
          const result = await api.commitAirswitchImport(file, null, id);
          await store.openImported(result.proxy);
          bakPreview = null;
          messages = {
            ...messages,
            import: `Imported into this Proxy${result.stored_passwords ? `; ${plural(result.stored_passwords, "password")} stored in the Vault` : ""}.${result.warnings.length ? ` ${result.warnings.join(" ")}` : ""}`,
          };
        } catch (failure) {
          if (failure instanceof ApiError && failure.code === "vault_locked") {
            store.runUnlocked(importNow);
            errors = { ...errors, import: "Unlock the vault to store the imported passwords." };
            return;
          }
          throw failure;
        }
      });
    if (needsVault) store.runUnlocked(importNow);
    else importNow();
  }
</script>

<section class="card" aria-labelledby={`${uid}-source`}>
  <h2 id={`${uid}-source`}>Config source</h2>
  {#if source === "managed"}
    <p><span class="pill ok">Managed</span> <span class="muted">This Proxy is edited in the app and saved with its settings.</span></p>
    <form onsubmit={link} autocomplete="off" aria-labelledby={`${uid}-link`}>
      <h3 id={`${uid}-link`}>Link to External TOML</h3>
      <p class="muted">
        Read this Proxy's settings from a CLI <code>config.toml</code>. Edits made to the file outside the app
        are applied live. Its name, enabled, autostart, and MITM settings stay in the app.
      </p>
      <div class="field">
        <label for={`${uid}-link-path`}>File</label>
        <div class="inline-form">
          <input id={`${uid}-link-path`} bind:value={linkPath} spellcheck="false" placeholder="Choose a config.toml" />
          <BrowseButton mode="open" title="Link TOML file" filters={TOML_FILES} onPick={(path) => (linkPath = path)} />
        </div>
      </div>
      <label class="field">
        <span>Debounce <small class="muted">ms, {MIN_DEBOUNCE_MS}–{MAX_DEBOUNCE_MS}</small></span>
        <input type="number" min={MIN_DEBOUNCE_MS} max={MAX_DEBOUNCE_MS} step="50" bind:value={debounceMs} />
      </label>
      <div class="form-actions">
        <button type="submit" class="primary" disabled={!!blockedReason || busy !== null || !linkPath.trim()}>
          Link to External TOML
        </button>
      </div>
    </form>
  {:else}
    <p><span class="pill busy">External TOML</span> <span class="muted">Read from a file and reloaded when it changes.</span></p>
    <dl class="fact-list">
      <dt>File</dt>
      <dd><code>{source.external_toml.path}</code></dd>
      <dt>Debounce</dt>
      <dd>{source.external_toml.debounce_ms} ms</dd>
    </dl>
    <p class="warning">
      Edits made to this file outside the app are hot-reloaded live. Changes made here are replaced the next time
      the file changes; unlink to edit in the app.
    </p>
    <div class="form-actions">
      <button onclick={reloadNow} disabled={!!blockedReason || busy !== null}>Reload Now</button>
      <button onclick={unlink} disabled={!!blockedReason || busy !== null}>Unlink (Switch to Managed)</button>
    </div>
  {/if}
  {#if blockedReason}<p class="muted">{blockedReason}</p>{/if}
  {#if errors.link}<p class="reason" role="alert">{errors.link}</p>{/if}
  {#if messages.link}<p class="ok-text" role="status">{messages.link}</p>{/if}
</section>

<section class="card" aria-labelledby={`${uid}-export`}>
  <h2 id={`${uid}-export`}>Export CLI <code>config.toml</code></h2>
  <p class="muted">
    Exports the saved Proxy. Passwords are never written: vaulted ones become <code>password_env</code> references
    to set before running the CLI.
  </p>
  <label class="field">
    Format
    <select
      bind:value={exportFormat}
      onchange={() => {
        exported = null;
        errors = { ...errors, export: undefined };
        messages = { ...messages, export: undefined };
      }}
    >
      {#each FORMATS as option (option.value)}
        <option value={option.value}>{option.label}</option>
      {/each}
    </select>
  </label>
  <div class="form-actions">
    <button onclick={previewToml} disabled={!saved || busy !== null}>Preview TOML</button>
    <button onclick={copyToml} disabled={!saved || busy !== null}>{copied ? "Copied" : "Copy TOML"}</button>
  </div>
  <form onsubmit={saveToml} autocomplete="off">
    <div class="field">
      <label for={`${uid}-export-path`}>Save to file</label>
      <div class="inline-form">
        <input id={`${uid}-export-path`} bind:value={exportPath} spellcheck="false" placeholder="Choose where to save" />
        <BrowseButton
          mode="save"
          title="Save CLI config"
          defaultPath={exportPath.trim() || "config.toml"}
          filters={TOML_FILES}
          onPick={(path) => (exportPath = path)}
        />
      </div>
    </div>
    <div class="form-actions">
      <button type="submit" disabled={!saved || busy !== null || !exportPath.trim()}>Save to File…</button>
    </div>
  </form>
  {#if !saved}<p class="muted">Save this Proxy first.</p>{:else if store.proxyDirty}<p class="muted">Unsaved changes are not included.</p>{/if}
  {#if errors.export}<p class="reason" role="alert">{errors.export}</p>{/if}
  {#if messages.export}<p class="ok-text" role="status">{messages.export}</p>{/if}
  {#if exported}
    {#if exported.notes.length}
      <div class="warning" role="status">
        <strong>Before running <code>{exported.format}</code></strong>
        <ul>{#each exported.notes as note}<li>{note}</li>{/each}</ul>
      </div>
    {/if}
    <label class="field">
      <span>Preview <small class="muted"><code>{exported.format}</code></small></span>
      <textarea class="toml-preview" readonly rows="14" spellcheck="false" value={exported.toml}></textarea>
    </label>
  {/if}
</section>

<section class="card" aria-labelledby={`${uid}-import`}>
  <h2 id={`${uid}-import`}>Import into this Proxy</h2>
  <p class="muted">
    Replaces this Proxy's upstream profiles and rules with those from an AirSwitch, ZeroOmega, or SwitchyOmega
    <code>.bak</code>. Listeners, MITM, logging, and filter settings stay. Inline passwords are stored in the Vault.
  </p>
  <form onsubmit={previewBak} autocomplete="off">
    <div class="field">
      <label for={`${uid}-bak-path`}>File</label>
      <div class="inline-form">
        <input
          id={`${uid}-bak-path`}
          bind:value={bakPath}
          oninput={() => (bakPreview = null)}
          spellcheck="false"
          placeholder="Choose a .bak file"
        />
        <BrowseButton
          mode="open"
          title="Open extension backup"
          filters={BAK_FILES}
          onPick={(path) => {
            bakPath = path;
            bakPreview = null;
          }}
        />
      </div>
    </div>
    <div class="form-actions">
      <button type="submit" disabled={busy !== null || !bakPath.trim()}>Preview</button>
    </div>
  </form>
  {#if bakPreview}
    <p>
      {plural(bakPreview.profile_count, "upstream profile")}, {plural(bakPreview.rule_count, "rule")}{bakPreview.extracted_password_count
        ? `, ${plural(bakPreview.extracted_password_count, "password")} to store in the Vault`
        : ""}.
    </p>
    {#if bakPreview.extracted_password_count && !store.vault.unlocked}
      <p class="warning">The vault is locked. You will be asked to unlock it so the passwords can be stored.</p>
    {/if}
    {#if bakPreview.warnings.length}
      <div class="warning" role="status">
        <strong>Not imported</strong>
        <ul>{#each bakPreview.warnings as w}<li>{w}</li>{/each}</ul>
      </div>
    {/if}
    <div class="form-actions">
      <button class="primary" onclick={commitBak} disabled={!!blockedReason || busy !== null}>
        Replace Profiles and Rules
      </button>
    </div>
    {#if blockedReason}<p class="muted">{blockedReason}</p>{/if}
  {/if}
  {#if errors.import}<p class="reason" role="alert">{errors.import}</p>{/if}
  {#if messages.import}<p class="ok-text" role="status">{messages.import}</p>{/if}
</section>

<style>
  .toml-preview {
    width: 100%;
    font-family: var(--mono, ui-monospace, monospace);
    font-size: 12px;
    white-space: pre;
  }
</style>
