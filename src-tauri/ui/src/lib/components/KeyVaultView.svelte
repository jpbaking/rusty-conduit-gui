<script lang="ts">
  import { tooltip } from "../tooltip";
  import { api, errorMessage } from "../api";
  import { formatDate } from "../format";
  import { store } from "../stores.svelte";
  import type { KeySource, KeyView, SecretRef, UpstreamPasswordSource, Usage } from "../types";
  import AddKeyModal, { type AddKeyMode } from "./AddKeyModal.svelte";
  import CaVaultSection from "./CaVaultSection.svelte";
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

  const usageLabel = (count: number) => `Used by ${count} ${count === 1 ? "item" : "items"}`;

  /** Every item a delete affects, with what kind it is. */
  const usageRefs = (usage: Usage) => [
    ...usage.hosts.map((ref) => ({ ...ref, kind: "Host" })),
    ...usage.sessions.map((ref) => ({ ...ref, kind: "Session" })),
    ...(usage.tunnels ?? []).map((ref) => ({ ...ref, kind: "Tunnel" })),
    ...(usage.proxies ?? []).map((ref) => ({ ...ref, kind: "Proxy" })),
    ...(usage.library_profiles ?? []).map((name) => ({ id: name, name, kind: "Profile Library" })),
  ];

  const usageNames = (usage: Usage) => usageRefs(usage).map((ref) => ref.name).join(", ");

  // Upstream proxy passwords: the vault holds them; Proxies and the Profile Library point at them.

  interface PasswordUse {
    /** Where the profile lives: a Proxy's name, or "Profile Library". */
    owner: string;
    profile: string;
  }

  interface VaultPassword {
    ref: SecretRef;
    uses: PasswordUse[];
  }

  const sourceLabel = (source: Exclude<UpstreamPasswordSource, { vault: SecretRef }>) =>
    "env" in source ? `Environment variable ${source.env}` : `File ${source.file}`;

  const passwordUses = $derived.by(() => {
    const vault = new Map<SecretRef, PasswordUse[]>();
    const outside: (PasswordUse & { source: string })[] = [];
    const note = (owner: string, profile: string, source: UpstreamPasswordSource | null) => {
      if (!source) return;
      if ("vault" in source) vault.set(source.vault, [...(vault.get(source.vault) ?? []), { owner, profile }]);
      else outside.push({ owner, profile, source: sourceLabel(source) });
    };
    for (const { profile: proxy } of store.proxies) {
      for (const upstream of proxy.profiles) note(proxy.name, upstream.name, upstream.password);
    }
    for (const upstream of store.profileLibrary) note("Profile Library", upstream.name, upstream.password);
    const stored: VaultPassword[] = [...vault].map(([ref, uses]) => ({ ref, uses }));
    return { stored, outside };
  });

  let deletingPassword = $state.raw<VaultPassword | null>(null);
  let passwordUsage = $state.raw<Usage | null>(null);
  let passwordUsageChanged = $state(false);

  async function startDeletePassword(entry: VaultPassword) {
    if (busy) return;
    deletingPassword = entry;
    passwordUsage = null;
    passwordUsageChanged = false;
    dialogError = null;
    busy = true;
    try {
      // Without force nothing in use is deleted; the answer lists what uses it.
      const first = await api.deleteSecret(entry.ref);
      if (first.deleted) {
        deletingPassword = null;
        await store.refresh();
      } else {
        passwordUsage = first.usage;
      }
    } catch (error) {
      dialogError = errorMessage(error);
    } finally {
      busy = false;
    }
  }

  /** Forces only past the items the user was shown, as for keys. */
  async function confirmDeletePassword() {
    const entry = deletingPassword;
    const shown = passwordUsage;
    if (!entry || !shown || busy) return;
    busy = true;
    dialogError = null;
    try {
      const again = await api.deleteSecret(entry.ref);
      if (!again.deleted) {
        const seen = new Set(usageRefs(shown).map((ref) => `${ref.kind}:${ref.id}`));
        if (usageRefs(again.usage).some((ref) => !seen.has(`${ref.kind}:${ref.id}`))) {
          passwordUsage = again.usage;
          passwordUsageChanged = true;
          return;
        }
        const forced = await api.deleteSecret(entry.ref, true);
        if (!forced.deleted) {
          passwordUsage = forced.usage;
          passwordUsageChanged = true;
          return;
        }
      }
      deletingPassword = null;
      await store.refresh();
    } catch (error) {
      dialogError = errorMessage(error);
    } finally {
      busy = false;
    }
  }

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

  const SOURCES: Record<KeySource, string> = { Uploaded: "uploaded", Pasted: "pasted", Generated: "generated here" };

  /** Everything about a key, for its name's tooltip. */
  function keyDetails(key: KeyView): string {
    return [
      key.name,
      `Algorithm: ${key.algorithm}`,
      `SHA-256: ${key.fingerprint_sha256.replace(/^SHA256:/, "")}`,
      `Added: ${formatDate(key.created_at)} (${SOURCES[key.source]})`,
    ].join("\n");
  }
</script>

<main class="content">
  <div class="view-header">
    <h1>Vault</h1>
  </div>

  {#if !ready}
    <p class="warning">
      {store.vault.initialized ? "The vault is locked." : "The vault has not been created yet."}
      <button onclick={() => store.requestUnlock()}>
        {store.vault.initialized ? "Unlock Vault" : "Create Vault"}
      </button>
    </p>
  {/if}

  <section class="vault-section first" aria-labelledby={`${uid}-keys-heading`}>
  <div class="view-header">
    <h2 id={`${uid}-keys-heading`}>SSH Keys <small class="muted">used to log in to hops and targets</small></h2>
    <div class="vault-actions">
      <button disabled={!ready} onclick={() => (adding = "upload")}>Upload File</button>
      <button disabled={!ready} onclick={() => (adding = "paste")}>Paste Private Key</button>
      <button class="primary" disabled={!ready} onclick={() => (adding = "generate")}>Generate New Key</button>
    </div>
  </div>

  {#if store.keys.length === 0}
    <p class="muted">No keys stored.</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Algorithm</th>
            <th scope="col">Created</th>
            <th scope="col">Usage</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each store.keys as key (key.id)}
            <tr>
              <td>
                <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
                <strong class="has-tip" tabindex="0" use:tooltip={keyDetails(key)}>{key.name}</strong>
              </td>
              <td>{key.algorithm}</td>
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
  </section>

  <CaVaultSection />

  <section class="vault-section" aria-labelledby={`${uid}-passwords-heading`}>
    <div class="view-header">
      <h2 id={`${uid}-passwords-heading`}>Upstream passwords <small class="muted">used by Proxies to log in to upstream proxies</small></h2>
    </div>
    {#if passwordUses.stored.length === 0 && passwordUses.outside.length === 0}
      <p class="muted">No Proxy uses an upstream password.</p>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">Stored in</th>
              <th scope="col">Used by</th>
              <th scope="col"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {#each passwordUses.stored as entry (entry.ref)}
              <tr>
                <td>Vault</td>
                <td>
                  <ul class="plain-list">
                    {#each entry.uses as use, index (index)}<li>{use.owner}: <code>{use.profile}</code></li>{/each}
                  </ul>
                </td>
                <td>
                  <div class="row-actions">
                    <button class="danger" disabled={!ready || busy} onclick={() => startDeletePassword(entry)}>Delete</button>
                  </div>
                </td>
              </tr>
            {/each}
            {#each passwordUses.outside as use, index (index)}
              <tr>
                <td>{use.source}</td>
                <td>{use.owner}: <code>{use.profile}</code></td>
                <td></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
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
  {@const refs = usageRefs(deleteUsage)}
  {@const affected = refs.length}
  <ModalDialog title="Delete key" onDismiss={() => { if (!busy) deleting = null; }}>
    <p>Delete <strong>{deleting.name}</strong>? This cannot be undone.</p>
    {#if usageChanged}
      <p class="reason" role="alert">The list of affected items changed. Review it before deleting.</p>
    {/if}
    {#if affected > 0}
      <p>This key will be removed from:</p>
      <ul class="plain-list">
        {#each refs as ref (`${ref.kind}-${ref.id}`)}<li>{ref.kind}: {ref.name}</li>{/each}
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

{#if deletingPassword}
  {@const refs = passwordUsage ? usageRefs(passwordUsage) : []}
  <ModalDialog title="Delete upstream password" onDismiss={() => { if (!busy) deletingPassword = null; }}>
    {#if !passwordUsage && !dialogError}
      <p class="muted">Checking what uses this password…</p>
    {:else}
      <p>Delete this upstream password from the vault? This cannot be undone.</p>
      {#if passwordUsageChanged}
        <p class="reason" role="alert">The list of affected items changed. Review it before deleting.</p>
      {/if}
      {#if refs.length > 0}
        <p>These keep pointing at it and cannot log in upstream until they get a new password:</p>
        <ul class="plain-list">
          {#each refs as ref (`${ref.kind}-${ref.id}`)}<li>{ref.kind}: {ref.name}</li>{/each}
        </ul>
      {/if}
    {/if}
    {#if dialogError}<p class="reason" role="alert">{dialogError}</p>{/if}
    {#snippet actions()}
      <button disabled={busy} onclick={() => (deletingPassword = null)}>Cancel</button>
      <button class="danger" disabled={busy || !passwordUsage} onclick={confirmDeletePassword}>
        {refs.length > 0 ? `Delete and affect ${refs.length}` : "Delete"}
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
