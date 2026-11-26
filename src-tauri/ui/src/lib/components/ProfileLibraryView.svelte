<script lang="ts">
  import { api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { SecretRef, UpstreamKind, UpstreamKindName, UpstreamProfile } from "../types";
  import { BUILTIN_PROFILES, isPort } from "../validate";
  import ModalDialog from "./ModalDialog.svelte";

  const uid = $props.id();

  const KINDS: { value: UpstreamKindName; label: string }[] = [
    { value: "http", label: "HTTP proxy" },
    { value: "https", label: "HTTPS proxy" },
    { value: "socks5", label: "SOCKS5 proxy" },
    { value: "socks4a", label: "SOCKS4a proxy" },
    { value: "composite", label: "Composite (per scheme)" },
    { value: "tunnel", label: "SSH Tunnel" },
  ];

  type PasswordMode = "none" | "vault" | "env" | "file";

  interface Editing {
    /** The saved name, or `null` for a new entry. */
    original: string | null;
    profile: UpstreamProfile;
    passwordMode: PasswordMode;
    /** A new vault password typed here. Empty keeps the stored one. */
    newPassword: string;
    envName: string;
    filePath: string;
    bypassText: string;
  }

  let editing = $state<Editing | null>(null);
  let saving = $state(false);
  let saveError = $state<string | null>(null);
  let deleting = $state.raw<UpstreamProfile | null>(null);

  const vaultReady = $derived(store.vault.initialized && store.vault.unlocked);

  function kindFor(name: UpstreamKindName, previous: UpstreamKind): UpstreamKind {
    if (name === previous.type) return previous;
    switch (name) {
      case "https":
        return { type: "https", tls_insecure_skip_verify: false };
      case "composite":
        return { type: "composite", http: "direct", https: "direct", fallback: "direct" };
      case "tunnel":
        return { type: "tunnel", tunnel_id: store.tunnels[0]?.profile.id ?? "" };
      default:
        return { type: name };
    }
  }

  const needsAddress = (kind: UpstreamKind) => !["composite", "tunnel"].includes(kind.type);

  function describe(profile: UpstreamProfile): string {
    const { kind } = profile;
    if (kind.type === "tunnel") {
      const tunnel = store.tunnels.find((t) => t.profile.id === kind.tunnel_id);
      return `Tunnel: ${tunnel?.profile.name ?? "missing tunnel"}`;
    }
    if (kind.type === "composite") return `HTTP → ${kind.http}, HTTPS → ${kind.https}, other → ${kind.fallback}`;
    const label = KINDS.find((k) => k.value === kind.type)?.label ?? kind.type;
    return `${label} ${profile.host ?? "?"}:${profile.port ?? "?"}`;
  }

  /** Proxies that have a profile of the same name, for the delete prompt. */
  const proxiesWith = (name: string) =>
    store.proxies.filter((p) => p.profile.profiles.some((u) => u.name === name)).map((p) => p.profile.name);

  function open(profile: UpstreamProfile | null) {
    const base: UpstreamProfile = profile
      ? structuredClone($state.snapshot(profile) as UpstreamProfile)
      : {
          name: "",
          kind: { type: "http" },
          host: "",
          port: 3128,
          username: null,
          password: null,
          bypass: [],
          color: null,
        };
    const password = base.password;
    editing = {
      original: profile?.name ?? null,
      profile: base,
      passwordMode: !password ? "none" : "vault" in password ? "vault" : "env" in password ? "env" : "file",
      newPassword: "",
      envName: password && "env" in password ? password.env : "",
      filePath: password && "file" in password ? password.file : "",
      bypassText: base.bypass.join("\n"),
    };
    saveError = null;
  }

  const errors = $derived.by<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    if (!editing) return out;
    const { profile, original } = editing;
    const name = profile.name.trim();
    if (!name) out.name = "Enter a name.";
    else if ((BUILTIN_PROFILES as readonly string[]).includes(name)) out.name = `"${name}" is a built-in target.`;
    else if (name !== original && store.profileLibrary.some((p) => p.name === name)) out.name = "That name is taken.";
    if (needsAddress(profile.kind)) {
      if (!profile.host?.trim()) out.host = "Enter the upstream host.";
      if (profile.port === null || !isPort(profile.port)) out.port = "Use a port from 1 to 65535.";
    }
    if (profile.kind.type === "tunnel" && !store.tunnels.some((t) => t.profile.id === (profile.kind as { tunnel_id: string }).tunnel_id)) {
      out.tunnel = "Choose a Tunnel.";
    }
    if (editing.passwordMode === "vault" && !(profile.password && "vault" in profile.password) && !editing.newPassword) {
      out.password = "Enter the password to store.";
    }
    if (editing.passwordMode === "vault" && editing.newPassword && !vaultReady) {
      out.password = "Unlock the vault to store a password.";
    }
    if (editing.passwordMode === "env" && !editing.envName.trim()) out.password = "Enter the variable name.";
    if (editing.passwordMode === "file" && !editing.filePath.trim()) out.password = "Enter the file path.";
    return out;
  });
  const valid = $derived(Object.keys(errors).length === 0);

  async function save() {
    const current = editing;
    if (!current || saving || !valid) return;
    saving = true;
    saveError = null;
    const before = current.profile.password;
    const oldRef: SecretRef | null = before && "vault" in before ? before.vault : null;
    try {
      const profile: UpstreamProfile = {
        ...current.profile,
        name: current.profile.name.trim(),
        host: needsAddress(current.profile.kind) ? (current.profile.host ?? "").trim() : null,
        port: needsAddress(current.profile.kind) ? current.profile.port : null,
        username: current.profile.username?.trim() ? current.profile.username.trim() : null,
        bypass: current.bypassText.split("\n").map((line) => line.trim()).filter((line) => line !== ""),
      };
      switch (current.passwordMode) {
        case "none":
          profile.password = null;
          break;
        case "env":
          profile.password = { env: current.envName.trim() };
          break;
        case "file":
          profile.password = { file: current.filePath.trim() };
          break;
        case "vault":
          if (current.newPassword) {
            const meta = await api.setUpstreamPassword(current.newPassword, oldRef);
            profile.password = { vault: meta.secret_ref };
          }
          break;
      }
      const saved = await store.saveLibraryProfile(profile);
      if (!saved) return;
      if (current.original !== null && current.original !== saved.name) {
        await store.deleteLibraryProfile(current.original);
      }
      const newRef = profile.password && "vault" in profile.password ? profile.password.vault : null;
      if (oldRef && oldRef !== newRef) {
        // Never forced: the backend keeps a record that a Proxy still uses.
        await api.deleteSecret(oldRef).catch(() => undefined);
      }
      editing = null;
    } catch (error) {
      saveError = errorMessage(error);
    } finally {
      saving = false;
    }
  }

  async function confirmDelete() {
    const profile = deleting;
    deleting = null;
    if (!profile) return;
    await store.deleteLibraryProfile(profile.name);
    const ref = profile.password && "vault" in profile.password ? profile.password.vault : null;
    if (ref) await api.deleteSecret(ref).catch(() => undefined);
  }

  function setKind(name: UpstreamKindName) {
    if (!editing) return;
    editing.profile.kind = kindFor(name, editing.profile.kind);
  }
</script>

<main class="content">
  <div class="view-header">
    <h1>Profile Library</h1>
    <button class="primary" onclick={() => open(null)}>+ New Profile</button>
  </div>
  <p class="muted">Upstream profiles saved here can be added to any Proxy. A Proxy keeps its own copy.</p>

  {#if store.profileLibrary.length === 0}
    <p class="muted">No shared profiles yet.</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Upstream</th>
            <th scope="col">Login</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each store.profileLibrary as profile (profile.name)}
            <tr>
              <td><strong>{profile.name}</strong></td>
              <td>{describe(profile)}</td>
              <td>
                {#if profile.username}{profile.username}{#if profile.password} · password{/if}{:else}<span class="muted">none</span>{/if}
              </td>
              <td>
                <div class="row-actions">
                  <button onclick={() => open(profile)}>Edit</button>
                  {#if store.proxyDraft && !store.proxyDraft.profiles.some((p) => p.name === profile.name)}
                    <button
                      title={`Add to ${store.proxyDraft.name}`}
                      onclick={() => store.addLibraryProfileToDraft(profile.name)}
                    >Add to Proxy</button>
                  {/if}
                  <button class="danger" onclick={() => (deleting = profile)}>Delete</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</main>

{#if editing}
  {@const edit = editing}
  {@const kind = edit.profile.kind}
  <ModalDialog title={edit.original === null ? "New upstream profile" : "Edit upstream profile"} onDismiss={() => !saving && (editing = null)}>
    <form id={`${uid}-form`} class="modal-form" onsubmit={(e) => { e.preventDefault(); void save(); }}>
      <label class="field">
        Name
        <input bind:value={edit.profile.name} spellcheck="false" aria-invalid={!!errors.name} />
      </label>
      {#if errors.name}<p class="field-error">{errors.name}</p>{/if}

      <label class="field">
        Type
        <select value={kind.type} onchange={(e) => setKind(e.currentTarget.value as UpstreamKindName)}>
          {#each KINDS as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
        </select>
      </label>

      {#if kind.type === "tunnel"}
        <label class="field">
          Tunnel
          <select bind:value={kind.tunnel_id} aria-invalid={!!errors.tunnel}>
            {#if store.tunnels.length === 0}<option value="">No tunnels yet</option>{/if}
            {#each store.tunnels as tunnel (tunnel.profile.id)}
              <option value={tunnel.profile.id}>{tunnel.profile.name}</option>
            {/each}
          </select>
        </label>
        {#if errors.tunnel}<p class="field-error">{errors.tunnel}</p>{/if}
      {:else if kind.type === "composite"}
        <label class="field">HTTP requests use <input bind:value={kind.http} spellcheck="false" /></label>
        <label class="field">HTTPS requests use <input bind:value={kind.https} spellcheck="false" /></label>
        <label class="field">Everything else uses <input bind:value={kind.fallback} spellcheck="false" /></label>
        <small class="muted">Profile names in the Proxy that uses this, or direct / block.</small>
      {:else}
        <div class="field-row">
          <label class="field grow">
            Host
            <input
              value={edit.profile.host ?? ""}
              spellcheck="false"
              aria-invalid={!!errors.host}
              oninput={(e) => (edit.profile.host = e.currentTarget.value)}
            />
          </label>
          <label class="field">
            Port
            <input
              type="number"
              min="1"
              max="65535"
              value={edit.profile.port ?? ""}
              aria-invalid={!!errors.port}
              oninput={(e) => (edit.profile.port = e.currentTarget.value === "" ? null : Number(e.currentTarget.value))}
            />
          </label>
        </div>
        {#if errors.host}<p class="field-error">{errors.host}</p>{/if}
        {#if errors.port}<p class="field-error">{errors.port}</p>{/if}
        {#if kind.type === "https"}
          <label class="check">
            <input type="checkbox" bind:checked={kind.tls_insecure_skip_verify} />
            Skip TLS certificate checks (unsafe)
          </label>
        {/if}

        <label class="field">
          Username
          <input
            value={edit.profile.username ?? ""}
            spellcheck="false"
            autocomplete="off"
            oninput={(e) => (edit.profile.username = e.currentTarget.value)}
          />
        </label>
        <label class="field">
          Password
          <select bind:value={edit.passwordMode}>
            <option value="none">None</option>
            <option value="vault">Stored in the vault</option>
            <option value="env">From an environment variable</option>
            <option value="file">From a file</option>
          </select>
        </label>
        {#if edit.passwordMode === "vault"}
          <label class="field">
            {edit.profile.password && "vault" in edit.profile.password ? "New password (empty keeps the stored one)" : "Password"}
            <input type="password" autocomplete="new-password" bind:value={edit.newPassword} disabled={!vaultReady} />
          </label>
          {#if !vaultReady}
            <button type="button" class="link-button" onclick={() => store.requestUnlock()}>Unlock the vault</button>
          {/if}
        {:else if edit.passwordMode === "env"}
          <label class="field">Variable name <input bind:value={edit.envName} spellcheck="false" /></label>
        {:else if edit.passwordMode === "file"}
          <label class="field">File path <input bind:value={edit.filePath} spellcheck="false" /></label>
        {/if}
        {#if errors.password}<p class="field-error">{errors.password}</p>{/if}
      {/if}

      <label class="field">
        Bypass <small class="muted">one host pattern per line; these go direct</small>
        <textarea rows="3" spellcheck="false" bind:value={edit.bypassText}></textarea>
      </label>
      {#if saveError}<p class="reason" role="alert">{saveError}</p>{/if}
    </form>
    {#snippet actions()}
      <button type="button" disabled={saving} onclick={() => (editing = null)}>Cancel</button>
      <button type="submit" form={`${uid}-form`} class="primary" disabled={saving || !valid}>
        {saving ? "Saving…" : "Save"}
      </button>
    {/snippet}
  </ModalDialog>
{/if}

{#if deleting}
  {@const users = proxiesWith(deleting.name)}
  <ModalDialog title="Delete shared profile" onDismiss={() => (deleting = null)}>
    <p>Delete <strong>{deleting.name}</strong> from the Profile Library?</p>
    {#if users.length > 0}
      <p class="muted">These Proxies have their own copy and keep working: {users.join(", ")}.</p>
    {/if}
    {#snippet actions()}
      <button onclick={() => (deleting = null)}>Cancel</button>
      <button class="danger" onclick={confirmDelete}>Delete</button>
    {/snippet}
  </ModalDialog>
{/if}
