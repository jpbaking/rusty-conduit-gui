<script lang="ts">
  import { api, errorMessage } from "../api";
  import { moved } from "../chain";
  import { store } from "../stores.svelte";
  import type { AuthMethod, HopEntry, HostProfile, SecretRef } from "../types";
  import type { FieldErrors } from "../validate";

  interface Props {
    host: HostProfile;
    /** Takes an updater so a slow password save applies to the latest values. */
    onHostChange: (edit: (host: HostProfile) => HostProfile) => void;
    /** Present when editing a session hop. Pins and agent forwarding belong to hops. */
    hop?: HopEntry | null;
    onHopChange?: (edit: (hop: HopEntry) => HopEntry) => void;
    /** Linked to a host profile, so connection details are edited there. */
    locked?: boolean;
    errors?: FieldErrors;
    errorPrefix?: string;
  }

  let {
    host,
    onHostChange,
    hop = null,
    onHopChange,
    locked = false,
    errors = {},
    errorPrefix = "",
  }: Props = $props();

  const uid = $props.id();

  // Held only until submit, then cleared before the request is awaited.
  let password = $state("");
  let replacing = $state<SecretRef | null>(null);
  let savingPassword = $state(false);
  let authError = $state<string | null>(null);
  let confirmReset = $state(false);
  let resetting = $state(false);

  const pin = $derived(hop ? store.pinFor(hop) : null);
  const usedKeys = $derived(
    new Set(host.auth.flatMap((m) => (typeof m === "object" && "Key" in m ? [m.Key.key] : []))),
  );
  const availableKeys = $derived(store.keys.filter((key) => !usedKeys.has(key.id)));
  const vaultReady = $derived(store.vault.initialized && store.vault.unlocked);
  const err = (field: string) => errors[`${errorPrefix}${field}`];

  function setAuth(edit: (auth: AuthMethod[]) => AuthMethod[]) {
    onHostChange((current) => ({ ...current, auth: edit(current.auth) }));
  }

  function setPort(text: string) {
    const port = text === "" ? Number.NaN : Number(text);
    onHostChange((current) => ({ ...current, port }));
  }

  function addKey(id: string) {
    if (id) setAuth((auth) => [...auth, { Key: { key: id } }]);
  }

  function methodKey(method: AuthMethod, index: number): string {
    if (typeof method === "string") return method;
    if ("Key" in method) return `key:${method.Key.key}`;
    if ("Password" in method) return `password:${method.Password.secret}`;
    return `keyboard:${index}`;
  }

  function keyName(id: string): string {
    return store.keys.find((key) => key.id === id)?.name ?? "Missing key";
  }

  async function savePassword(event: SubmitEvent) {
    event.preventDefault();
    const value = password;
    password = "";
    if (!value || savingPassword) return;
    const target = replacing;
    savingPassword = true;
    authError = null;
    try {
      // Always a new record: passing `existing` would rewrite every saved user of the old one
      // right away, before this edit is saved.
      const { secret_ref } = await api.setPasswordSecret(value);
      const method: AuthMethod = { Password: { secret: secret_ref } };
      setAuth((auth) =>
        target
          ? auth.map((m) => (typeof m === "object" && "Password" in m && m.Password.secret === target ? method : m))
          : [...auth, method],
      );
      replacing = null;
    } catch (error) {
      authError = errorMessage(error);
    } finally {
      savingPassword = false;
    }
  }

  async function resetPin() {
    if (!hop) return;
    resetting = true;
    await store.resetPin(hop);
    resetting = false;
    confirmReset = false;
  }
</script>

<div class="hop-editor">
  {#if hop}
    <label class="field">
      Hop label
      <input
        value={hop.name}
        placeholder={host.host || "Optional"}
        oninput={(e) => {
          const name = e.currentTarget.value;
          onHopChange?.((current) => ({ ...current, name }));
        }}
      />
    </label>
  {/if}

  {#if locked}
    <p class="muted">Connection details and sign-in come from the linked host profile. Edit them in Host Profiles.</p>
  {/if}

  <div class="field-row">
    <div class="field grow">
      <label class="field">
      Host
      <input
        value={host.host}
        disabled={locked}
        spellcheck="false"
        aria-invalid={!!err("host")}
        aria-describedby={err("host") ? `${uid}-err-host` : undefined}
        oninput={(e) => {
          const value = e.currentTarget.value;
          onHostChange((current) => ({ ...current, host: value }));
        }}
      />
      </label>
      {#if err("host")}<span id={`${uid}-err-host`} class="field-error">{err("host")}</span>{/if}
    </div>
    <div class="field port">
      <label class="field">
      Port
      <input
        type="number"
        min="1"
        max="65535"
        value={Number.isNaN(host.port) ? "" : host.port}
        disabled={locked}
        aria-invalid={!!err("port")}
        aria-describedby={err("port") ? `${uid}-err-port` : undefined}
        oninput={(e) => setPort(e.currentTarget.value)}
      />
      </label>
      {#if err("port")}<span id={`${uid}-err-port`} class="field-error">{err("port")}</span>{/if}
    </div>
    <div class="field grow">
      <label class="field">
      User
      <input
        value={host.user}
        disabled={locked}
        spellcheck="false"
        aria-invalid={!!err("user")}
        aria-describedby={err("user") ? `${uid}-err-user` : undefined}
        oninput={(e) => {
          const value = e.currentTarget.value;
          onHostChange((current) => ({ ...current, user: value }));
        }}
      />
      </label>
      {#if err("user")}<span id={`${uid}-err-user`} class="field-error">{err("user")}</span>{/if}
    </div>
  </div>

  <h3>Sign-in methods <small class="muted">tried in this order</small></h3>
  {#if host.auth.length === 0}
    <p class="muted">No sign-in methods yet.</p>
  {:else}
    <ol class="auth-list">
      {#each host.auth as method, index (methodKey(method, index))}
        <li>
          <span class="auth-label">
            {#if typeof method === "string"}
              System agent
            {:else if "Key" in method}
              Key: {keyName(method.Key.key)}
            {:else if "Password" in method}
              <span class="pill ok">Saved password</span>
            {:else}
              Keyboard-interactive
            {/if}
          </span>
          {#if !locked}
            <button class="icon" aria-label="Move method {index + 1} up" disabled={index === 0} onclick={() => setAuth((auth) => moved(auth, index, index - 1))}>↑</button>
            <button class="icon" aria-label="Move method {index + 1} down" disabled={index === host.auth.length - 1} onclick={() => setAuth((auth) => moved(auth, index, index + 1))}>↓</button>
            {#if typeof method === "object" && "Password" in method}
              <button onclick={() => { replacing = method.Password.secret; authError = null; }}>Replace</button>
              <button onclick={() => { if (replacing === method.Password.secret) replacing = null; setAuth((auth) => auth.filter((_, i) => i !== index)); }}>Clear</button>
            {:else}
              <button onclick={() => setAuth((auth) => auth.filter((_, i) => i !== index))}>Remove</button>
            {/if}
          {/if}
        </li>
      {/each}
    </ol>
  {/if}

  {#if !locked}
    <div class="auth-add">
      <label class="field-inline">
        Add key
        <select
          value=""
          disabled={availableKeys.length === 0}
          onchange={(e) => {
            addKey(e.currentTarget.value);
            e.currentTarget.value = "";
          }}
        >
          <option value="">{store.keys.length === 0 ? "No keys in vault" : "Choose a key…"}</option>
          {#each availableKeys as key (key.id)}
            <option value={key.id}>{key.name} ({key.algorithm})</option>
          {/each}
        </select>
      </label>

      <form class="password-form" onsubmit={savePassword}>
        <input
          type="password"
          bind:value={password}
          autocomplete="new-password"
          spellcheck="false"
          disabled={!vaultReady || savingPassword}
          aria-label={replacing ? "Replacement password" : "New password"}
          placeholder={replacing ? "Replacement password" : "Add password"}
        />
        <button type="submit" disabled={!password || !vaultReady || savingPassword}>
          {savingPassword ? "Saving…" : replacing ? "Replace" : "Save password"}
        </button>
        {#if replacing}
          <button type="button" onclick={() => { replacing = null; password = ""; }}>Cancel</button>
        {/if}
      </form>
    </div>
    {#if !vaultReady}
      <p class="muted">Unlock the vault in Key Vault to save a password.</p>
    {/if}
    {#if authError}<p class="reason" role="alert">{authError}</p>{/if}
  {/if}

  {#if hop}
    <h3>Agent forwarding</h3>
    <label class="check">
      <input
        type="checkbox"
        checked={hop.agent_forward}
        onchange={(e) => {
          const agent_forward = e.currentTarget.checked;
          onHopChange?.((current) => ({ ...current, agent_forward }));
        }}
      />
      Forward my agent to this hop
    </label>
    {#if hop.agent_forward}
      <p class="warning" role="alert">
        <strong>Security warning:</strong> root on this remote host can use your forwarded keys while
        connected. This choice is saved, but this version does not forward the agent yet.
      </p>
    {/if}

    <h3>Host key</h3>
    {#if pin}
      <p>
        <code>{pin.record.fingerprint_sha256}</code>
        <span class="muted">{pin.record.algorithm}, first seen {new Date(pin.record.first_seen * 1000).toLocaleString()}</span>
      </p>
      {#if confirmReset}
        <p class="warning">The next connection will ask you to approve this host's key again.</p>
        <button onclick={() => (confirmReset = false)}>Cancel</button>
        <button class="danger" disabled={resetting} onclick={resetPin}>Confirm Reset</button>
      {:else}
        <button onclick={() => (confirmReset = true)}>Reset Pin</button>
      {/if}
    {:else}
      <p class="muted">No key pinned yet. You will be asked to approve it on first connection.</p>
    {/if}
  {/if}
</div>
