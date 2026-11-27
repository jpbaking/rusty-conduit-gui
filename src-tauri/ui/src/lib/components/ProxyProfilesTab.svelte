<script lang="ts">
  import { api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { Proxy, UpstreamKind, UpstreamKindName, UpstreamPasswordSource, UpstreamProfile } from "../types";
  import { BUILTIN_PROFILES } from "../validate";

  const KINDS: { value: Exclude<UpstreamKindName, "tunnel">; label: string }[] = [
    { value: "http", label: "HTTP proxy" },
    { value: "https", label: "HTTPS proxy" },
    { value: "socks5", label: "SOCKS5 proxy" },
    { value: "socks4a", label: "SOCKS4a proxy" },
    { value: "composite", label: "Composite (per scheme)" },
  ];

  const COMPOSITE_FIELDS = ["http", "https", "fallback"] as const;

  type PasswordMode = "none" | "vault" | "env" | "file";

  const uid = $props.id();
  const proxy = $derived(store.proxyDraft as Proxy);
  const profiles = $derived(proxy.profiles);
  const errors = $derived(store.proxyDraftErrors);
  const vaultReady = $derived(store.vault.initialized && store.vault.unlocked);
  const names = $derived([...BUILTIN_PROFILES, ...profiles.map((p) => p.name).filter((n) => n)]);
  const importable = $derived(store.profileLibrary.filter((p) => !profiles.some((own) => own.name === p.name)));
  /** Live traffic per profile while the Proxy runs. */
  const counters = $derived(store.selectedProxy?.snapshot.profile_counters ?? {});

  // Write-only password fields, by profile index. Never read back from the backend.
  let passwordText = $state<Record<number, string>>({});
  let passwordBusy = $state<number | null>(null);
  let passwordError = $state<Record<number, string>>({});

  // Test Upstream (per-profile target host & port).
  let probeHostFor = $state<Record<number, string>>({});
  let probePortFor = $state<Record<number, number>>({});
  const probeHost = (index: number) => probeHostFor[index] ?? "example.com";
  const probePort = (index: number) => probePortFor[index] ?? 443;
  let probing = $state<number | null>(null);
  let probedIndex = $state<number | null>(null);
  const probe = $derived(store.upstreamTest);

  const needsAddress = (kind: UpstreamKind) => kind.type !== "composite" && kind.type !== "tunnel";
  const passwordMode = (password: UpstreamPasswordSource | null): PasswordMode =>
    !password ? "none" : "vault" in password ? "vault" : "env" in password ? "env" : "file";

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

  function editProfile(index: number, edit: (profile: UpstreamProfile) => UpstreamProfile) {
    store.updateProxyDraft((p) => ({ ...p, profiles: p.profiles.map((u, i) => (i === index ? edit(u) : u)) }));
  }

  function setKind(index: number, name: UpstreamKindName) {
    editProfile(index, (u) => {
      const kind = kindFor(name, u.kind);
      if (needsAddress(kind)) return { ...u, kind, host: u.host ?? "", port: u.port ?? 3128 };
      return { ...u, kind, host: null, port: null, username: null, password: null };
    });
  }

  function addProfile() {
    let n = profiles.length + 1;
    while (names.includes(`upstream-${n}`)) n += 1;
    const profile: UpstreamProfile = {
      name: `upstream-${n}`,
      kind: { type: "http" },
      host: "",
      port: 3128,
      username: null,
      password: null,
      bypass: [],
      color: null,
    };
    store.updateProxyDraft((p) => ({ ...p, profiles: [...p.profiles, profile] }));
  }

  function removeProfile(index: number) {
    store.updateProxyDraft((p) => ({ ...p, profiles: p.profiles.filter((_, i) => i !== index) }));
    passwordText = {};
    passwordError = {};
    probeHostFor = {};
    probePortFor = {};
    if (probedIndex === index) probedIndex = null;
  }

  function setPasswordMode(index: number, mode: PasswordMode) {
    passwordError = { ...passwordError, [index]: "" };
    editProfile(index, (u) => {
      switch (mode) {
        case "none":
          return { ...u, password: null };
        case "env":
          return { ...u, password: { env: "" } };
        case "file":
          return { ...u, password: { file: "" } };
        case "vault":
          // Stays unset until a password is stored.
          return u.password && "vault" in u.password ? u : { ...u, password: null };
      }
    });
    vaultModeFor = { ...vaultModeFor, [index]: mode === "vault" };
  }

  /** Profiles whose password picker is on "vault" before one is stored. */
  let vaultModeFor = $state<Record<number, boolean>>({});

  async function storePassword(index: number) {
    const value = passwordText[index] ?? "";
    const profile = profiles[index];
    if (!value || !profile || passwordBusy !== null) return;
    passwordBusy = index;
    try {
      const existing = profile.password && "vault" in profile.password ? profile.password.vault : null;
      const meta = await api.setUpstreamPassword(value, existing);
      editProfile(index, (u) => ({ ...u, password: { vault: meta.secret_ref } }));
      passwordText = { ...passwordText, [index]: "" };
      passwordError = { ...passwordError, [index]: "" };
    } catch (error) {
      passwordError = { ...passwordError, [index]: errorMessage(error) };
    } finally {
      passwordBusy = null;
    }
  }

  async function testUpstream(index: number) {
    const profile = profiles[index];
    const host = probeHost(index).trim();
    const port = probePort(index);
    if (!profile || probing !== null || !host) return;
    probing = index;
    probedIndex = index;
    store.upstreamTest = null;
    try {
      await store.testUpstream(profile.name, host, port);
    } finally {
      probing = null;
    }
  }

  const profileErrors = (index: number) =>
    Object.entries(errors).filter(([key]) => key.startsWith(`profiles:${index}:`));

  const selfReferences = (profile: UpstreamProfile) =>
    profile.kind.type === "composite" &&
    [profile.kind.http, profile.kind.https, profile.kind.fallback].includes(profile.name);
</script>

<section class="card" aria-labelledby={`${uid}-builtins`}>
  <h2 id={`${uid}-builtins`}>Built-in targets</h2>
  <ul class="plain-list">
    <li><span class="pill ok">DIRECT</span> <span class="muted">connects straight to the destination</span></li>
    <li><span class="pill alert">BLOCK</span> <span class="muted">refuses the connection</span></li>
    <li><span class="pill idle">SSH Tunnels</span> <span class="muted">picked directly in the Routing tab (including tagged local proxy forwards)</span></li>
  </ul>
</section>

<section class="card" aria-labelledby={`${uid}-profiles`}>
  <div class="card-head">
    <h2 id={`${uid}-profiles`}>Upstream servers</h2>
    <div class="inline-form">
      {#if importable.length > 0}
        <select
          aria-label="Import from the Profile Library"
          value=""
          onchange={(e) => {
            const name = e.currentTarget.value;
            e.currentTarget.value = "";
            if (name) store.addLibraryProfileToDraft(name);
          }}
        >
          <option value="">Import from Profile Library…</option>
          {#each importable as entry (entry.name)}<option value={entry.name}>{entry.name}</option>{/each}
        </select>
      {/if}
      <button type="button" onclick={addProfile}>+ Add upstream server</button>
    </div>
  </div>

  {#if profiles.length === 0}
    <p class="muted">No custom upstream servers. Routing can still use DIRECT, BLOCK, and any SSH Tunnel.</p>
  {/if}

  {#each profiles as profile, index (index)}
    {@const kind = profile.kind}
    {@const mode = vaultModeFor[index] && !profile.password ? "vault" : passwordMode(profile.password)}
    {@const traffic = counters[profile.name]}
    <article class="profile-card" style:border-left-color={profile.color ?? undefined}>
      <div class="field-row">
        <label class="field grow">
          Name
          <input
            value={profile.name}
            spellcheck="false"
            aria-invalid={!!errors[`profiles:${index}:name`]}
            oninput={(e) => {
              const name = e.currentTarget.value.trim();
              editProfile(index, (u) => ({ ...u, name }));
            }}
          />
        </label>
        <label class="field">
          Type
          <select value={kind.type} onchange={(e) => setKind(index, e.currentTarget.value as UpstreamKindName)}>
            {#if kind.type === "tunnel"}
              <option value="tunnel" disabled>SSH Tunnel (legacy)</option>
            {/if}
            {#each KINDS as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
          </select>
        </label>
        <label class="field">
          Color
          <input
            type="color"
            value={profile.color ?? "#888888"}
            onchange={(e) => {
              const color = e.currentTarget.value;
              editProfile(index, (u) => ({ ...u, color }));
            }}
          />
        </label>
      </div>

      {#if kind.type === "tunnel"}
        <p class="note" role="note">
          Tunnels are now picked directly in the <strong>Routing</strong> tab without defining an upstream server here.
          This legacy profile still works, or you can switch your rules to the Tunnel directly and remove it.
        </p>
        <label class="field">
          Tunnel
          <select
            value={kind.tunnel_id}
            onchange={(e) => {
              const tunnel_id = e.currentTarget.value;
              editProfile(index, (u) => ({ ...u, kind: { type: "tunnel", tunnel_id } }));
            }}
          >
            {#if !store.tunnels.some((t) => t.profile.id === kind.tunnel_id)}<option value={kind.tunnel_id}>Choose a tunnel…</option>{/if}
            {#each store.tunnels as tunnel (tunnel.profile.id)}
              <option value={tunnel.profile.id}>{tunnel.profile.name}</option>
            {/each}
          </select>
        </label>
      {:else if kind.type === "composite"}
        <div class="field-row">
          {#each COMPOSITE_FIELDS as field (field)}
            <label class="field grow">
              {field === "http" ? "HTTP uses" : field === "https" ? "HTTPS uses" : "Everything else uses"}
              <select
                value={kind[field]}
                onchange={(e) => {
                  const value = e.currentTarget.value;
                  editProfile(index, (u) => (u.kind.type === "composite" ? { ...u, kind: { ...u.kind, [field]: value } } : u));
                }}
              >
                {#if !names.includes(kind[field])}<option value={kind[field]}>{kind[field] || "(none)"}</option>{/if}
                {#each names as name (name)}<option value={name}>{name}</option>{/each}
              </select>
            </label>
          {/each}
        </div>
        {#if selfReferences(profile)}
          <p class="warning">This composite profile points at itself, which loops.</p>
        {/if}
      {:else}
        <div class="field-row">
          <label class="field grow">
            Host
            <input
              value={profile.host ?? ""}
              spellcheck="false"
              aria-invalid={!!errors[`profiles:${index}:host`]}
              oninput={(e) => {
                const host = e.currentTarget.value;
                editProfile(index, (u) => ({ ...u, host }));
              }}
            />
          </label>
          <label class="field port">
            Port
            <input
              type="number"
              min="1"
              max="65535"
              value={profile.port ?? ""}
              aria-invalid={!!errors[`profiles:${index}:port`]}
              oninput={(e) => {
                const text = e.currentTarget.value;
                editProfile(index, (u) => ({ ...u, port: text === "" ? null : Number(text) }));
              }}
            />
          </label>
        </div>
        {#if kind.type === "https"}
          <label class="check">
            <input
              type="checkbox"
              checked={kind.tls_insecure_skip_verify}
              onchange={(e) => {
                const tls_insecure_skip_verify = e.currentTarget.checked;
                editProfile(index, (u) => ({ ...u, kind: { type: "https", tls_insecure_skip_verify } }));
              }}
            />
            Skip TLS certificate checks (unsafe)
          </label>
        {/if}
        <div class="field-row">
          <label class="field grow">
            Username
            <input
              value={profile.username ?? ""}
              spellcheck="false"
              autocomplete="off"
              oninput={(e) => {
                const text = e.currentTarget.value;
                editProfile(index, (u) => ({ ...u, username: text ? text : null }));
              }}
            />
          </label>
          <label class="field">
            Password
            <select value={mode} onchange={(e) => setPasswordMode(index, e.currentTarget.value as PasswordMode)}>
              <option value="none">None</option>
              <option value="vault">Stored in the vault</option>
              <option value="env">From an environment variable</option>
              <option value="file">From a file</option>
            </select>
          </label>
        </div>
        {#if mode === "vault"}
          <div class="inline-form">
            <input
              type="password"
              autocomplete="new-password"
              aria-label={`Password for ${profile.name}`}
              placeholder={profile.password ? "Stored. Type a new one to replace it." : "Password"}
              disabled={!vaultReady}
              value={passwordText[index] ?? ""}
              oninput={(e) => (passwordText = { ...passwordText, [index]: e.currentTarget.value })}
            />
            <button
              type="button"
              disabled={!vaultReady || !passwordText[index] || passwordBusy !== null}
              onclick={() => void storePassword(index)}
            >
              {passwordBusy === index ? "Storing…" : profile.password ? "Replace" : "Store"}
            </button>
            {#if !vaultReady}
              <button type="button" class="link-button" onclick={() => store.requestUnlock()}>Unlock the vault</button>
            {:else if profile.password}
              <small class="ok-text">Stored in the vault</small>
            {/if}
          </div>
        {:else if mode === "env" && profile.password && "env" in profile.password}
          <label class="field">
            Variable name
            <input
              value={profile.password.env}
              spellcheck="false"
              oninput={(e) => {
                const env = e.currentTarget.value.trim();
                editProfile(index, (u) => ({ ...u, password: { env } }));
              }}
            />
          </label>
        {:else if mode === "file" && profile.password && "file" in profile.password}
          <label class="field">
            File path
            <input
              value={profile.password.file}
              spellcheck="false"
              oninput={(e) => {
                const file = e.currentTarget.value.trim();
                editProfile(index, (u) => ({ ...u, password: { file } }));
              }}
            />
          </label>
        {/if}
        {#if passwordError[index]}<p class="field-error" role="alert">{passwordError[index]}</p>{/if}
      {/if}

      <label class="field">
        Bypass <small class="muted">one host pattern per line; these go direct</small>
        <textarea
          rows="2"
          spellcheck="false"
          value={profile.bypass.join("\n")}
          onchange={(e) => {
            const bypass = e.currentTarget.value.split("\n").map((l) => l.trim()).filter((l) => l !== "");
            editProfile(index, (u) => ({ ...u, bypass }));
          }}
        ></textarea>
      </label>

      {#each profileErrors(index) as [key, message] (key)}<p class="field-error">{message}</p>{/each}

      <div class="inline-form">
        <span class="muted">Test dials</span>
        <input
          aria-label={`Test host for ${profile.name || `upstream ${index + 1}`}`}
          value={probeHost(index)}
          spellcheck="false"
          oninput={(e) => (probeHostFor = { ...probeHostFor, [index]: e.currentTarget.value })}
        />
        <input
          aria-label={`Test port for ${profile.name || `upstream ${index + 1}`}`}
          type="number"
          min="1"
          max="65535"
          value={probePort(index)}
          oninput={(e) => {
            const port = Number(e.currentTarget.value);
            if (!Number.isNaN(port)) probePortFor = { ...probePortFor, [index]: port };
          }}
        />
        <button
          type="button"
          disabled={probing !== null || !profile.name || !probeHost(index).trim()}
          onclick={() => void testUpstream(index)}
        >
          {probing === index ? "Testing…" : "Test Upstream"}
        </button>
        {#if traffic}
          <small class="muted">{traffic.active} active · {traffic.hits} hits</small>
        {/if}
        <span class="spacer"></span>
        <button type="button" class="danger" onclick={() => removeProfile(index)}>Remove</button>
      </div>
      {#if probedIndex === index && probe}
        <p role="status">
          {#if probe.ok}
            <span class="pill ok">Reached</span>
          {:else}
            <span class="pill alert">Failed</span>
          {/if}
          <span class="muted">{probe.elapsed_ms} ms via <code>{probe.redacted_upstream}</code></span>
          {#if probe.error}<span class="field-error">{probe.error}</span>{/if}
        </p>
      {/if}
    </article>
  {/each}
</section>

<style>
  .profile-card {
    border: 1px solid var(--border, #ccc);
    border-left-width: 4px;
    border-radius: 6px;
    padding: 0.6rem;
    margin-top: 0.6rem;
  }
</style>
