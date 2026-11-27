<script lang="ts">
  import { caExpiry } from "../format";
  import { store } from "../stores.svelte";
  import type { MitmConfig, MitmUpstreamTlsMode, SessionProfile, VaultCaMeta } from "../types";
  import { MIN_CERT_TTL_SECS, type FieldErrors } from "../validate";
  import AddCaModal from "./AddCaModal.svelte";
  import NumberField from "./NumberField.svelte";

  const DEFAULT_CERT_TTL_SECS = 3600;
  const DEFAULT_CACHE_ENTRIES = 10_000;

  const UPSTREAM_TLS_MODES: { value: MitmUpstreamTlsMode; label: string }[] = [
    { value: "strict", label: "Strict (OS trust store)" },
    { value: "allowlist", label: "Allowlist (skip verification for listed hosts/IPs)" },
    { value: "insecure_all", label: "Blind trust (ignore all upstream cert errors — unsafe)" },
  ];

  /** What a Proxy editor hands in. Without it, the selected session's MITM is edited. */
  interface MitmTarget {
    mitm: MitmConfig | null;
    socksBlockWeb?: boolean;
    errors: FieldErrors;
    set: (mitm: MitmConfig | null) => void;
    setSocksBlockWeb?: (enabled: boolean) => void;
  }

  interface Props {
    target?: MitmTarget;
  }

  let { target }: Props = $props();

  const uid = $props.id();
  const mitm = $derived(target ? target.mitm : (store.draft as SessionProfile).mitm);
  const errors = $derived(target ? target.errors : store.draftErrors);
  const socksBlockWeb = $derived(target?.socksBlockWeb ?? mitm?.socks_block_web ?? false);

  function update(edit: (mitm: MitmConfig | null) => MitmConfig | null) {
    if (target) target.set(edit(target.mitm));
    else store.updateDraft((p) => ({ ...p, mitm: edit(p.mitm) }));
  }

  function updateSocksBlockWeb(enabled: boolean) {
    if (target?.setSocksBlockWeb) {
      target.setSocksBlockWeb(enabled);
    } else if (mitm) {
      setMitm({ socks_block_web: enabled });
    }
  }
  const selected = $derived(mitm?.ca ? (store.cas.find((ca) => ca.id === mitm.ca) ?? null) : null);
  const expiry = $derived(selected ? caExpiry(selected.not_after) : null);
  const vaultReady = $derived(store.vault.initialized && store.vault.unlocked);

  // Settings from before MITM was switched off, restored if it is switched back on.
  let lastSettings: MitmConfig | null = null;
  let uploading = $state(false);

  function setMitm(patch: Partial<MitmConfig>) {
    update((current) => (current ? { ...current, ...patch } : current));
  }

  function setEnabled(enabled: boolean) {
    if (enabled === !!mitm) return;
    if (!enabled) {
      lastSettings = mitm;
      update(() => null);
      return;
    }
    // A CA deleted while MITM was off must not come back.
    const restored = lastSettings && store.cas.some((ca) => ca.id === lastSettings?.ca) ? lastSettings : null;
    const settings: MitmConfig = restored ?? {
      ca: store.cas.length === 1 ? (store.cas[0]?.id ?? null) : null,
      cert_ttl: lastSettings?.cert_ttl ?? DEFAULT_CERT_TTL_SECS,
      cert_cache_max_entries: lastSettings?.cert_cache_max_entries ?? DEFAULT_CACHE_ENTRIES,
      socks_block_web: lastSettings?.socks_block_web ?? false,
      upstream_tls_mode: lastSettings?.upstream_tls_mode ?? "strict",
      insecure_hosts: lastSettings?.insecure_hosts ?? [],
    };
    update(() => ({ ...settings }));
  }

  // The textarea keeps what was typed (blank lines included) while it still parses to the
  // saved list; otherwise it shows the saved list.
  const parseHosts = (text: string) =>
    text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== "");
  let hostsDraft = $state<string | null>(null);
  const hostsText = $derived.by(() => {
    const saved = mitm?.insecure_hosts ?? [];
    const draft = hostsDraft === null ? null : parseHosts(hostsDraft);
    const same = draft !== null && draft.length === saved.length && draft.every((h, i) => h === saved[i]);
    return same && hostsDraft !== null ? hostsDraft : saved.join("\n");
  });

  function setInsecureHosts(text: string) {
    hostsDraft = text;
    setMitm({ insecure_hosts: parseHosts(text) });
  }

  function added(ca: VaultCaMeta) {
    setMitm({ ca: ca.id });
  }
</script>

<section class="card" aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>HTTPS MITM <small class="muted">decrypts HTTPS using your own CA</small></h2>

  <div class="segmented" role="group" aria-label="MITM mode">
    <button type="button" aria-pressed={!mitm} onclick={() => setEnabled(false)}>Off</button>
    <button type="button" aria-pressed={!!mitm} onclick={() => setEnabled(true)}>On</button>
  </div>

  {#if !mitm}
    <p class="muted">MITM is off. HTTPS traffic passes through unchanged.</p>
  {:else}
    <div class="field-row">
      <div class="field grow">
        <label class="field">
          CA
          <select
            value={mitm.ca ?? ""}
            aria-invalid={!!errors["mitm.ca"]}
            onchange={(e) => setMitm({ ca: e.currentTarget.value || null })}
          >
            <option value="" disabled>{store.cas.length ? "Choose a CA…" : "No CAs in the vault yet"}</option>
            {#each store.cas as ca (ca.id)}
              <option value={ca.id}>{ca.name} ({ca.subject})</option>
            {/each}
          </select>
        </label>
        {#if errors["mitm.ca"]}<span class="field-error">{errors["mitm.ca"]}</span>{/if}
      </div>
    </div>
    <div class="inline-form">
      <button type="button" disabled={!vaultReady} onclick={() => (uploading = true)}>Upload CA…</button>
      {#if !vaultReady}
        <small class="muted">Unlock the vault to upload a CA.</small>
      {:else}
        <small class="muted">Uploaded CAs are kept in the vault and listed in the Key Vault.</small>
      {/if}
    </div>

    {#if selected && expiry}
      <dl class="fact-list">
        <dt>Subject</dt>
        <dd>{selected.subject}</dd>
        <dt>Fingerprint</dt>
        <dd><code>{selected.fingerprint_sha256}</code></dd>
        <dt>Expiry</dt>
        <dd><span class={`pill ${expiry.tone}`}>{expiry.label}</span></dd>
      </dl>
      {#if expiry.tone === "alert"}
        <p class="field-error">This CA has expired. It will not start until you choose another.</p>
      {/if}
    {:else if mitm.ca}
      <p class="field-error">This CA is no longer in the vault. Choose another.</p>
    {/if}
  {/if}
</section>

{#if mitm}
  <section class="card" aria-labelledby={`${uid}-certs`}>
    <h2 id={`${uid}-certs`}>Generated certificates</h2>
    <div class="field-row">
      <NumberField
        label="Certificate lifetime (seconds)"
        value={mitm.cert_ttl}
        min={MIN_CERT_TTL_SECS}
        hint={`At least ${MIN_CERT_TTL_SECS} seconds`}
        error={errors["mitm.cert_ttl"]}
        onValue={(cert_ttl) => setMitm({ cert_ttl })}
      />
      <NumberField
        label="Certificate cache size"
        value={mitm.cert_cache_max_entries}
        hint="0 = unlimited"
        error={errors["mitm.cert_cache_max_entries"]}
        onValue={(cert_cache_max_entries) => setMitm({ cert_cache_max_entries })}
      />
    </div>
  </section>
{/if}

{#if mitm}
  <section class="card" aria-labelledby={`${uid}-upstream-tls`}>
    <h2 id={`${uid}-upstream-tls`}>Upstream TLS certificates</h2>
    <label class="field">
      Verification
      <select
        value={mitm.upstream_tls_mode}
        onchange={(e) => setMitm({ upstream_tls_mode: e.currentTarget.value as MitmUpstreamTlsMode })}
      >
        {#each UPSTREAM_TLS_MODES as mode (mode.value)}
          <option value={mode.value}>{mode.label}</option>
        {/each}
      </select>
    </label>

    {#if mitm.upstream_tls_mode === "allowlist"}
      <label class="field">
        <span>Insecure hosts <small class="muted">one domain, *.wildcard, IP, or CIDR per line</small></span>
        <textarea
          class="code-text"
          spellcheck="false"
          placeholder={"localhost\n*.corp.local\n10.0.0.0/8"}
          aria-invalid={!!errors["mitm.insecure_hosts"]}
          value={hostsText}
          oninput={(e) => setInsecureHosts(e.currentTarget.value)}
        ></textarea>
      </label>
      {#if errors["mitm.insecure_hosts"]}<span class="field-error">{errors["mitm.insecure_hosts"]}</span>{/if}
      <small class="muted">Certificates of these upstream servers are not verified; all others are.</small>
    {:else}
      {#if errors["mitm.insecure_hosts"]}
        <span class="field-error">
          The saved insecure host list is invalid: {errors["mitm.insecure_hosts"]} Choose Allowlist to fix it.
        </span>
      {/if}
      {#if mitm.upstream_tls_mode === "insecure_all"}
        <p class="warning" role="alert">
          <strong>Blind trust:</strong> upstream HTTPS certificates are NOT verified at all. Any server,
          including an attacker on the network, is trusted for every destination. Use this only for testing.
        </p>
      {:else}
        <p class="muted">Every upstream server certificate is verified against the OS trust store.</p>
      {/if}
    {/if}
  </section>
{/if}

{#if target?.setSocksBlockWeb || mitm}
  <section class="card" aria-labelledby={`${uid}-socks-web`}>
    <h2 id={`${uid}-socks-web`}>SOCKS web blocking</h2>
    <label class="check">
      <input
        type="checkbox"
        checked={socksBlockWeb}
        onchange={(e) => updateSocksBlockWeb(e.currentTarget.checked)}
      />
      Block HTTP/HTTPS traffic over SOCKS
      <small class="muted">rejects plaintext HTTP and HTTPS over SOCKS4/5, with or without MITM enabled</small>
    </label>
  </section>
{/if}

{#if uploading}
  <AddCaModal onClose={() => (uploading = false)} onAdded={added} />
{/if}
