<script lang="ts">
  import { caExpiry } from "../format";
  import { store } from "../stores.svelte";
  import type { MitmConfig, SessionProfile, VaultCaMeta } from "../types";
  import { MIN_CERT_TTL_SECS, type FieldErrors } from "../validate";
  import AddCaModal from "./AddCaModal.svelte";
  import NumberField from "./NumberField.svelte";

  const DEFAULT_CERT_TTL_SECS = 3600;
  const DEFAULT_CACHE_ENTRIES = 10_000;

  /** What a Proxy editor hands in. Without it, the selected session's MITM is edited. */
  interface MitmTarget {
    mitm: MitmConfig | null;
    errors: FieldErrors;
    set: (mitm: MitmConfig | null) => void;
  }

  interface Props {
    target?: MitmTarget;
  }

  let { target }: Props = $props();

  const uid = $props.id();
  const mitm = $derived(target ? target.mitm : (store.draft as SessionProfile).mitm);
  const errors = $derived(target ? target.errors : store.draftErrors);

  function update(edit: (mitm: MitmConfig | null) => MitmConfig | null) {
    if (target) target.set(edit(target.mitm));
    else store.updateDraft((p) => ({ ...p, mitm: edit(p.mitm) }));
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
    };
    update(() => ({ ...settings }));
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

    <label class="check">
      <input
        type="checkbox"
        checked={mitm.socks_block_web}
        onchange={(e) => setMitm({ socks_block_web: e.currentTarget.checked })}
      />
      Block web ports over SOCKS <small class="muted">so web traffic must use the MITM HTTP proxy</small>
    </label>

  </section>
{/if}

{#if uploading}
  <AddCaModal onClose={() => (uploading = false)} onAdded={added} />
{/if}
