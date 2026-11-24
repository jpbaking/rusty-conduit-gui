<script lang="ts">
  import { api, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type {
    MitmCaInfo,
    MitmCaMode,
    MitmConfig,
    MitmPassphraseSource,
    SessionProfile,
  } from "../types";
  import { MIN_CERT_TTL_SECS } from "../validate";
  import NumberField from "./NumberField.svelte";

  type CaKind = "off" | "pem" | "pkcs12";

  const KINDS: { value: CaKind; label: string }[] = [
    { value: "off", label: "Off" },
    { value: "pem", label: "PEM (cert + key)" },
    { value: "pkcs12", label: "PKCS#12" },
  ];
  const DEFAULT_CERT_TTL_SECS = 3600;
  const DEFAULT_CACHE_ENTRIES = 10_000;
  const EXPIRY_WARNING_DAYS = 30;

  const uid = $props.id();
  const mitm = $derived((store.draft as SessionProfile).mitm);
  const errors = $derived(store.draftErrors);
  const kind = $derived<CaKind>(!mitm ? "off" : "Pem" in mitm.ca_mode ? "pem" : "pkcs12");
  const pem = $derived(mitm && "Pem" in mitm.ca_mode ? mitm.ca_mode.Pem : null);
  const p12 = $derived(mitm && "Pkcs12" in mitm.ca_mode ? mitm.ca_mode.Pkcs12 : null);
  const caReady = $derived(
    pem ? !!pem.cert.trim() && !!pem.key.trim() : !!p12 && !!p12.path.trim(),
  );
  const storeBlocker = $derived.by(() => {
    if (store.isNew || store.dirty) return "Save the session first, then set the passphrase.";
    if (!store.vault.unlocked) return "Unlock the vault to set the passphrase.";
    return null;
  });

  // Paths and settings from a mode the user switched away from.
  let lastPem = { cert: "", key: "" };
  let lastP12 = "";
  let lastSettings: Pick<
    MitmConfig,
    "ca_passphrase_file" | "cert_ttl" | "cert_cache_max_entries" | "socks_block_web"
  > | null = null;

  /** Write-only. Never stored outside this field and cleared as soon as it is submitted. */
  let passphrase = $state("");
  let savingPassphrase = $state(false);
  let passphraseError = $state<string | null>(null);
  let inspecting = $state(false);
  let caInfo = $state.raw<MitmCaInfo | null>(null);
  let inspectError = $state<string | null>(null);
  let inspectRun = 0;

  function setMitm(patch: Partial<MitmConfig>) {
    store.updateDraft((p) => (p.mitm ? { ...p, mitm: { ...p.mitm, ...patch } } : p));
  }

  function remember() {
    if (pem) lastPem = { ...pem };
    if (p12) lastP12 = p12.path;
    if (mitm) {
      const { ca_passphrase_file, cert_ttl, cert_cache_max_entries, socks_block_web } = mitm;
      lastSettings = { ca_passphrase_file, cert_ttl, cert_cache_max_entries, socks_block_web };
    }
  }

  function setKind(next: CaKind) {
    if (next === kind) return;
    remember();
    if (next === "off") {
      passphrase = "";
      store.updateDraft((p) => ({ ...p, mitm: null }));
      return;
    }
    const ca_mode: MitmCaMode = next === "pem" ? { Pem: { ...lastPem } } : { Pkcs12: { path: lastP12 } };
    // Only the saved reference is safe to restore: a dropped one may already be deleted.
    const savedRef = store.selected?.profile.mitm?.passphrase ?? null;
    store.updateDraft((p) => {
      if (p.mitm) return { ...p, mitm: { ...p.mitm, ca_mode } };
      const settings = lastSettings ?? {
        ca_passphrase_file: null,
        cert_ttl: DEFAULT_CERT_TTL_SECS,
        cert_cache_max_entries: DEFAULT_CACHE_ENTRIES,
        socks_block_web: false,
      };
      const passphraseRef = settings.ca_passphrase_file ? null : savedRef;
      return { ...p, mitm: { ...settings, ca_mode, passphrase: passphraseRef } };
    });
  }

  async function savePassphrase(event: SubmitEvent) {
    event.preventDefault();
    const id = store.selectedId;
    const value = passphrase;
    if (id === null || !value || storeBlocker || mitm?.ca_passphrase_file) return;
    passphrase = "";
    passphraseError = null;
    savingPassphrase = true;
    try {
      await store.setMitmPassphrase(id, value);
    } catch (error) {
      passphraseError = errorMessage(error);
    } finally {
      savingPassphrase = false;
    }
  }

  async function inspect() {
    if (!mitm || !caReady) return;
    const source: MitmPassphraseSource = passphrase
      ? { passphrase }
      : mitm.passphrase
        ? { passphraseRef: mitm.passphrase }
        : mitm.ca_passphrase_file
          ? { passphraseFile: mitm.ca_passphrase_file }
          : {};
    const run = ++inspectRun;
    inspecting = true;
    caInfo = null;
    inspectError = null;
    try {
      const info = await api.inspectMitmCa(mitm.ca_mode, source);
      if (run === inspectRun) caInfo = info;
    } catch (error) {
      if (run === inspectRun) inspectError = errorMessage(error);
    } finally {
      if (run === inspectRun) inspecting = false;
    }
  }

  // A parsed result only describes the exact CA source it was read from.
  $effect(() => {
    void JSON.stringify([mitm?.ca_mode, mitm?.passphrase, mitm?.ca_passphrase_file]);
    inspectRun += 1;
    inspecting = false;
    caInfo = null;
    inspectError = null;
  });
</script>

{#snippet pathField(label: string, value: string, error: string | undefined, onValue: (path: string) => void)}
  <div class="field grow">
    <label class="field">
      {label}
      <input
        {value}
        spellcheck="false"
        aria-invalid={!!error}
        oninput={(e) => onValue(e.currentTarget.value)}
      />
    </label>
    {#if error}<span class="field-error">{error}</span>{/if}
  </div>
{/snippet}

<section aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>HTTPS MITM <small class="muted">decrypts HTTPS using your own CA</small></h2>

  <div class="segmented" role="group" aria-label="MITM mode">
    {#each KINDS as option (option.value)}
      <button type="button" aria-pressed={kind === option.value} onclick={() => setKind(option.value)}>
        {option.label}
      </button>
    {/each}
  </div>

  {#if !mitm}
    <p class="muted">MITM is off. HTTPS traffic passes through unchanged.</p>
  {:else}
    <div class="field-row">
      {#if pem}
        {@render pathField("CA certificate path", pem.cert, errors["mitm.cert"], (cert) =>
          setMitm({ ca_mode: { Pem: { cert, key: pem.key } } }),
        )}
        {@render pathField("CA private key path", pem.key, errors["mitm.key"], (key) =>
          setMitm({ ca_mode: { Pem: { cert: pem.cert, key } } }),
        )}
      {:else if p12}
        {@render pathField("PKCS#12 bundle path", p12.path, errors["mitm.path"], (path) =>
          setMitm({ ca_mode: { Pkcs12: { path } } }),
        )}
      {/if}
    </div>

    <h3>CA passphrase <small class="muted">use a saved passphrase or a file, not both</small></h3>
    {#if errors["mitm.passphrase"]}<p class="field-error">{errors["mitm.passphrase"]}</p>{/if}
    {#if mitm.passphrase}
      <p>
        <span class="pill ok">Saved passphrase</span>
        <button type="button" onclick={() => setMitm({ passphrase: null })}>Remove</button>
      </p>
    {/if}
    <form class="inline-form" onsubmit={savePassphrase} autocomplete="off">
      <input
        type="password"
        bind:value={passphrase}
        autocomplete="new-password"
        placeholder={mitm.passphrase ? "Enter a new passphrase to replace it" : "Passphrase"}
        aria-label="CA passphrase"
        disabled={!!mitm.ca_passphrase_file || savingPassphrase}
      />
      <button type="submit" disabled={!passphrase || !!storeBlocker || !!mitm.ca_passphrase_file || savingPassphrase}>
        {savingPassphrase ? "Saving…" : "Save to vault"}
      </button>
    </form>
    {#if passphrase && storeBlocker}<small class="muted">{storeBlocker}</small>{/if}
    {#if passphraseError}<span class="field-error" role="alert">{passphraseError}</span>{/if}

    <label class="field">
      Passphrase file path
      <input
        value={mitm.ca_passphrase_file ?? ""}
        spellcheck="false"
        disabled={!!mitm.passphrase || !!passphrase}
        oninput={(e) => setMitm({ ca_passphrase_file: e.currentTarget.value || null })}
      />
    </label>

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

    <div class="inline-form">
      <button type="button" disabled={!caReady || inspecting} onclick={inspect}>
        {inspecting ? "Inspecting…" : "Inspect CA"}
      </button>
    </div>
    <div role="status">
      {#if caInfo}
        <dl class="fact-list">
          <dt>Subject</dt>
          <dd>{caInfo.subject}</dd>
          <dt>Expires</dt>
          <dd>{new Date(caInfo.not_after).toLocaleString()}</dd>
        </dl>
        {#if caInfo.expired}
          <p class="field-error">This CA has expired. Sessions using it will not start.</p>
        {:else if caInfo.days_remaining <= EXPIRY_WARNING_DAYS}
          <p class="warning">
            This CA expires in {caInfo.days_remaining} {caInfo.days_remaining === 1 ? "day" : "days"}.
          </p>
        {/if}
      {/if}
      {#if inspectError}<p class="field-error">Could not read the CA: {inspectError}</p>{/if}
    </div>
  {/if}
</section>
