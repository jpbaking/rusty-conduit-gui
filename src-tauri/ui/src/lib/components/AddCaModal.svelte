<script lang="ts">
  import { api, ApiError, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { MitmCaUpload, VaultCaMeta } from "../types";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    onClose: () => void;
    /** Called with the stored CA before the dialog closes. */
    onAdded?: (ca: VaultCaMeta) => void;
  }

  let { onClose, onAdded }: Props = $props();

  type Format = "pkcs12" | "pem";

  const uid = $props.id();
  const formId = `${uid}-form`;
  const MAX_CA_FILE_BYTES = 1024 * 1024;

  let name = $state("");
  let format = $state<Format>("pkcs12");
  // File handles, not their contents. Files are read only at submit.
  let bundle = $state.raw<File | null>(null);
  let cert = $state.raw<File | null>(null);
  let key = $state.raw<File | null>(null);
  // Held only until submit, then cleared before any request is awaited.
  let passphrase = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);

  const ready = $derived(!!name.trim() && (format === "pkcs12" ? !!bundle : !!cert && !!key));

  function picker(set: (file: File | null) => void) {
    return (event: Event & { currentTarget: HTMLInputElement }) => {
      const file = event.currentTarget.files?.[0] ?? null;
      set(file);
      if (file && !name.trim()) name = file.name.replace(/\.(p12|pfx|pem|crt|cer|key)$/i, "");
      error = null;
    };
  }

  function checkSize(file: File) {
    if (file.size > MAX_CA_FILE_BYTES) {
      throw new ApiError("invalid", `${file.name} is too large to be a CA file.`);
    }
  }

  async function readText(file: File): Promise<string> {
    checkSize(file);
    try {
      return await file.text();
    } catch {
      throw new ApiError("io", `Could not read ${file.name}.`);
    }
  }

  async function readBase64(file: File): Promise<string> {
    checkSize(file);
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
    } catch {
      throw new ApiError("io", `Could not read ${file.name}.`);
    }
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
  }

  async function readUpload(): Promise<MitmCaUpload> {
    if (format === "pkcs12") {
      if (!bundle) throw new ApiError("invalid", "Choose a PKCS#12 file.");
      return { format, data: await readBase64(bundle) };
    }
    if (!cert || !key) throw new ApiError("invalid", "Choose the certificate and the key file.");
    return { format, cert: await readText(cert), key: await readText(key) };
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !ready) return;
    const caPassphrase = passphrase;
    passphrase = "";
    busy = true;
    error = null;
    try {
      const upload = await readUpload();
      const ca = await api.importMitmCa(name, upload, caPassphrase || null);
      await store.refresh();
      onAdded?.(ca);
      onClose();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  function dismiss() {
    if (!busy) onClose();
  }
</script>

<ModalDialog title="Upload MITM CA" onDismiss={dismiss}>
  <form id={formId} class="modal-form" onsubmit={submit} autocomplete="off">
    <label class="field">
      Name
      <input bind:value={name} required />
    </label>

    <div class="segmented" role="group" aria-label="CA file format">
      <button type="button" aria-pressed={format === "pkcs12"} onclick={() => (format = "pkcs12")}>
        PKCS#12 (.p12, .pfx)
      </button>
      <button type="button" aria-pressed={format === "pem"} onclick={() => (format = "pem")}>
        PEM certificate + key
      </button>
    </div>

    {#if format === "pkcs12"}
      <label class="field">
        PKCS#12 file
        <input type="file" accept=".p12,.pfx" onchange={picker((file) => (bundle = file))} />
      </label>
    {:else}
      <label class="field">
        CA certificate (PEM, may include a chain)
        <input type="file" accept=".pem,.crt,.cer" onchange={picker((file) => (cert = file))} />
      </label>
      <label class="field">
        CA private key (PEM: PKCS#8, PKCS#1 or SEC1)
        <input type="file" accept=".pem,.key" onchange={picker((file) => (key = file))} />
      </label>
    {/if}

    <label class="field">
      Passphrase (only if the file is encrypted)
      <input type="password" bind:value={passphrase} autocomplete="off" />
    </label>
    <p class="muted">
      The CA is decrypted once and stored in the vault. The original files and the passphrase are
      not needed afterwards, and the key can never be shown again.
    </p>

    {#if error}
      <p class="reason" role="alert">{error} Re-enter the passphrase if the file has one.</p>
    {/if}
  </form>
  {#snippet actions()}
    <button type="button" disabled={busy} onclick={dismiss}>Cancel</button>
    <button type="submit" form={formId} class="primary" disabled={busy || !ready}>
      {busy ? "Saving…" : "Add CA"}
    </button>
  {/snippet}
</ModalDialog>
