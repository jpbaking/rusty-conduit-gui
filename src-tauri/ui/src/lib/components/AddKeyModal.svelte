<script lang="ts" module>
  export type AddKeyMode = "upload" | "paste" | "generate";
</script>

<script lang="ts">
  import { api, ApiError, errorMessage } from "../api";
  import { store } from "../stores.svelte";
  import type { GenerateAlgorithm } from "../types";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    mode: AddKeyMode;
    onClose: () => void;
  }

  let { mode, onClose }: Props = $props();

  const uid = $props.id();
  const formId = `${uid}-form`;
  const MAX_KEY_FILE_BYTES = 1024 * 1024;
  const TITLES: Record<AddKeyMode, string> = {
    upload: "Upload key file",
    paste: "Paste private key",
    generate: "Generate new key",
  };

  let name = $state("");
  // Secrets are held only until submit, then cleared before any request is awaited.
  let pem = $state("");
  let passphrase = $state("");
  // A file handle, not its contents. The file is read only at submit.
  let file = $state.raw<File | null>(null);
  let algorithm = $state<GenerateAlgorithm>("ed25519");
  let busy = $state(false);
  let error = $state<string | null>(null);

  const ready = $derived(
    !!name.trim() && (mode === "generate" || (mode === "paste" ? !!pem.trim() : !!file)),
  );

  function pickFile(event: Event & { currentTarget: HTMLInputElement }) {
    file = event.currentTarget.files?.[0] ?? null;
    if (file && !name.trim()) name = file.name;
    error = null;
  }

  async function readKeyFile(): Promise<string> {
    if (!file) throw new ApiError("invalid", "Choose a key file.");
    if (file.size > MAX_KEY_FILE_BYTES) {
      throw new ApiError("invalid", "That file is too large to be a private key.");
    }
    try {
      return await file.text();
    } catch {
      throw new ApiError("io", "Could not read that file.");
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !ready) return;
    const pastedKey = pem;
    const keyPassphrase = passphrase;
    pem = "";
    passphrase = "";
    busy = true;
    error = null;
    try {
      if (mode === "generate") {
        await api.generateKey(name, algorithm);
      } else {
        const material = mode === "upload" ? await readKeyFile() : pastedKey;
        const source = mode === "upload" ? "Uploaded" : "Pasted";
        await api.importKeyPem(name, material, keyPassphrase || null, source);
      }
      await store.refresh();
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

<ModalDialog title={TITLES[mode]} onDismiss={dismiss}>
  <form id={formId} class="modal-form" onsubmit={submit} autocomplete="off">
    <label class="field">
      Name
      <input bind:value={name} required />
    </label>

    {#if mode === "upload"}
      <label class="field">
        Private key file (OpenSSH, PEM, PKCS#8 or PuTTY)
        <input type="file" onchange={pickFile} />
      </label>
    {:else if mode === "paste"}
      <label class="field">
        Private key
        <textarea
          class="secret-text"
          bind:value={pem}
          spellcheck="false"
          autocapitalize="off"
          autocomplete="off"
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
        ></textarea>
      </label>
    {:else}
      <label class="field">
        Algorithm
        <select bind:value={algorithm}>
          <option value="ed25519">Ed25519 (recommended)</option>
          <option value="ecdsa-p256">ECDSA-P256</option>
        </select>
      </label>
    {/if}

    {#if mode !== "generate"}
      <label class="field">
        Passphrase (only if the key is encrypted)
        <input type="password" bind:value={passphrase} autocomplete="off" />
      </label>
      <p class="muted">The key is stored encrypted in the vault and can never be shown again.</p>
    {/if}

    {#if error}
      <p class="reason" role="alert">
        {error}
        {#if mode === "paste"}Paste the key again to retry.{:else if mode === "upload"}Re-enter the passphrase if the key has one.{/if}
      </p>
    {/if}
  </form>
  {#snippet actions()}
    <button type="button" disabled={busy} onclick={dismiss}>Cancel</button>
    <button type="submit" form={formId} class="primary" disabled={busy || !ready}>
      {busy ? "Saving…" : mode === "generate" ? "Generate" : "Add Key"}
    </button>
  {/snippet}
</ModalDialog>
