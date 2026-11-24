<script lang="ts">
  import { untrack } from "svelte";
  import { opensshCheck, type Fallback } from "../opensshCheck.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    fallback: Fallback;
    /** A supported program was found: switch the session to OpenSSH with it. */
    onUse: (bin: string) => void;
    onClose: () => void;
  }

  let { fallback, onUse, onClose }: Props = $props();

  const uid = $props.id();
  // Starts from the failed check, then keeps the latest attempt, so a retry that also fails
  // shows its own reason.
  let attempt = $state<Fallback>(untrack(() => ({ ...fallback })));
  let program = $state(untrack(() => fallback.bin));
  let checking = $state(false);

  const reason = $derived(
    attempt.info?.message ?? `Could not check ${attempt.bin || "ssh"}: ${attempt.error ?? "unknown error"}`,
  );

  async function retry() {
    const bin = program.trim();
    checking = true;
    try {
      await opensshCheck.run(bin);
    } finally {
      checking = false;
    }
    if (opensshCheck.bin !== bin) return;
    if (opensshCheck.info?.supported) {
      onUse(bin);
      return;
    }
    attempt = { bin, info: opensshCheck.info, error: opensshCheck.error };
  }
</script>

<ModalDialog title="OpenSSH can't be used" onDismiss={onClose}>
  <p role="alert">
    <strong>{reason}</strong> This session is back on the built-in Rust SSH engine.
  </p>
  <dl class="fact-list">
    <dt>Program</dt>
    <dd>{attempt.bin || "ssh"}</dd>
    <dt>Found at</dt>
    <dd>{attempt.info?.resolved_path ?? "Not found"}</dd>
    <dt>Version</dt>
    <dd>{attempt.info?.version_raw ?? "Unknown"}</dd>
  </dl>
  <form
    class="field"
    onsubmit={(e) => {
      e.preventDefault();
      void retry();
    }}
  >
    <label for={`${uid}-program`}>Try another ssh program <small class="muted">a name on PATH or a full path</small></label>
    <div class="inline-form">
      <input id={`${uid}-program`} bind:value={program} spellcheck="false" placeholder="ssh" />
      <button type="submit" disabled={checking}>{checking ? "Checking…" : "Check and use"}</button>
    </div>
  </form>
  {#snippet actions()}
    <button class="primary" onclick={onClose}>Keep Rust SSH</button>
  {/snippet}
</ModalDialog>
