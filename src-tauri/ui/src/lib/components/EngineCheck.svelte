<script lang="ts">
  import { opensshCheck } from "../opensshCheck.svelte";
  import { store } from "../stores.svelte";
  import type { SessionProfile } from "../types";

  interface Props {
    /** Opens the tab where the `ssh` program is set. */
    onChangeProgram: () => void;
  }

  let { onChangeProgram }: Props = $props();

  const check = opensshCheck;
  const sshBin = $derived((store.draft as SessionProfile).openssh.ssh_bin.trim());
  // Only a result for the configured program counts; until then the check is pending.
  const shown = $derived(check.bin === sshBin);
  const info = $derived(shown ? check.info : null);
  const status = $derived(shown ? check.status : null);
  const error = $derived(shown ? check.error : null);
  const program = $derived(sshBin || "ssh");
</script>

<div class="engine-check" role="status">
  {#if info && status}
    <p class="engine-check-head">
      <span class={`pill ${status.tone}`}>{status.label}</span>
      {#if info.major !== null}<span>OpenSSH {info.major}.{info.minor}</span>{/if}
    </p>
    {#if info.resolved_path}<small class="muted path">{info.resolved_path}</small>{/if}
    {#if info.supported}
      {#if info.note}<p class="warning">{info.note}</p>{/if}
    {:else}
      <p class="field-error">{info.message}</p>
      <button type="button" class="link-button" onclick={onChangeProgram}>Change the ssh program…</button>
    {/if}
  {:else if error}
    <p class="field-error">Could not check {program}: {error}</p>
    <button type="button" class="link-button" onclick={onChangeProgram}>Change the ssh program…</button>
  {:else}
    <p class="muted">Checking {program}…</p>
  {/if}
</div>
