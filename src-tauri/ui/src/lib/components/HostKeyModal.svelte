<script lang="ts">
  import { api, errorMessage } from "../api";
  import { store, type PendingHostKey } from "../stores.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    pending: PendingHostKey;
  }

  let { pending }: Props = $props();

  let busy = $state(false);
  let error = $state<string | null>(null);

  const session = $derived(store.sessions.find((s) => s.profile.id === pending.sessionId));
  const hops = $derived(session?.profile.hops ?? []);
  const hop = $derived(hops.find((entry) => entry.hop_id === pending.prompt.hop_id));
  const hopName = $derived(hop?.name || pending.prompt.host);

  /** Sends exactly the fingerprint on screen, so a changed key cannot be approved unseen. */
  async function decide(approve: boolean) {
    if (busy) return;
    const { sessionId, prompt } = pending;
    busy = true;
    error = null;
    try {
      await (approve ? api.approveHostKey(sessionId, prompt.sha256) : api.rejectHostKey(sessionId));
      await store.refresh();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
</script>

<!-- Escape does nothing: an unknown host key needs an explicit decision. -->
<ModalDialog title="Verify host key" onDismiss={() => {}}>
  <p><strong>{pending.sessionName}</strong> is connecting to a host it has not seen before.</p>
  <dl class="fact-list">
    <dt>Hop</dt>
    <dd>{hopName} ({pending.prompt.hop_index + 1} of {Math.max(hops.length, pending.prompt.hop_index + 1)})</dd>
    <dt>Address</dt>
    <dd><code>{pending.prompt.host}:{pending.prompt.port}</code></dd>
    <dt>Algorithm</dt>
    <dd>{pending.prompt.algorithm}</dd>
    <dt>SHA-256</dt>
    <dd><code>{pending.prompt.sha256}</code></dd>
  </dl>
  <p class="muted">Trust this key only if the fingerprint matches the one from the server's administrator.</p>
  {#if error}<p class="reason" role="alert">{error}</p>{/if}
  {#snippet actions()}
    <button class="danger" disabled={busy} onclick={() => decide(false)}>Reject</button>
    <button class="primary" disabled={busy} onclick={() => decide(true)}>Trust &amp; Pin</button>
  {/snippet}
</ModalDialog>
