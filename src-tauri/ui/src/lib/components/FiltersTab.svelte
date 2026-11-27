<script lang="ts">
  import type { SessionProfile } from "../types";
  import FilterEditor from "./FilterEditor.svelte";
  import { chainEditor } from "./JumpChainBuilder.svelte";

  const ed = chainEditor();
  const draft = $derived(ed.draft as SessionProfile);
  const errors = $derived(ed.draftErrors);
  const isTunnel = $derived(!!ed.isTunnel);
</script>

{#if isTunnel}
  <p class="note">
    Forward filters apply both to this tunnel's optional Forward listener and to all Proxy traffic routed through this tunnel.
  </p>
{/if}

<FilterEditor
  title="Forward filters"
  scope="forward"
  allow={draft.forward.allow}
  block={draft.forward.block}
  {errors}
  onChange={(allow, block) =>
    ed.updateDraft((p) => ({ ...p, forward: { ...p.forward, allow, block } }))}
/>

<FilterEditor
  title="Reverse filters"
  scope="reverse"
  allow={draft.reverse.reverse_allow}
  block={draft.reverse.reverse_block}
  {errors}
  onChange={(reverse_allow, reverse_block) =>
    ed.updateDraft((p) => ({ ...p, reverse: { ...p.reverse, reverse_allow, reverse_block } }))}
/>
