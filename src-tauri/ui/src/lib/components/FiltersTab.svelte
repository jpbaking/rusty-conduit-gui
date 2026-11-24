<script lang="ts">
  import { store } from "../stores.svelte";
  import type { SessionProfile } from "../types";
  import FilterEditor from "./FilterEditor.svelte";

  const draft = $derived(store.draft as SessionProfile);
  const errors = $derived(store.draftErrors);
</script>

<FilterEditor
  title="Forward filters"
  scope="forward"
  allow={draft.forward.allow}
  block={draft.forward.block}
  {errors}
  onChange={(allow, block) =>
    store.updateDraft((p) => ({ ...p, forward: { ...p.forward, allow, block } }))}
/>

<FilterEditor
  title="Reverse filters"
  scope="reverse"
  allow={draft.reverse.reverse_allow}
  block={draft.reverse.reverse_block}
  {errors}
  onChange={(reverse_allow, reverse_block) =>
    store.updateDraft((p) => ({ ...p, reverse: { ...p.reverse, reverse_allow, reverse_block } }))}
/>
