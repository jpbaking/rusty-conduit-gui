<script lang="ts">
  import { store } from "../stores.svelte";
  import ForwardProxyTab from "./ForwardProxyTab.svelte";
  import ReverseProxyTab from "./ReverseProxyTab.svelte";

  const listenersError = $derived(store.draftErrors.listeners);
</script>

<!-- Both directions share one "at least one listener" rule, so its error shows once, here. -->
{#if listenersError}<p class="field-error">{listenersError}</p>{/if}

<!-- Keyed so the forward port-conflict check never carries across sessions. -->
{#key store.selectedId}
  <ForwardProxyTab />
{/key}

<ReverseProxyTab />
