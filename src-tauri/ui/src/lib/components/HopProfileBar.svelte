<script lang="ts">
  import { hopRole, hopTitle, NIL_UUID } from "../chain";
  import { store } from "../stores.svelte";
  import type { HopEntry } from "../types";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    hop: HopEntry;
  }

  let { hop }: Props = $props();

  const uid = $props.id();
  const hops = $derived(store.draft?.hops ?? []);
  const index = $derived(hops.findIndex((h) => h.hop_id === hop.hop_id));
  const linkedProfile = $derived(store.hosts.find((h) => h.id === hop.host.id) ?? null);

  // A hop can only be promoted once it is saved, because the backend reads the saved session.
  const promoteBlocker = $derived.by(() => {
    if (linkedProfile) return "This hop already uses a host profile.";
    if (store.dirty || !store.selected) return "Save the session first.";
    if (!hop.host.host.trim() || !hop.host.user.trim()) return "Enter a host and user first.";
    return null;
  });

  let promoteName = $state("");
  let promoting = $state(false);
  let promoteOpen = $state(false);

  function applyProfile(id: string) {
    const profile = store.hosts.find((h) => h.id === id);
    store.updateDraft((draft) => ({
      ...draft,
      hops: draft.hops.map((h) => {
        if (h.hop_id !== hop.hop_id) return h;
        // Choosing "Inline" keeps the values and only removes the link.
        return profile
          ? { ...h, name: profile.name, host: profile }
          : { ...h, host: { ...h.host, id: NIL_UUID } };
      }),
    }));
  }

  function openPromote() {
    promoteName = hopTitle(hop);
    promoteOpen = true;
  }

  async function promote() {
    const name = promoteName.trim();
    if (!name || promoting) return;
    promoting = true;
    const done = await store.promoteHop(hop.hop_id, name);
    promoting = false;
    if (done) promoteOpen = false;
  }
</script>

<div class="hop-head">
  <div class="hop-head-title">
    <small>{index >= 0 ? hopRole(index, hops.length) : "Hop"}</small>
    <h2 id="{uid}-hop-title">{hopTitle(hop)}</h2>
  </div>
  <label class="field-inline">
    <span class="sr-only">Host profile for this hop</span>
    <select value={linkedProfile?.id ?? ""} onchange={(e) => applyProfile(e.currentTarget.value)}>
      <option value="">Inline (no profile)</option>
      {#each store.hosts as host (host.id)}
        <option value={host.id}>{host.name} ({host.user}@{host.host}:{host.port})</option>
      {/each}
    </select>
  </label>
  <button disabled={promoteBlocker !== null} title={promoteBlocker ?? undefined} onclick={openPromote}>
    Save as Profile
  </button>
</div>

{#if promoteOpen}
  <ModalDialog title="Save as Host Profile" onDismiss={() => (promoteOpen = false)}>
    <label class="field">
      Profile name
      <input bind:value={promoteName} />
    </label>
    {#snippet actions()}
      <button onclick={() => (promoteOpen = false)}>Cancel</button>
      <button class="primary" disabled={!promoteName.trim() || promoting} onclick={promote}>
        {promoting ? "Saving…" : "Save"}
      </button>
    {/snippet}
  </ModalDialog>
{/if}
