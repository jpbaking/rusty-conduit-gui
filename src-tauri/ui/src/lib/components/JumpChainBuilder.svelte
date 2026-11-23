<script lang="ts">
  import { tick } from "svelte";
  import { hopBadge, hopRole, hopTitle, moved, newHop, NIL_UUID } from "../chain";
  import { store } from "../stores.svelte";
  import type { HopEntry } from "../types";
  import ModalDialog from "./ModalDialog.svelte";

  const hops = $derived(store.draft?.hops ?? []);
  const selected = $derived(store.selectedHop);
  const results = $derived(new Map((store.chainResult?.hops ?? []).map((r) => [r.hop_id, r])));
  const failed = $derived(store.chainResult?.hops.find((r) => r.status === "failed") ?? null);
  const linkedProfile = $derived(
    selected ? (store.hosts.find((h) => h.id === selected.host.id) ?? null) : null,
  );

  // A hop can only be promoted once it is saved, because the backend reads the saved session.
  const promoteBlocker = $derived.by(() => {
    if (!selected) return "Select a hop first.";
    if (linkedProfile) return "This hop already uses a host profile.";
    if (store.dirty || !store.selected) return "Save the session first.";
    if (!selected.host.host.trim() || !selected.host.user.trim()) return "Enter a host and user first.";
    return null;
  });

  let list = $state<HTMLOListElement>();
  let dragId = $state<string | null>(null);
  let dropIndex = $state<number | null>(null);
  let announcement = $state("");
  let promoteName = $state("");
  let promoting = $state(false);
  let promoteOpen = $state(false);

  function setHops(edit: (current: HopEntry[]) => HopEntry[]) {
    store.updateDraft((profile) => ({ ...profile, hops: edit(profile.hops) }));
  }

  function addJump() {
    const hop = newHop();
    // The last hop is the target, so a new jump goes in front of it.
    setHops((current) => {
      const at = Math.max(current.length - 1, 0);
      return [...current.slice(0, at), hop, ...current.slice(at)];
    });
    store.selectedHopId = hop.hop_id;
    announcement = "Hop added.";
  }

  function removeHop(hop: HopEntry) {
    setHops((current) => current.filter((h) => h.hop_id !== hop.hop_id));
    announcement = `${hopTitle(hop)} removed.`;
  }

  function moveTo(hop: HopEntry, to: number) {
    const from = hops.findIndex((h) => h.hop_id === hop.hop_id);
    if (from < 0 || from === to) return;
    const count = hops.length;
    setHops((current) => moved(current, from, to));
    announcement = `${hopTitle(hop)} is now ${hopRole(to, count)}.`;
  }

  async function moveByKey(hop: HopEntry, index: number, delta: -1 | 1) {
    moveTo(hop, index + delta);
    await tick();
    // The pressed button is disabled at either end, so keep focus on its partner.
    const node = list?.querySelector<HTMLElement>(`[data-hop="${hop.hop_id}"]`);
    const same = node?.querySelector<HTMLButtonElement>(delta < 0 ? ".move-back" : ".move-forward");
    const other = node?.querySelector<HTMLButtonElement>(delta < 0 ? ".move-forward" : ".move-back");
    (same && !same.disabled ? same : other)?.focus();
  }

  // Pointer events, because Tauri's native file-drop handling can swallow HTML5 drag events.
  function startDrag(event: PointerEvent, hop: HopEntry, index: number) {
    if (event.button !== 0) return;
    event.preventDefault();
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    dragId = hop.hop_id;
    dropIndex = index;
    store.selectedHopId = hop.hop_id;
  }

  function onDragMove(event: PointerEvent) {
    if (!dragId || !list) return;
    let best = Infinity;
    list.querySelectorAll<HTMLElement>("[data-hop]").forEach((node, index) => {
      const box = node.getBoundingClientRect();
      const distance = Math.hypot(
        event.clientX - (box.left + box.width / 2),
        event.clientY - (box.top + box.height / 2),
      );
      if (distance < best) {
        best = distance;
        dropIndex = index;
      }
    });
  }

  function endDrag(commit: boolean) {
    const hop = hops.find((h) => h.hop_id === dragId);
    const to = dropIndex;
    dragId = null;
    dropIndex = null;
    if (commit && hop && to !== null) moveTo(hop, to);
  }

  function applyProfile(id: string) {
    const hop = selected;
    if (!hop) return;
    const profile = store.hosts.find((h) => h.id === id);
    setHops((current) =>
      current.map((h) => {
        if (h.hop_id !== hop.hop_id) return h;
        // Choosing "Inline" keeps the values and only removes the link.
        return profile
          ? { ...h, name: profile.name, host: profile }
          : { ...h, host: { ...h.host, id: NIL_UUID } };
      }),
    );
  }

  function openPromote() {
    promoteName = selected ? hopTitle(selected) : "";
    promoteOpen = true;
  }

  async function promote() {
    const name = promoteName.trim();
    if (!selected || !name || promoting) return;
    promoting = true;
    const done = await store.promoteHop(selected.hop_id, name);
    promoting = false;
    if (done) promoteOpen = false;
  }
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && dragId && endDrag(false)} />

<section aria-labelledby="chain-heading">
  <h2 id="chain-heading">Jump chain</h2>

  <ol class="chain-builder" bind:this={list} aria-label="Jump chain, from local to target">
    <li class="chain-local">Local</li>
    {#each hops as hop, index (hop.hop_id)}
      {@const result = results.get(hop.hop_id)}
      {@const badge = result ? hopBadge(result) : null}
      <li
        class="chain-node"
        class:selected={selected?.hop_id === hop.hop_id}
        class:dragging={dragId === hop.hop_id}
        class:drop-target={dragId !== null && dropIndex === index && dragId !== hop.hop_id}
        data-hop={hop.hop_id}
      >
        <button
          class="drag-handle"
          tabindex="-1"
          aria-label="Drag {hopTitle(hop)} to reorder"
          title="Drag to reorder"
          onpointerdown={(e) => startDrag(e, hop, index)}
          onpointermove={onDragMove}
          onpointerup={() => endDrag(true)}
          onpointercancel={() => endDrag(false)}
        >⠿</button>
        <button
          class="hop-select"
          aria-pressed={selected?.hop_id === hop.hop_id}
          onclick={() => (store.selectedHopId = hop.hop_id)}
        >
          <small>{hopRole(index, hops.length)}</small>
          <span class="hop-name">{hopTitle(hop)}</span>
          {#if hop.host.host}<small>{hop.host.host}:{hop.host.port}</small>{/if}
        </button>
        {#if badge && result}
          <span class="hop-badge {badge.tone}" title={badge.label}>
            <span aria-hidden="true">{badge.glyph}</span>
            {#if result.status === "connected"}{result.elapsed_ms} ms{/if}
            <span class="sr-only">{badge.label}</span>
          </span>
        {/if}
        <span class="hop-actions">
          <button
            class="icon move-back"
            aria-label="Move {hopTitle(hop)} earlier"
            title="Move earlier"
            disabled={index === 0}
            onclick={() => moveByKey(hop, index, -1)}
          >←</button>
          <button
            class="icon move-forward"
            aria-label="Move {hopTitle(hop)} later"
            title="Move later"
            disabled={index === hops.length - 1}
            onclick={() => moveByKey(hop, index, 1)}
          >→</button>
          <button
            class="icon"
            aria-label="Remove {hopTitle(hop)}"
            title="Remove hop"
            onclick={() => removeHop(hop)}
          >×</button>
        </span>
      </li>
    {/each}
  </ol>
  <p class="sr-only" role="status">{announcement}</p>

  {#if failed}
    <p class="reason" role="alert">
      Hop {failed.hop_index + 1} ({failed.host}:{failed.port}) failed: {failed.error ?? "unknown error"}
    </p>
  {:else if store.chainResult?.all_connected}
    <p class="ok" role="status">All hops connected.</p>
  {/if}

  <div class="chain-toolbar">
    <button onclick={addJump}>{hops.length === 0 ? "+ Add Target" : "+ Add Jump"}</button>
    <label class="field-inline">
      Host profile
      <select
        disabled={!selected}
        value={linkedProfile?.id ?? ""}
        onchange={(e) => applyProfile(e.currentTarget.value)}
      >
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
</section>

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
