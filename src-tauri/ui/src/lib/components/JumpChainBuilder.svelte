<script lang="ts">
  import { tick } from "svelte";
  import { hopBadge, hopRole, hopTitle, moved, newHop } from "../chain";
  import { store } from "../stores.svelte";
  import type { HopEntry } from "../types";

  const hops = $derived(store.draft?.hops ?? []);
  const selected = $derived(store.selectedHop);
  const results = $derived(new Map((store.chainResult?.hops ?? []).map((r) => [r.hop_id, r])));
  // Only one hop's form shows at a time, so the route marks the others that have errors.
  const invalidHops = $derived(
    new Set(
      Object.keys(store.draftErrors).flatMap((field) => {
        const match = /^hop:([^:]+):/.exec(field);
        return match ? [match[1]] : [];
      }),
    ),
  );
  const failed = $derived(
    store.chainResult?.hops.find((r) => r.status === "failed" || r.status === "host_key_unknown") ?? null,
  );

  let list = $state<HTMLOListElement>();
  let dragId = $state<string | null>(null);
  let dropIndex = $state<number | null>(null);
  let announcement = $state("");

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
      const distance = Math.abs(event.clientY - (box.top + box.height / 2));
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
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && dragId && endDrag(false)} />

<section class="route" aria-labelledby="chain-heading">
  <h2 id="chain-heading">Route</h2>

  <ol class="route-list" bind:this={list} aria-label="Jump chain, from local to target">
    <li class="route-stop route-local">
      <span class="route-dot" aria-hidden="true"></span>
      <span class="route-text"><span class="hop-name">Local</span><small>this computer</small></span>
    </li>
    {#each hops as hop, index (hop.hop_id)}
      {@const result = results.get(hop.hop_id)}
      {@const badge = result ? hopBadge(result) : null}
      {@const isTarget = index === hops.length - 1}
      <li
        class="route-stop route-node"
        class:target={isTarget}
        class:invalid={invalidHops.has(hop.hop_id)}
        class:selected={selected?.hop_id === hop.hop_id}
        class:dragging={dragId === hop.hop_id}
        class:drop-target={dragId !== null && dropIndex === index && dragId !== hop.hop_id}
        data-hop={hop.hop_id}
      >
        <button
          class="route-dot drag-handle"
          tabindex="-1"
          aria-label="Drag {hopTitle(hop)} to reorder"
          title="Drag to reorder"
          onpointerdown={(e) => startDrag(e, hop, index)}
          onpointermove={onDragMove}
          onpointerup={() => endDrag(true)}
          onpointercancel={() => endDrag(false)}
        ></button>
        <button
          class="hop-select"
          aria-pressed={selected?.hop_id === hop.hop_id}
          onclick={() => (store.selectedHopId = hop.hop_id)}
        >
          <small class="hop-role">
            {hopRole(index, hops.length)}
            {#if badge && result}
              <span class="hop-badge {badge.tone}" title={badge.label}>
                <span aria-hidden="true">{badge.glyph}</span>
                {#if result.status === "connected"}{result.elapsed_ms} ms{/if}
                <span class="sr-only">{badge.label}</span>
              </span>
            {/if}
          </small>
          <span class="hop-name">{hopTitle(hop)}</span>
          {#if invalidHops.has(hop.hop_id)}<span class="sr-only">, needs attention</span>{/if}
          <small class="hop-addr">{hop.host.host ? `${hop.host.host}:${hop.host.port}` : "not set"}</small>
        </button>
        <span class="hop-actions">
          <button
            class="icon move-back"
            aria-label="Move {hopTitle(hop)} earlier"
            title="Move up"
            disabled={index === 0}
            onclick={() => moveByKey(hop, index, -1)}
          >↑</button>
          <button
            class="icon move-forward"
            aria-label="Move {hopTitle(hop)} later"
            title="Move down"
            disabled={index === hops.length - 1}
            onclick={() => moveByKey(hop, index, 1)}
          >↓</button>
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

  <button class="route-add" onclick={addJump}>{hops.length === 0 ? "+ Add target" : "+ Add jump"}</button>

  {#if failed?.status === "host_key_unknown"}
    <p class="reason" role="alert">
      Hop {failed.hop_index + 1} ({failed.host}:{failed.port}): host key not trusted.
      <button class="link-button" onclick={() => store.testSelected()}>Review again</button>
    </p>
  {:else if failed}
    <p class="reason" role="alert">
      Hop {failed.hop_index + 1} ({failed.host}:{failed.port}) failed: {failed.error ?? "unknown error"}
    </p>
  {:else if store.chainResult?.all_connected}
    <p class="ok" role="status">All hops connected.</p>
  {/if}
</section>
