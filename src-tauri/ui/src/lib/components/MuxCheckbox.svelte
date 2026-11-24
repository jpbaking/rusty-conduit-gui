<script lang="ts">
  import type { PortMux } from "../portMux.svelte";

  interface Props {
    mux: PortMux;
    /** Whether there is a usable port to share when the box is ticked. */
    canShare: boolean;
    onToggle: (on: boolean) => void;
  }

  let { mux, canShare, onToggle }: Props = $props();

  const uid = $props.id();
</script>

<!-- Highlighted when the app ticks it, so the merged port field is not a surprise. -->
<label class="check mux-check" class:auto-on={mux.autoOn}>
  <input
    type="checkbox"
    checked={mux.on}
    disabled={!mux.on && !canShare}
    aria-describedby={mux.autoOn ? `${uid}-auto` : undefined}
    onchange={(e) => onToggle(e.currentTarget.checked)}
  />
  Single-port multiplex <small class="muted">HTTP and SOCKS share one port</small>
</label>
{#if mux.autoOn}
  <p id={`${uid}-auto`} class="note mux-note" role="status">
    Turned on automatically: HTTP and SOCKS use the same port, so they now share one field. Untick
    it to set separate ports.
  </p>
{/if}
