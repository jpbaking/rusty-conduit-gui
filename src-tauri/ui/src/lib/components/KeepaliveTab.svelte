<script lang="ts">
  import { store } from "../stores.svelte";
  import type { SessionProfile, TunnelConfig } from "../types";
  import NumberField from "./NumberField.svelte";

  const uid = $props.id();
  const draft = $derived(store.draft as SessionProfile);
  const tunnel = $derived(draft.tunnel);
  const errors = $derived(store.draftErrors);

  function setTunnel(patch: Partial<TunnelConfig>) {
    store.updateDraft((p) => ({ ...p, tunnel: { ...p.tunnel, ...patch } }));
  }
</script>

<section aria-labelledby={`${uid}-keepalive`}>
  <h2 id={`${uid}-keepalive`}>Keepalive</h2>
  <div class="field-row">
    <NumberField
      label="Server alive interval (seconds)"
      value={tunnel.server_alive_interval}
      hint="0 turns keepalives off"
      error={errors["tunnel.server_alive_interval"]}
      onValue={(server_alive_interval) => setTunnel({ server_alive_interval })}
    />
    <NumberField
      label="Server alive count max"
      value={tunnel.server_alive_count_max}
      hint="Missed replies before disconnecting"
      error={errors["tunnel.server_alive_count_max"]}
      onValue={(server_alive_count_max) => setTunnel({ server_alive_count_max })}
    />
  </div>
</section>

<section aria-labelledby={`${uid}-reconnect`}>
  <h2 id={`${uid}-reconnect`}>Reconnect</h2>
  <label class="check">
    <input
      type="checkbox"
      checked={!tunnel.no_reconnect}
      onchange={(e) => setTunnel({ no_reconnect: !e.currentTarget.checked })}
    />
    Reconnect automatically
  </label>
  <!-- Stay editable while reconnect is off: the backend validates them either way. -->
  <div class="field-row">
    <NumberField
      label="Initial delay (seconds)"
      value={tunnel.reconnect_initial_delay}
      error={errors["tunnel.reconnect_initial_delay"]}
      onValue={(reconnect_initial_delay) => setTunnel({ reconnect_initial_delay })}
    />
    <NumberField
      label="Maximum delay (seconds)"
      value={tunnel.reconnect_max_delay}
      error={errors["tunnel.reconnect_max_delay"]}
      onValue={(reconnect_max_delay) => setTunnel({ reconnect_max_delay })}
    />
  </div>
  {#if !tunnel.no_reconnect && tunnel.reconnect_initial_delay === 0}
    <p class="warning">An initial delay of 0 retries with no pause while the server is unreachable.</p>
  {/if}
</section>

<section aria-labelledby={`${uid}-startup`}>
  <h2 id={`${uid}-startup`}>Startup</h2>
  <div class="field-row">
    <NumberField
      label="Startup timeout (seconds)"
      value={tunnel.startup_timeout}
      error={errors["tunnel.startup_timeout"]}
      onValue={(startup_timeout) => setTunnel({ startup_timeout })}
    />
  </div>
  {#if tunnel.startup_timeout === 0}
    <p class="warning">A timeout of 0 leaves no time to connect, so the session is likely to fail.</p>
  {/if}
  <label class="check">
    <input
      type="checkbox"
      checked={draft.autostart}
      onchange={(e) => {
        const autostart = e.currentTarget.checked;
        store.updateDraft((p) => ({ ...p, autostart }));
      }}
    />
    Start with the app
  </label>
</section>
