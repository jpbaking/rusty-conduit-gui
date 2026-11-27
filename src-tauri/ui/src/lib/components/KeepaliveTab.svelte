<script lang="ts">
  import { chainEditor } from "./JumpChainBuilder.svelte";
  import type { SessionProfile, TunnelConfig } from "../types";
  import NumberField from "./NumberField.svelte";

  const uid = $props.id();
  const ed = chainEditor();
  const startMode = $derived(ed.startMode);
  const startModeValue = $derived(
    startMode === "linked"
      ? "linked"
      : typeof startMode === "object" && startMode.manual.autostart
        ? "autostart"
        : "manual",
  );
  const draft = $derived(ed.draft as SessionProfile);
  const tunnel = $derived(draft.tunnel);
  const errors = $derived(ed.draftErrors);

  // Worst case for the OS to drop a dead peer: idle, then every unanswered probe.
  const tcpDeadAfter = $derived(
    tunnel.tcp_keepalive + tunnel.tcp_keepalive_interval * tunnel.tcp_keepalive_retries,
  );
  const tcpValid = $derived(
    !errors["tunnel.tcp_keepalive"] &&
      !errors["tunnel.tcp_keepalive_interval"] &&
      !errors["tunnel.tcp_keepalive_retries"],
  );

  function setTunnel(patch: Partial<TunnelConfig>) {
    ed.updateDraft((p) => ({ ...p, tunnel: { ...p.tunnel, ...patch } }));
  }
</script>

<div class="card-grid">
<section class="card" aria-labelledby={`${uid}-keepalive`}>
  <h2 id={`${uid}-keepalive`}>SSH keepalive</h2>
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

<section class="card" aria-labelledby={`${uid}-tcp-keepalive`}>
  <h2 id={`${uid}-tcp-keepalive`}>TCP keepalive</h2>
  <div class="field-row">
    <NumberField
      label="Idle before probes (seconds)"
      value={tunnel.tcp_keepalive}
      hint="0 turns TCP keepalive off"
      error={errors["tunnel.tcp_keepalive"]}
      onValue={(tcp_keepalive) => setTunnel({ tcp_keepalive })}
    />
  </div>
  <!-- Stay editable while TCP keepalive is off: the values come back when it is turned on. -->
  <div class="field-row">
    <NumberField
      label="Probe interval (seconds)"
      value={tunnel.tcp_keepalive_interval}
      min={1}
      error={errors["tunnel.tcp_keepalive_interval"]}
      onValue={(tcp_keepalive_interval) => setTunnel({ tcp_keepalive_interval })}
    />
    <NumberField
      label="Probes before closing"
      value={tunnel.tcp_keepalive_retries}
      min={1}
      error={errors["tunnel.tcp_keepalive_retries"]}
      onValue={(tcp_keepalive_retries) => setTunnel({ tcp_keepalive_retries })}
    />
  </div>
  {#if tunnel.tcp_keepalive === 0}
    <p class="warning">TCP keepalive is off: idle proxy connections can be dropped by NAT, firewall, or VPN timeouts.</p>
  {:else}
    <p class="note">
      Keeps idle proxy client connections and reverse proxy upstream connections alive. A dead
      peer is closed after about {tcpValid ? `${tcpDeadAfter} seconds` : "the idle time plus every probe"}.
    </p>
  {/if}
</section>
</div>

<div class="card-grid">
<section class="card" aria-labelledby={`${uid}-reconnect`}>
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

<section class="card" aria-labelledby={`${uid}-startup`}>
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
  {#if startMode !== undefined && ed.setStartMode}
    {@const setStartMode = ed.setStartMode}
    <div class="field-row">
      <label class="field">
        Start mode
        <select
          value={startModeValue}
          onchange={(e) => {
            const v = e.currentTarget.value;
            setStartMode(
              v === "linked"
                ? "linked"
                : v === "autostart"
                  ? { manual: { autostart: true } }
                  : { manual: { autostart: false } },
            );
          }}
        >
          <option value="linked">Run only while a Proxy uses it</option>
          <option value="manual">Start manually</option>
          <option value="autostart">Start with the app</option>
        </select>
      </label>
    </div>
    {#if !draft.enabled}
      <p class="note">This tunnel is disabled, so it does not start with the app or with Start All. Enable it from the tunnel list's right-click menu.</p>
    {/if}
  {:else}
    <label class="check">
      <input
        type="checkbox"
        checked={draft.autostart}
        onchange={(e) => {
          const autostart = e.currentTarget.checked;
          ed.updateDraft((p) => ({ ...p, autostart }));
        }}
      />
      Start with the app
    </label>
    {#if !draft.enabled}
      <p class="note">This session is disabled, so it does not start with the app or with Start All. Enable it from the session list's right-click menu.</p>
    {/if}
  {/if}
</section>
</div>
