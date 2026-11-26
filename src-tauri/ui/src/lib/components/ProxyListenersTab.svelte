<script lang="ts">
  import { api, errorMessage } from "../api";
  import { PortMux, shareablePort } from "../portMux.svelte";
  import { NEW_SESSION_ID, store } from "../stores.svelte";
  import type { ListenerConfig, NetworkConfig, PortConflict, Proxy } from "../types";
  import { isIpAddress, isLoopback, isPort } from "../validate";
  import MuxCheckbox from "./MuxCheckbox.svelte";
  import NumberField from "./NumberField.svelte";
  import PortField from "./PortField.svelte";

  const CHECK_DELAY_MS = 300;

  const uid = $props.id();
  const proxy = $derived(store.proxyDraft as Proxy);
  const listeners = $derived(proxy.listeners);
  const network = $derived(proxy.network);
  const errors = $derived(store.proxyDraftErrors);
  const exposed = $derived(isIpAddress(listeners.bind) && !isLoopback(listeners.bind));
  const mux = new PortMux(() => ({ http: listeners.http_port, socks: listeners.socks_port }));
  const canShare = $derived(shareablePort({ http: listeners.http_port, socks: listeners.socks_port }) !== null);

  let conflicts = $state.raw<PortConflict[]>([]);
  let checkError = $state<string | null>(null);

  function setListeners(patch: Partial<ListenerConfig>) {
    store.updateProxyDraft((p) => ({ ...p, listeners: { ...p.listeners, ...patch } }));
  }

  function setNetwork(patch: Partial<NetworkConfig>) {
    store.updateProxyDraft((p) => ({ ...p, network: { ...p.network, ...patch } }));
  }

  function setMux(on: boolean) {
    const ports = mux.toggle(on);
    if (ports) setListeners({ http_port: ports.http, socks_port: ports.socks });
  }

  // Live port-conflict check against other Proxies, sessions, and the OS.
  $effect(() => {
    const id = store.selectedProxyId;
    const { bind, http_port, socks_port } = listeners;
    conflicts = [];
    checkError = null;
    const checkable =
      isIpAddress(bind) && isPort(http_port, true) && isPort(socks_port, true) && (http_port !== 0 || socks_port !== 0);
    if (!checkable) return;

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const proxyId = id === NEW_SESSION_ID ? null : id;
        const report = await api.checkProxyPortConflicts(proxyId, bind, http_port, socks_port);
        if (!cancelled) conflicts = report.conflicts;
      } catch (error) {
        if (!cancelled) checkError = errorMessage(error);
      }
    }, CHECK_DELAY_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  });
</script>

<section class="card" aria-labelledby={`${uid}-listeners`}>
  <h2 id={`${uid}-listeners`}>Listeners <small class="muted">port 0 turns a listener off</small></h2>
  <div class="field-row">
    <div class="field grow">
      <label class="field">
        Bind address
        <input
          value={listeners.bind}
          spellcheck="false"
          aria-invalid={!!errors["listeners.bind"]}
          aria-describedby={errors["listeners.bind"] ? `${uid}-bind-error` : undefined}
          oninput={(e) => setListeners({ bind: e.currentTarget.value.trim() })}
        />
      </label>
      {#if errors["listeners.bind"]}
        <span id={`${uid}-bind-error`} class="field-error">{errors["listeners.bind"]}</span>
      {/if}
    </div>
    <div class="port-group" bind:this={mux.group} onfocusout={mux.onFocusOut}>
      <PortField
        label={mux.on ? "Shared port" : "HTTP port"}
        value={listeners.http_port}
        error={errors["listeners.http_port"]}
        onValue={(port) => setListeners(mux.on ? { http_port: port, socks_port: port } : { http_port: port })}
      />
      {#if !mux.on}
        <PortField
          label="SOCKS port"
          value={listeners.socks_port}
          error={errors["listeners.socks_port"]}
          onValue={(socks_port) => setListeners({ socks_port })}
        />
      {/if}
    </div>
    <NumberField
      label="Max connections"
      value={listeners.max_connections}
      hint="0 = unlimited"
      error={errors["listeners.max_connections"]}
      onValue={(max_connections) => setListeners({ max_connections })}
    />
  </div>

  <MuxCheckbox {mux} {canShare} onToggle={setMux} />
  {#if errors["listeners.ports"]}<p class="field-error">{errors["listeners.ports"]}</p>{/if}

  {#if exposed}
    <p class="warning">This address is not loopback, so other devices on the network may reach this proxy.</p>
  {/if}

  <div role="status">
    {#if conflicts.length > 0}
      <div class="warning">
        <strong>Port conflict:</strong>
        <ul class="plain-list">
          {#each conflicts as conflict, index (index)}
            <li>Port {conflict.port}: {conflict.detail}</li>
          {/each}
        </ul>
      </div>
    {/if}
    {#if checkError}<p class="muted">Could not check ports: {checkError}</p>{/if}
  </div>
</section>

<section class="card" aria-labelledby={`${uid}-network`}>
  <h2 id={`${uid}-network`}>Network</h2>
  <div class="field-row">
    <NumberField
      label="Connect timeout (seconds)"
      value={network.connect_timeout}
      min={1}
      error={errors["network.connect_timeout"]}
      onValue={(connect_timeout) => setNetwork({ connect_timeout })}
    />
    <NumberField
      label="TCP keepalive idle (seconds)"
      value={network.tcp_keepalive}
      hint="0 turns TCP keepalive off"
      error={errors["network.tcp_keepalive"]}
      onValue={(tcp_keepalive) => setNetwork({ tcp_keepalive })}
    />
  </div>
  <div class="field-row">
    <NumberField
      label="Probe interval (seconds)"
      value={network.tcp_keepalive_interval}
      min={1}
      error={errors["network.tcp_keepalive_interval"]}
      onValue={(tcp_keepalive_interval) => setNetwork({ tcp_keepalive_interval })}
    />
    <NumberField
      label="Probes before closing"
      value={network.tcp_keepalive_retries}
      min={1}
      error={errors["network.tcp_keepalive_retries"]}
      onValue={(tcp_keepalive_retries) => setNetwork({ tcp_keepalive_retries })}
    />
  </div>
  {#if network.tcp_keepalive === 0}
    <p class="warning">TCP keepalive is off: idle connections can be dropped by NAT, firewall, or VPN timeouts.</p>
  {/if}
</section>
