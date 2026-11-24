<script lang="ts">
  import { api, errorMessage } from "../api";
  import { NEW_SESSION_ID, store } from "../stores.svelte";
  import type { ForwardConfig, PortConflict, SessionProfile } from "../types";
  import { PortMux, shareablePort } from "../portMux.svelte";
  import { isIpAddress, isLoopback, isPort } from "../validate";
  import MuxCheckbox from "./MuxCheckbox.svelte";
  import PortField from "./PortField.svelte";
  import ProxySwitch from "./ProxySwitch.svelte";

  const CHECK_DELAY_MS = 300;

  const uid = $props.id();
  const forward = $derived((store.draft as SessionProfile).forward);
  const reverseOn = $derived((store.draft as SessionProfile).reverse.enabled);
  const errors = $derived(store.draftErrors);
  const forwardOn = $derived(forward.enabled && (forward.http_port !== 0 || forward.socks_port !== 0));
  const exposed = $derived(forwardOn && isIpAddress(forward.bind) && !isLoopback(forward.bind));
  const mux = new PortMux(() => ({ http: forward.http_port, socks: forward.socks_port }));
  const canShare = $derived(shareablePort({ http: forward.http_port, socks: forward.socks_port }) !== null);

  let conflicts = $state.raw<PortConflict[]>([]);
  let checkError = $state<string | null>(null);
  function setForward(patch: Partial<ForwardConfig>) {
    store.updateDraft((profile) => ({ ...profile, forward: { ...profile.forward, ...patch } }));
  }

  /** Turning on with no ports set fills in the usual ones, so the proxy has a listener. */
  function setEnabled(enabled: boolean) {
    const unset = forward.http_port === 0 && forward.socks_port === 0;
    setForward(enabled && unset ? { enabled, http_port: 3128, socks_port: 1080 } : { enabled });
  }

  function setMux(on: boolean) {
    const ports = mux.toggle(on);
    if (ports) setForward({ http_port: ports.http, socks_port: ports.socks });
  }

  $effect(() => {
    const id = store.selectedId;
    const { enabled, bind, http_port, socks_port } = forward;
    conflicts = [];
    checkError = null;
    const checkable =
      enabled &&
      isIpAddress(bind) &&
      isPort(http_port, true) &&
      isPort(socks_port, true) &&
      (http_port !== 0 || socks_port !== 0);
    if (!checkable) return;

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const sessionId = id === NEW_SESSION_ID ? null : id;
        const report = await api.checkPortConflicts(sessionId, bind, http_port, socks_port);
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

<section class="card" class:inactive={!forward.enabled} aria-labelledby={`${uid}-heading`}>
  <div class="card-head">
    <h2 id={`${uid}-heading`}>Forward proxy <small class="muted">port 0 turns a listener off</small></h2>
    <ProxySwitch
      name="Forward proxy"
      on={forward.enabled}
      lockedReason={reverseOn ? undefined : "To turn this off, turn on the reverse proxy first"}
      onToggle={setEnabled}
    />
  </div>
  <!-- Switched off, the values stay as they are for when the proxy is turned back on. -->
  <fieldset class="card-body" disabled={!forward.enabled}>
  <legend class="sr-only">Forward proxy settings</legend>
  <div class="field-row">
    <div class="field grow">
      <label class="field">
        Bind address
        <input
          value={forward.bind}
          spellcheck="false"
          aria-invalid={!!errors["forward.bind"]}
          aria-describedby={errors["forward.bind"] ? `${uid}-bind-error` : undefined}
          oninput={(e) => setForward({ bind: e.currentTarget.value.trim() })}
        />
      </label>
      {#if errors["forward.bind"]}
        <span id={`${uid}-bind-error`} class="field-error">{errors["forward.bind"]}</span>
      {/if}
    </div>
    <div class="port-group" bind:this={mux.group} onfocusout={mux.onFocusOut}>
      <PortField
        label={mux.on ? "Shared port" : "HTTP port"}
        value={forward.http_port}
        error={errors["forward.http"]}
        onValue={(port) => setForward(mux.on ? { http_port: port, socks_port: port } : { http_port: port })}
      />
      {#if !mux.on}
        <PortField
          label="SOCKS port"
          value={forward.socks_port}
          error={errors["forward.socks"]}
          onValue={(socks_port) => setForward({ socks_port })}
        />
      {/if}
    </div>
    <div class="field cap" title="HTTP and SOCKS connections count together">
      <label class="field">
        Max connections
        <input
          type="number"
          min="0"
          value={Number.isNaN(forward.max_connections) ? "" : forward.max_connections}
          aria-invalid={!!errors["forward.max_connections"]}
          aria-describedby={errors["forward.max_connections"] ? `${uid}-max-error` : `${uid}-max-hint`}
          oninput={(e) => {
            const text = e.currentTarget.value;
            setForward({ max_connections: text === "" ? Number.NaN : Number(text) });
          }}
        />
      </label>
      {#if errors["forward.max_connections"]}
        <span id={`${uid}-max-error`} class="field-error">{errors["forward.max_connections"]}</span>
      {:else}
        <small id={`${uid}-max-hint`} class="muted">0 = unlimited</small>
      {/if}
    </div>
  </div>

  <MuxCheckbox {mux} {canShare} onToggle={setMux} />
  {#if errors["forward.ports"]}<p class="field-error">{errors["forward.ports"]}</p>{/if}
  </fieldset>

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
