<script lang="ts">
  import { api, errorMessage } from "../api";
  import { NEW_SESSION_ID, store } from "../stores.svelte";
  import type { ForwardConfig, PortConflict, SessionProfile } from "../types";
  import { isIpAddress, isLoopback, isPort } from "../validate";
  import PortField from "./PortField.svelte";

  const CHECK_DELAY_MS = 300;

  const uid = $props.id();
  const forward = $derived((store.draft as SessionProfile).forward);
  const errors = $derived(store.draftErrors);
  const forwardOn = $derived(forward.http_port !== 0 || forward.socks_port !== 0);
  const exposed = $derived(forwardOn && isIpAddress(forward.bind) && !isLoopback(forward.bind));
  // `Object.is` so that clearing the shared field (NaN in both) does not end multiplexing.
  const muxOn = $derived(Object.is(forward.http_port, forward.socks_port) && forward.http_port !== 0);
  const muxPort = $derived(
    [forward.http_port, forward.socks_port].find((port) => port !== 0 && isPort(port)) ?? null,
  );

  let conflicts = $state.raw<PortConflict[]>([]);
  let checkError = $state<string | null>(null);
  /** The SOCKS port to restore when multiplexing is turned off. */
  let separateSocksPort = 0;

  function setForward(patch: Partial<ForwardConfig>) {
    store.updateDraft((profile) => ({ ...profile, forward: { ...profile.forward, ...patch } }));
  }

  function setMux(on: boolean) {
    if (on) {
      if (muxPort === null) return;
      separateSocksPort = forward.socks_port;
      setForward({ http_port: muxPort, socks_port: muxPort });
    } else {
      const restored = separateSocksPort === forward.http_port ? 0 : separateSocksPort;
      setForward({ socks_port: restored });
    }
  }

  $effect(() => {
    const id = store.selectedId;
    const { bind, http_port, socks_port } = forward;
    conflicts = [];
    checkError = null;
    const checkable =
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

<section aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>Forward proxy <small class="muted">port 0 turns a listener off</small></h2>
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
    <PortField
      label={muxOn ? "Shared port" : "HTTP port"}
      value={forward.http_port}
      error={errors["forward.http"]}
      onValue={(port) => setForward(muxOn ? { http_port: port, socks_port: port } : { http_port: port })}
    />
    {#if !muxOn}
      <PortField
        label="SOCKS port"
        value={forward.socks_port}
        error={errors["forward.socks"]}
        onValue={(socks_port) => setForward({ socks_port })}
      />
    {/if}
    <div class="field port">
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

  <label class="check">
    <input
      type="checkbox"
      checked={muxOn}
      disabled={!muxOn && muxPort === null}
      onchange={(e) => setMux(e.currentTarget.checked)}
    />
    Single-port multiplex <small class="muted">HTTP and SOCKS share one port</small>
  </label>

  {#if exposed}
    <p class="warning">This address is not loopback, so other devices on the network may reach this proxy.</p>
  {/if}
  {#if errors.listeners}<p class="field-error">{errors.listeners}</p>{/if}

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
