<script lang="ts">
  import { store } from "../stores.svelte";
  import type { ReverseConfig, SessionProfile } from "../types";
  import { PortMux, shareablePort } from "../portMux.svelte";
  import { isIpAddress, isLoopback } from "../validate";
  import MuxCheckbox from "./MuxCheckbox.svelte";
  import PortField from "./PortField.svelte";
  import ProxySwitch from "./ProxySwitch.svelte";

  /** Filled in when the reverse proxy is turned on with no ports: one multiplexed port. */
  const DEFAULT_REVERSE_PORT = 8888;

  const uid = $props.id();
  const reverse = $derived((store.draft as SessionProfile).reverse);
  const forwardCap = $derived((store.draft as SessionProfile).forward.max_connections);
  const forwardEnabled = $derived((store.draft as SessionProfile).forward.enabled);
  const capError = $derived(store.draftErrors["reverse.max_connections"]);
  const errors = $derived(store.draftErrors);
  const reverseOn = $derived(
    reverse.enabled && (reverse.reverse_http_port !== 0 || reverse.reverse_socks_port !== 0),
  );
  const exposed = $derived(
    reverseOn && isIpAddress(reverse.reverse_bind) && !isLoopback(reverse.reverse_bind),
  );
  const ports = () => ({ http: reverse.reverse_http_port, socks: reverse.reverse_socks_port });
  const mux = new PortMux(ports);
  const canShare = $derived(shareablePort(ports()) !== null);

  function setReverse(patch: Partial<ReverseConfig>) {
    store.updateDraft((profile) => ({ ...profile, reverse: { ...profile.reverse, ...patch } }));
  }

  /** Turning on with no ports set fills in a shared port, so the proxy has a listener. */
  function setEnabled(enabled: boolean) {
    const unset = reverse.reverse_http_port === 0 && reverse.reverse_socks_port === 0;
    if (enabled && unset) mux.announce();
    setReverse(
      enabled && unset
        ? { enabled, reverse_http_port: DEFAULT_REVERSE_PORT, reverse_socks_port: DEFAULT_REVERSE_PORT }
        : { enabled },
    );
  }

  function setMux(on: boolean) {
    const next = mux.toggle(on);
    if (next) setReverse({ reverse_http_port: next.http, reverse_socks_port: next.socks });
  }
</script>

<section class="card" class:inactive={!reverse.enabled} aria-labelledby={`${uid}-heading`}>
  <div class="card-head">
    <h2 id={`${uid}-heading`}>Reverse proxy <small class="muted">opened on the target host, port 0 turns a listener off</small></h2>
    <ProxySwitch
      name="Reverse proxy"
      on={reverse.enabled}
      lockedReason={forwardEnabled ? undefined : "To turn this off, turn on the forward proxy first"}
      onToggle={setEnabled}
    />
  </div>
  <!-- Switched off, the values stay as they are for when the proxy is turned back on. -->
  <fieldset class="card-body" disabled={!reverse.enabled}>
  <legend class="sr-only">Reverse proxy settings</legend>
  <div class="field-row">
    <div class="field grow">
      <label class="field">
        Remote bind address
        <input
          value={reverse.reverse_bind}
          spellcheck="false"
          aria-invalid={!!errors["reverse.bind"]}
          aria-describedby={errors["reverse.bind"] ? `${uid}-bind-error` : undefined}
          oninput={(e) => setReverse({ reverse_bind: e.currentTarget.value.trim() })}
        />
      </label>
      {#if errors["reverse.bind"]}
        <span id={`${uid}-bind-error`} class="field-error">{errors["reverse.bind"]}</span>
      {/if}
    </div>
    <div class="port-group" bind:this={mux.group} onfocusout={mux.onFocusOut}>
      <PortField
        label={mux.on ? "Shared port" : "HTTP port"}
        value={reverse.reverse_http_port}
        error={errors["reverse.http"]}
        onValue={(port) =>
          setReverse(mux.on ? { reverse_http_port: port, reverse_socks_port: port } : { reverse_http_port: port })}
      />
      {#if !mux.on}
        <PortField
          label="SOCKS port"
          value={reverse.reverse_socks_port}
          error={errors["reverse.socks"]}
          onValue={(reverse_socks_port) => setReverse({ reverse_socks_port })}
        />
      {/if}
    </div>
    <div class="field cap" title="HTTP and SOCKS connections count together. Leave empty to use the Forward limit.">
      <label class="field">
        Max connections
        <input
          type="number"
          min="0"
          value={reverse.reverse_max_connections === null || Number.isNaN(reverse.reverse_max_connections)
            ? ""
            : reverse.reverse_max_connections}
          placeholder={Number.isSafeInteger(forwardCap) ? `${forwardCap} (Forward)` : "Same as Forward"}
          aria-invalid={!!capError}
          aria-describedby={capError ? `${uid}-cap-error` : `${uid}-cap-hint`}
          oninput={(e) => {
            const text = e.currentTarget.value;
            // Empty follows the forward cap. A typed value that is not a number is kept as NaN.
            setReverse({ reverse_max_connections: text === "" ? null : Number(text) });
          }}
        />
      </label>
      {#if capError}
        <span id={`${uid}-cap-error`} class="field-error">{capError}</span>
      {:else}
        <small id={`${uid}-cap-hint`} class="muted">0 = unlimited</small>
      {/if}
    </div>
  </div>

  <MuxCheckbox {mux} {canShare} onToggle={setMux} />
  {#if errors["reverse.ports"]}<p class="field-error">{errors["reverse.ports"]}</p>{/if}
  </fieldset>
  {#if exposed}
    <p class="warning">
      This address may expose the proxy to other hosts. sshd only uses it with
      <code>GatewayPorts clientspecified</code> (recommended) or <code>yes</code>; with the default
      <code>no</code> it binds loopback instead.
    </p>
  {:else if reverseOn}
    <p class="note">
      <strong>The SSH server decides the final bind address.</strong> If the target's
      <code>sshd_config</code> has <code>GatewayPorts yes</code>, it listens on all interfaces even for
      127.0.0.1, and this proxy has no authentication. Use <code>GatewayPorts clientspecified</code>
      on the target, and consider a reverse blocklist in Filters.
    </p>
  {/if}
</section>
