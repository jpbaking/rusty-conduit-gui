<script lang="ts">
  import { store } from "../stores.svelte";
  import type { ReverseConfig, SessionProfile } from "../types";
  import { isIpAddress, isLoopback, isPort } from "../validate";
  import PortField from "./PortField.svelte";

  const uid = $props.id();
  const reverse = $derived((store.draft as SessionProfile).reverse);
  const errors = $derived(store.draftErrors);
  const reverseOn = $derived(reverse.reverse_http_port !== 0 || reverse.reverse_socks_port !== 0);
  const exposed = $derived(
    reverseOn && isIpAddress(reverse.reverse_bind) && !isLoopback(reverse.reverse_bind),
  );
  const muxed = $derived(
    reverse.reverse_http_port === reverse.reverse_socks_port &&
      reverse.reverse_http_port !== 0 &&
      isPort(reverse.reverse_http_port),
  );

  function setReverse(patch: Partial<ReverseConfig>) {
    store.updateDraft((profile) => ({ ...profile, reverse: { ...profile.reverse, ...patch } }));
  }
</script>

<section aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>Reverse proxy <small class="muted">opened on the target host, port 0 turns a listener off</small></h2>
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
    <PortField
      label="Remote HTTP port"
      value={reverse.reverse_http_port}
      error={errors["reverse.http"]}
      onValue={(reverse_http_port) => setReverse({ reverse_http_port })}
    />
    <PortField
      label="Remote SOCKS port"
      value={reverse.reverse_socks_port}
      error={errors["reverse.socks"]}
      onValue={(reverse_socks_port) => setReverse({ reverse_socks_port })}
    />
  </div>

  {#if muxed}
    <p><span class="pill ok">Single-port mux</span> <span class="muted">HTTP and SOCKS share remote port {reverse.reverse_http_port}.</span></p>
  {/if}
  {#if exposed}
    <p class="warning">This address may expose the proxy to other hosts if the server allows GatewayPorts.</p>
  {/if}
  {#if errors.listeners}<p class="field-error">{errors.listeners}</p>{/if}
</section>
