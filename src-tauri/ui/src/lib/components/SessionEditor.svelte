<script lang="ts">
  import { stateReason } from "../format";
  import { store } from "../stores.svelte";
  import type { ForwardConfig, HopEntry, ReverseConfig, SessionProfile } from "../types";
  import { isIpAddress, isLoopback } from "../validate";
  import HopEditor from "./HopEditor.svelte";
  import JumpChainBuilder from "./JumpChainBuilder.svelte";

  const uid = $props.id();
  const draft = $derived(store.draft as SessionProfile);
  const hop = $derived(store.selectedHop);
  const errors = $derived(store.draftErrors);
  const reason = $derived(store.selected ? stateReason(store.selected.runtime.state) : null);
  const locked = $derived(!!hop && store.hosts.some((h) => h.id === hop.host.id));
  const forwardOn = $derived(draft.forward.http_port !== 0 || draft.forward.socks_port !== 0);
  const reverseOn = $derived(
    draft.reverse.reverse_http_port !== 0 || draft.reverse.reverse_socks_port !== 0,
  );
  const forwardExposed = $derived(
    forwardOn && isIpAddress(draft.forward.bind) && !isLoopback(draft.forward.bind),
  );
  const reverseExposed = $derived(
    reverseOn && isIpAddress(draft.reverse.reverse_bind) && !isLoopback(draft.reverse.reverse_bind),
  );

  const toPort = (text: string) => (text === "" ? Number.NaN : Number(text));
  const shownPort = (port: number) => (Number.isNaN(port) ? "" : port);

  function editHop(id: string, edit: (hop: HopEntry) => HopEntry) {
    store.updateDraft((profile) => ({
      ...profile,
      hops: profile.hops.map((h) => (h.hop_id === id ? edit(h) : h)),
    }));
  }

  function setForward(patch: Partial<ForwardConfig>) {
    store.updateDraft((profile) => ({ ...profile, forward: { ...profile.forward, ...patch } }));
  }

  function setReverse(patch: Partial<ReverseConfig>) {
    store.updateDraft((profile) => ({ ...profile, reverse: { ...profile.reverse, ...patch } }));
  }
</script>

{#snippet portField(label: string, value: number, field: string, onValue: (port: number) => void)}
  <div class="field port">
    <label class="field">
    {label}
    <input
      type="number"
      min="0"
      max="65535"
      value={shownPort(value)}
      aria-invalid={!!errors[field]}
      aria-describedby={errors[field] ? `${uid}-${field}` : undefined}
      oninput={(e) => onValue(toPort(e.currentTarget.value))}
    />
    </label>
    {#if errors[field]}<span id={`${uid}-${field}`} class="field-error">{errors[field]}</span>{/if}
  </div>
{/snippet}

<div class="session-editor">
  {#if reason}<p class="reason" role="alert">{reason}</p>{/if}
  {#if errors.name}<p class="field-error">{errors.name}</p>{/if}

  <JumpChainBuilder />
  {#if errors.hops}<p class="field-error">{errors.hops}</p>{/if}

  {#if hop}
    {#key hop.hop_id}
      <HopEditor
        host={hop.host}
        {hop}
        {locked}
        {errors}
        errorPrefix={`hop:${hop.hop_id}:`}
        onHostChange={(edit) => editHop(hop.hop_id, (h) => ({ ...h, host: edit(h.host) }))}
        onHopChange={(edit) => editHop(hop.hop_id, edit)}
      />
    {/key}
  {/if}

  <section aria-labelledby="connection-heading">
    <h2 id="connection-heading">Connection</h2>
    <div class="field-row">
      <label class="field">
        IP version
        <select
          value={draft.tunnel.ip_version}
          onchange={(e) => {
            const ip_version = e.currentTarget.value;
            store.updateDraft((p) => ({ ...p, tunnel: { ...p.tunnel, ip_version } }));
          }}
        >
          <option value="4">IPv4</option>
          <option value="6">IPv6</option>
          <option value="auto">Auto</option>
        </select>
      </label>
      <label class="field">
        Engine
        <select
          value={draft.engine}
          onchange={(e) => {
            const engine = e.currentTarget.value as SessionProfile["engine"];
            store.updateDraft((p) => ({ ...p, engine }));
          }}
        >
          <option value="Russh">Built-in Rust SSH</option>
          <option value="OpenSsh" disabled>OpenSSH (Phase 4)</option>
        </select>
      </label>
      <label class="check autostart">
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
    </div>
  </section>

  <section aria-labelledby="forward-heading">
    <h2 id="forward-heading">Forward proxy <small class="muted">port 0 turns a listener off</small></h2>
    <div class="field-row">
      <div class="field grow">
        <label class="field">
        Bind address
        <input
          value={draft.forward.bind}
          spellcheck="false"
          aria-invalid={!!errors["forward.bind"]}
          aria-describedby={errors["forward.bind"] ? `${uid}-errors-forward-bind` : undefined}
          oninput={(e) => setForward({ bind: e.currentTarget.value.trim() })}
        />
        </label>
        {#if errors["forward.bind"]}<span id={`${uid}-errors-forward-bind`} class="field-error">{errors["forward.bind"]}</span>{/if}
      </div>
      {@render portField("HTTP port", draft.forward.http_port, "forward.http", (http_port) => setForward({ http_port }))}
      {@render portField("SOCKS port", draft.forward.socks_port, "forward.socks", (socks_port) => setForward({ socks_port }))}
    </div>
    {#if forwardExposed}
      <p class="warning">This address is not loopback, so other devices on the network may reach this proxy.</p>
    {/if}
  </section>

  <section aria-labelledby="reverse-heading">
    <h2 id="reverse-heading">Reverse proxy <small class="muted">opened on the target host</small></h2>
    <div class="field-row">
      <div class="field grow">
        <label class="field">
        Remote bind address
        <input
          value={draft.reverse.reverse_bind}
          spellcheck="false"
          aria-invalid={!!errors["reverse.bind"]}
          aria-describedby={errors["reverse.bind"] ? `${uid}-errors-reverse-bind` : undefined}
          oninput={(e) => setReverse({ reverse_bind: e.currentTarget.value.trim() })}
        />
        </label>
        {#if errors["reverse.bind"]}<span id={`${uid}-errors-reverse-bind`} class="field-error">{errors["reverse.bind"]}</span>{/if}
      </div>
      {@render portField("HTTP port", draft.reverse.reverse_http_port, "reverse.http", (reverse_http_port) => setReverse({ reverse_http_port }))}
      {@render portField("SOCKS port", draft.reverse.reverse_socks_port, "reverse.socks", (reverse_socks_port) => setReverse({ reverse_socks_port }))}
    </div>
    {#if reverseExposed}
      <p class="warning">This address may expose the proxy to other hosts if the server allows GatewayPorts.</p>
    {/if}
    {#if errors.listeners}<p class="field-error">{errors.listeners}</p>{/if}
  </section>

  {#if store.selected?.runtime.listeners.length}
    <section aria-labelledby="listeners-heading">
      <h2 id="listeners-heading">Active listeners</h2>
      <ul class="plain-list">
        {#each store.selected.runtime.listeners as listener (listener.role + listener.addr)}
          <li>{listener.role}: <code>{listener.addr}</code></li>
        {/each}
      </ul>
    </section>
  {/if}
</div>
