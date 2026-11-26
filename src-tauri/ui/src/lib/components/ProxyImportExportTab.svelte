<script lang="ts">
  import { store } from "../stores.svelte";
  import type { Proxy } from "../types";

  const uid = $props.id();
  const source = $derived((store.proxyDraft as Proxy).source);
</script>

<section class="card" aria-labelledby={`${uid}-source`}>
  <h2 id={`${uid}-source`}>Config source</h2>
  {#if source === "managed"}
    <p><span class="pill ok">Managed</span> <span class="muted">This Proxy is edited in the app and saved with its settings.</span></p>
  {:else}
    <p><span class="pill busy">External TOML</span> <span class="muted">Read from a file and reloaded when it changes.</span></p>
    <dl class="fact-list">
      <dt>File</dt>
      <dd><code>{source.external_toml.path}</code></dd>
      <dt>Debounce</dt>
      <dd>{source.external_toml.debounce_ms} ms</dd>
    </dl>
  {/if}
</section>

<section class="card" aria-labelledby={`${uid}-coming`}>
  <h2 id={`${uid}-coming`}>Import / Export & TOML <small class="muted">coming in Milestone U4</small></h2>
  <p class="muted">These tools are not available yet. They will let you:</p>
  <ul>
    <li>Import an AirSwitch <code>.bak</code> backup into this Proxy.</li>
    <li>Import or export a CLI <code>config.toml</code>.</li>
    <li>Link this Proxy to an external TOML file, so edits made outside the app are picked up live.</li>
  </ul>
</section>
