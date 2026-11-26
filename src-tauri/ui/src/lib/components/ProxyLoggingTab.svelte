<script lang="ts">
  import { store } from "../stores.svelte";
  import type { LoggingConfig, Proxy } from "../types";
  import { LOG_LEVELS } from "../validate";

  const uid = $props.id();
  const proxy = $derived(store.proxyDraft as Proxy);
  const logging = $derived(proxy.logging);
  const errors = $derived(store.proxyDraftErrors);

  function setLogging(patch: Partial<LoggingConfig>) {
    store.updateProxyDraft((p) => ({ ...p, logging: { ...p.logging, ...patch } }));
  }

  const pathOrNull = (text: string) => (text.trim() ? text : null);
</script>

<section class="card" aria-labelledby={`${uid}-general`}>
  <h2 id={`${uid}-general`}>General</h2>
  <label class="field">
    Name
    <input
      value={proxy.name}
      aria-invalid={!!errors.name}
      oninput={(e) => {
        const name = e.currentTarget.value;
        store.updateProxyDraft((p) => ({ ...p, name }));
      }}
    />
  </label>
  {#if errors.name}<p class="field-error">{errors.name}</p>{/if}
  <label class="check">
    <input
      type="checkbox"
      checked={proxy.enabled}
      onchange={(e) => {
        const enabled = e.currentTarget.checked;
        store.updateProxyDraft((p) => ({ ...p, enabled }));
      }}
    />
    Enabled <small class="muted">included in Start All and autostart</small>
  </label>
  <label class="check">
    <input
      type="checkbox"
      checked={proxy.autostart}
      onchange={(e) => {
        const autostart = e.currentTarget.checked;
        store.updateProxyDraft((p) => ({ ...p, autostart }));
      }}
    />
    Start when the app starts
  </label>
</section>

<section class="card" aria-labelledby={`${uid}-logging`}>
  <h2 id={`${uid}-logging`}>Logging</h2>
  <div class="field-row">
    <label class="field">
      Level
      <select
        value={logging.level.toUpperCase()}
        aria-invalid={!!errors["logging.level"]}
        onchange={(e) => setLogging({ level: e.currentTarget.value })}
      >
        {#each LOG_LEVELS as level (level)}<option value={level}>{level}</option>{/each}
      </select>
    </label>
    <label class="field">
      Format
      <select
        value={logging.format.toLowerCase()}
        aria-invalid={!!errors["logging.format"]}
        onchange={(e) => setLogging({ format: e.currentTarget.value })}
      >
        <option value="text">Text</option>
        <option value="json">JSON</option>
      </select>
    </label>
  </div>
  {#if errors["logging.level"]}<p class="field-error">{errors["logging.level"]}</p>{/if}
  {#if errors["logging.format"]}<p class="field-error">{errors["logging.format"]}</p>{/if}
  <label class="field">
    <span>HTTP access log file <small class="muted">optional; empty keeps it in the app only</small></span>
    <input
      value={logging.http_access_log ?? ""}
      spellcheck="false"
      oninput={(e) => setLogging({ http_access_log: pathOrNull(e.currentTarget.value) })}
    />
  </label>
  <label class="field">
    <span>SOCKS log file <small class="muted">optional</small></span>
    <input
      value={logging.socks_log ?? ""}
      spellcheck="false"
      oninput={(e) => setLogging({ socks_log: pathOrNull(e.currentTarget.value) })}
    />
  </label>
</section>
