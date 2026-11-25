<script lang="ts">
  import { api, errorMessage } from "../api";
  import { forwardFlag } from "../portForwards";
  import { NEW_SESSION_ID, store } from "../stores.svelte";
  import type { ForwardDirection, ForwardStatus, PortConflict, PortForward } from "../types";
  import { isIpAddress, isLoopback, isPort } from "../validate";
  import PortField from "./PortField.svelte";
  import ProxySwitch from "./ProxySwitch.svelte";

  const CHECK_DELAY_MS = 300;

  interface Props {
    forward: PortForward;
    /** The SSH target's name, for labels. */
    target: string;
    /** Live state while the session runs, or `undefined`. */
    status: ForwardStatus | undefined;
    running: boolean;
    /** Whether the running session uses this forward as it is now. */
    applied: boolean;
    /** Set when this forward is the only listener, so it cannot be switched off. */
    lockedReason?: string;
    onChange: (patch: Partial<PortForward>) => void;
    onRemove: () => void;
  }

  let { forward, target, status, running, applied, lockedReason, onChange, onRemove }: Props = $props();

  const uid = $props.id();
  const errors = $derived(store.draftErrors);
  const key = (field: string) => `forwards:${forward.id}:${field}`;
  const local = $derived(forward.direction === "local");
  const here = "this computer";
  const listenSide = $derived(local ? here : target);
  const connectSide = $derived(local ? target : here);
  const complete = $derived(
    isIpAddress(forward.bind) && isPort(forward.port) && isPort(forward.dest_port) && !!forward.dest_host.trim(),
  );
  const flag = $derived(complete ? forwardFlag(forward) : null);
  const exposed = $derived(isIpAddress(forward.bind) && !isLoopback(forward.bind));
  const privileged = $derived(local && isPort(forward.port) && forward.port < 1024);

  let copied = $state(false);
  let conflicts = $state.raw<PortConflict[]>([]);
  let checkError = $state<string | null>(null);

  async function copyFlag() {
    if (!flag) return;
    try {
      await navigator.clipboard.writeText(flag);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      store.clipboardUrl = flag;
    }
  }

  function setDirection(direction: ForwardDirection) {
    if (direction === forward.direction) return;
    // Each side has its usual destination: a remote forward most often shares a local service.
    const patch: Partial<PortForward> = { direction };
    if (direction === "remote" && !forward.dest_host.trim()) patch.dest_host = "localhost";
    onChange(patch);
  }

  // Only a local forward listens on this computer, so only it can clash with other sessions.
  $effect(() => {
    const id = store.selectedId;
    const { enabled, bind, port } = forward;
    conflicts = [];
    checkError = null;
    if (!local || !enabled || !isIpAddress(bind) || !isPort(port)) return;

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const sessionId = id === NEW_SESSION_ID ? null : id;
        const report = await api.checkPortConflicts(sessionId, bind, port, 0);
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

<section class="card forward-card" class:inactive={!forward.enabled} aria-labelledby={`${uid}-heading`}>
  <div class="card-head">
    <h2 id={`${uid}-heading`}>
      {local ? "Local" : "Remote"} <small class="muted">{local ? "-L" : "-R"}{forward.name.trim() ? ` · ${forward.name.trim()}` : ""}</small>
    </h2>
    <div class="forward-actions">
      {#if running && !applied}
        <span class="pill muted" title="Save, then stop and start the session to use this change">Restart to apply</span>
      {:else if running && forward.enabled}
        {#if status?.error}
          <span class="pill alert" title={status.error}>Failed</span>
        {:else if status}
          <span class="pill ok">Listening</span>
        {:else}
          <span class="pill muted" title="A remote forward listens while the session is connected">Waiting</span>
        {/if}
      {/if}
      <ProxySwitch name={`Port forward ${forward.name || forward.port}`} on={forward.enabled} {lockedReason} onToggle={(enabled) => onChange({ enabled })} />
      <button type="button" class="icon danger" title="Remove this forward" aria-label="Remove this forward" onclick={onRemove}>✕</button>
    </div>
  </div>

  <fieldset class="card-body">
    <legend class="sr-only">Port forward settings</legend>
    <div class="field-row">
      <div class="segmented" role="group" aria-label="Direction">
        <button type="button" aria-pressed={local} onclick={() => setDirection("local")} title="ssh -L: listen here, connect from the target">
          Local -L
        </button>
        <button type="button" aria-pressed={!local} onclick={() => setDirection("remote")} title="ssh -R: listen on the target, connect from here">
          Remote -R
        </button>
      </div>
      <label class="field grow">
        <span>Name <small class="muted">optional</small></span>
        <input value={forward.name} placeholder={local ? "Database" : "Dev server"} oninput={(e) => onChange({ name: e.currentTarget.value })} />
      </label>
    </div>

    <div class="field-row">
      <div class="field grow">
        <label class="field">
          Listen on {listenSide}
          <input
            value={forward.bind}
            spellcheck="false"
            aria-invalid={!!errors[key("bind")]}
            oninput={(e) => onChange({ bind: e.currentTarget.value.trim() })}
          />
        </label>
        {#if errors[key("bind")]}<span class="field-error">{errors[key("bind")]}</span>{/if}
      </div>
      <PortField label="Port" value={forward.port} error={errors[key("port")]} onValue={(port) => onChange({ port })} />
      <span class="forward-arrow" aria-hidden="true">→</span>
      <div class="field grow">
        <label class="field">
          Connect to, from {connectSide}
          <input
            value={forward.dest_host}
            spellcheck="false"
            placeholder={local ? "db.internal" : "localhost"}
            aria-invalid={!!errors[key("dest_host")]}
            oninput={(e) => onChange({ dest_host: e.currentTarget.value })}
          />
        </label>
        {#if errors[key("dest_host")]}<span class="field-error">{errors[key("dest_host")]}</span>{/if}
      </div>
      <PortField label="Port" value={forward.dest_port} error={errors[key("dest_port")]} onValue={(dest_port) => onChange({ dest_port })} />
    </div>

    {#if complete}
      <p class="forward-summary">
        <span>
          Connections to <code>{forward.bind}:{forward.port}</code> on {listenSide} reach
          <code>{forward.dest_host.trim()}:{forward.dest_port}</code> as seen from {connectSide}.
        </span>
        <span class="forward-flag">
          <code>{flag}</code>
          <button type="button" class="icon" title="Copy the ssh flag" aria-label="Copy the ssh flag" onclick={copyFlag}>
            {copied ? "✓" : "⧉"}
          </button>
        </span>
      </p>
    {/if}

    {#if status?.error && running && applied}<p class="field-error">{status.error}</p>{/if}
    {#if exposed && local}
      <p class="warning">
        This address is not loopback, so other devices on your network can use this forward to
        reach {forward.dest_host.trim() || "the destination"}. Use 127.0.0.1 unless you need otherwise.
      </p>
    {:else if exposed}
      <p class="warning">
        Listening on {forward.bind} on {target} lets other machines there reach this computer, and
        the target's sshd must allow it (<code>GatewayPorts clientspecified</code> or <code>yes</code>).
        Otherwise it listens on loopback only.
      </p>
    {/if}
    {#if privileged}
      <p class="note">Ports below 1024 may need administrator rights on this computer.</p>
    {/if}
    {#if conflicts.length > 0}
      <div class="warning" role="status">
        <strong>Port conflict:</strong>
        <ul>
          {#each conflicts as conflict, index (index)}
            <li>Port {conflict.port}: {conflict.detail}</li>
          {/each}
        </ul>
      </div>
    {/if}
    {#if checkError}<p class="muted">Could not check for port conflicts: {checkError}</p>{/if}
  </fieldset>
</section>
