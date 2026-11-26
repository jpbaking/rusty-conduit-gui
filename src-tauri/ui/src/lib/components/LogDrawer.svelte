<script lang="ts">
  import { untrack } from "svelte";
  import { api, errorMessage } from "../api";
  import { formatBytes, formatTime, logLevel, passesLevel, type LogFilter, type LogLevel } from "../format";
  import { store, type LogTarget } from "../stores.svelte";
  import type { AccessRecordView, LogLine } from "../types";

  const ROW_HEIGHT = 20;
  const OVERSCAN = 10;
  const POLL_MS = 1_000;

  /** `app`: the text log. `access`: HTTP and SOCKS access records of a Proxy. */
  type KindFilter = "all" | "app" | "access" | "http" | "socks";

  type Row =
    | { type: "text"; key: string; time: number; level: LogLevel; line: LogLine }
    | { type: "access"; key: string; time: number; level: LogLevel; record: AccessRecordView };

  let lines = $state.raw<LogLine[]>([]);
  let records = $state.raw<AccessRecordView[]>([]);
  let filter = $state<LogFilter>("all");
  let kind = $state<KindFilter>("all");
  let profileFilter = $state("");
  let ruleFilter = $state("");
  let query = $state("");
  let paused = $state(false);
  let autoscroll = $state(true);
  let error = $state<string | null>(null);
  let copied = $state(false);
  let scrollTop = $state(0);
  let viewportHeight = $state(0);
  let viewport = $state<HTMLDivElement | null>(null);
  /** Bumped on clear and target change, so a response already in flight is ignored. */
  let generation = 0;

  /** The selected item of the open view; the last explicit target otherwise. */
  const target = $derived.by<LogTarget | null>(() => {
    if (store.view === "proxy" && store.selectedProxy) return { kind: "proxy", id: store.selectedProxy.profile.id };
    if (store.view === "tunnel" && store.selectedTunnel) return { kind: "tunnel", id: store.selectedTunnel.profile.id };
    if (store.view === "sessions" && store.selected) return { kind: "session", id: store.selected.profile.id };
    return store.logTarget;
  });
  const targetKey = $derived(target ? `${target.kind}:${target.id}` : null);
  const isProxy = $derived(target?.kind === "proxy");
  const targetName = $derived.by(() => {
    if (!target) return null;
    if (target.kind === "proxy") return store.proxies.find((p) => p.profile.id === target.id)?.profile.name ?? null;
    if (target.kind === "tunnel") return store.tunnels.find((t) => t.profile.id === target.id)?.profile.name ?? null;
    return store.sessions.find((s) => s.profile.id === target.id)?.profile.name ?? null;
  });

  const profiles = $derived([...new Set(records.map((r) => r.profile).filter((p) => p))].sort());
  const rules = $derived([...new Set(records.map((r) => r.rule).filter((r) => r))].sort());

  const accessLevel = (record: AccessRecordView): LogLevel => {
    const code = Number(record.status);
    if (Number.isFinite(code) && code >= 500) return "error";
    if (Number.isFinite(code) && code >= 400) return "warn";
    if (!Number.isFinite(code) && !["succeeded", "ok", "success"].includes(record.status.toLowerCase())) return "warn";
    return "info";
  };

  const accessText = (r: AccessRecordView) =>
    `${r.kind.toUpperCase()} ${r.method} ${r.target} ${r.status} rule=${r.rule || "-"} profile=${r.profile || "-"} ` +
    `via=${r.upstream} ${r.client}${r.mitm ? " mitm" : ""} ↓${formatBytes(r.bytes_in)} ↑${formatBytes(r.bytes_out)} ${r.duration_ms}ms`;

  const allRows = $derived.by<Row[]>(() => {
    const text: Row[] = lines.map((line) => ({
      type: "text",
      key: `t${line.seq}`,
      time: line.timestamp,
      level: logLevel(line.text),
      line,
    }));
    const access: Row[] = records.map((record, index) => ({
      type: "access",
      key: `a${record.ts_ms}:${index}`,
      time: record.ts_ms / 1000,
      level: accessLevel(record),
      record,
    }));
    return access.length === 0 ? text : [...text, ...access].sort((a, b) => a.time - b.time);
  });

  const visibleRows = $derived.by(() => {
    const needle = query.trim().toLowerCase();
    return allRows.filter((row) => {
      if (!passesLevel(row.level, filter)) return false;
      if (row.type === "text") {
        if (kind !== "all" && kind !== "app") return false;
        if (profileFilter || ruleFilter) return false;
        return !needle || row.line.text.toLowerCase().includes(needle);
      }
      const r = row.record;
      if (kind === "app" || ((kind === "http" || kind === "socks") && r.kind !== kind)) return false;
      if (profileFilter && r.profile !== profileFilter) return false;
      if (ruleFilter && r.rule !== ruleFilter) return false;
      return !needle || accessText(r).toLowerCase().includes(needle);
    });
  });

  const firstRow = $derived(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN));
  const lastRow = $derived(
    Math.min(visibleRows.length, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN),
  );
  const rows = $derived(visibleRows.slice(firstRow, lastRow));

  // A different target starts with an empty view and no access filters.
  $effect(() => {
    void targetKey;
    untrack(() => {
      generation += 1;
      lines = [];
      records = [];
      error = null;
      autoscroll = true;
      profileFilter = "";
      ruleFilter = "";
      if (kind !== "all" && kind !== "app") kind = "all";
    });
  });

  // Logs are fetched only while the drawer is open and not paused.
  $effect(() => {
    const current = target;
    if (!store.logsOpen || paused || current === null) return;

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const load = async () => {
      const startedAt = generation;
      try {
        let nextLines: LogLine[];
        let nextRecords: AccessRecordView[] = [];
        if (current.kind === "proxy") {
          [nextLines, nextRecords] = await Promise.all([
            api.getProxyLogs(current.id),
            api.getProxyAccessRecords(current.id),
          ]);
        } else if (current.kind === "tunnel") {
          nextLines = await api.getTunnelLogs(current.id);
        } else {
          nextLines = await api.getSessionLogs(current.id);
        }
        if (cancelled || startedAt !== generation) return;
        lines = nextLines;
        records = nextRecords;
        error = null;
      } catch (e) {
        if (!cancelled) error = errorMessage(e);
      }
      if (!cancelled) timer = setTimeout(load, POLL_MS);
    };
    void load();

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  });

  // A reopened drawer has a new viewport that starts at the top.
  $effect(() => {
    if (!store.logsOpen) scrollTop = 0;
  });

  $effect(() => {
    void visibleRows.length;
    if (autoscroll && viewport) viewport.scrollTop = viewport.scrollHeight;
  });

  function onScroll() {
    if (!viewport) return;
    scrollTop = viewport.scrollTop;
    const distance = viewport.scrollHeight - viewport.clientHeight - viewport.scrollTop;
    autoscroll = distance < ROW_HEIGHT;
  }

  async function clearLogs() {
    const current = target;
    if (current === null) return;
    try {
      if (current.kind === "proxy") await api.clearProxyLogs(current.id);
      else if (current.kind === "tunnel") await api.clearTunnelLogs(current.id);
      else await api.clearSessionLogs(current.id);
      generation += 1;
      lines = [];
      records = [];
      scrollTop = 0;
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function copyLogs() {
    const text = visibleRows
      .map((row) => `${formatTime(row.time)} ${row.type === "text" ? row.line.text : accessText(row.record)}`)
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 1_500);
    } catch {
      error = "Could not copy to the clipboard.";
    }
  }

  function quickAction(action: "test_route" | "create_rule", record: AccessRecordView) {
    if (target?.kind !== "proxy") return;
    store.requestProxyQuickAction(action, target.id, record.target, record.kind);
  }
</script>

<section class="log-drawer" class:open={store.logsOpen} aria-label="Logs">
  <div class="log-toolbar">
    <button
      class="log-toggle"
      aria-expanded={store.logsOpen}
      onclick={() => (store.logsOpen = !store.logsOpen)}
    >
      <span aria-hidden="true">{store.logsOpen ? "▾" : "▸"}</span> Logs{#if targetName}: {targetName}{/if}
    </button>

    {#if store.logsOpen}
      {#if isProxy}
        <select aria-label="Log kind" bind:value={kind}>
          <option value="all">All kinds</option>
          <option value="app">App log</option>
          <option value="access">Access (HTTP + SOCKS)</option>
          <option value="http">HTTP access</option>
          <option value="socks">SOCKS access</option>
        </select>
      {/if}
      <select aria-label="Log level" bind:value={filter}>
        <option value="all">All levels</option>
        <option value="error">Errors</option>
        <option value="warn">Warnings and up</option>
        <option value="info">Info and up</option>
        <option value="debug">Debug and up</option>
      </select>
      {#if isProxy}
        <select aria-label="Profile" bind:value={profileFilter}>
          <option value="">All profiles</option>
          {#each profiles as name (name)}<option value={name}>{name}</option>{/each}
        </select>
        <select aria-label="Rule" bind:value={ruleFilter}>
          <option value="">All rules</option>
          {#each rules as name (name)}<option value={name}>{name}</option>{/each}
        </select>
      {/if}
      <input type="search" placeholder="Search logs" aria-label="Search logs" bind:value={query} />
      <span class="log-count">{visibleRows.length} / {allRows.length}</span>
      <span class="spacer"></span>
      {#if error}<span class="log-error" role="alert">{error}</span>{/if}
      <button aria-pressed={paused} onclick={() => (paused = !paused)}>
        {paused ? "Resume" : "Pause"}
      </button>
      <label class="check">
        <input type="checkbox" bind:checked={autoscroll} /> Autoscroll
      </label>
      <button disabled={visibleRows.length === 0} onclick={copyLogs}>
        {copied ? "Copied" : "Copy"}
      </button>
      <button disabled={target === null} onclick={clearLogs}>Clear</button>
    {/if}
  </div>

  {#if store.logsOpen}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div
      class="log-viewport"
      role="log"
      tabindex="0"
      aria-label="Log lines"
      bind:this={viewport}
      bind:clientHeight={viewportHeight}
      onscroll={onScroll}
    >
      {#if visibleRows.length === 0}
        <p class="log-empty">
          {target === null ? "Select a saved Proxy or Tunnel to see its logs." : "No log lines."}
        </p>
      {:else}
        <div class="log-spacer" style:height="{visibleRows.length * ROW_HEIGHT}px">
          <div class="log-rows" style:transform="translateY({firstRow * ROW_HEIGHT}px)">
            {#each rows as row (row.key)}
              <div class="log-row {row.level}" style:height="{ROW_HEIGHT}px">
                <span class="log-time">{formatTime(row.time)}</span>
                {#if row.type === "text"}
                  <span class="log-text">{row.line.text}</span>
                {:else}
                  <span class="log-actions">
                    <button
                      type="button"
                      title={`Open the Route Tester with ${row.record.target}`}
                      onclick={() => quickAction("test_route", row.record)}
                    >Test route</button>
                    <button
                      type="button"
                      title={`Add a routing rule for ${row.record.target}`}
                      onclick={() => quickAction("create_rule", row.record)}
                    >Create rule for this host…</button>
                  </span>
                  <span class="log-text">{accessText(row.record)}</span>
                {/if}
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .log-actions {
    display: inline-flex;
    gap: 4px;
  }
  .log-actions button {
    font-size: 0.75em;
    line-height: 1;
    padding: 1px 6px;
  }
</style>
