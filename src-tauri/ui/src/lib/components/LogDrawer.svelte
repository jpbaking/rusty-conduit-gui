<script lang="ts">
  import { api, errorMessage } from "../api";
  import { formatTime, logLevel, passesLevel, type LogFilter } from "../format";
  import { store } from "../stores.svelte";
  import type { LogLine } from "../types";

  const ROW_HEIGHT = 20;
  const OVERSCAN = 10;
  const POLL_MS = 1_000;

  let lines = $state.raw<LogLine[]>([]);
  let filter = $state<LogFilter>("all");
  let query = $state("");
  let paused = $state(false);
  let autoscroll = $state(true);
  let error = $state<string | null>(null);
  let copied = $state(false);
  let scrollTop = $state(0);
  let viewportHeight = $state(0);
  let viewport = $state<HTMLDivElement | null>(null);
  /** Bumped on clear and session change, so a response already in flight is ignored. */
  let generation = 0;

  const sessionId = $derived(store.selected?.profile.id ?? null);

  const visibleLines = $derived.by(() => {
    const needle = query.trim().toLowerCase();
    return lines
      .map((line) => ({ line, level: logLevel(line.text) }))
      .filter(
        ({ line, level }) =>
          passesLevel(level, filter) && (!needle || line.text.toLowerCase().includes(needle)),
      );
  });

  const firstRow = $derived(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN));
  const lastRow = $derived(
    Math.min(
      visibleLines.length,
      Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN,
    ),
  );
  const rows = $derived(visibleLines.slice(firstRow, lastRow));

  // A different session starts with an empty view.
  $effect(() => {
    void sessionId;
    generation += 1;
    lines = [];
    error = null;
    autoscroll = true;
  });

  // Logs are fetched only while the drawer is open and not paused.
  $effect(() => {
    const id = sessionId;
    if (!store.logsOpen || paused || id === null) return;

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const load = async () => {
      const startedAt = generation;
      try {
        const next = await api.getSessionLogs(id);
        if (cancelled || startedAt !== generation) return;
        lines = next;
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
    void visibleLines.length;
    if (autoscroll && viewport) viewport.scrollTop = viewport.scrollHeight;
  });

  function onScroll() {
    if (!viewport) return;
    scrollTop = viewport.scrollTop;
    const distance = viewport.scrollHeight - viewport.clientHeight - viewport.scrollTop;
    autoscroll = distance < ROW_HEIGHT;
  }

  async function clearLogs() {
    if (sessionId === null) return;
    try {
      await api.clearSessionLogs(sessionId);
      generation += 1;
      lines = [];
      scrollTop = 0;
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function copyLogs() {
    const text = visibleLines
      .map(({ line }) => `${formatTime(line.timestamp)} ${line.text}`)
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 1_500);
    } catch {
      error = "Could not copy to the clipboard.";
    }
  }
</script>

<section class="log-drawer" class:open={store.logsOpen} aria-label="Session logs">
  <div class="log-toolbar">
    <button
      class="log-toggle"
      aria-expanded={store.logsOpen}
      onclick={() => (store.logsOpen = !store.logsOpen)}
    >
      <span aria-hidden="true">{store.logsOpen ? "▾" : "▸"}</span> Logs
    </button>

    {#if store.logsOpen}
      <select aria-label="Log level" bind:value={filter}>
        <option value="all">All levels</option>
        <option value="error">Errors</option>
        <option value="warn">Warnings and up</option>
        <option value="info">Info and up</option>
        <option value="debug">Debug and up</option>
      </select>
      <input type="search" placeholder="Search logs" aria-label="Search logs" bind:value={query} />
      <span class="log-count">{visibleLines.length} / {lines.length}</span>
      <span class="spacer"></span>
      {#if error}<span class="log-error" role="alert">{error}</span>{/if}
      <button aria-pressed={paused} onclick={() => (paused = !paused)}>
        {paused ? "Resume" : "Pause"}
      </button>
      <label class="check">
        <input type="checkbox" bind:checked={autoscroll} /> Autoscroll
      </label>
      <button disabled={visibleLines.length === 0} onclick={copyLogs}>
        {copied ? "Copied" : "Copy"}
      </button>
      <button disabled={sessionId === null} onclick={clearLogs}>Clear</button>
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
      {#if visibleLines.length === 0}
        <p class="log-empty">
          {sessionId === null ? "Select a saved session to see its logs." : "No log lines."}
        </p>
      {:else}
        <div class="log-spacer" style:height="{visibleLines.length * ROW_HEIGHT}px">
          <div class="log-rows" style:transform="translateY({firstRow * ROW_HEIGHT}px)">
            {#each rows as { line, level } (line.seq)}
              <div class="log-row {level}" style:height="{ROW_HEIGHT}px">
                <span class="log-time">{formatTime(line.timestamp)}</span>
                <span class="log-text">{line.text}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  {/if}
</section>
