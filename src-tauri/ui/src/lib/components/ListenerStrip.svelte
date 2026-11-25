<script lang="ts">
  import { hopTitle } from "../chain";
  import { isActive, proxyUrls, type ProxyUrl } from "../format";
  import { store } from "../stores.svelte";
  import type { ListenerInfo } from "../types";

  // A stopped session's last listeners are no longer bound, so show none for it.
  const runtime = $derived(
    store.selected && isActive(store.selected.runtime.state) ? store.selected.runtime : null,
  );
  const local = $derived(urlsOf(runtime?.listeners));
  const remote = $derived(urlsOf(runtime?.remote_listeners));
  const forwards = $derived(runtime?.port_forwards ?? []);
  const names = $derived(
    new Map((store.selected?.profile.port_forwards ?? []).map((f) => [f.id, f.name.trim()])),
  );
  const target = $derived.by(() => {
    const hops = store.selected?.profile.hops ?? [];
    const last = hops[hops.length - 1];
    return last ? hopTitle(last) : "the target";
  });

  let copied = $state<string | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;

  function urlsOf(listeners: ListenerInfo[] | undefined): ProxyUrl[] {
    return (listeners ?? []).flatMap(proxyUrls);
  }

  async function copy(url: string) {
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // The tray's fallback dialog lets the user copy by hand.
      store.clipboardUrl = url;
      return;
    }
    copied = url;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = null), 1500);
  }
</script>

{#snippet card(title: string, where: string, urls: ProxyUrl[])}
  <section class="listener-card" aria-label="{title} listeners">
    <header>
      <span class="ok" aria-hidden="true">●</span>
      <strong>{title}</strong>
      <small class="muted">{where}</small>
    </header>
    <ul>
      {#each urls as { label, url } (url)}
        <li>
          <span class="listener-label">{label}</span>
          <code>{url}</code>
          <button class="icon" title="Copy {url}" aria-label="Copy {title} {label} proxy URL" onclick={() => copy(url)}>
            {copied === url ? "✓" : "⧉"}
          </button>
        </li>
      {/each}
    </ul>
  </section>
{/snippet}

{#snippet forwardCard()}
  <section class="listener-card forward-listeners" class:has-error={forwards.some((f) => f.error)} aria-label="Port forwards">
    <header>
      <span class="ok" aria-hidden="true">●</span>
      <strong>Port forwards</strong>
    </header>
    <ul>
      {#each forwards as forward (forward.id)}
        <li title={forward.error ?? undefined}>
          <span class="listener-label">{forward.direction === "local" ? "-L" : "-R"}</span>
          {#if forward.error}<span class="alert" aria-label="Failed">⚠</span>{/if}
          <code>{forward.listen}</code>
          <span class="muted" aria-hidden="true">→</span>
          <code>{forward.destination}</code>
          {#if names.get(forward.id)}<small class="muted">{names.get(forward.id)}</small>{/if}
          {#if forward.error}
            <span class="sr-only">failed: {forward.error}</span>
          {:else if forward.direction === "local"}
            <button class="icon" title="Copy {forward.listen}" aria-label="Copy forward address {forward.listen}" onclick={() => copy(forward.listen)}>
              {copied === forward.listen ? "✓" : "⧉"}
            </button>
          {/if}
        </li>
      {/each}
    </ul>
  </section>
{/snippet}

{#if local.length > 0 || remote.length > 0 || forwards.length > 0}
  <div class="listener-cards">
    {#if local.length > 0}{@render card("Local", "on this computer", local)}{/if}
    {#if remote.length > 0}{@render card("Remote", `on ${target}`, remote)}{/if}
    {#if forwards.length > 0}{@render forwardCard()}{/if}
  </div>
  <p class="sr-only" role="status">{copied ? "Copied." : ""}</p>
{/if}
