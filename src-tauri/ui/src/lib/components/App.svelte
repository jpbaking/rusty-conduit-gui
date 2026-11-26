<script lang="ts">
  import { onMount } from "svelte";
  import { store } from "../stores.svelte";
  import HeaderBar from "./HeaderBar.svelte";
  import HostKeyModal from "./HostKeyModal.svelte";
  import HostProfilesView from "./HostProfilesView.svelte";
  import KeyVaultView from "./KeyVaultView.svelte";
  import LogDrawer from "./LogDrawer.svelte";
  import ModalDialog from "./ModalDialog.svelte";
  import NewProxyWizardModal from "./NewProxyWizardModal.svelte";
  import ProfileLibraryView from "./ProfileLibraryView.svelte";
  import ProxyEditor from "./ProxyEditor.svelte";
  import SessionEditor from "./SessionEditor.svelte";
  import SettingsView from "./SettingsView.svelte";
  import Sidebar from "./Sidebar.svelte";
  import TunnelEditor from "./TunnelEditor.svelte";
  import VaultUnlockModal from "./VaultUnlockModal.svelte";
  import type { PendingHostKey } from "../stores.svelte";

  let copyFailed = $state(false);
  let wizardOpen = $state(false);

  /** A running Tunnel waiting for a host-key answer: the selected one first. */
  const tunnelHostKey = $derived.by<PendingHostKey | null>(() => {
    const waiting = store.tunnels.filter((t) => t.snapshot.state.state === "awaiting_host_key");
    const tunnel = waiting.find((t) => t.profile.id === store.selectedTunnelId) ?? waiting[0];
    if (!tunnel || tunnel.snapshot.state.state !== "awaiting_host_key") return null;
    const { state: _state, ...prompt } = tunnel.snapshot.state;
    return { sessionId: tunnel.profile.id, sessionName: tunnel.profile.name, prompt, source: "session" };
  });

  onMount(() => {
    // The sidebar lists Proxies and Tunnels; the v1 session editor only opens for a session's logs.
    if (store.view === "sessions") store.navigate("proxy");
    void store.start();
    return () => store.stop();
  });

  function selectOnFocus(node: HTMLInputElement) {
    node.focus();
    node.select();
  }

  async function copyFallbackUrl() {
    if (!store.clipboardUrl) return;
    try {
      await navigator.clipboard.writeText(store.clipboardUrl);
      closeClipboard();
    } catch {
      copyFailed = true;
    }
  }

  function closeClipboard() {
    store.clipboardUrl = null;
    copyFailed = false;
  }
</script>

<div class="shell">
  <Sidebar onNewProxy={() => (wizardOpen = true)} />

  <div class="workspace">
    {#if !store.trayAvailable && !store.trayBannerDismissed}
      <div class="banner info" role="status">
        <span>No system tray was found. Closing this window will ask whether to keep tunnels running.</span>
        <button onclick={() => (store.trayBannerDismissed = true)}>Dismiss</button>
      </div>
    {/if}
    {#if store.migrationNotice}
      <div
        class={store.migrationNotice.is_warning ? "banner error" : "banner info"}
        role={store.migrationNotice.is_warning ? "alert" : "status"}
      >
        <span>{store.migrationNotice.message}</span>
        <button onclick={() => (store.migrationNotice = null)}>Dismiss</button>
      </div>
    {/if}
    {#if store.notice}
      <div class="banner error" role="alert">
        <span>{store.notice}</span>
        <button onclick={() => (store.notice = null)}>Dismiss</button>
      </div>
    {/if}
    {#if store.view === "proxy"}
      {#if !store.loaded}
        <main class="content"><p class="muted">Loading…</p></main>
      {:else if !store.proxyDraft}
        <main class="content">
          <div class="empty-state">
            <h2>No proxy selected</h2>
            <p class="muted">Create a proxy to get started.</p>
            <button class="primary" onclick={() => (wizardOpen = true)}>+ New Proxy</button>
          </div>
        </main>
      {:else}
        {#key store.selectedProxyId}
          <ProxyEditor />
        {/key}
      {/if}
    {:else if store.view === "tunnel"}
      {#if !store.loaded}
        <main class="content"><p class="muted">Loading…</p></main>
      {:else if !store.tunnelDraft}
        <main class="content">
          <div class="empty-state">
            <h2>No tunnel selected</h2>
            <p class="muted">A Tunnel is an SSH connection that Proxies can route through.</p>
            <button class="primary" onclick={() => store.newTunnel()}>+ New Tunnel</button>
          </div>
        </main>
      {:else}
        {#key store.selectedTunnelId}
          <TunnelEditor />
        {/key}
      {/if}
    {:else if store.view === "sessions"}
      <HeaderBar />
      <main class="content">
        {#if !store.loaded}
          <p class="muted">Loading…</p>
        {:else if !store.draft}
          <div class="empty-state">
            <h2>No session selected</h2>
            <p class="muted">Create a session to get started.</p>
            <button class="primary" onclick={() => store.newSession()}>+ New Session</button>
          </div>
        {:else}
          <SessionEditor />
        {/if}
      </main>
    {:else if store.view === "hosts"}
      <HostProfilesView />
    {:else if store.view === "profileLibrary"}
      <ProfileLibraryView />
    {:else if store.view === "keys" || store.view === "vault"}
      <KeyVaultView />
    {:else}
      <SettingsView />
    {/if}

    <LogDrawer />
  </div>
</div>

{#if store.showUnlock}
  <VaultUnlockModal />
{:else if store.pendingHostKey ?? store.testHostKey}
  {@const pending = (store.pendingHostKey ?? store.testHostKey)!}
  {#key `${pending.source}:${pending.sessionId}:${pending.prompt.hop_id}:${pending.prompt.sha256}`}
    <HostKeyModal {pending} />
  {/key}
{:else if tunnelHostKey}
  {#key `tunnel:${tunnelHostKey.sessionId}:${tunnelHostKey.prompt.hop_id}:${tunnelHostKey.prompt.sha256}`}
    <HostKeyModal pending={tunnelHostKey} kind="tunnel" />
  {/key}
{/if}

{#if wizardOpen}
  <NewProxyWizardModal onClose={() => (wizardOpen = false)} />
{/if}

{#if store.clipboardUrl}
  <ModalDialog title="Copy proxy URL" onDismiss={closeClipboard}>
    <p>The tray could not write to the clipboard. Copy this URL instead.</p>
    <input class="url-field" readonly aria-label="Proxy URL" value={store.clipboardUrl} use:selectOnFocus />
    {#if copyFailed}<p class="reason" role="alert">Copy failed. Press Ctrl+C or ⌘C.</p>{/if}
    {#snippet actions()}
      <button onclick={closeClipboard}>Close</button>
      <button class="primary" onclick={copyFallbackUrl}>Copy</button>
    {/snippet}
  </ModalDialog>
{/if}

{#if store.closePrompt === "close"}
  <ModalDialog title="Close window" onDismiss={() => store.resolveClose("cancel")}>
    <p>No system tray is available. Keep tunnels running in the background, or quit?</p>
    {#snippet actions()}
      <button onclick={() => store.resolveClose("cancel")}>Cancel</button>
      <button class="danger" onclick={() => store.resolveClose("quit")}>Quit</button>
      <button class="primary" onclick={() => store.resolveClose("keep_running")}>Keep running</button>
    {/snippet}
  </ModalDialog>
{:else if store.closePrompt === "quit"}
  <ModalDialog title="Quit" onDismiss={() => store.resolveClose("cancel")}>
    <p>Sessions are still active. Quitting stops all tunnels.</p>
    {#snippet actions()}
      <button onclick={() => store.resolveClose("cancel")}>Cancel</button>
      <button class="danger" onclick={() => store.resolveClose("quit")}>Quit</button>
    {/snippet}
  </ModalDialog>
{/if}
