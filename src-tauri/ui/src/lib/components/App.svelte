<script lang="ts">
  import { onMount } from "svelte";
  import { store } from "../stores.svelte";
  import HeaderBar from "./HeaderBar.svelte";
  import HostKeyModal from "./HostKeyModal.svelte";
  import HostProfilesView from "./HostProfilesView.svelte";
  import KeyVaultView from "./KeyVaultView.svelte";
  import LogDrawer from "./LogDrawer.svelte";
  import ModalDialog from "./ModalDialog.svelte";
  import SessionEditor from "./SessionEditor.svelte";
  import SettingsView from "./SettingsView.svelte";
  import Sidebar from "./Sidebar.svelte";
  import VaultUnlockModal from "./VaultUnlockModal.svelte";

  let copyFailed = $state(false);

  onMount(() => {
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
  <Sidebar />

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
    {#if store.view === "sessions"}
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
    {:else if store.view === "keys"}
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
