<script lang="ts">
  import { onMount } from "svelte";
  import { api, errorMessage } from "../api";
  import type { AutostartStatus } from "../types";
  import BackupSection from "./BackupSection.svelte";
  import ForwardPresetsSection from "./ForwardPresetsSection.svelte";
  import VaultSettingsSection from "./VaultSettingsSection.svelte";

  let autostart = $state.raw<AutostartStatus | null>(null);
  let autostartBusy = $state(false);
  let autostartError = $state<string | null>(null);

  onMount(async () => {
    try {
      autostart = await api.getAutostart();
    } catch (error) {
      autostartError = errorMessage(error);
    }
  });

  async function toggleAutostart(event: Event & { currentTarget: HTMLInputElement }) {
    const input = event.currentTarget;
    const enabled = input.checked;
    autostartBusy = true;
    autostartError = null;
    try {
      autostart = await api.setAutostart(enabled);
    } catch (error) {
      autostartError = errorMessage(error);
    } finally {
      input.checked = autostart?.enabled ?? false;
      autostartBusy = false;
    }
  }
</script>

<main class="content">
  <h1>Settings</h1>
  <div class="settings">
    <section aria-labelledby="settings-startup">
      <h2 id="settings-startup">Startup</h2>
      <label class="check">
        <input
          type="checkbox"
          checked={autostart?.enabled ?? false}
          disabled={!autostart || autostartBusy}
          onchange={toggleAutostart}
        />
        Start at login, in the tray
      </label>
      {#if autostartError}<p class="reason" role="alert">{autostartError}</p>{/if}
    </section>

    <ForwardPresetsSection />

    <VaultSettingsSection />

    <BackupSection />
  </div>
</main>
