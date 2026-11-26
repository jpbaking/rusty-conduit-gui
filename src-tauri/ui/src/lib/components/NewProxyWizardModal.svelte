<script lang="ts">
  import { store, type ProxyPreset } from "../stores.svelte";
  import ModalDialog from "./ModalDialog.svelte";

  interface Props {
    onClose: () => void;
  }

  let { onClose }: Props = $props();

  const uid = $props.id();

  const PRESETS: { preset: ProxyPreset; title: string; binary: string; summary: string }[] = [
    {
      preset: "direct",
      title: "Direct",
      binary: "rusty-conduit",
      summary: "A local HTTP and SOCKS proxy that connects straight out. No upstreams, no rules.",
    },
    {
      preset: "tunnel",
      title: "Through a tunnel",
      binary: "rusty-conduit-ssh",
      summary: "Sends everything through an SSH Tunnel by default.",
    },
    {
      preset: "switch",
      title: "Auto Switch",
      binary: "rusty-conduit-switch",
      summary: "Starts direct; add rules that pick a tunnel or upstream per host, port, or time.",
    },
  ];

  let preset = $state<ProxyPreset>("direct");
  let tunnelId = $state<string>(store.tunnels[0]?.profile.id ?? "");

  const needsTunnel = $derived(preset === "tunnel");
  const noTunnels = $derived(store.tunnels.length === 0);
  const canCreate = $derived(!needsTunnel || tunnelId !== "");

  function create() {
    if (!canCreate) return;
    store.newProxyFromPreset(preset, preset === "direct" || tunnelId === "" ? null : tunnelId);
    onClose();
  }

  function createTunnelFirst() {
    store.newTunnel();
    onClose();
  }
</script>

<ModalDialog title="New Proxy" onDismiss={onClose}>
  <fieldset class="wizard-presets">
    <legend>How should this proxy reach the internet?</legend>
    {#each PRESETS as option (option.preset)}
      <label class="wizard-option" class:selected={preset === option.preset}>
        <input
          type="radio"
          name={`${uid}-preset`}
          value={option.preset}
          checked={preset === option.preset}
          onchange={() => (preset = option.preset)}
        />
        <span class="wizard-text">
          <strong>{option.title}</strong>
          <small class="muted"><code>{option.binary}</code></small>
          <span>{option.summary}</span>
        </span>
      </label>
    {/each}
  </fieldset>

  {#if preset !== "direct"}
    {#if noTunnels}
      <p class={needsTunnel ? "warning" : "muted"}>
        {needsTunnel
          ? "There is no Tunnel yet. Create one first, then make this proxy."
          : "There is no Tunnel yet. Rules can still use direct, block, or an upstream you add."}
      </p>
      <button type="button" class="link-button" onclick={createTunnelFirst}>+ Create a Tunnel</button>
    {:else}
      <label class="field">
        Tunnel
        <select bind:value={tunnelId}>
          {#if !needsTunnel}<option value="">None for now</option>{/if}
          {#each store.tunnels as tunnel (tunnel.profile.id)}
            <option value={tunnel.profile.id}>{tunnel.profile.name}</option>
          {/each}
        </select>
      </label>
      <button type="button" class="link-button" onclick={createTunnelFirst}>Or create a new Tunnel first</button>
    {/if}
  {/if}

  {#snippet actions()}
    <button onclick={onClose}>Cancel</button>
    <button class="primary" disabled={!canCreate} onclick={create}>Create</button>
  {/snippet}
</ModalDialog>

<style>
  .wizard-presets {
    border: none;
    margin: 0 0 0.75rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .wizard-presets legend {
    margin-bottom: 0.5rem;
  }
  .wizard-option {
    display: flex;
    gap: 0.6rem;
    align-items: flex-start;
    padding: 0.5rem 0.6rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
  }
  .wizard-option.selected {
    background: var(--surface-2);
  }
  .wizard-text {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
</style>
