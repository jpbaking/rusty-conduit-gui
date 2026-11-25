<script lang="ts">
  import { blankPreset, presetSummary } from "../portForwards";
  import { store } from "../stores.svelte";
  import type { ForwardDirection, ForwardPreset } from "../types";
  import { presetErrors } from "../validate";
  import PortField from "./PortField.svelte";

  const uid = $props.id();

  /** The preset being edited or created, or `null`. */
  let draft = $state<ForwardPreset | null>(null);
  let saving = $state(false);
  /** Errors show once the user has tried to save, so a new form does not open in red. */
  let attempted = $state(false);
  const errors = $derived(draft && attempted ? presetErrors(draft) : {});
  const isNew = $derived(draft !== null && !store.presets.some((p) => p.id === draft?.id));

  function edit(preset: ForwardPreset) {
    draft = { ...preset };
    attempted = false;
  }

  function create() {
    draft = blankPreset();
    attempted = false;
  }

  function set(patch: Partial<ForwardPreset>) {
    if (draft) draft = { ...draft, ...patch };
  }

  function setDirection(direction: ForwardDirection) {
    if (!draft || draft.direction === direction) return;
    const patch: Partial<ForwardPreset> = { direction };
    if (direction === "remote" && !draft.dest_host.trim()) patch.dest_host = "localhost";
    set(patch);
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!draft || saving) return;
    attempted = true;
    if (Object.keys(presetErrors(draft)).length > 0) return;
    saving = true;
    try {
      if (await store.saveForwardPreset(draft)) draft = null;
    } finally {
      saving = false;
    }
  }

  async function remove(preset: ForwardPreset) {
    if (draft?.id === preset.id) draft = null;
    await store.deleteForwardPreset(preset.id);
  }
</script>

<section aria-labelledby="settings-presets">
  <h2 id="settings-presets">Port forward presets</h2>
  <p class="muted">
    Offered by "Add from a preset…" on a session's Ports tab. Adding one copies its values, so
    editing a preset here does not change forwards already added. Leave the destination host
    empty to choose it for each session.
  </p>

  {#if store.presets.length === 0}
    <p class="muted">No presets.</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Forward</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each store.presets as preset (preset.id)}
            <tr>
              <td><strong>{preset.name}</strong></td>
              <td><code>{presetSummary(preset)}</code></td>
              <td>
                <div class="row-actions">
                  <button type="button" onclick={() => edit(preset)}>Edit</button>
                  <button type="button" class="danger" onclick={() => remove(preset)}>Delete</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if draft}
    <form class="preset-form" onsubmit={save} aria-labelledby={`${uid}-form-heading`}>
      <h3 id={`${uid}-form-heading`}>{isNew ? "New preset" : `Edit ${draft.name || "preset"}`}</h3>
      <div class="field-row">
        <div class="segmented" role="group" aria-label="Direction">
          <button type="button" aria-pressed={draft.direction === "local"} onclick={() => setDirection("local")}>
            Local -L
          </button>
          <button type="button" aria-pressed={draft.direction === "remote"} onclick={() => setDirection("remote")}>
            Remote -R
          </button>
        </div>
        <div class="field grow">
          <label class="field">
            Name
            <input value={draft.name} aria-invalid={!!errors.name} oninput={(e) => set({ name: e.currentTarget.value })} />
          </label>
          {#if errors.name}<span class="field-error">{errors.name}</span>{/if}
        </div>
      </div>
      <div class="field-row">
        <div class="field grow">
          <label class="field">
            <span>Listen address <small class="muted">empty is 127.0.0.1</small></span>
            <input
              value={draft.bind ?? ""}
              placeholder="127.0.0.1"
              spellcheck="false"
              aria-invalid={!!errors.bind}
              oninput={(e) => set({ bind: e.currentTarget.value.trim() || null })}
            />
          </label>
          {#if errors.bind}<span class="field-error">{errors.bind}</span>{/if}
        </div>
        <PortField label="Port" value={draft.port} error={errors.port} onValue={(port) => set({ port })} />
      </div>
      <div class="field-row">
        <div class="field grow">
          <label class="field">
            <span>Destination host <small class="muted">empty to choose per session</small></span>
            <input
              value={draft.dest_host}
              spellcheck="false"
              aria-invalid={!!errors.dest_host}
              oninput={(e) => set({ dest_host: e.currentTarget.value })}
            />
          </label>
          {#if errors.dest_host}<span class="field-error">{errors.dest_host}</span>{/if}
        </div>
        <PortField label="Port" value={draft.dest_port} error={errors.dest_port} onValue={(dest_port) => set({ dest_port })} />
      </div>
      <div class="field-row">
        <button type="submit" class="primary" disabled={saving}>{saving ? "Saving…" : "Save preset"}</button>
        <button type="button" onclick={() => (draft = null)}>Cancel</button>
      </div>
    </form>
  {:else}
    <div class="field-row">
      <button type="button" class="primary" onclick={create}>+ New preset</button>
      <button type="button" onclick={() => store.restoreForwardPresets()}>Restore built-in presets</button>
    </div>
  {/if}
</section>
