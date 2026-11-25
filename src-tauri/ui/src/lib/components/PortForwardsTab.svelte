<script lang="ts">
  import { hopTitle } from "../chain";
  import { isActive } from "../format";
  import { FLAG, PRESETS, findForwardFlags, forwardSpec, newForward, parseForwardFlags } from "../portForwards";
  import { store } from "../stores.svelte";
  import type { ForwardDirection, PortForward, SessionProfile } from "../types";
  import PortForwardRow from "./PortForwardRow.svelte";

  const uid = $props.id();
  const draft = $derived(store.draft as SessionProfile);
  const forwards = $derived(draft.port_forwards);
  const listenersError = $derived(store.draftErrors.listeners);
  const target = $derived.by(() => {
    const last = draft.hops[draft.hops.length - 1];
    return last ? hopTitle(last) : "the target";
  });
  const runtime = $derived(
    store.selected && isActive(store.selected.runtime.state) ? store.selected.runtime : null,
  );
  // A running session keeps the forwards it started with until it is restarted.
  const startedWith = $derived(
    new Map((store.selected?.profile.port_forwards ?? []).map((f) => [f.id, JSON.stringify(f)])),
  );
  // The only listener left cannot be switched off, as with the proxies.
  const proxiesOn = $derived(draft.forward.enabled || draft.reverse.enabled);
  const enabledCount = $derived(forwards.filter((f) => f.enabled).length);
  const lockedReason = $derived(
    !proxiesOn && enabledCount === 1 ? "This is the only listener: turn on another first" : undefined,
  );

  // `-L` / `-R` flags typed into the Advanced tab's extra arguments.
  const extraFlags = $derived(findForwardFlags(draft.openssh.extra_args));
  const movable = $derived(extraFlags.filter((m) => "forward" in m.result));

  let pasteText = $state("");
  let pasteErrors = $state<string[]>([]);
  let pasteOpen = $state(false);
  let presetValue = $state("");

  function setForwards(edit: (list: PortForward[]) => PortForward[]) {
    store.updateDraft((p) => ({ ...p, port_forwards: edit(p.port_forwards) }));
  }

  function update(id: string, patch: Partial<PortForward>) {
    setForwards((list) => list.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  }

  function remove(id: string) {
    setForwards((list) => list.filter((f) => f.id !== id));
  }

  function add(direction: ForwardDirection) {
    setForwards((list) => [...list, newForward(direction)]);
  }

  function addPreset(label: string) {
    const preset = PRESETS.find((p) => p.label === label);
    presetValue = "";
    if (!preset) return;
    const { label: _, ...fields } = preset;
    setForwards((list) => [...list, newForward(preset.direction, fields)]);
  }

  function addPasted() {
    const { forwards: parsed, errors } = parseForwardFlags(pasteText);
    pasteErrors = errors;
    if (parsed.length === 0 && errors.length === 0) {
      pasteErrors = ["No -L or -R flags found."];
      return;
    }
    if (parsed.length > 0) setForwards((list) => [...list, ...parsed]);
    if (errors.length === 0) {
      pasteText = "";
      pasteOpen = false;
    }
  }

  /** Moves the readable `-L` / `-R` flags out of the extra arguments and into this list. */
  function moveFromExtraArgs() {
    const taken = new Set(movable.flatMap((m) => m.indices));
    const moved = movable.flatMap((m) => ("forward" in m.result ? [m.result.forward] : []));
    store.updateDraft((p) => ({
      ...p,
      port_forwards: [...p.port_forwards, ...moved],
      openssh: { ...p.openssh, extra_args: p.openssh.extra_args.filter((_, i) => !taken.has(i)) },
    }));
  }
</script>

{#if listenersError}<p class="field-error">{listenersError}</p>{/if}

<section class="card" aria-labelledby={`${uid}-heading`}>
  <div class="card-head">
    <h2 id={`${uid}-heading`}>Port forwards <small class="muted">fixed ports, like ssh -L and -R, with either engine</small></h2>
  </div>
  <p class="muted forward-intro">
    <strong>Local (-L)</strong> listens on this computer and connects from {target}: use it to reach a
    database or web UI that only {target} can see. <strong>Remote (-R)</strong> listens on {target} and
    connects from this computer: use it to let {target} reach a service running here.
  </p>
  <div class="field-row">
    <button type="button" onclick={() => add("local")}>+ Local forward</button>
    <button type="button" onclick={() => add("remote")}>+ Remote forward</button>
    <label class="field-inline">
      <span class="sr-only">Add from a preset</span>
      <select bind:value={presetValue} onchange={(e) => addPreset(e.currentTarget.value)}>
        <option value="" disabled>Add from a preset…</option>
        {#each PRESETS as preset (preset.label)}
          <option value={preset.label}>{preset.label} ({FLAG[preset.direction]})</option>
        {/each}
      </select>
    </label>
    <button type="button" aria-expanded={pasteOpen} onclick={() => (pasteOpen = !pasteOpen)}>Paste ssh flags…</button>
  </div>

  {#if pasteOpen}
    <div class="field">
      <label class="field">
        ssh flags or a whole ssh command
        <textarea
          class="code-text"
          bind:value={pasteText}
          spellcheck="false"
          placeholder={"-L 15432:db.internal:5432 -R 8000:localhost:3000"}
        ></textarea>
      </label>
      <div class="field-row">
        <button type="button" class="primary" disabled={!pasteText.trim()} onclick={addPasted}>Add forwards</button>
        <button type="button" onclick={() => ((pasteOpen = false), (pasteErrors = []))}>Cancel</button>
      </div>
      {#each pasteErrors as error (error)}<p class="field-error">{error}</p>{/each}
    </div>
  {/if}

  {#if movable.length > 0}
    <div class="warning config-line">
      <span>
        The Advanced tab's extra arguments have
        {#each movable as match, index (match.indices[0])}{#if "forward" in match.result}{index > 0 ? ", " : " "}<code>{FLAG[match.result.forward.direction]} {forwardSpec(match.result.forward)}</code>{/if}{/each}.
        Those only work with the OpenSSH engine. Move them here to run them with either engine.
      </span>
      <button type="button" onclick={moveFromExtraArgs}>Move here</button>
    </div>
  {/if}
</section>

{#if forwards.length === 0}
  <p class="muted">No port forwards. Add one above.</p>
{/if}

{#each forwards as forward (forward.id)}
  <PortForwardRow
    {forward}
    {target}
    running={runtime !== null}
    applied={startedWith.get(forward.id) === JSON.stringify(forward)}
    status={runtime?.port_forwards.find((s) => s.id === forward.id)}
    lockedReason={forward.enabled ? lockedReason : undefined}
    onChange={(patch) => update(forward.id, patch)}
    onRemove={() => remove(forward.id)}
  />
{/each}
