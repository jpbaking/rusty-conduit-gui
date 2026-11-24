<script lang="ts">
  interface Props {
    /** What the switch turns on and off, for screen readers, such as "Forward proxy". */
    name: string;
    on: boolean;
    /** Set when this is the only proxy on: it cannot be turned off, and this tooltip says why. */
    lockedReason?: string;
    onToggle: (on: boolean) => void;
  }

  let { name, on, lockedReason, onToggle }: Props = $props();

  const uid = $props.id();
  const locked = $derived(on && !!lockedReason);
</script>

<!-- A CSS tooltip, not `title`: the OS shows `title` only after a long, fixed delay. -->
<label class="check proxy-switch" data-tip={locked ? lockedReason : undefined}>
  <input
    type="checkbox"
    role="switch"
    aria-label={`${name} on`}
    aria-describedby={locked ? `${uid}-reason` : undefined}
    checked={on}
    disabled={locked}
    onchange={(e) => onToggle(e.currentTarget.checked)}
  />
  {on ? "On" : "Off"}
  {#if locked}<span id={`${uid}-reason`} class="sr-only">{lockedReason}</span>{/if}
</label>
