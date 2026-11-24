<script lang="ts" module>
  export interface MenuItem {
    label: string;
    danger?: boolean;
    disabled?: boolean;
    /** Shown as a tooltip, for example why the item is disabled. */
    title?: string;
    onSelect: () => void;
  }
</script>

<script lang="ts">
  import { tick } from "svelte";

  interface Props {
    /** Viewport coordinates of the pointer, or of the element the menu was opened for. */
    x: number;
    y: number;
    label: string;
    items: MenuItem[];
    /** Called after an item is chosen and whenever the menu is dismissed. */
    onClose: (restoreFocus: boolean) => void;
  }

  let { x, y, label, items, onClose }: Props = $props();

  const EDGE = 6;

  let menu = $state<HTMLDivElement>();
  let left = $state(0);
  let top = $state(0);

  // Keep the whole menu on screen, flipping it left or up near an edge.
  $effect(() => {
    if (!menu) return;
    const { width, height } = menu.getBoundingClientRect();
    left = Math.max(EDGE, Math.min(x, window.innerWidth - width - EDGE));
    top = Math.max(EDGE, Math.min(y, window.innerHeight - height - EDGE));
    void tick().then(() => buttons()[0]?.focus());
  });

  function buttons(): HTMLButtonElement[] {
    return [...(menu?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? [])];
  }

  function choose(item: MenuItem) {
    if (item.disabled) return;
    onClose(false);
    item.onSelect();
  }

  function onKeydown(event: KeyboardEvent) {
    const list = buttons();
    const at = list.indexOf(document.activeElement as HTMLButtonElement);
    const moves: Record<string, number> = {
      ArrowDown: (at + 1) % list.length,
      ArrowUp: (at - 1 + list.length) % list.length,
      Home: 0,
      End: list.length - 1,
    };
    if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      onClose(true);
    } else if (event.key in moves) {
      event.preventDefault();
      list[moves[event.key] ?? 0]?.focus();
    }
  }

  function onWindowPointer(event: PointerEvent) {
    if (menu && !menu.contains(event.target as Node)) onClose(false);
  }
</script>

<svelte:window
  onpointerdown={onWindowPointer}
  onblur={() => onClose(false)}
  onresize={() => onClose(false)}
  onwheel={() => onClose(false)}
/>

<div
  bind:this={menu}
  class="context-menu"
  role="menu"
  aria-label={label}
  tabindex="-1"
  style:left="{left}px"
  style:top="{top}px"
  onkeydown={onKeydown}
>
  {#each items as item (item.label)}
    <button
      type="button"
      role="menuitem"
      class:danger={item.danger}
      disabled={item.disabled}
      title={item.title}
      onclick={() => choose(item)}
    >
      {item.label}
    </button>
  {/each}
</div>
