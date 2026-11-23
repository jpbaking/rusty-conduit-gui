<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    title: string;
    /** Called for Escape. The parent decides what dismissing means. */
    onDismiss: () => void;
    children: Snippet;
    actions: Snippet;
  }

  let { title, onDismiss, children, actions }: Props = $props();
  // Modals can stack, so each needs its own title id.
  const uid = $props.id();
  const titleId = `${uid}-title`;
  let dialog: HTMLDialogElement;

  // `showModal` traps focus and restores it when the dialog closes.
  $effect(() => {
    dialog.showModal();
    return () => dialog.close();
  });

  function onCancel(event: Event) {
    event.preventDefault();
    onDismiss();
  }
</script>

<dialog bind:this={dialog} class="modal" aria-labelledby={titleId} oncancel={onCancel}>
  <h2 id={titleId}>{title}</h2>
  <div class="modal-body">{@render children()}</div>
  <div class="modal-actions">{@render actions()}</div>
</dialog>
