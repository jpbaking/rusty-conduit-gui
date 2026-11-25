// A hover and focus tooltip drawn in a fixed layer, so a scrolling or clipped container cannot
// cut it off. The OS `title` tooltip only appears after a long, fixed delay.

const SHOW_DELAY_MS = 150;
const GAP_PX = 6;
const MARGIN_PX = 8;

/**
 * Svelte action: `<span use:tooltip={"text"}>`. Newlines in the text start new lines. An empty
 * text shows nothing. The text is also given to screen readers through `aria-description`.
 */
export function tooltip(node: HTMLElement, text: string | null | undefined) {
  let current = text ?? "";
  let tip: HTMLDivElement | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;

  function place() {
    if (!tip) return;
    const anchor = node.getBoundingClientRect();
    const box = tip.getBoundingClientRect();
    const left = Math.min(Math.max(anchor.left, MARGIN_PX), window.innerWidth - box.width - MARGIN_PX);
    const below = anchor.bottom + GAP_PX;
    const top = below + box.height > window.innerHeight - MARGIN_PX ? anchor.top - GAP_PX - box.height : below;
    tip.style.left = `${Math.max(left, MARGIN_PX)}px`;
    tip.style.top = `${Math.max(top, MARGIN_PX)}px`;
  }

  function show() {
    clearTimeout(timer);
    if (!current || tip) return;
    timer = setTimeout(() => {
      tip = document.createElement("div");
      tip.className = "floating-tip";
      tip.setAttribute("role", "tooltip");
      tip.textContent = current;
      document.body.append(tip);
      place();
    }, SHOW_DELAY_MS);
  }

  function hide() {
    clearTimeout(timer);
    tip?.remove();
    tip = null;
  }

  function onKey(event: KeyboardEvent) {
    if (event.key === "Escape") hide();
  }

  function describe() {
    if (current) node.setAttribute("aria-description", current);
    else node.removeAttribute("aria-description");
  }

  describe();
  node.addEventListener("mouseenter", show);
  node.addEventListener("mouseleave", hide);
  node.addEventListener("focus", show);
  node.addEventListener("blur", hide);
  node.addEventListener("keydown", onKey);

  return {
    update(next: string | null | undefined) {
      current = next ?? "";
      describe();
      if (tip) {
        if (current) {
          tip.textContent = current;
          place();
        } else hide();
      }
    },
    destroy() {
      hide();
      node.removeEventListener("mouseenter", show);
      node.removeEventListener("mouseleave", hide);
      node.removeEventListener("focus", show);
      node.removeEventListener("blur", hide);
      node.removeEventListener("keydown", onKey);
    },
  };
}
