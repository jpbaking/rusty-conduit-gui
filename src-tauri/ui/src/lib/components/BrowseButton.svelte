<script lang="ts">
  import { errorMessage } from "../api";
  import { chooseOpenPath, chooseSavePath, type FileFilter } from "../fileDialog";

  interface Props {
    /** `save` asks where to write a new file; `open` picks an existing one. */
    mode: "open" | "save";
    /** The dialog's title, such as "Save backup". */
    title: string;
    defaultPath?: string;
    filters?: FileFilter[];
    disabled?: boolean;
    onPick: (path: string) => void;
  }

  let { mode, title, defaultPath, filters, disabled = false, onPick }: Props = $props();

  let busy = $state(false);
  let error = $state<string | null>(null);

  async function browse() {
    busy = true;
    error = null;
    try {
      const options = { title, defaultPath: defaultPath || undefined, filters };
      const path = mode === "save" ? await chooseSavePath(options) : await chooseOpenPath(options);
      if (path) onPick(path);
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
</script>

<button type="button" disabled={disabled || busy} onclick={browse} aria-label={`${title}: browse`}>Browse…</button>
{#if error}<span class="field-error" role="alert">{error}</span>{/if}
