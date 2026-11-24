<script lang="ts">
  interface Props {
    label: string;
    value: number;
    min?: number;
    hint?: string;
    error?: string;
    /** Receives `NaN` while the field is empty, which validation then reports. */
    onValue: (value: number) => void;
  }

  let { label, value, min = 0, hint, error, onValue }: Props = $props();

  const uid = $props.id();
</script>

<div class="field grow">
  <label class="field">
    {label}
    <input
      type="number"
      {min}
      step="1"
      value={Number.isNaN(value) ? "" : value}
      aria-invalid={!!error}
      aria-describedby={error ? `${uid}-error` : hint ? `${uid}-hint` : undefined}
      oninput={(e) => {
        const text = e.currentTarget.value;
        onValue(text === "" ? Number.NaN : Number(text));
      }}
    />
  </label>
  {#if error}
    <span id={`${uid}-error`} class="field-error">{error}</span>
  {:else if hint}
    <small id={`${uid}-hint`} class="muted">{hint}</small>
  {/if}
</div>
