<script lang="ts">
  interface Props {
    label: string;
    value: number;
    error?: string;
    /** Receives `NaN` while the field is empty, which validation then reports. */
    onValue: (port: number) => void;
  }

  let { label, value, error, onValue }: Props = $props();

  const uid = $props.id();
</script>

<div class="field port">
  <label class="field">
    {label}
    <input
      type="number"
      min="0"
      max="65535"
      value={Number.isNaN(value) ? "" : value}
      aria-invalid={!!error}
      aria-describedby={error ? `${uid}-error` : undefined}
      oninput={(e) => {
        const text = e.currentTarget.value;
        onValue(text === "" ? Number.NaN : Number(text));
      }}
    />
  </label>
  {#if error}<span id={`${uid}-error`} class="field-error">{error}</span>{/if}
</div>
