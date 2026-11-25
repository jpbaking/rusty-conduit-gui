<script lang="ts">
  import { PASSWORD_RULES } from "../password";

  interface Props {
    password: string;
    id?: string;
  }

  let { password, id }: Props = $props();
</script>

<ul class="password-rules" {id} aria-label="Password requirements">
  {#each PASSWORD_RULES as rule (rule.label)}
    {@const met = rule.met(password)}
    <li class:met>
      <span aria-hidden="true">{met ? "✓" : "•"}</span>
      {rule.label}<span class="sr-only">{met ? ", met" : ", not met"}</span>
    </li>
  {/each}
</ul>
