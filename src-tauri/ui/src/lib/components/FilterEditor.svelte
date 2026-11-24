<script lang="ts">
  import { api, errorMessage } from "../api";
  import type { FilterTestResult } from "../types";
  import { filterRuleError, type FieldErrors } from "../validate";

  type Mode = "off" | "allow" | "block";

  interface Props {
    title: string;
    scope: "forward" | "reverse";
    allow: string[];
    block: string[];
    errors: FieldErrors;
    onChange: (allow: string[], block: string[]) => void;
  }

  let { title, scope, allow, block, errors, onChange }: Props = $props();

  const MODES: { value: Mode; label: string }[] = [
    { value: "off", label: "Disabled" },
    { value: "allow", label: "Allowlist" },
    { value: "block", label: "Blocklist" },
  ];

  const uid = $props.id();

  /** Which mode to show while both lists are empty. */
  let picked = $state<Mode>("off");
  /** Rules cleared by a mode switch, so switching back in this editor restores them. */
  let stash: { allow: string[]; block: string[] } = { allow: [], block: [] };

  const mode = $derived<Mode>(allow.length > 0 ? "allow" : block.length > 0 ? "block" : picked);
  const rules = $derived(mode === "allow" ? allow : mode === "block" ? block : []);
  const conflict = $derived(errors[`filters.${scope}.conflict`]);

  let ruleText = $state("");
  let ruleError = $state<string | null>(null);
  let bulkText = $state("");
  let bulkNote = $state<string | null>(null);
  let target = $state("");
  let testing = $state(false);
  let result = $state.raw<FilterTestResult | null>(null);
  let testError = $state<string | null>(null);
  let testRun = 0;

  const ruleKey = (rule: string) => rule.trim().toLowerCase();

  function setRules(next: string[]) {
    if (mode === "allow") onChange(next, block);
    else if (mode === "block") onChange(allow, next);
  }

  function setMode(next: Mode) {
    stash = {
      allow: allow.length > 0 || mode === "allow" ? allow : stash.allow,
      block: block.length > 0 || mode === "block" ? block : stash.block,
    };
    picked = next;
    ruleError = null;
    bulkNote = null;
    if (next === "off") onChange([], []);
    else if (next === "allow") onChange(allow.length > 0 ? allow : stash.allow, []);
    else onChange([], block.length > 0 ? block : stash.block);
  }

  function addRule(event: SubmitEvent) {
    event.preventDefault();
    const rule = ruleText.trim();
    if (!rule) return;
    ruleError = filterRuleError(rule);
    if (ruleError) return;
    if (rules.some((existing) => ruleKey(existing) === ruleKey(rule))) {
      ruleError = "That rule is already in the list.";
      return;
    }
    picked = mode;
    setRules([...rules, rule]);
    ruleText = "";
  }

  function removeRule(index: number) {
    // Keeps the mode selected when the last rule is removed.
    picked = mode;
    setRules(rules.filter((_, i) => i !== index));
  }

  function importBulk() {
    const seen = new Set(rules.map(ruleKey));
    const added: string[] = [];
    const rejected: string[] = [];
    let duplicates = 0;
    for (const part of bulkText.split(/[\n,]/)) {
      const rule = part.trim();
      if (!rule) continue;
      if (filterRuleError(rule)) rejected.push(rule);
      else if (seen.has(ruleKey(rule))) duplicates += 1;
      else {
        seen.add(ruleKey(rule));
        added.push(rule);
      }
    }
    if (added.length > 0) {
      picked = mode;
      setRules([...rules, ...added]);
    }
    // Rejected rules stay in the box so they can be corrected.
    bulkText = rejected.join("\n");
    bulkNote =
      `Added ${added.length}, skipped ${duplicates} duplicate${duplicates === 1 ? "" : "s"}` +
      (rejected.length > 0 ? `. ${rejected.length} invalid left below.` : ".");
  }

  async function runTest(event: SubmitEvent) {
    event.preventDefault();
    const run = ++testRun;
    testing = true;
    result = null;
    testError = null;
    try {
      const outcome = await api.testFilterRules(mode === "block" ? "block" : "allow", rules, target);
      if (run === testRun) result = outcome;
    } catch (error) {
      if (run === testRun) testError = errorMessage(error);
    } finally {
      if (run === testRun) testing = false;
    }
  }

  // A result only describes the exact rules and host it was run with.
  $effect(() => {
    void mode;
    void rules;
    void target;
    testRun += 1;
    testing = false;
    result = null;
    testError = null;
  });
</script>

<section aria-labelledby={`${uid}-heading`}>
  <h2 id={`${uid}-heading`}>{title}</h2>

  <div class="segmented" role="group" aria-label={`${title} mode`}>
    {#each MODES as option (option.value)}
      <button type="button" aria-pressed={mode === option.value} onclick={() => setMode(option.value)}>
        {option.label}
      </button>
    {/each}
  </div>

  {#if conflict}
    <p class="field-error">{conflict} Pick the mode to keep. The other list is cleared.</p>
  {/if}

  {#if mode === "off"}
    <p class="muted">No filter. Every destination is allowed.</p>
  {:else}
    <p class="muted">
      {mode === "allow" ? "Only these destinations are allowed." : "These destinations are blocked."}
      {#if rules.length === 0}An empty list means no filter is active.{/if}
    </p>

    {#if rules.length > 0}
      <ul class="rule-list" aria-label={`${title} rules`}>
        {#each rules as rule, index (`${index}:${rule}`)}
          {@const problem = errors[`filters.${scope}.${mode}:${index}`]}
          <li class="rule-chip" class:bad={!!problem} title={problem}>
            {rule}
            <button type="button" aria-label={`Remove ${rule}`} onclick={() => removeRule(index)}>×</button>
          </li>
        {/each}
      </ul>
      {#each rules as _rule, index (index)}
        {@const problem = errors[`filters.${scope}.${mode}:${index}`]}
        {#if problem}<span class="field-error">{problem}</span>{/if}
      {/each}
    {/if}

    <form class="inline-form" onsubmit={addRule}>
      <input
        bind:value={ruleText}
        spellcheck="false"
        placeholder="IP, CIDR, example.com, or *.example.com"
        aria-label={`Add ${title} rule`}
        aria-invalid={!!ruleError}
        oninput={() => (ruleError = null)}
      />
      <button type="submit" disabled={!ruleText.trim()}>Add rule</button>
    </form>
    {#if ruleError}<span class="field-error" role="alert">{ruleError}</span>{/if}

    <label class="field">
      Bulk paste <small class="muted">one per line or comma separated</small>
      <textarea class="code-text" bind:value={bulkText} spellcheck="false"></textarea>
    </label>
    <div class="inline-form">
      <button type="button" disabled={!bulkText.trim()} onclick={importBulk}>Import rules</button>
      {#if bulkNote}<span class="muted" role="status">{bulkNote}</span>{/if}
    </div>
  {/if}

  <form class="inline-form" onsubmit={runTest}>
    <input
      bind:value={target}
      spellcheck="false"
      placeholder="Test a host, such as api.example.com"
      aria-label={`Test host against ${title} rules`}
    />
    <button type="submit" disabled={testing || !target.trim()}>{testing ? "Testing…" : "Test host"}</button>
  </form>
  <div role="status">
    {#if result}
      {#if result.allowed === true}
        <p><span class="pill ok">Allowed</span> <span class="muted">{result.reason}</span></p>
      {:else if result.allowed === false}
        <p><span class="pill alert">Blocked</span> <span class="muted">{result.reason}</span></p>
      {:else}
        <p class="field-error">{result.reason}</p>
      {/if}
      {#if result.rule_errors.length > 0}
        <ul class="plain-list field-error">
          {#each result.rule_errors as ruleProblem (ruleProblem.index)}
            <li><code>{ruleProblem.rule}</code>: {ruleProblem.message}</li>
          {/each}
        </ul>
      {/if}
    {/if}
    {#if testError}<p class="field-error">Could not test: {testError}</p>{/if}
  </div>
</section>
