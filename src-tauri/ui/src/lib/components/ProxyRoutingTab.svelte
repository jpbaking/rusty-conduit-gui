<script lang="ts" module>
  import type { RouteOneOrMany, RoutePortSpec, RouteTarget, RoutingRule } from "../types";

  export type RoutingTableKey = "unified" | "http" | "socks";

  /** A target as a list: one name, or a failover chain. */
  export const targetList = (target: RouteTarget | undefined): string[] =>
    target === undefined ? [] : Array.isArray(target) ? target : [target];

  /** A list back to the wire shape: one name stays a string, more become a chain. */
  export const toTarget = (names: string[]): RouteTarget => (names.length === 1 ? (names[0] ?? "direct") : names);

  const asList = <T,>(value: RouteOneOrMany<T> | undefined): T[] =>
    value === undefined ? [] : Array.isArray(value) ? value : [value];

  /** Splits comma or newline separated text; empty gives `undefined` so the key is left out. */
  function toOneOrMany(text: string): RouteOneOrMany<string> | undefined {
    const items = text.split(/[\n,]/).map((item) => item.trim()).filter((item) => item !== "");
    if (items.length === 0) return undefined;
    return items.length === 1 ? items[0] : items;
  }

  function toPorts(text: string): RouteOneOrMany<RoutePortSpec> | undefined {
    const items = asList(toOneOrMany(text)).map((item) => (/^\d+$/.test(item) ? Number(item) : item));
    if (items.length === 0) return undefined;
    return items.length === 1 ? items[0] : items;
  }

  const LIST_MATCHERS = [
    { key: "host", label: "Host", hint: "exact host names" },
    { key: "host_wildcard", label: "Host wildcard", hint: "such as *.example.com" },
    { key: "host_regex", label: "Host regex", hint: "regular expressions" },
    { key: "cidr", label: "CIDR", hint: "such as 10.0.0.0/8" },
    { key: "ip", label: "IP", hint: "IP addresses" },
    { key: "bypass", label: "Bypass", hint: "hosts this rule never matches" },
    { key: "weekday", label: "Weekday", hint: "such as mon, tue or mon-fri" },
    { key: "time", label: "Time", hint: "such as 09:00-17:30" },
    { key: "url_wildcard", label: "URL wildcard", hint: "needs MITM for HTTPS" },
    { key: "url_regex", label: "URL regex", hint: "needs MITM for HTTPS" },
    { key: "keyword", label: "Keyword", hint: "text anywhere in the URL" },
  ] as const;

  type ListMatcher = (typeof LIST_MATCHERS)[number]["key"];

  /** The condition chips shown on a rule row. */
  export function conditionChips(rule: RoutingRule): string[] {
    const chips: string[] = [];
    if (rule.match_all) chips.push("match all");
    if (rule.inbound) chips.push(`inbound: ${rule.inbound}`);
    for (const { key, label } of LIST_MATCHERS) {
      const values = asList(rule[key]);
      if (values.length > 0) chips.push(`${label.toLowerCase()}: ${values.join(", ")}`);
    }
    const ports = asList(rule.port);
    if (ports.length > 0) chips.push(`port: ${ports.join(", ")}`);
    if (rule.host_levels) chips.push(`levels: ${rule.host_levels.min ?? 0}–${rule.host_levels.max ?? "∞"}`);
    if (rule.resolve_dns !== undefined) chips.push(rule.resolve_dns ? "resolve DNS" : "no DNS");
    return chips;
  }

  /** Whether a rule matches on the URL, which HTTPS hides unless MITM decrypts it. */
  export const usesUrl = (rule: RoutingRule): boolean =>
    [rule.url_wildcard, rule.url_regex, rule.keyword].some((v) => asList(v).length > 0);

  /** The label the engine reports for a matched rule: its name, or its 1-based position. */
  export function ruleMatches(rule: RoutingRule, index: number, label: string | null): boolean {
    if (label === null) return false;
    if (rule.name !== undefined && rule.name !== "") return rule.name === label;
    return [`${index + 1}`, `#${index + 1}`, `rule ${index + 1}`, `rule-${index + 1}`].includes(label);
  }

  /** Text fields of the rule editor drawer. */
  export interface RuleForm {
    name: string;
    inbound: "" | "http" | "socks";
    lists: Record<ListMatcher, string>;
    port: string;
    levelsMin: string;
    levelsMax: string;
    match_all: boolean;
    disabled: boolean;
    resolve_dns: "inherit" | "on" | "off";
    target: string[];
  }

  export function ruleToForm(rule: RoutingRule): RuleForm {
    const lists = Object.fromEntries(
      LIST_MATCHERS.map(({ key }) => [key, asList(rule[key]).join("\n")]),
    ) as Record<ListMatcher, string>;
    return {
      name: rule.name ?? "",
      inbound: rule.inbound ?? "",
      lists,
      port: asList(rule.port).join(", "),
      levelsMin: rule.host_levels?.min?.toString() ?? "",
      levelsMax: rule.host_levels?.max?.toString() ?? "",
      match_all: rule.match_all,
      disabled: rule.disabled,
      resolve_dns: rule.resolve_dns === undefined ? "inherit" : rule.resolve_dns ? "on" : "off",
      target: targetList(rule.target),
    };
  }

  export function formToRule(form: RuleForm): RoutingRule {
    const rule: RoutingRule = {
      match_all: form.match_all,
      disabled: form.disabled,
      target: toTarget(form.target.length > 0 ? form.target : ["direct"]),
    };
    if (form.name.trim()) rule.name = form.name.trim();
    if (form.inbound) rule.inbound = form.inbound;
    for (const { key } of LIST_MATCHERS) {
      const value = toOneOrMany(form.lists[key]);
      if (value !== undefined) rule[key] = value;
    }
    const port = toPorts(form.port);
    if (port !== undefined) rule.port = port;
    if (form.levelsMin.trim() || form.levelsMax.trim()) {
      rule.host_levels = {};
      if (form.levelsMin.trim()) rule.host_levels.min = Number(form.levelsMin);
      if (form.levelsMax.trim()) rule.host_levels.max = Number(form.levelsMax);
    }
    if (form.resolve_dns !== "inherit") rule.resolve_dns = form.resolve_dns === "on";
    return rule;
  }

  export { LIST_MATCHERS };
</script>

<script lang="ts">
  import { tick } from "svelte";
  import { store, type ProxyQuickAction } from "../stores.svelte";
  import type { Proxy, RouteInbound, RoutingTable } from "../types";
  import { BUILTIN_PROFILES } from "../validate";

  interface Props {
    /** A Log drawer quick action to run once when it arrives. */
    quickAction: ProxyQuickAction | null;
  }

  let { quickAction }: Props = $props();

  const uid = $props.id();
  const proxy = $derived(store.proxyDraft as Proxy);
  const routing = $derived(proxy.routing);
  const errors = $derived(store.proxyDraftErrors);
  const targetNames = $derived([...BUILTIN_PROFILES, ...proxy.profiles.map((p) => p.name).filter((n) => n)]);

  const TABLES: { value: RoutingTableKey; label: string; wire: string }[] = [
    { value: "unified", label: "Unified", wire: "[routing]" },
    { value: "http", label: "HTTP override", wire: "[routing.http]" },
    { value: "socks", label: "SOCKS override", wire: "[routing.socks]" },
  ];

  let tableKey = $state<RoutingTableKey>("unified");
  const override = $derived<RoutingTable | undefined>(tableKey === "unified" ? undefined : routing[tableKey]);
  const rules = $derived(tableKey === "unified" ? routing.rules : (override?.rules ?? []));
  const errorPrefix = $derived(tableKey === "unified" ? "routing.rules" : `routing.${tableKey}.rules`);
  const tableWire = $derived(TABLES.find((t) => t.value === tableKey)?.wire ?? "[routing]");

  function updateRouting(edit: (routing: Proxy["routing"]) => Proxy["routing"]) {
    store.updateProxyDraft((p) => ({ ...p, routing: edit(p.routing) }));
  }

  function setRules(next: RoutingRule[]) {
    const key = tableKey;
    updateRouting((r) => {
      if (key === "unified") return { ...r, rules: next };
      const table = r[key] ?? { inherit: true, rules: [] };
      return { ...r, [key]: { ...table, rules: next } };
    });
  }

  function setOverride(next: RoutingTable | undefined) {
    const key = tableKey;
    if (key === "unified") return;
    updateRouting((r) => {
      const { [key]: _dropped, ...rest } = r;
      return next === undefined ? rest : { ...rest, [key]: next };
    });
  }

  // Reordering.
  let moveButtons = $state<HTMLButtonElement[]>([]);

  async function move(index: number, delta: number) {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    const next = [...rules];
    const [rule] = next.splice(index, 1);
    if (rule === undefined) return;
    next.splice(target, 0, rule);
    setRules(next);
    await tick();
    moveButtons[target]?.focus();
  }

  function onRowKeydown(event: KeyboardEvent, index: number) {
    if (!event.altKey) return;
    if (event.key === "ArrowUp") {
      event.preventDefault();
      void move(index, -1);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      void move(index, 1);
    }
  }

  function toggleRule(index: number, enabled: boolean) {
    setRules(rules.map((rule, i) => (i === index ? { ...rule, disabled: !enabled } : rule)));
  }

  function removeRule(index: number) {
    setRules(rules.filter((_, i) => i !== index));
  }

  // Rule editor drawer.
  let editing = $state<{ index: number | null; form: RuleForm } | null>(null);

  function openRule(index: number | null, base?: RoutingRule) {
    const rule = index === null ? base : rules[index];
    editing = {
      index,
      form: ruleToForm(rule ?? { match_all: false, disabled: false, target: targetList(routing.default)[0] ?? "direct" }),
    };
  }

  function applyRule(event: SubmitEvent) {
    event.preventDefault();
    if (!editing) return;
    const rule = formToRule(editing.form);
    const { index } = editing;
    setRules(index === null ? [...rules, rule] : rules.map((r, i) => (i === index ? rule : r)));
    editing = null;
  }

  // Route Tester.
  let testTarget = $state("");
  let testInbound = $state<RouteInbound>("http");
  let testing = $state(false);
  let testerInput = $state<HTMLInputElement | null>(null);
  const result = $derived(store.routeTest);
  const resultTable = $derived(result?.table ?? null);

  async function runTest(event?: SubmitEvent) {
    event?.preventDefault();
    if (!testTarget.trim() || testing) return;
    testing = true;
    try {
      await store.testRoute(testTarget.trim(), testInbound);
    } finally {
      testing = false;
    }
  }

  const isMatched = (rule: RoutingRule, index: number) =>
    !!result && resultTable === tableWire && ruleMatches(rule, index, result.matched_rule);

  // Log drawer quick actions, each run once.
  let handledNonce = 0;
  $effect(() => {
    const action = quickAction;
    if (!action || action.nonce === handledNonce) return;
    handledNonce = action.nonce;
    if (action.kind === "test_route") {
      // An empty host (the header's Test Route shortcut) only focuses the tester.
      if (action.host) {
        testTarget = action.host;
        testInbound = action.inbound;
      }
      void tick().then(() => {
        testerInput?.scrollIntoView({ block: "nearest" });
        testerInput?.focus();
        void runTest();
      });
    } else {
      tableKey = "unified";
      const hostName = action.host.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
      openRule(null, {
        name: hostName,
        host: hostName,
        match_all: false,
        disabled: false,
        target: targetList(routing.default)[0] ?? "direct",
      });
    }
  });
</script>

{#snippet targetPicker(label: string, names: string[], onChange: (names: string[]) => void, error?: string)}
  <div class="field">
    <span>{label} <small class="muted">more than one is a failover chain, tried in order</small></span>
    <ol class="target-chain" aria-label={label}>
      {#each names as name, index (`${index}:${name}`)}
        <li class="rule-chip" class:bad={!targetNames.includes(name)}>
          {#if index > 0}<span class="muted" aria-hidden="true">→</span>{/if}
          {name}
          <button
            type="button"
            aria-label={`Remove ${name} from ${label}`}
            disabled={names.length === 1}
            onclick={() => onChange(names.filter((_, i) => i !== index))}
          >×</button>
        </li>
      {/each}
    </ol>
    <select
      aria-label={`Add to ${label}`}
      value=""
      onchange={(e) => {
        const name = e.currentTarget.value;
        e.currentTarget.value = "";
        if (name && !names.includes(name)) onChange([...names, name]);
      }}
    >
      <option value="">{names.length === 0 ? "Choose a profile…" : "Add a failover profile…"}</option>
      {#each targetNames.filter((n) => !names.includes(n)) as name (name)}
        <option value={name}>{name}</option>
      {/each}
    </select>
    {#if error}<span class="field-error">{error}</span>{/if}
  </div>
{/snippet}

<section class="card" aria-labelledby={`${uid}-table`}>
  <h2 id={`${uid}-table`}>Routing table</h2>
  <div class="segmented" role="group" aria-label="Routing table">
    {#each TABLES as table (table.value)}
      <button type="button" aria-pressed={tableKey === table.value} onclick={() => (tableKey = table.value)}>
        {table.label}
        {#if table.value !== "unified" && routing[table.value]}<span class="muted"> ●</span>{/if}
      </button>
    {/each}
  </div>

  {#if tableKey === "unified"}
    {@render targetPicker(
      "Default target",
      targetList(routing.default),
      (names) => updateRouting((r) => ({ ...r, default: toTarget(names) })),
      errors["routing.default"],
    )}
    <label class="check">
      <input
        type="checkbox"
        checked={routing.resolve_dns}
        onchange={(e) => {
          const resolve_dns = e.currentTarget.checked;
          updateRouting((r) => ({ ...r, resolve_dns }));
        }}
      />
      Resolve DNS locally before matching IP and CIDR rules
    </label>
    <p class="note" role="note">
      {#if routing.resolve_dns}
        Host names are looked up on this computer, so your local DNS server sees every destination
        (a DNS leak) even when traffic goes through an upstream.
      {:else}
        Host names are not looked up here. IP and CIDR rules only match targets given as IP addresses.
      {/if}
    </p>
  {:else if !override}
    <p class="muted">
      No {tableKey === "http" ? "HTTP" : "SOCKS"} override. {tableKey === "http" ? "HTTP" : "SOCKS"} traffic uses the
      unified table.
    </p>
    <button type="button" onclick={() => setOverride({ inherit: true, rules: [] })}>Add override table</button>
  {:else}
    {@const table = override}
    <label class="check">
      <input
        type="checkbox"
        checked={table.inherit}
        onchange={(e) => setOverride({ ...table, inherit: e.currentTarget.checked })}
      />
      Fall back to the unified rules when none of these match
    </label>
    <label class="check">
      <input
        type="checkbox"
        checked={table.default !== undefined}
        onchange={(e) => {
          const { default: _dropped, ...rest } = table;
          setOverride(e.currentTarget.checked ? { ...rest, default: routing.default } : rest);
        }}
      />
      Own default target
    </label>
    {#if table.default !== undefined}
      {@render targetPicker(
        "Override default target",
        targetList(table.default),
        (names) => setOverride({ ...table, default: toTarget(names) }),
        errors[`routing.${tableKey}.default`],
      )}
    {/if}
    <button type="button" class="danger" onclick={() => setOverride(undefined)}>Remove override table</button>
  {/if}
</section>

{#if tableKey === "unified" || override}
  <section class="card" aria-labelledby={`${uid}-rules`}>
    <div class="card-head">
      <h2 id={`${uid}-rules`}>Rules <small class="muted">first match wins · Alt+↑/↓ reorders</small></h2>
      <button type="button" onclick={() => openRule(null)}>+ Add rule</button>
    </div>
    {#if rules.length === 0}
      <p class="muted">No rules. Everything goes to the default target.</p>
    {:else}
      <ol class="plain-list routing-rules" aria-label="Routing rules">
        {#each rules as rule, index (index)}
          {@const chain = targetList(rule.target)}
          {@const problems = Object.entries(errors).filter(([key]) => key.startsWith(`${errorPrefix}:${index}:`))}
          <li class="routing-rule" class:matched={isMatched(rule, index)} class:off={rule.disabled}>
            <div class="rule-order">
              <button
                type="button"
                bind:this={moveButtons[index]}
                aria-label={`Move rule ${index + 1} up`}
                disabled={index === 0}
                onclick={() => void move(index, -1)}
                onkeydown={(e) => onRowKeydown(e, index)}
              >↑</button>
              <button
                type="button"
                aria-label={`Move rule ${index + 1} down`}
                disabled={index === rules.length - 1}
                onclick={() => void move(index, 1)}
                onkeydown={(e) => onRowKeydown(e, index)}
              >↓</button>
            </div>
            <label class="check">
              <input
                type="checkbox"
                checked={!rule.disabled}
                aria-label={`Rule ${index + 1} enabled`}
                onchange={(e) => toggleRule(index, e.currentTarget.checked)}
              />
            </label>
            <div class="rule-body">
              <button
                type="button"
                class="link-button"
                onclick={() => openRule(index)}
                onkeydown={(e) => onRowKeydown(e, index)}
              >
                {index + 1}. {rule.name || "Unnamed rule"}
              </button>
              {#if isMatched(rule, index)}<span class="pill ok">Matched</span>{/if}
              <span class="muted">→ {chain.join(" → ")}</span>
              {#if chain.length > 1}<span class="pill busy" title="Tried in order">failover ×{chain.length}</span>{/if}
              {#if usesUrl(rule) && !proxy.mitm}
                <span class="pill alert" title="HTTPS URLs are hidden unless MITM is on, so this only matches plain HTTP">
                  URL rule without MITM
                </span>
              {/if}
              <ul class="rule-list" aria-label="Conditions">
                {#each conditionChips(rule) as chip, chipIndex (chipIndex)}<li class="rule-chip">{chip}</li>{/each}
              </ul>
              {#each problems as [key, message] (key)}<p class="field-error">{message}</p>{/each}
            </div>
            <button type="button" class="danger" aria-label={`Delete rule ${index + 1}`} onclick={() => removeRule(index)}>
              Delete
            </button>
          </li>
        {/each}
      </ol>
    {/if}
  </section>
{/if}

{#if editing}
  {@const form = editing.form}
  <aside class="rule-drawer card" aria-labelledby={`${uid}-drawer`}>
    <form onsubmit={applyRule}>
      <h2 id={`${uid}-drawer`}>{editing.index === null ? "New rule" : `Edit rule ${editing.index + 1}`}</h2>
      <div class="field-row">
        <label class="field grow">Name <input bind:value={form.name} spellcheck="false" /></label>
        <label class="field">
          Inbound
          <select bind:value={form.inbound}>
            <option value="">Any</option>
            <option value="http">HTTP</option>
            <option value="socks">SOCKS</option>
          </select>
        </label>
      </div>
      <label class="check">
        <input type="checkbox" bind:checked={form.match_all} />
        Match all <small class="muted">every condition must match (otherwise any one does)</small>
      </label>
      <label class="check"><input type="checkbox" bind:checked={form.disabled} /> Disabled</label>
      <div class="matcher-grid">
        {#each LIST_MATCHERS as matcher (matcher.key)}
          <label class="field">
            <span>{matcher.label} <small class="muted">{matcher.hint}</small></span>
            <textarea rows="2" spellcheck="false" bind:value={form.lists[matcher.key]}></textarea>
          </label>
        {/each}
        <label class="field">
          <span>Port <small class="muted">such as 443 or 8000-8999</small></span>
          <input bind:value={form.port} spellcheck="false" />
        </label>
        <div class="field-row">
          <label class="field grow">
            Host levels min
            <input type="number" min="0" bind:value={form.levelsMin} />
          </label>
          <label class="field grow">
            Host levels max
            <input type="number" min="0" bind:value={form.levelsMax} />
          </label>
        </div>
        <label class="field">
          Resolve DNS
          <select bind:value={form.resolve_dns}>
            <option value="inherit">Use the table setting</option>
            <option value="on">Resolve locally</option>
            <option value="off">Do not resolve</option>
          </select>
        </label>
      </div>
      {@render targetPicker("Rule target", form.target, (names) => (form.target = names))}
      {#if (form.lists.url_wildcard.trim() || form.lists.url_regex.trim() || form.lists.keyword.trim()) && !proxy.mitm}
        <p class="note">URL conditions only see HTTPS URLs when HTTPS MITM is on.</p>
      {/if}
      <div class="form-actions">
        <button type="button" onclick={() => (editing = null)}>Cancel</button>
        <button type="submit" class="primary" disabled={form.target.length === 0}>
          {editing.index === null ? "Add rule" : "Apply"}
        </button>
      </div>
    </form>
  </aside>
{/if}

<section class="card" aria-labelledby={`${uid}-tester`}>
  <h2 id={`${uid}-tester`}>Route Tester <small class="muted">checks the unsaved rules; nothing is dialed</small></h2>
  <form class="inline-form" onsubmit={runTest}>
    <input
      bind:this={testerInput}
      bind:value={testTarget}
      spellcheck="false"
      placeholder="Host, host:port, or URL"
      aria-label="Target to test"
    />
    <select aria-label="Inbound listener" bind:value={testInbound}>
      <option value="http">HTTP</option>
      <option value="socks">SOCKS</option>
    </select>
    <button type="submit" disabled={testing || !testTarget.trim()}>{testing ? "Testing…" : "Test route"}</button>
  </form>
  <div role="status">
    {#if result}
      {#if result.blocked_by_filter}
        <p><span class="pill alert">Blocked by the global filter</span> <span class="muted">{result.filter_reason}</span></p>
      {:else}
        <dl class="fact-list">
          <dt>Table</dt>
          <dd><code>{result.table}</code></dd>
          <dt>Matched</dt>
          <dd>{result.matched_rule ?? "No rule (the table default)"}</dd>
          <dt>Route</dt>
          <dd>
            <ol class="plain-list">
              {#each result.targets as target, index (index)}
                <li>
                  {index + 1}. <strong>{target.name}</strong>
                  {#if target.profile !== target.name}<span class="muted">via {target.profile}</span>{/if}
                  <code>{target.redacted_upstream}</code>
                  {#if target.bypassed}<span class="pill idle">bypassed → direct</span>{/if}
                </li>
              {/each}
            </ol>
          </dd>
        </dl>
      {/if}
    {/if}
  </div>
</section>

<style>
  .target-chain {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    list-style: none;
    margin: 0.25rem 0;
    padding: 0;
  }
  .routing-rules {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .routing-rule {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.4rem;
    border: 1px solid var(--border, #ccc);
    border-radius: 6px;
  }
  .routing-rule.matched {
    outline: 2px solid var(--ok, #2e7d32);
  }
  .routing-rule.off {
    opacity: 0.6;
  }
  .rule-order {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .rule-body {
    flex: 1;
    min-width: 0;
  }
  .matcher-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
    gap: 0.5rem;
  }
  .rule-drawer {
    border-left: 3px solid var(--accent, #3b82f6);
  }
</style>
