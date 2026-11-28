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

  /** The condition chips shown on an Advanced rule row. */
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
    if (rule.bypass_mitm) chips.push("bypass MITM");
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

  /** Text fields of the Advanced rule editor drawer. */
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
    bypass_mitm: boolean;
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
      bypass_mitm: Boolean(rule.bypass_mitm),
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
    if (form.bypass_mitm) rule.bypass_mitm = true;
    return rule;
  }

  export { LIST_MATCHERS };
</script>

<script lang="ts">
  import { tick } from "svelte";
  import {
    CONDITION_GROUPS,
    WEEKDAYS,
    applySimpleCondition,
    buildProfileOptionGroups,
    classifyRule,
    conditionPlaceholder,
    formatTargetLabel,
    formatTimeRange,
    formatWeekdays,
    isKnownProfileOption,
    isUrlConditionKind,
    parseTimeRange,
    parseWeekdays,
    reorderList,
    ruleDetailText,
    type ConditionKind,
    type SimpleConditionKind,
    type WeekdayKey,
  } from "../routingRows";
  import { store, type ProxyQuickAction } from "../stores.svelte";
  import type { Proxy, RouteInbound, RoutingTable } from "../types";

  interface Props {
    /** A Log drawer quick action to run once when it arrives. */
    quickAction: ProxyQuickAction | null;
  }

  let { quickAction }: Props = $props();

  // Hidden until the Advanced routing & HTTP/SOCKS split UX is reworked (see docs/TODO.md).
  const SHOW_ADVANCED_ROUTING = false;

  const uid = $props.id();
  const proxy = $derived(store.proxyDraft as Proxy);
  const routing = $derived(proxy.routing);
  const showMitmBypass = $derived(proxy.mitm !== null);
  const errors = $derived(store.proxyDraftErrors);
  const tunnels = $derived(store.tunnels.map((t) => t.profile));
  const profileGroups = $derived(buildProfileOptionGroups(tunnels, proxy.profiles));

  const TABLES: { value: RoutingTableKey; label: string; wire: string }[] = [
    { value: "unified", label: "Unified", wire: "[routing]" },
    { value: "http", label: "HTTP override", wire: "[routing.http]" },
    { value: "socks", label: "SOCKS override", wire: "[routing.socks]" },
  ];

  let tableKey = $state<RoutingTableKey>("unified");
  let splitTablesOpen = $state(false);
  let lastProxyId = $state<string | null>(null);

  // Auto-open the HTTP/SOCKS split disclosure when switching to a Proxy that has an override.
  $effect(() => {
    const id = store.selectedProxyId;
    if (id !== lastProxyId) {
      lastProxyId = id;
      const hasSplit = routing.http !== undefined || routing.socks !== undefined;
      splitTablesOpen = hasSplit;
      tableKey = "unified";
      kindOverrides = {};
      editing = null;
    }
  });

  const override = $derived<RoutingTable | undefined>(tableKey === "unified" ? undefined : routing[tableKey]);
  const rules = $derived(tableKey === "unified" ? routing.rules : (override?.rules ?? []));
  const errorPrefix = $derived(tableKey === "unified" ? "routing.rules" : `routing.${tableKey}.rules`);
  const defaultErrorKey = $derived(tableKey === "unified" ? "routing.default" : `routing.${tableKey}.default`);
  const tableWire = $derived(TABLES.find((t) => t.value === tableKey)?.wire ?? "[routing]");
  const activeDefault = $derived<RouteTarget | undefined>(
    tableKey === "unified" ? routing.default : override?.default,
  );
  const defaultSingleTarget = $derived(targetList(routing.default)[0] ?? "direct");

  // Remembers the chosen condition kind for rows that have no value typed yet.
  let kindOverrides = $state<Record<number, SimpleConditionKind>>({});

  function rowKind(rule: RoutingRule, index: number): ConditionKind {
    const classified = classifyRule(rule);
    if (classified === "advanced") return "advanced";
    const hasMatcher =
      rule.match_all ||
      rule.host !== undefined ||
      rule.host_wildcard !== undefined ||
      rule.host_regex !== undefined ||
      rule.cidr !== undefined ||
      rule.ip !== undefined ||
      rule.port !== undefined ||
      rule.host_levels !== undefined ||
      rule.weekday !== undefined ||
      rule.time !== undefined ||
      rule.url_wildcard !== undefined ||
      rule.url_regex !== undefined ||
      rule.keyword !== undefined;
    return hasMatcher ? classified : (kindOverrides[index] ?? classified);
  }

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

  function setRule(index: number, nextRule: RoutingRule) {
    setRules(rules.map((r, i) => (i === index ? nextRule : r)));
  }

  function setOverride(next: RoutingTable | undefined) {
    const key = tableKey;
    if (key === "unified") return;
    updateRouting((r) => {
      const { [key]: _dropped, ...rest } = r;
      return next === undefined ? rest : { ...rest, [key]: next };
    });
  }

  function setActiveDefault(next: RouteTarget) {
    if (tableKey === "unified") {
      updateRouting((r) => ({ ...r, default: next }));
    } else if (override) {
      setOverride({ ...override, default: next });
    }
  }

  function addCondition() {
    const nextRule: RoutingRule = {
      match_all: false,
      disabled: false,
      target: defaultSingleTarget,
    };
    setRules([...rules, nextRule]);
  }

  function toggleRule(index: number, enabled: boolean) {
    const rule = rules[index];
    if (!rule) return;
    setRule(index, { ...rule, disabled: !enabled });
  }

  function toggleBypassMitm(index: number, bypass: boolean) {
    const rule = rules[index];
    if (!rule) return;
    if (bypass) {
      setRule(index, { ...rule, bypass_mitm: true });
    } else {
      const { bypass_mitm: _dropped, ...rest } = rule;
      setRule(index, rest);
    }
  }

  function removeRule(index: number) {
    const nextOverrides: Record<number, SimpleConditionKind> = {};
    for (const [k, v] of Object.entries(kindOverrides)) {
      const i = Number(k);
      if (i < index) nextOverrides[i] = v;
      else if (i > index) nextOverrides[i - 1] = v;
    }
    kindOverrides = nextOverrides;
    setRules(rules.filter((_, i) => i !== index));
  }

  function onKindChange(index: number, nextKind: ConditionKind) {
    const rule = rules[index];
    if (!rule) return;
    if (nextKind === "advanced") {
      openRule(index);
      return;
    }
    if (nextKind === "match_all") {
      const { [index]: _dropped, ...rest } = kindOverrides;
      kindOverrides = rest;
      setRule(index, applySimpleCondition(rule, "match_all", ""));
      return;
    }
    kindOverrides = { ...kindOverrides, [index]: nextKind };
    setRule(index, applySimpleCondition(rule, nextKind, ""));
  }

  function onDetailChange(index: number, kind: SimpleConditionKind, value: string) {
    const rule = rules[index];
    if (!rule) return;
    if (value.trim() === "") {
      kindOverrides = { ...kindOverrides, [index]: kind };
    }
    setRule(index, applySimpleCondition(rule, kind, value));
  }

  function onHostLevelsChange(index: number, minText: string, maxText: string) {
    const rule = rules[index];
    if (!rule) return;
    const combined = minText.trim() || maxText.trim() ? `${minText.trim()}~${maxText.trim()}` : "";
    onDetailChange(index, "host_levels", combined);
  }

  function onWeekdayToggle(index: number, day: WeekdayKey, checked: boolean) {
    const rule = rules[index];
    if (!rule) return;
    const current = parseWeekdays(rule.weekday);
    current[day] = checked;
    const formatted = formatWeekdays(current);
    const next = applySimpleCondition(rule, "weekday", "");
    if (formatted !== undefined) next.weekday = formatted;
    else kindOverrides = { ...kindOverrides, [index]: "weekday" };
    setRule(index, next);
  }

  function onTimeChange(index: number, start: string, end: string) {
    const rule = rules[index];
    if (!rule) return;
    const formatted = formatTimeRange(start, end);
    const next = applySimpleCondition(rule, "time", "");
    if (formatted !== undefined) next.time = formatted;
    else kindOverrides = { ...kindOverrides, [index]: "time" };
    setRule(index, next);
  }

  // Drag-and-drop reordering via pointer events (safe in Tauri webview) + Alt+↑/↓ fallback.
  let tableBody = $state<HTMLTableSectionElement | null>(null);
  let dragHandles = $state<HTMLButtonElement[]>([]);
  let dragFrom = $state<number | null>(null);
  let dragOver = $state<number | null>(null);
  let announcement = $state("");

  function reorderRules(from: number, to: number) {
    if (from === to || from < 0 || to < 0 || from >= rules.length || to >= rules.length) return;
    const nextOverrides: Record<number, SimpleConditionKind> = {};
    const order = reorderList(
      rules.map((_, i) => i),
      from,
      to,
    );
    order.forEach((oldIdx, newIdx) => {
      const ov = kindOverrides[oldIdx];
      if (ov) nextOverrides[newIdx] = ov;
    });
    kindOverrides = nextOverrides;
    setRules(reorderList(rules, from, to));
    announcement = `Moved rule ${from + 1} to position ${to + 1}.`;
  }

  async function moveByKey(index: number, delta: -1 | 1) {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    reorderRules(index, target);
    await tick();
    dragHandles[target]?.focus();
  }

  function onHandleKeydown(event: KeyboardEvent, index: number) {
    if (!event.altKey) return;
    if (event.key === "ArrowUp") {
      event.preventDefault();
      void moveByKey(index, -1);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      void moveByKey(index, 1);
    }
  }

  function startDrag(event: PointerEvent, index: number) {
    if (event.button !== 0 || rules.length < 2) return;
    event.preventDefault();
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    dragFrom = index;
    dragOver = index;
  }

  function onDragMove(event: PointerEvent) {
    if (dragFrom === null || !tableBody) return;
    let best = Infinity;
    let bestIdx = dragOver ?? dragFrom;
    tableBody.querySelectorAll<HTMLElement>("tr[data-rule-index]").forEach((row) => {
      const idx = Number(row.dataset.ruleIndex);
      const box = row.getBoundingClientRect();
      const distance = Math.abs(event.clientY - (box.top + box.height / 2));
      if (distance < best) {
        best = distance;
        bestIdx = idx;
      }
    });
    dragOver = bestIdx;
  }

  function endDrag(commit: boolean) {
    const from = dragFrom;
    const to = dragOver;
    dragFrom = null;
    dragOver = null;
    if (commit && from !== null && to !== null && from !== to) {
      reorderRules(from, to);
    }
  }

  // Advanced rule editor drawer.
  let editing = $state<{ index: number | null; form: RuleForm } | null>(null);

  function openRule(index: number | null, base?: RoutingRule) {
    const rule = index === null ? base : rules[index];
    editing = {
      index,
      form: ruleToForm(rule ?? { match_all: false, disabled: false, target: defaultSingleTarget }),
    };
  }

  function applyRule(event: SubmitEvent) {
    event.preventDefault();
    if (!editing) return;
    const rule = formToRule(editing.form);
    const { index } = editing;
    if (index === null) {
      setRules([...rules, rule]);
    } else {
      const { [index]: _dropped, ...rest } = kindOverrides;
      kindOverrides = rest;
      setRule(index, rule);
    }
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
    !!result && !result.blocked_by_filter && resultTable === tableWire && ruleMatches(rule, index, result.matched_rule);

  const isDefaultMatched = $derived(
    !!result && !result.blocked_by_filter && resultTable === tableWire && result.matched_rule === null,
  );

  // Log drawer quick actions, each run once.
  let handledNonce = 0;
  $effect(() => {
    const action = quickAction;
    if (!action || action.nonce === handledNonce) return;
    handledNonce = action.nonce;
    if (action.kind === "test_route") {
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
        target: defaultSingleTarget,
      });
    }
  });
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && dragFrom !== null && endDrag(false)} />

{#snippet profileSelect(value: string, ariaLabel: string, onChange: (value: string) => void, invalid = false)}
  {@const known = isKnownProfileOption(value, profileGroups)}
  <select
    class="profile-select"
    class:bad-select={invalid || !known}
    aria-label={ariaLabel}
    aria-invalid={invalid || !known}
    {value}
    onchange={(e) => onChange(e.currentTarget.value)}
  >
    {#if !known}
      <option value={value} disabled>{formatTargetLabel(value, tunnels, proxy.profiles)}</option>
    {/if}
    {#each profileGroups as group (group.label)}
      <optgroup label={group.label}>
        {#each group.options as opt (opt.value)}
          <option value={opt.value}>{opt.label}</option>
        {/each}
      </optgroup>
    {/each}
  </select>
{/snippet}

{#snippet targetPicker(label: string, names: string[], onChange: (names: string[]) => void, error?: string)}
  <div class="field">
    <span>{label} <small class="muted">more than one is a failover chain, tried in order</small></span>
    <ol class="target-chain" aria-label={label}>
      {#each names as name, index (`${index}:${name}`)}
        <li class="rule-chip" class:bad={!isKnownProfileOption(name, profileGroups)}>
          {#if index > 0}<span class="muted" aria-hidden="true">→</span>{/if}
          {formatTargetLabel(name, tunnels, proxy.profiles)}
          <button
            type="button"
            aria-label={`Remove ${formatTargetLabel(name, tunnels, proxy.profiles)} from ${label}`}
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
      {#each profileGroups as group (group.label)}
        {@const available = group.options.filter((opt) => !names.includes(opt.value))}
        {#if available.length > 0}
          <optgroup label={group.label}>
            {#each available as opt (opt.value)}
              <option value={opt.value}>{opt.label}</option>
            {/each}
          </optgroup>
        {/if}
      {/each}
    </select>
    {#if error}<span class="field-error">{error}</span>{/if}
  </div>
{/snippet}

<section class="card" aria-labelledby={`${uid}-rules`}>
  <div class="card-head">
    <h2 id={`${uid}-rules`}>
      Routing rules
      {#if tableKey !== "unified"}
        <span class="pill busy">{tableKey === "http" ? "HTTP override" : "SOCKS override"}</span>
      {/if}
      <small class="muted">first match wins · drag ⋮⋮ or Alt+↑/↓ to reorder</small>
    </h2>
    {#if tableKey === "unified" || override}
      <button type="button" onclick={addCondition}>+ Add condition</button>
    {/if}
  </div>

  {#if tableKey !== "unified" && !override}
    <p class="muted">
      No {tableKey === "http" ? "HTTP" : "SOCKS"} override. {tableKey === "http" ? "HTTP" : "SOCKS"} traffic uses the
      unified table.
    </p>
    <div>
      <button type="button" onclick={() => setOverride({ inherit: true, rules: [] })}>Add override table</button>
    </div>
  {:else}
    {#if tableKey !== "unified" && override}
      {@const table = override}
      <div class="override-controls">
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
        <span class="spacer"></span>
        <button type="button" class="danger" onclick={() => setOverride(undefined)}>Remove override table</button>
      </div>
    {/if}

    <div class="routing-table-wrap">
      <table class="routing-table" aria-label="Routing conditions">
        <thead>
          <tr>
            <th class="col-drag"><span class="sr-only">Order</span></th>
            <th class="col-enabled"><span class="sr-only">Enabled</span></th>
            <th class="col-type">Condition type</th>
            <th class="col-details">Condition details</th>
            <th class="col-profile">Profile</th>
            {#if showMitmBypass}
              <th
                class="col-mitm-bypass"
                title="Bypass HTTPS MITM interception for matching requests (use an opaque tunnel instead)"
              >
                <svg
                  class="mitm-bypass-icon"
                  viewBox="0 0 24 24"
                  width="15"
                  height="15"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18" />
                  <path d="M4.73 4.73 4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38" />
                  <line x1="2" y1="2" x2="22" y2="22" />
                </svg>
                <span class="sr-only">Bypass MITM</span>
              </th>
            {/if}
            <th class="col-delete"><span class="sr-only">Delete</span></th>
          </tr>
        </thead>
        <tbody bind:this={tableBody}>
          {#each rules as rule, index (index)}
            {@const kind = rowKind(rule, index)}
            {@const chain = targetList(rule.target)}
            {@const problems = Object.entries(errors).filter(([key]) => key.startsWith(`${errorPrefix}:${index}:`))}
            {@const matched = isMatched(rule, index)}
            {@const isDragging = dragFrom === index}
            {@const dropBefore = dragFrom !== null && dragOver === index && dragFrom > index}
            {@const dropAfter = dragFrom !== null && dragOver === index && dragFrom < index}
            <tr
              class="routing-row"
              class:off={rule.disabled}
              class:matched
              class:dragging={isDragging}
              class:drop-before={dropBefore}
              class:drop-after={dropAfter}
              data-rule-index={index}
            >
              <td class="col-drag">
                <button
                  type="button"
                  bind:this={dragHandles[index]}
                  class="icon drag-handle"
                  aria-label={`Reorder rule ${index + 1}; drag or press Alt+Up / Alt+Down`}
                  title="Drag to reorder (or Alt+↑ / Alt+↓)"
                  disabled={rules.length < 2}
                  onpointerdown={(e) => startDrag(e, index)}
                  onpointermove={onDragMove}
                  onpointerup={() => endDrag(true)}
                  onpointercancel={() => endDrag(false)}
                  onkeydown={(e) => onHandleKeydown(e, index)}
                >⋮⋮</button>
              </td>
              <td class="col-enabled">
                <input
                  type="checkbox"
                  checked={!rule.disabled}
                  aria-label={`Rule ${index + 1} enabled`}
                  onchange={(e) => toggleRule(index, e.currentTarget.checked)}
                />
              </td>
              <td class="col-type">
                <select
                  aria-label={`Rule ${index + 1} condition type`}
                  value={kind}
                  onchange={(e) => {
                    const nextKind = e.currentTarget.value as ConditionKind;
                    if (nextKind === "advanced") e.currentTarget.value = kind;
                    onKindChange(index, nextKind);
                  }}
                >
                  {#each CONDITION_GROUPS as group (group.label)}
                    <optgroup label={group.label}>
                      {#each group.options as opt (opt.value)}
                        <option value={opt.value}>{opt.label}</option>
                      {/each}
                    </optgroup>
                  {/each}
                  {#if SHOW_ADVANCED_ROUTING}
                    <option value="advanced">Advanced…</option>
                  {:else if kind === "advanced"}
                    <option value="advanced" disabled>Advanced</option>
                  {/if}
                </select>
              </td>
              <td class="col-details">
                <div class="detail-cell">
                  {#if kind === "advanced"}
                    <div class="advanced-summary">
                      {#if rule.name}<strong>{rule.name}</strong>{/if}
                      <ul class="rule-list" aria-label="Advanced conditions">
                        {#each conditionChips(rule) as chip, chipIndex (chipIndex)}
                          <li class="rule-chip">{chip}</li>
                        {/each}
                      </ul>
                      {#if SHOW_ADVANCED_ROUTING}
                        <button type="button" onclick={() => openRule(index)}>Edit…</button>
                      {/if}
                    </div>
                  {:else if kind === "match_all"}
                    <span class="muted">Matches every request</span>
                  {:else if kind === "host_levels"}
                    <div class="levels-editor">
                      <input
                        type="number"
                        min="0"
                        class="compact-num"
                        placeholder="min"
                        aria-label={`Rule ${index + 1} minimum host levels`}
                        value={rule.host_levels?.min ?? ""}
                        oninput={(e) =>
                          onHostLevelsChange(index, e.currentTarget.value, rule.host_levels?.max?.toString() ?? "")}
                      />
                      <span class="muted" aria-hidden="true">~</span>
                      <input
                        type="number"
                        min="0"
                        class="compact-num"
                        placeholder="max"
                        aria-label={`Rule ${index + 1} maximum host levels`}
                        value={rule.host_levels?.max ?? ""}
                        oninput={(e) =>
                          onHostLevelsChange(index, rule.host_levels?.min?.toString() ?? "", e.currentTarget.value)}
                      />
                    </div>
                  {:else if kind === "weekday"}
                    {@const days = parseWeekdays(rule.weekday)}
                    <div class="weekday-editor" role="group" aria-label={`Rule ${index + 1} weekdays`}>
                      {#each WEEKDAYS as day (day.key)}
                        <label class="day-check">
                          <input
                            type="checkbox"
                            checked={days[day.key]}
                            onchange={(e) => onWeekdayToggle(index, day.key, e.currentTarget.checked)}
                          />
                          <span>{day.label}</span>
                        </label>
                      {/each}
                    </div>
                  {:else if kind === "time"}
                    {@const range = parseTimeRange(rule.time)}
                    <div class="time-editor">
                      <input
                        type="time"
                        aria-label={`Rule ${index + 1} start time`}
                        value={range.start}
                        onchange={(e) => onTimeChange(index, e.currentTarget.value, range.end)}
                      />
                      <span class="muted" aria-hidden="true">–</span>
                      <input
                        type="time"
                        aria-label={`Rule ${index + 1} end time`}
                        value={range.end}
                        onchange={(e) => onTimeChange(index, range.start, e.currentTarget.value)}
                      />
                    </div>
                  {:else if kind === "cidr"}
                    <input
                      type="text"
                      class="detail-input"
                      spellcheck="false"
                      aria-label={`Rule ${index + 1} IP or CIDR`}
                      placeholder={conditionPlaceholder("cidr")}
                      aria-invalid={!!errors[`${errorPrefix}:${index}:cidr`] || !!errors[`${errorPrefix}:${index}:ip`]}
                      value={ruleDetailText(rule, "cidr")}
                      onchange={(e) => onDetailChange(index, "cidr", e.currentTarget.value)}
                    />
                  {:else}
                    <input
                      type="text"
                      class="detail-input"
                      spellcheck="false"
                      aria-label={`Rule ${index + 1} condition details`}
                      placeholder={conditionPlaceholder(kind)}
                      aria-invalid={problems.some(([k]) => !k.endsWith(":target"))}
                      value={ruleDetailText(rule, kind)}
                      oninput={(e) => onDetailChange(index, kind, e.currentTarget.value)}
                    />
                  {/if}

                  {#if matched || ((isUrlConditionKind(kind) || usesUrl(rule)) && !proxy.mitm)}
                    <div class="detail-badges">
                      {#if matched}<span class="pill ok">Matched</span>{/if}
                      {#if (isUrlConditionKind(kind) || usesUrl(rule)) && !proxy.mitm}
                        <span
                          class="pill alert"
                          title="HTTPS URLs are hidden unless MITM is on, so this only matches plain HTTP"
                        >
                          Needs MITM
                        </span>
                      {/if}
                    </div>
                  {/if}
                  {#each problems as [key, message] (key)}
                    <span class="field-error">{message}</span>
                  {/each}
                </div>
              </td>
              <td class="col-profile">
                {#if chain.length > 1}
                  <div class="failover-cell">
                    <span class="pill busy" title={formatTargetLabel(rule.target, tunnels, proxy.profiles)}>
                      failover ×{chain.length}
                    </span>
                    {#if SHOW_ADVANCED_ROUTING}
                      <button type="button" class="link-button" onclick={() => openRule(index)}>Edit…</button>
                    {:else}
                      <button
                        type="button"
                        class="link-button"
                        onclick={() => setRule(index, { ...rule, target: chain[0] ?? "direct" })}
                        title="Collapse failover chain to its primary target"
                      >
                        Simplify
                      </button>
                    {/if}
                  </div>
                {:else}
                  {@render profileSelect(
                    chain[0] ?? "direct",
                    `Rule ${index + 1} target profile`,
                    (next) => setRule(index, { ...rule, target: next }),
                    !!errors[`${errorPrefix}:${index}:target`],
                  )}
                {/if}
              </td>
              {#if showMitmBypass}
                {@const urlRule = isUrlConditionKind(kind) || usesUrl(rule)}
                <td class="col-mitm-bypass">
                  <input
                    type="checkbox"
                    checked={!urlRule && Boolean(rule.bypass_mitm)}
                    disabled={urlRule}
                    aria-label={`Rule ${index + 1} bypass MITM`}
                    title={urlRule
                      ? "URL conditions require MITM to inspect HTTPS URLs"
                      : "Skip HTTPS MITM interception for matching requests"}
                    onchange={(e) => toggleBypassMitm(index, e.currentTarget.checked)}
                  />
                </td>
              {/if}
              <td class="col-delete">
                <button
                  type="button"
                  class="icon danger"
                  aria-label={`Delete rule ${index + 1}`}
                  title="Delete condition"
                  onclick={() => removeRule(index)}
                >✕</button>
              </td>
            </tr>
          {/each}

          <!-- Pinned non-draggable Default row -->
          {#if tableKey === "unified" || activeDefault !== undefined}
            {@const defaultChain = targetList(activeDefault ?? routing.default)}
            {@const defaultError = errors[defaultErrorKey]}
            <tr class="routing-row default-row" class:matched={isDefaultMatched}>
              <td class="col-drag" aria-hidden="true"></td>
              <td class="col-enabled" aria-hidden="true"></td>
              <td class="col-type"><strong>Default</strong></td>
              <td class="col-details">
                <div class="detail-cell">
                  <span class="muted">Everything else</span>
                  {#if isDefaultMatched}
                    <div class="detail-badges"><span class="pill ok">Matched</span></div>
                  {/if}
                  {#if defaultError}<span class="field-error">{defaultError}</span>{/if}
                </div>
              </td>
              <td class="col-profile">
                {#if defaultChain.length > 1}
                  <div class="failover-cell">
                    <span class="pill busy" title={formatTargetLabel(defaultChain, tunnels, proxy.profiles)}>
                      failover ×{defaultChain.length}
                    </span>
                    <button
                      type="button"
                      class="link-button"
                      onclick={() => setActiveDefault(defaultChain[0] ?? "direct")}
                      title="Collapse failover chain to its primary target"
                    >
                      Simplify
                    </button>
                  </div>
                {:else}
                  {@render profileSelect(
                    defaultChain[0] ?? "direct",
                    "Default target profile",
                    (next) => setActiveDefault(next),
                    !!defaultError,
                  )}
                {/if}
              </td>
              {#if showMitmBypass}
                <td class="col-mitm-bypass" aria-hidden="true"></td>
              {/if}
              <td class="col-delete" aria-hidden="true"></td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
    <p class="sr-only" role="status">{announcement}</p>
  {/if}

  {#if tableKey === "unified"}
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
  {/if}

  {#if SHOW_ADVANCED_ROUTING}
    <details
      class="split-disclosure"
      open={splitTablesOpen}
      ontoggle={(e) => (splitTablesOpen = e.currentTarget.open)}
    >
      <summary>
        Advanced: HTTP / SOCKS split tables
        {#if routing.http || routing.socks}
          <span class="pill busy">active</span>
        {/if}
      </summary>
      <div class="split-body">
        <p class="muted">
          Optionally override routing separately for HTTP or SOCKS listeners.
        </p>
        <div class="segmented" role="group" aria-label="Routing table">
          {#each TABLES as table (table.value)}
            <button type="button" aria-pressed={tableKey === table.value} onclick={() => (tableKey = table.value)}>
              {table.label}
              {#if table.value !== "unified" && routing[table.value]}<span class="muted"> ●</span>{/if}
            </button>
          {/each}
        </div>
      </div>
    </details>
  {/if}
</section>

{#if SHOW_ADVANCED_ROUTING && editing}
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
        Match all (matches every request unconditionally; multiple conditions on one rule are always ANDed)
      </label>
      <label class="check"><input type="checkbox" bind:checked={form.disabled} /> Disabled</label>
      {#if showMitmBypass}
        <label class="check">
          <input type="checkbox" bind:checked={form.bypass_mitm} />
          Bypass HTTPS MITM (tunnel matching HTTPS connections without interception)
        </label>
      {/if}
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
          <dd>
            {result.matched_rule ?? "Default (everything else)"}
            {#if showMitmBypass && result.bypass_mitm}
              <span class="pill idle">MITM bypassed</span>
            {/if}
          </dd>
          <dt>Route</dt>
          <dd>
            <ol class="plain-list">
              {#each result.targets as target, index (index)}
                <li>
                  {index + 1}. <strong>{formatTargetLabel(target.name, tunnels, proxy.profiles)}</strong>
                  {#if target.profile !== target.name}
                    <span class="muted">via {formatTargetLabel(target.profile, tunnels, proxy.profiles)}</span>
                  {/if}
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
  .routing-table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .routing-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
  }
  .routing-table th,
  .routing-table td {
    padding: 5px 6px;
    text-align: left;
    vertical-align: middle;
    border-bottom: 1px solid var(--border);
  }
  .routing-table th {
    color: var(--muted);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }
  .routing-table tbody tr:last-child td {
    border-bottom: 0;
  }
  .col-drag {
    width: 28px;
    text-align: center;
  }
  .col-enabled {
    width: 28px;
    text-align: center;
  }
  .col-type {
    width: 165px;
  }
  .col-type select {
    width: 100%;
  }
  .col-details {
    min-width: 220px;
  }
  .col-profile {
    width: 210px;
  }
  .col-profile .profile-select {
    width: 100%;
  }
  .routing-table th.col-mitm-bypass,
  .routing-table td.col-mitm-bypass {
    width: 34px;
    text-align: center;
  }
  .mitm-bypass-icon {
    display: inline-block;
    vertical-align: middle;
  }
  .col-delete {
    width: 32px;
    text-align: center;
  }
  .routing-row.off {
    opacity: 0.55;
  }
  .routing-row.matched {
    background: color-mix(in srgb, var(--ok) 12%, transparent);
  }
  .routing-row.dragging {
    opacity: 0.45;
  }
  .routing-row.drop-before td {
    box-shadow: inset 0 2px 0 0 var(--accent);
  }
  .routing-row.drop-after td {
    box-shadow: inset 0 -2px 0 0 var(--accent);
  }
  .default-row {
    background: var(--surface-2);
  }
  .detail-cell {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .detail-input {
    width: 100%;
    min-width: 0;
  }
  .detail-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .levels-editor,
  .time-editor {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .compact-num {
    width: 72px;
  }
  .weekday-editor {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 8px;
  }
  .day-check {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    font-size: 12px;
    cursor: pointer;
  }
  .advanced-summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .failover-cell {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .bad-select {
    border-color: var(--alert);
    color: var(--alert);
  }
  .override-controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }
  .split-disclosure {
    border-top: 1px solid var(--border);
    padding-top: 8px;
  }
  .split-disclosure summary {
    cursor: pointer;
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .split-body {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 8px;
  }
  .target-chain {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    list-style: none;
    margin: 0.25rem 0;
    padding: 0;
  }
  .matcher-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
    gap: 0.75rem 0.6rem;
    align-items: stretch;
  }
  .matcher-grid .field {
    justify-content: space-between;
  }
  .matcher-grid .field > input,
  .matcher-grid .field > textarea,
  .matcher-grid .field > select {
    margin-top: auto;
  }
  .matcher-grid .field-row {
    align-items: end;
  }
  .rule-drawer {
    border-left: 3px solid var(--accent);
  }
</style>
