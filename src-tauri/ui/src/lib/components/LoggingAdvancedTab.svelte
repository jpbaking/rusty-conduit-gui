<script lang="ts">
  import { untrack } from "svelte";
  import { store } from "../stores.svelte";
  import type { LoggingConfig, OpenSshOptions, SessionProfile } from "../types";
  import { denylistedFlag, LOG_FORMATS, LOG_LEVELS, redactArgs } from "../validate";
  import PortField from "./PortField.svelte";

  const parseArgs = (text: string) =>
    text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "");

  const sameArgs = (a: readonly string[], b: readonly string[]) =>
    a.length === b.length && a.every((arg, index) => arg === b[index]);

  const uid = $props.id();
  const draft = $derived(store.draft as SessionProfile);
  const logging = $derived(draft.logging);
  const openssh = $derived(draft.openssh);
  const errors = $derived(store.draftErrors);
  // The backend accepts any letter case. Showing the canonical form keeps the select in step.
  const level = $derived(logging.level.trim().toUpperCase());
  const format = $derived(logging.format.trim().toLowerCase());
  const argErrors = $derived(
    openssh.extra_args.flatMap((_, index) => errors[`openssh.extra_args:${index}`] ?? []),
  );
  const preview = $derived(
    [openssh.ssh_bin.trim() || "ssh", "[managed options]", ...redactArgs(openssh.extra_args)].join(" "),
  );

  // Raw text, so a newline being typed is not removed before the next argument exists.
  let argsText = $state(untrack(() => openssh.extra_args.join("\n")));

  $effect(() => {
    const saved = openssh.extra_args;
    if (!sameArgs(saved, parseArgs(untrack(() => argsText)))) argsText = saved.join("\n");
  });

  function setLogging(patch: Partial<LoggingConfig>) {
    store.updateDraft((p) => ({ ...p, logging: { ...p.logging, ...patch } }));
  }

  function setOpenssh(patch: Partial<OpenSshOptions>) {
    store.updateDraft((p) => ({ ...p, openssh: { ...p.openssh, ...patch } }));
  }
</script>

<section aria-labelledby={`${uid}-logging`}>
  <h2 id={`${uid}-logging`}>Logging</h2>
  <div class="field-row">
    <div class="field grow">
      <label class="field">
        Level
        <select value={level} onchange={(e) => setLogging({ level: e.currentTarget.value })}>
          {#each LOG_LEVELS as option (option)}<option value={option}>{option}</option>{/each}
        </select>
      </label>
      {#if errors["logging.level"]}<span class="field-error">{errors["logging.level"]}</span>{/if}
    </div>
    <div class="field grow">
      <label class="field">
        Format
        <select value={format} onchange={(e) => setLogging({ format: e.currentTarget.value })}>
          {#each LOG_FORMATS as option (option)}<option value={option}>{option}</option>{/each}
        </select>
      </label>
      {#if errors["logging.format"]}<span class="field-error">{errors["logging.format"]}</span>{/if}
    </div>
  </div>
  <div class="field-row">
    <label class="field grow">
      HTTP access log file <small class="muted">optional</small>
      <input
        value={logging.http_access_log ?? ""}
        spellcheck="false"
        oninput={(e) => setLogging({ http_access_log: e.currentTarget.value || null })}
      />
    </label>
    <label class="field grow">
      SOCKS log file <small class="muted">optional</small>
      <input
        value={logging.socks_log ?? ""}
        spellcheck="false"
        oninput={(e) => setLogging({ socks_log: e.currentTarget.value || null })}
      />
    </label>
  </div>
</section>

<section aria-labelledby={`${uid}-openssh`}>
  <h2 id={`${uid}-openssh`}>OpenSSH only <small class="muted">used when the engine is OpenSSH</small></h2>
  <div class="field-row">
    <div class="field grow">
      <label class="field">
        ssh program
        <input
          value={openssh.ssh_bin}
          spellcheck="false"
          aria-invalid={!!errors["openssh.ssh_bin"]}
          oninput={(e) => setOpenssh({ ssh_bin: e.currentTarget.value })}
        />
      </label>
      {#if errors["openssh.ssh_bin"]}<span class="field-error">{errors["openssh.ssh_bin"]}</span>{/if}
    </div>
    <div class="field grow">
      <label class="field">
        SOCKS bind address
        <input
          value={openssh.ssh_socks_bind}
          spellcheck="false"
          aria-invalid={!!errors["openssh.ssh_socks_bind"]}
          oninput={(e) => setOpenssh({ ssh_socks_bind: e.currentTarget.value.trim() })}
        />
      </label>
      {#if errors["openssh.ssh_socks_bind"]}
        <span class="field-error">{errors["openssh.ssh_socks_bind"]}</span>
      {/if}
    </div>
    <PortField
      label="SOCKS port"
      value={openssh.ssh_socks_port}
      error={errors["openssh.ssh_socks_port"]}
      onValue={(ssh_socks_port) => setOpenssh({ ssh_socks_port })}
    />
  </div>

  <label class="field">
    Extra arguments <small class="muted">one per line, passed to ssh as written</small>
    <textarea
      class="code-text"
      bind:value={argsText}
      spellcheck="false"
      aria-invalid={argErrors.length > 0}
      oninput={(e) => setOpenssh({ extra_args: parseArgs(e.currentTarget.value) })}
    ></textarea>
  </label>

  {#if openssh.extra_args.length > 0}
    <ul class="rule-list" aria-label="Parsed arguments">
      {#each openssh.extra_args as arg, index (`${index}:${arg}`)}
        <li class="rule-chip" class:bad={denylistedFlag(arg) !== null}>{arg}&nbsp;</li>
      {/each}
    </ul>
  {/if}
  {#each argErrors as problem, index (index)}
    <span class="field-error">{problem} It breaks tunnel isolation.</span>
  {/each}

  <div class="field">
    Command preview <small class="muted">values are hidden</small>
    <code class="command-preview">{preview}</code>
  </div>
</section>
