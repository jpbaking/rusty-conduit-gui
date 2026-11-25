<script lang="ts">
  import { untrack } from "svelte";
  import { opensshCheck } from "../opensshCheck.svelte";
  import { store } from "../stores.svelte";
  import type { LoggingConfig, OpenSshOptions, SessionProfile } from "../types";
  import { configLineArgs, denylistedFlag, isIpAddress, isLoopback, LOG_FORMATS, LOG_LEVELS, redactArgs } from "../validate";
  import BrowseButton from "./BrowseButton.svelte";
  import PortField from "./PortField.svelte";

  /** Long enough that a path being typed is not run one partial value at a time. */
  const AUTO_CHECK_DELAY_MS = 500;

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
  // Lines written like ssh_config, which ssh would not read as options.
  const configLines = $derived(configLineArgs(openssh.extra_args));

  /** Rewrites one ssh_config-style line as `-o` and `Keyword=value`. */
  function fixConfigLine(index: number, fix: [string, string]) {
    const args = [...openssh.extra_args];
    args.splice(index, 1, ...fix);
    setOpenssh({ extra_args: args });
  }

  const preview = $derived(
    [openssh.ssh_bin.trim() || "ssh", "[managed options]", ...redactArgs(openssh.extra_args)].join(" "),
  );

  // Raw text, so a newline being typed is not removed before the next argument exists.
  let argsText = $state(untrack(() => openssh.extra_args.join("\n")));

  $effect(() => {
    const saved = openssh.extra_args;
    if (!sameArgs(saved, parseArgs(untrack(() => argsText)))) argsText = saved.join("\n");
  });

  // Primitive values, so edits to other draft fields do not trigger a new check.
  const sshBin = $derived(openssh.ssh_bin.trim());
  const usesOpenssh = $derived(draft.engine === "OpenSsh");
  // ssh's own SOCKS listener has no filters or MITM, so it should stay on this machine.
  const socksExposed = $derived(
    isIpAddress(openssh.ssh_socks_bind) && !isLoopback(openssh.ssh_socks_bind),
  );

  const check = opensshCheck;
  // Only a result for the program in the field is shown, never one for an earlier value.
  const shown = $derived(usesOpenssh && check.bin === sshBin);
  const binInfo = $derived(shown ? check.info : null);
  const binStatus = $derived(shown ? check.status : null);
  const binError = $derived(shown ? check.error : null);
  const checkingBin = $derived(shown && check.checking);

  function checkBinary() {
    void check.run(sshBin);
  }

  // While the OpenSSH engine is chosen, a changed program is checked once typing pauses.
  $effect(() => {
    const bin = sshBin;
    if (!usesOpenssh || check.covers(bin)) return;
    const timer = setTimeout(() => check.ensure(bin), AUTO_CHECK_DELAY_MS);
    return () => clearTimeout(timer);
  });

  const LOG_FILES = [{ name: "Log files", extensions: ["log", "txt", "jsonl"] }];

  function setLogging(patch: Partial<LoggingConfig>) {
    store.updateDraft((p) => ({ ...p, logging: { ...p.logging, ...patch } }));
  }

  function setOpenssh(patch: Partial<OpenSshOptions>) {
    store.updateDraft((p) => ({ ...p, openssh: { ...p.openssh, ...patch } }));
  }
</script>

<section class="card" aria-labelledby={`${uid}-logging`}>
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
    <div class="field grow">
      <label for={`${uid}-http-log`}>HTTP access log file <small class="muted">optional</small></label>
      <div class="inline-form">
        <input
          id={`${uid}-http-log`}
          value={logging.http_access_log ?? ""}
          spellcheck="false"
          oninput={(e) => setLogging({ http_access_log: e.currentTarget.value || null })}
        />
        <BrowseButton
          mode="save"
          title="HTTP access log file"
          defaultPath={logging.http_access_log || "http-access.log"}
          filters={LOG_FILES}
          onPick={(path) => setLogging({ http_access_log: path })}
        />
      </div>
    </div>
    <div class="field grow">
      <label for={`${uid}-socks-log`}>SOCKS log file <small class="muted">optional</small></label>
      <div class="inline-form">
        <input
          id={`${uid}-socks-log`}
          value={logging.socks_log ?? ""}
          spellcheck="false"
          oninput={(e) => setLogging({ socks_log: e.currentTarget.value || null })}
        />
        <BrowseButton
          mode="save"
          title="SOCKS log file"
          defaultPath={logging.socks_log || "socks.log"}
          filters={LOG_FILES}
          onPick={(path) => setLogging({ socks_log: path })}
        />
      </div>
    </div>
  </div>
</section>

<section class="card" class:inactive={!usesOpenssh} aria-labelledby={`${uid}-openssh`}>
  <h2 id={`${uid}-openssh`}>OpenSSH engine</h2>
  {#if !usesOpenssh}
    <p class="note">
      Not used: this session runs on the built-in Rust SSH engine. Choose OpenSSH as the engine on
      the Connection tab to edit these settings.
    </p>
  {/if}
  <!-- A disabled fieldset turns off every control inside it, buttons included. -->
  <fieldset class="card-body" disabled={!usesOpenssh}>
  <legend class="sr-only">OpenSSH engine settings</legend>
  <div class="field-row">
    <div class="field grow">
      <label for={`${uid}-ssh-bin`}>ssh program</label>
      <div class="inline-form">
        <input
          id={`${uid}-ssh-bin`}
          value={openssh.ssh_bin}
          spellcheck="false"
          aria-invalid={!!errors["openssh.ssh_bin"]}
          oninput={(e) => setOpenssh({ ssh_bin: e.currentTarget.value })}
        />
        <BrowseButton mode="open" title="Choose the ssh program" onPick={(path) => setOpenssh({ ssh_bin: path })} />
        <button type="button" disabled={checkingBin} onclick={checkBinary}>
          {checkingBin ? "Checking…" : "Check binary"}
        </button>
      </div>
      {#if errors["openssh.ssh_bin"]}<span class="field-error">{errors["openssh.ssh_bin"]}</span>{/if}
    </div>
    <div class="field grow">
      <label class="field">
        Internal SOCKS bind
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
      label="Internal SOCKS port"
      value={openssh.ssh_socks_port}
      error={errors["openssh.ssh_socks_port"]}
      onValue={(ssh_socks_port) => setOpenssh({ ssh_socks_port })}
    />
  </div>
  <p class="note">
    <strong>Not the proxy your apps use.</strong> With the OpenSSH engine, <code>ssh</code> opens its
    own SOCKS listener here (<code>ssh -D</code>), and the proxy on the Proxy tab sends its traffic
    through it. Point browsers and tools at the Proxy tab's ports. Port 0 picks a free port each
    time the session connects.
  </p>
  {#if socksExposed}
    <p class="warning">
      This address is not loopback, so other devices may reach ssh's SOCKS listener directly. It
      skips the Proxy tab's filters and MITM. Use 127.0.0.1 unless you need otherwise.
    </p>
  {/if}

  <div role="status">
    {#if binInfo && binStatus}
      <p><span class={`pill ${binStatus.tone}`}>{binStatus.label}</span></p>
      <dl class="fact-list">
        <dt>Version</dt>
        <dd>{binInfo.version_raw ?? "Unknown"}</dd>
        <dt>Path</dt>
        <dd>{binInfo.resolved_path ?? "Not found"}</dd>
      </dl>
      {#if binInfo.supported && binInfo.note}
        <p class="warning">{binInfo.note}</p>
      {:else if binStatus.tone === "busy"}
        <p class="warning">{binInfo.message}</p>
      {:else if binStatus.tone === "alert"}
        <p class="field-error">{binInfo.message}</p>
      {/if}
    {/if}
    {#if binError}<p class="field-error">Could not check the program: {binError}</p>{/if}
  </div>

  <label class="field">
    <span>
      Extra arguments
      <small class="muted">ssh command-line arguments, not ssh_config lines · one argument per line</small>
    </span>
    <textarea
      class="code-text"
      bind:value={argsText}
      spellcheck="false"
      placeholder={"-o\nCompression=yes\n-v"}
      aria-describedby={`${uid}-args-help`}
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
  <p id={`${uid}-args-help`} class="note">
    Each line is passed to <code>ssh</code> as one command-line argument, exactly as written. To
    set an ssh_config option, put <code>-o</code> on one line and <code>Option=value</code> on the
    next, such as <code>-o</code> then <code>Compression=yes</code>. A flag and its value can also
    share a line with no space: <code>-oCompression=yes</code>.
  </p>
  {#each configLines as line (line.index)}
    <div class="warning config-line">
      <span>
        Line {line.index + 1}, <code>{openssh.extra_args[line.index]}</code>, is written like an
        ssh_config line, so ssh would not read it as an option.
        {#if line.fix}
          Write it as <code>{line.fix[0]}</code> then <code>{line.fix[1]}</code>.
        {:else}
          {line.keyword} blocks are not supported here: every option applies to the whole session.
        {/if}
      </span>
      {#if line.fix}
        {@const fix = line.fix}
        <button type="button" onclick={() => fixConfigLine(line.index, fix)}>Fix</button>
      {/if}
    </div>
  {/each}
  {#each argErrors as problem, index (index)}
    <span class="field-error">{problem} It breaks tunnel isolation.</span>
  {/each}

  <div class="field">
    <span>Command preview <small class="muted">values are hidden</small></span>
    <code class="command-preview">{preview}</code>
  </div>
  </fieldset>
</section>
