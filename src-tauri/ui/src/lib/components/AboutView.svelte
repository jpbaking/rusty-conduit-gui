<script lang="ts">
  import { errorMessage, openExternal } from "../api";
  import { releaseNotesUrl, releaseStage } from "../version";

  /** The release tag's version, such as `0.2.0-beta.6`, or `0.2.0-dev` for a local build. */
  const VERSION = __APP_VERSION__;
  /** The tag's label (`beta`), shown as a pill; none for a final release. */
  const STAGE = releaseStage(VERSION);
  const ENGINE_VERSION = __ENGINE_VERSION__;
  const REPO = "https://github.com/jpbaking/rusty-conduit-gui";

  const LINKS: { label: string; url: string; note: string }[] = [
    {
      label: "Website",
      url: "https://jpbaking.github.io/rusty-conduit-series/",
      note: "Guides and use cases for the whole Rusty Conduit family",
    },
    { label: "Source code", url: REPO, note: "jpbaking/rusty-conduit-gui on GitHub" },
    {
      label: "Release notes",
      url: releaseNotesUrl(REPO, VERSION),
      note: STAGE === "dev" ? "What changed in each version" : `What changed in ${VERSION}`,
    },
    { label: "Report an issue", url: `${REPO}/issues`, note: "Bugs and feature requests" },
  ];

  let linkError = $state<string | null>(null);
  let copied = $state(false);

  async function open(event: MouseEvent, url: string) {
    // Keep the Manage Window on the app: hand the page to the default browser instead.
    event.preventDefault();
    linkError = null;
    try {
      await openExternal(url);
    } catch (error) {
      linkError = `Could not open ${url}: ${errorMessage(error)}`;
    }
  }

  async function copyVersion() {
    try {
      await navigator.clipboard.writeText(`Rusty Conduit GUI v${VERSION} (rusty-conduit-engine ${ENGINE_VERSION})`);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      // The clipboard can be unavailable in restricted webviews; the text stays selectable.
    }
  }
</script>

<main class="content">
  <div class="about">
    <header class="about-hero">
      <svg class="about-logo" viewBox="0 0 64 64" width="72" height="72" aria-hidden="true">
        <circle cx="32" cy="32" r="30" fill="#2563eb" />
        <rect x="2" y="29" width="60" height="6" fill="#fff" />
        <circle cx="32" cy="32" r="11" fill="none" stroke="#fff" stroke-width="6" />
      </svg>
      <div>
        <h1>
          Rusty Conduit GUI
          {#if STAGE}<span class="stage-tag" title={STAGE === "dev" ? "A local build, not a release" : undefined}>{STAGE}</span>{/if}
        </h1>
        <p class="about-version">
          <span>Version {VERSION}</span>
          <button class="link-button" onclick={copyVersion} title="Copy version details">
            {copied ? "Copied" : "Copy"}
          </button>
        </p>
        <p class="muted">Built on rusty-conduit-engine {ENGINE_VERSION}</p>
      </div>
    </header>

    <section class="about-card" aria-labelledby="about-what">
      <h2 id="about-what">What it does</h2>
      <p>
        One tray app and Manage Window for the Rusty Conduit proxy family. Build local
        <strong>Proxies</strong> whose traffic goes direct, through <strong>SSH Tunnels</strong>, through
        other upstream proxies, or wherever <strong>Auto Switch</strong> rules send it. Save, run,
        autostart, and auto-reconnect them all at once, without touching <code>~/.ssh</code>.
      </p>
      <p class="muted">
        Secrets stay in an encrypted vault. Made for development, testing, labs, and homelabs.
      </p>
    </section>

    <section class="about-card" aria-labelledby="about-links">
      <h2 id="about-links">Links</h2>
      <ul class="about-links">
        {#each LINKS as link (link.url)}
          <li>
            <a href={link.url} onclick={(e) => open(e, link.url)}>{link.label}</a>
            <span class="muted">{link.note}</span>
          </li>
        {/each}
      </ul>
      {#if linkError}<p class="reason" role="alert">{linkError}</p>{/if}
    </section>

    <p class="muted about-legal">
      Copyright © 2026 Joseph Baking. Released under the BSD 3-Clause License. Built with Tauri,
      Svelte, and Rust.
    </p>
  </div>
</main>

<style>
  .about {
    display: flex;
    flex-direction: column;
    gap: 12px;
    max-width: 640px;
  }
  .about-hero {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 4px 0 8px;
  }
  .about-logo {
    flex: none;
  }
  .about-hero h1 {
    margin: 0 0 4px;
    font-size: 22px;
  }
  .about-hero p {
    margin: 0;
  }
  .stage-tag {
    margin-left: 6px;
    padding: 1px 8px;
    border: 1px solid var(--busy);
    border-radius: 999px;
    color: var(--busy);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    vertical-align: middle;
  }
  .about-version {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    user-select: text;
  }
  .link-button {
    font-size: 11px;
    padding: 1px 8px;
  }
  .about-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .about-card h2,
  .about-card p {
    margin: 0;
  }
  .about-links {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .about-links li {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px 10px;
  }
  .about-links a {
    color: var(--accent);
    font-weight: 600;
  }
  .about-legal {
    margin: 0;
    font-size: 12px;
  }
</style>
