# Rusty Conduit GUI — Master Plan

> **Status:** Draft v2 (Unification Plan). Supersedes the v1 "Rusty Conduit SSH GUI" plan, whose phases 0–6 shipped as `v0.1.0-beta.1`…`beta.5`, and the unimplemented `rusty-conduit-switch-gui` draft.
> **App:** **Rusty Conduit GUI**, repository `rusty-conduit-gui` (renamed from `rusty-conduit-ssh-gui`; see §3).
> **Engine:** [`rusty-conduit-engine`](../rusty-conduit-engine/docs/MASTER-PLAN.md) (shared by `rusty-conduit`, `rusty-conduit-ssh`, `rusty-conduit-switch`), replacing the direct dependency on `rusty-conduit-ssh`.
> **Work branch:** `feat/one-gui`. Engine work happens on `feat/one-engine` in the three CLI repositories.
> **Platforms:** Windows (x64/arm64), macOS (Universal Apple Silicon + Intel), Linux (x64/arm64 — XFCE/X11 & Wayland, KDE, GNOME, wlroots).

---

## 1. Vision & Core Requirements

One lightweight, cross-platform **system tray app** and **Manage Window** for the whole Rusty Conduit family. Users no longer pick between a plain proxy, an SSH proxy, and an Auto Switch proxy, or run several tray apps chained over loopback: they build **Proxies** whose traffic goes direct, through **SSH Tunnels**, through other upstream proxies, or wherever **Auto Switch rules** send it.

### 1.1 Concepts

| Concept | What it is | Covers |
| :--- | :--- | :--- |
| **Proxy** | Local HTTP/HTTPS + SOCKS4/4a/5 listeners (optionally one multiplexed port) with a routing table, global filter, optional MITM, and logging. | `rusty-conduit`, `rusty-conduit-switch` |
| **Tunnel** | A saved SSH connection (multi-hop jump chain, auth, host-key pins, keepalive/reconnect, `russh` or OpenSSH engine) plus its reverse proxy (`-R`) and fixed `-L`/`-R` port forwards. | `rusty-conduit-ssh` |
| **Upstream Profile** | A named target a Proxy routes to: built-in `direct` / `block`, `http`, `https`, `socks5`, `socks4a`, `composite`, or **`tunnel`** (one of the user's Tunnels). | `rusty-conduit-switch` profiles + SSH |
| **Vault** | `vault.bin`: SSH keys, hop passwords, upstream proxy passwords, MITM CAs. | All |

The three CLIs become three presets of the same thing:

```text
rusty-conduit         = Proxy  → default: direct
rusty-conduit-ssh     = Proxy  → default: tunnel "Prod Bastion"     (+ the Tunnel's reverse proxy)
rusty-conduit-switch  = Proxy  → rules → [corp, tunnel "Bastion", direct]
```

### 1.2 Non-Negotiable Requirements

1. **Full option parity with all three CLIs.** Every `rusty-conduit`, `rusty-conduit-ssh`, and `rusty-conduit-switch` option is configurable from the Manage Window. Because the GUI and the CLIs run the same engine, parity is structural, not re-implemented.
2. **No regression for existing users.** Sessions, keys, CAs, host-key pins, presets, and settings from `v0.1.0` betas load unchanged after the upgrade and rename (§3.3, §6.4); each old session keeps its ports and behavior.
3. **Everything from v1 stays:** first-class multi-hop jump chains, saved password and keyboard-interactive auth with lockout protection, zero `~/.ssh` dependence (config, keys, `known_hosts`, `SSH_AUTH_SOCK`), no agent forwarding, dual SSH engine, encrypted vault, sleep/wake reconnect.
4. **Auto Switch routing** with a visual rule builder, failover chains, split HTTP/SOCKS tables, all condition matchers, and a live **Route Tester**.
5. **Zero-downtime hot-reload:** saving profile, rule, filter, timeout, or keepalive changes on a running Proxy swaps its `ArcSwap<RoutingState>` without dropping connections; non-reloadable changes (bind, ports, `max_connections`, MITM CA, log sinks) show a **Restart to Apply** banner.
6. **Import & interop:** AirSwitch / ZeroOmega / SwitchyOmega `.bak` import, and `config.toml` import/export for all three CLIs, with secrets moved into the vault and never written out in plaintext.
7. **Zero caching and remote DNS preserved:** no HTTP response or DNS caching; hostnames routed to a Tunnel or proxy upstream are sent unresolved; MITM strictly opt-in and never auto-generates a CA.
8. **True cross-platform desktop and tray,** low idle RAM with the Manage Window closed (v1 §4 rules unchanged).

---

## 2. Architecture Decisions (ADR Summary)

| Area | Decision | Rationale |
| :--- | :--- | :--- |
| **Engine** | **Embed `rusty-conduit-engine`**, not the CLI crates. Path dependency during development; pinned git tag at release (engine plan §5). | Embedding all three CLIs would ship three diverged copies of the HTTP/SOCKS/MITM front end. The engine has the router, upstream dialers, and hot-reload `-switch` built, plus the extension points this app needs (engine plan §4). |
| **Tunnels as dialers** | Each running Tunnel registers an **external dialer** (`ProfileRegistry::with_external`) that Proxies reference as a `tunnel` profile. `russh` channels are returned as `UpstreamStream::Boxed`. The OpenSSH engine's dialer speaks SOCKS5 to its worker's `ssh -D` port, gated on tunnel state. | One routing model for every upstream. Removes the per-dial loopback TCP pair. Failover works naturally: a down Tunnel returns `NotConnected`, so `["bastion", "direct"]` falls through. |
| **SSH engines** | Unchanged from v1: **`russh` default** (pure Rust, `ring`) + **opt-in isolated OpenSSH** worker. | Proven in v0.1.0 betas (§4). |
| **Process & UI isolation** | UI-agnostic Rust workspace; proxies, tunnels, vault, and tray live outside the webview; destroy webview on close. | Unchanged from v1. |
| **Desktop GUI** | Tauri v2 + Svelte 5 + TypeScript. | Unchanged. |
| **System tray** | `TrayBackend` trait: Tauri tray on Windows/macOS, `ksni` on Linux. | Unchanged. |
| **Secret vault** | Hybrid envelope encryption (`vault.bin`), adding one record type: upstream proxy passwords. | Unchanged design; one vault for the family instead of one per app. |
| **Hot-reload** | In-process `ArcSwap<RoutingState>` swap per Proxy; tray overrides swap a temporary rule-less `RoutingState`. | From the switch-gui draft. |
| **Identity** | Rename to **Rusty Conduit GUI** with a one-time data migration (§3). | The app is no longer SSH-only. |

---

## 3. Rebrand: `rusty-conduit-ssh-gui` → `rusty-conduit-gui`

### 3.1 Names

| Item | Before | After |
| :--- | :--- | :--- |
| GitHub repository | `jpbaking/rusty-conduit-ssh-gui` | `jpbaking/rusty-conduit-gui` (GitHub redirects old URLs and remotes) |
| Local folder | `rusty-conduit-ssh-gui/` | `rusty-conduit-gui/` (renamed by hand, after the GitHub rename) |
| Product name / window & tray title | `Rusty Conduit (SSH)` (`tauri.conf.json`, `conduit-tray::model::APP_TITLE`) | `Rusty Conduit GUI` |
| Cargo package & binary | `rusty-conduit-ssh-gui` (`src-tauri/Cargo.toml`) | `rusty-conduit-gui` |
| Bundle identifier | `io.github.rusty-conduit-ssh-gui` | `io.github.rusty-conduit-gui` |
| Autostart entry | `rusty-conduit-ssh-gui` (`AUTOSTART_NAME`) | `rusty-conduit-gui` |
| Crate descriptions, README, `docs/RELEASING.md`, `--help` text | "Rusty Conduit SSH GUI" | "Rusty Conduit GUI" |
| CI / release workflows, `scripts/validate-release-config.py`, `scripts/smoke-test-bundle.py` | `rusty-conduit-ssh-gui` paths and binary names; `UPSTREAM_REPO = rusty-conduit-ssh` | new names; upstream checkout of `rusty-conduit-engine` |
| Keyring service | `conduit-vault` | **unchanged** (already generic; keeps existing DEKs reachable) |
| Crate names | `conduit-*` | **unchanged** (already generic) |

### 3.2 Order of operations

1. On `feat/one-gui`: change every name in §3.1 in code, configs, scripts, and docs; implement the migration in §3.3; CI green.
2. Rename the GitHub repository (`gh repo rename rusty-conduit-gui`), then update repository variables (`UPSTREAM_REPO`, `UPSTREAM_REF`) if set.
3. Rename the local folder by hand, then `git remote set-url origin git@github.com:jpbaking/rusty-conduit-gui.git` (optional; the redirect works) and `cargo clean` (the old `target/` embeds absolute paths).
4. Update sibling docs that link to `../rusty-conduit-ssh-gui` (engine plan, CLI READMEs if any).
5. Archive or delete `rusty-conduit-switch-gui/` (its draft plan is folded into this document).

### 3.3 One-time upgrade migration (changing the bundle identifier moves the app data directory)

Tauri's `app_data_dir()` is derived from the identifier, so `v0.1.0` data (`vault.bin`, sessions, host profiles, `known_hosts.json`, presets, settings) would be invisible after the rename without this step. On startup, before opening any store:

1. If the new data directory does not exist and the old one does, **move** it (atomic rename on the same volume; copy-then-verify-then-remove across volumes), keeping owner-only permissions. Never merge into a non-empty new directory; show a notice instead.
2. If login autostart was enabled under the old name, register the new entry and remove the old one (Windows Run key, macOS LaunchAgent, Linux `~/.config/autostart/rusty-conduit-ssh-gui.desktop`).
3. Leave the old keyring entries in place (service `conduit-vault`, keyed by vault id, which does not change).
4. Record the migration in the diagnostic log and show a one-time "Rusty Conduit (SSH) is now Rusty Conduit GUI" banner.
5. **Single-instance across names:** during the transition, the new app refuses to start (with a clear message) if the old `Rusty Conduit (SSH)` is still running, so two apps never bind the same ports or write the same vault.

Platform packaging (Phase U5): Windows installs under a new product name, so the NSIS installer detects and offers to uninstall `Rusty Conduit (SSH)`; Linux `.deb`/`.rpm` declare `Replaces`/`Conflicts` (`Obsoletes`) on the old package; macOS users delete the old `.app`. On macOS, the Keychain may ask once to allow the renamed app to read the vault key (unsigned/ad-hoc builds change identity on every update anyway).

---

## 4. Tunnels (SSH) — carried forward from v1

The v1 design is implemented and stays authoritative; the only change is the integration point (§4.2).

### 4.1 Dual engine
- **`russh` (default):** pure Rust with `ring`; per-hop auth over nested `direct-tcpip`; remote-only DNS; strict host-key pinning. Verified with a 3-hop chain (encrypted Ed25519 → password → key) and 20 MiB round-trips both directions.
- **OpenSSH (opt-in):** for raw `extra_args`, custom `ProxyCommand`, GSSAPI, and FIDO2/hardware keys. One `conduit-worker` subprocess per tunnel (orphan-guarded: Job Object / `PR_SET_PDEATHSIG` / PID sweep), hardened per-tunnel `-F` in a short space-free path, per-hop `ProxyCommand` wrapper with authenticated IPC askpass (never `ProxyJump`, never prompt parsing), `extra_args` isolation denylist, Windows OpenSSH ≥ 8.4.
- **Why not OpenSSH-only:** `ProxyJump` breaks multi-hop passwords and paths with spaces; `-F none` still reads `~/.ssh/id_*` and `known_hosts`; Windows quirks (see v1 history in git).

### 4.2 Integration with the engine (changed)
- `RusshDialer` returns the SSH channel as `UpstreamStream::Boxed` — the loopback TCP pair is removed.
- `russh::ChannelOpenFailure` maps to typed dial errors (`ConnectFailed` → refused, `AdministrativelyProhibited` → permission denied, timeout → timed out) so HTTP `502`/`504` and SOCKS reply codes stay accurate.
- A running Tunnel registers its dialer with every Proxy that references it; while reconnecting, it returns `NotConnected` (failover chains move on; single-target routes fail fast as today).
- **Reverse proxy (`-R`)** is a Tunnel feature: a local engine `Server` with direct egress and the reverse allow/block filter, bound once on ephemeral loopback ports that survive reconnects, exposed via `tcpip-forward`. Unexpected `forwarded-tcpip` addresses are rejected.
- **Port forwards (`-L`/`-R`)** and presets: unchanged.

### 4.3 Lifecycle & security (unchanged)
- Sequential hop connect with host-key verification **before** credentials; ordered per-hop auth (vault key / password / keyboard-interactive / explicit system-agent opt-in).
- **Lockout protection:** auth failure or host-key mismatch → `NeedsAttention`, no auto-retry.
- Backoff reset only after stable uptime (5 s when `-R` is active).
- Hardening: reject agent-forward channels; reject unrequested `forwarded-tcpip`; never use `russh`'s `~/.ssh/known_hosts` helpers; no agent forwarding at all (removed 2026-11-25; `-A`/`ForwardAgent` in the OpenSSH denylist).
- Host keys: app-owned `known_hosts.json` keyed by `hop_id + host + port`; TOFU via approval modal; unattended starts never trust unknown keys; changed key is a hard stop with tray alert; optional one-time manual import from a `known_hosts` file.
- Sleep/wake: debounced (2–5 s) recycle of `Connected`/`Reconnecting` tunnels on OS wake events.

```text
Tunnel:  Stopped ─► Starting ─► Connected ◄─► Reconnecting (backoff)
                       ├─► WaitingForNetwork
                       ├─► Locked (vault locked)
                       ├─► AwaitingHostKey ─► NeedsAttention (auth / host key; no auto-retry)
                       └─► Failed
```

---

## 5. Proxies & Routing — new (from the switch-gui draft)

### 5.1 Runtime
For each Proxy start:
1. Resolve vaulted upstream passwords into zeroized memory; build the engine config; validate (`Config::validate()` equivalents + engine notices).
2. Build `AccessLogger` feeding the Proxy's bounded ring buffer (and optional file sinks), plus the structured `AccessRecord` sink for the log drawer.
3. Build `RoutingState` (`SharedRouting`, `Arc<ArcSwap<…>>`), registering an external dialer for each referenced Tunnel.
4. If MITM is on, build `MitmState::from_pem_bytes` from the vaulted CA — no temporary file.
5. Build `EngineHandlers` + `Server`, spawn `run()` and the MITM leaf-cert reaper.
6. **Save on a running Proxy:** compile the next `RoutingState` (including the self-loop check against all running listeners, across Proxies and Tunnels' reverse listeners); on success `store()` it and bump `config_generation`; on failure keep the current state and show the error.
7. **Tray override:** *Auto Switch* / *Force Direct* / *Force &lt;profile&gt;* swaps a temporary rule-less `RoutingState`; returning to *Auto Switch* restores the saved compiled state.
8. **Shutdown:** cancel → drain `Server` → stop reaper → flush loggers.

```text
Proxy:   Stopped ─► Starting ─► Running (Auto | Override: <profile>) ◄─► Reloading
                       ├─► Locked (needs vaulted secrets or CA)
                       ├─► NeedsAttention (invalid config, port conflict, self-loop, missing CA/tunnel)
                       └─► Stopping ─► Stopped
```

### 5.2 Proxy ↔ Tunnel dependencies
- A Tunnel's **start mode** is **Linked** (runs while any running Proxy references it; the default for migrated sessions) or **Manual** (started and stopped by the user; useful for tunnels used only for port forwards or the reverse proxy).
- Starting a Proxy starts its Linked Tunnels first (staggered); a Proxy is `Running` as soon as its listeners are bound, and routes to a still-connecting Tunnel fail or fail over like any other down upstream.
- Deleting a Tunnel referenced by Proxies lists them and requires confirmation; references become an error that keeps those Proxies from starting until fixed.
- The tray and header show both states (e.g. `Running · tunnel "Bastion" reconnecting`).

### 5.3 Route Tester & Test Upstream
- **Route Tester:** evaluate a `host[:port]` or URL against the draft config with `Router` + `ParsedTarget` + `RouteRequest` on each keystroke; show the table used, matched rule, bypass result, failover chain, and redacted upstreams; highlight the rule in the list.
- **Test Upstream:** dial through the profile's dialer (including Tunnels) to a user-chosen target with timing and redacted errors.
- **Test Chain** (Tunnels): prefix-by-prefix connect, showing the exact failing hop (unchanged).

---

## 6. Secret Vault & Security Model

Unchanged from v1 (`conduit-vault`), with one new record type.

### 6.1 Contents
1. SSH private keys (`KeyId`): uploaded (OpenSSH, PEM, PKCS#1/5/8, PuTTY), pasted, or generated (`ed25519` default, `ecdsa-p256`); passphrases verified once and never needed again.
2. Hop / target passwords and keyboard-interactive answers (`SecretRef`).
3. **New:** upstream proxy passwords for `http`, `https`, `socks5` profiles (`SecretRef`).
4. MITM CAs (`MitmCaId`): uploaded PKCS#12 or PEM chain + key, validated by the engine's CA loader, stored normalized; duplicates refused by fingerprint; expiry flagged within 30 days and once expired.

### 6.2 Encryption & controls
- Random 256-bit DEK; per-record `XChaCha20-Poly1305` with fresh nonce and AAD `(record_id, record_type, vault_version)`.
- DEK wrapped by the OS keyring (`keyring-core` 1.1; serialized D-Bus calls on Linux) and/or a Master Password (`Argon2id`, 128 MiB / `t=3` / `p=1`, calibrated params in header; memory returned to the OS after derivation).
- Never plaintext: locked vault → Tunnels and Proxies that need secrets enter `Locked`; others start normally. A vanished keyring entry never silently recreates the vault.
- Write-only WebView fields; `secrecy`/`zeroize`; atomic `0600` / owner-ACL writes; core dumps disabled; panic hook never prints secrets; logs redact by type (`upstream=` never carries credentials).
- **Safe deletion:** deleting a key, CA, or password in use lists the affected Tunnels/Proxies (and which are running); forcing it clears the reference and stops running holders.
- **Refused at start:** `start` validates before binding or connecting (Start, Restart, Start All, autostart, tray); refusals show `NeedsAttention` and are not retried.

### 6.3 Exports & backups
- CLI TOML exports use `password_env` placeholders, never secrets.
- App backup: secrets omitted by default; optional passphrase-encrypted full backup. The backup format version is bumped for Tunnels/Proxies; older backups import through the §6.4 migration.

### 6.4 Data migration from v0.1.0 sessions
Each saved `SessionProfile` becomes:
- a **Tunnel** (`engine`, `hops`, `reverse`, `port_forwards`, `tunnel` keepalive/reconnect, `openssh` options, Linked start mode), and
- a **Proxy** with the same name, `autostart`, `enabled`, listeners (`forward.bind/http_port/socks_port/max_connections`), global filter (`forward` allow/block), `mitm`, and `logging`, whose routing default is the `tunnel` profile for that Tunnel and which has no rules.

Ports, filters, logging, and MITM behave exactly as before. The migration is one-way, runs once, and keeps a backup copy of the old `config.json` in the data directory.

---

## 7. Desktop GUI, Tray & Platform — carried forward from v1

- **Destroy webview on close;** recreate from tray or `--show`. macOS `Accessory` while tray-only, `Regular` with the window open; monochrome template icon.
- **Linux tray via `ksni`:** menu-first; no tray-anchored popups; wait up to 10 s for a `StatusNotifierWatcher`, keep autostart items running without a tray host, open the Manage Window with a banner if none appears, register later if one does; Wayland clipboard fallback dialog.
- **NVIDIA + WebKitGTK:** targeted env fixes only when NVIDIA is detected, stripped from child/worker processes; `--safe-rendering`.
- **Autostart & single instance:** `tauri-plugin-autostart` with `--tray` (stable `$APPIMAGE` path), `tauri-plugin-single-instance`; second launch opens the window unless `--tray` is passed alone. Stagger autostart Tunnels/Proxies 250–500 ms after vault unlock and network availability; items without secrets don't wait for the vault.
- **CLI flags:** `--tray`, `--show`, `--safe-rendering`, `-h/--help`, `-V/--version` (binary `rusty-conduit-gui`).

---

## 8. Data Model & Workspace Layout

### 8.1 Workspace

```text
rusty-conduit-gui/
├── Cargo.toml              # depends on ../rusty-conduit-engine (path in dev, git tag at release)
├── docs/                   # MASTER-PLAN.md, RELEASING.md, TODO.md
├── scripts/                # check-pure-rust-crypto.py, validate-release-config.py, smoke-test-bundle.py
├── crates/
│   ├── conduit-core/       # Tunnel, Proxy, UpstreamProfile, rules, HostProfile, validation, engine mapping,
│   │                       # TOML & AirSwitch import/export, v0.1.0 migration, atomic persistence
│   ├── conduit-vault/      # vault.bin (+ upstream password records)
│   ├── conduit-ssh/        # russh chain, host-key policy, RusshDialer (boxed streams), reverse, port forwards
│   ├── conduit-openssh/    # isolated OpenSSH worker engine (conduit-worker)
│   ├── conduit-runtime/    # TunnelManager (was SessionManager), ProxyManager (hot-reload, overrides,
│   │                       # route tester, upstream probe), dependency wiring, logs, events, stats, wake
│   └── conduit-tray/       # TrayBackend (ksni on Linux, Tauri tray on Windows/macOS)
└── src-tauri/              # Tauri shell (rusty-conduit-gui binary), IPC, lifecycle, migration
    └── ui/                 # Svelte 5 + TypeScript
```

### 8.2 Core model (sketch)

```rust
struct Tunnel {                 // was SessionProfile (SSH half)
    id: Uuid, name: String, enabled: bool,
    start_mode: TunnelStartMode,  // Linked (default) | Manual { autostart: bool }
    engine: SshEngine,            // Russh | OpenSsh
    hops: Vec<HopEntry>,          // [Jump 1, …, Target]; HostProfile refs or inline
    reverse: ReverseConfig,       // -R reverse proxy: bind, ports, allow/block
    port_forwards: Vec<PortForward>,
    keepalive: TunnelConfig,      // ip_version, server_alive_*, reconnect, delays, startup_timeout
    logging: LoggingConfig,
    openssh: OpenSshOptions,
}

struct Proxy {                  // was SessionProfile (proxy half) + switch-gui SwitchInstance
    id: Uuid, name: String, enabled: bool, autostart: bool,
    source: SourceMode,           // Managed | ExternalToml { path, debounce }
    listeners: ListenerConfig,    // bind, http_port, socks_port (equal = mux, 0 = off), max_connections
    network: NetworkConfig,       // connect_timeout, tcp_keepalive
    profiles: Vec<UpstreamProfile>,
    routing: RoutingTablesConfig, // [routing] + optional [routing.http] / [routing.socks]
    filter: GlobalFilterConfig,   // Off | Allow | Block
    mitm: Option<MitmConfig>,     // MitmCaId, cert_ttl, cache_max, socks_block_web
    logging: LoggingConfig,
}

enum UpstreamKind {
    Http, Https { tls_insecure_skip_verify: bool }, Socks5, Socks4a,
    Composite { http: String, https: String, fallback: String },
    Tunnel(TunnelId),             // new: an SSH Tunnel as the upstream
}
```

Profiles can also live in a shared **Profile Library** and be referenced from several Proxies.

---

## 9. UX & Information Architecture

### 9.1 Tray menu

```text
Rusty Conduit GUI                2 proxies running · 1 tunnel needs attention
────────────────────────────────────────────────────────────────
PROXIES
● Work                           Auto Switch · HTTP :3128 · SOCKS :1080
    ├── Mode ▸  ✓ Auto Switch (14 rules) | Force Direct | Force corp | Force tunnel Bastion
    ├── Stop / Restart
    ├── Copy HTTP Proxy URL      (http://127.0.0.1:3128)
    ├── Copy SOCKS Proxy URL     (socks5h://127.0.0.1:1080)
    └── View Logs
○ Lab                            Stopped → Start
TUNNELS
● Bastion                        Connected (linked to Work)
! Client VPN                     Auth rejected → Open Manage Window
────────────────────────────────────────────────────────────────
Start All  |  Stop All
Unlock Vault…                    (only when locked)
Open Manage Window…
Quit                             (confirms when anything is running)
```

Always copy `socks5h://`, never `socks5://`, so clients keep DNS remote.

### 9.2 Manage Window
- **Sidebar:** **Proxies** and **Tunnels** lists (search, live status, mode pill), `+ New Proxy`, `+ New Tunnel`, `Import…` (AirSwitch `.bak`, CLI `config.toml`), then **Host Profiles**, **Profile Library**, **Vault** (keys, passwords, MITM CAs), **Settings**.
- **New Proxy wizard:** *Direct* (plain `rusty-conduit`), *Through a tunnel* (`rusty-conduit-ssh`), *Auto Switch* (`rusty-conduit-switch`). Each is a starting point in the same editor; rules stay hidden until used.
- **Proxy editor tabs:** 1 Routing Rules (table selector, default target/chain, `resolve_dns` with leak notice, drag-and-drop/keyboard-reorderable rules with enable toggles, condition chips, failover badges, URL-rule-without-MITM badge, rule drawer with every matcher, inline Route Tester) · 2 Upstream Profiles (built-ins, all kinds incl. `tunnel`, colors, write-only vaulted passwords or `password_env`, self-loop warnings, bypass lists, Test Upstream) · 3 Listeners & Network (non-loopback warning, ports, mux, `max_connections`, port-conflict check across Proxies/Tunnels/OS, timeouts, keepalive) · 4 Global Filter (mode, editor, bulk paste, host checker) · 5 HTTPS MITM · 6 Import / Export & TOML (AirSwitch wizard, CLI TOML import/export, External TOML link mode) · 7 Logging & General.
- **Tunnel editor tabs:** 1 Connection & Jump Chain (chain builder, Host Profiles, per-hop auth, host-key status, IP version, engine) · 2 Reverse Proxy (`-R`) · 3 Port Forwards (+ presets) · 4 Keepalive & Reconnect, start mode · 5 Logging & Advanced (OpenSSH options with isolation validation) · "Used by" list of Proxies.
- **Header:** title, state pill, `gen #N · hot-reloaded` (Proxies), live counters, Test Route / Test Chain, Save (Hot-Reload vs Restart Required), Start/Stop.
- **Log drawer:** virtualized live stream from bounded Rust ring buffers (only while the window is open), filter by kind/level/profile/rule/text, pause/copy/clear; on access rows: **Test route** and **Create rule for this host…**.

### 9.3 Import / export matrix

| Source / target | Import | Export |
| :--- | :--- | :--- |
| AirSwitch / ZeroOmega / SwitchyOmega `.bak` | Proxy (profiles + rules; browser-only items listed as warnings; passwords → vault) | — |
| `rusty-conduit` `config.toml` | Proxy (direct) | Proxies with no rules and only `direct` |
| `rusty-conduit-ssh` `config.toml` | Tunnel + Proxy. The CLI's destination may be a `~/.ssh/config` alias, which the app never reads, so hops and auth are completed by hand. | Proxies routing only to one Tunnel: the target becomes the CLI destination; vault keys, passwords, and jump hosts cannot be exported and are listed as `~/.ssh/config` setup notes |
| `rusty-conduit-switch` `config.toml` | Proxy (inline passwords → vault) | Any Proxy; `tunnel` profiles exported as commented `socks5` placeholders |

---

## 10. Roadmap

Phases 0–6 of v1 (validation spikes; core, vault, multi-hop runtime; Tauri shell and tray; full `rusty-conduit-ssh` parity; OpenSSH engine; packaging; audit polish) are **done** (`v0.1.0-beta.5`). The unification phases follow.

### U0 — Rebrand (no engine change; can ship alone as `v0.2.0-beta.1`)
- §3 renames in code, configs, scripts, CI, docs; §3.3 data-dir and autostart migration with tests (fresh install, upgrade, non-empty new dir, cross-volume, old app running).
- GitHub repository rename, then the manual folder rename (§3.2).
- **Done when:** full CI passes (`cargo test --workspace`, clippy `-D warnings`, `npm run check && npm test && npm run build`, `check-pure-rust-crypto.py`, `validate-release-config.py`, secret-leak scan) and an upgraded `beta.5` profile starts with the same sessions and vault.

### U1 — Move to `rusty-conduit-engine` (gated on engine milestone E2 / tag `v0.1.0`)
- Replace `rusty-conduit-ssh` with `rusty-conduit-engine`; `RusshDialer` returns boxed streams (drop loopback bridge); reverse proxy via an engine `Server`; MITM CA from bytes (drop temp-file staging); OpenSSH engine dialer via the engine's SOCKS5 dialer.
- Still the v1 data model: each session = one engine Proxy routed to its tunnel.
- **Done when:** all existing tests pass (444 Rust + 55 frontend at the time of writing), including multi-hop E2E, reverse, MITM, reconnect, and the secret-leak scan.

### U2 — Tunnels + Proxies model
- `conduit-core` split (`Tunnel`, `Proxy`, `UpstreamProfile` incl. `tunnel`, rules), validation, §6.4 migration; vault upstream-password records.
- `conduit-runtime`: `TunnelManager` + `ProxyManager`, Linked/Manual start modes, hot-reload, tray overrides, route tester, upstream probe, per-rule/profile counters.
- Headless tests: multi-Proxy routing, Tunnel failover, hot-reload under active `CONNECT` and SOCKS5 tunnels, override swap/restore, self-loop detection across Proxies and reverse listeners, migration round-trip.

### U3 — Manage Window & tray
- Sidebar, New Proxy wizard, Proxy editor (7 tabs), Tunnel editor re-homed, Vault additions, log drawer quick actions, tray Proxies/Tunnels sections with Mode submenu.

### U4 — Import / export
- AirSwitch `.bak` wizard; CLI TOML import/export per §9.3; External TOML link mode; backup format bump.

### U5 — Packaging & release
- Renamed installers and the upgrade path from `Rusty Conduit (SSH)` (§3.3); release-config validation and bundle smoke tests updated; release `v0.2.0`.

---

## 11. Open Decisions

1. **Tunnel start mode default for new Tunnels:** Linked (proposed; migrated sessions use Linked so behavior is unchanged) or Manual.
2. **Ship U0 alone** as `v0.2.0-beta.1` before the engine is ready (proposed), or ship the rename together with U1.
3. **Bundle identifier:** change it with the §3.3 migration (proposed), or keep `io.github.rusty-conduit-ssh-gui` forever to avoid any migration.
4. **Code signing** for U5: still unsigned/ad-hoc, or Apple Developer ID / Windows Authenticode.
