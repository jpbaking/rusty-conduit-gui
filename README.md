# Rusty Conduit GUI

One system tray app and **Manage Window** for the whole Rusty Conduit proxy family. Build local **Proxies** whose traffic goes direct, through **SSH Tunnels**, through other upstream proxies, or wherever **Auto Switch** rules send it. Save, run, autostart, and auto-reconnect them all at once, without touching `~/.ssh`.

Built with Tauri v2, Svelte 5, and TypeScript over a UI-agnostic Rust workspace that embeds the shared [`rusty-conduit-engine`](https://github.com/jpbaking/rusty-conduit-engine) `v0.4.0`. It replaces the earlier **Rusty Conduit (SSH)** app (`rusty-conduit-ssh-gui` `v0.1.0`); see [Upgrading from v0.1.0](docs/RELEASING.md#8-upgrading-from-v010-rusty-conduit-ssh-gui).

## Features

- **Proxies and Tunnels.** A Proxy is a local HTTP/HTTPS and SOCKS4/4a/5 listener. A Tunnel is a saved SSH connection that Proxies can route through. Each Proxy runs in one of these modes: **Direct**, **Forward** (through an upstream proxy or a Tunnel), **Auto Switch** (rules with failover chains and a live Route Tester), **PAC**, or **External TOML** (linked to a CLI config file).
- **Hot reload.** Saving a routing change on a running Proxy applies it without dropping open connections.
- **Import and export.** Import AirSwitch / ZeroOmega `.bak` files, and import or export `config.toml` for all three CLIs (`rusty-conduit`, `rusty-conduit-ssh`, `rusty-conduit-switch`). Secrets move into the vault and are never written out in plaintext. App backups use format v2, and v1 backups from v0.1.0 still import.
- **Two SSH engines.** The default is pure-Rust [`russh`](https://crates.io/crates/russh), with no external `ssh` binary. An opt-in OpenSSH engine runs in an isolated worker process for cases `russh` cannot cover (raw `extra_args`, custom `ProxyCommand`, GSSAPI, hardware keys).
- **Visual multi-hop jump chain.** Build `Local → Jump 1 → … → Target` with per-hop port, user, auth, and host-key settings.
- **Encrypted vault.** Secrets live in `vault.bin`, encrypted per record with XChaCha20-Poly1305. The vault key is wrapped by the OS keyring and/or a master password (Argon2id). It never falls back to plaintext.
- **Embedded scoped agent.** An in-app key store and per-session `ssh-agent`. Your own `SSH_AUTH_SOCK` is never read or leaked.
- **Zero `~/.ssh` dependence.** The app never reads or writes `~/.ssh/config`, `~/.ssh/id_*`, or `~/.ssh/known_hosts`. Host keys are pinned in an app-owned store. You can import a key from an OpenSSH `known_hosts` file once, by hand.
- **Cross-platform tray.** **PROXIES** and **TUNNELS** menu sections. Tauri's tray on Windows and macOS. On Linux, a pure-Rust [`ksni`](https://crates.io/crates/ksni) (D-Bus StatusNotifierItem) tray that works on XFCE (X11 and Wayland), KDE, GNOME with AppIndicator, and Waybar.
- **Autostart and reconnect.** Per-user login autostart (`--tray`), single instance, and reconnect on wake from sleep.
- **Smooth upgrade from v0.1.0.** The first launch moves the old app's vault, sessions, and settings to the new name. Linux packages and the Windows installer replace the old app.

## Workspace layout

| Path | Purpose |
| --- | --- |
| `crates/conduit-core` | Data model for Proxies and Tunnels, validation, engine config mapping, import/export, and atomic persistence |
| `crates/conduit-vault` | Envelope-encrypted secret vault (`vault.bin`) |
| `crates/conduit-ssh` | `russh` multi-hop chain, host-key pinning, and scoped agent |
| `crates/conduit-openssh` | Isolated, opt-in OpenSSH engine and the `conduit-worker` binary |
| `crates/conduit-runtime` | Proxy and Tunnel managers over `rusty-conduit-engine`, state machine, hot reload, External TOML watcher, backoff, logs, events, and wake listener |
| `crates/conduit-tray` | UI-agnostic tray model and backends |
| `src-tauri` | Tauri v2 desktop shell (`rusty-conduit-gui` binary) |
| `src-tauri/ui` | Svelte 5 + TypeScript frontend |
| `scripts` | Build, release, and policy check scripts |
| `docs` | Master plan and release runbook |

## Prerequisites

- Rust stable, Node 22, and Python 3
- On Debian or Ubuntu:

  ```sh
  sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev \
    librsvg2-dev patchelf libdbus-1-dev libgtk-3-dev
  ```

`Cargo.toml` pulls `rusty-conduit-engine` from its Git tag `v0.4.0`, so no sibling checkout is needed. Cargo fetches it on the first build. If Cargo's built-in Git client fails (for example behind a proxy), set `CARGO_NET_GIT_FETCH_WITH_CLI=true`.

## Development

Build the frontend, then run the app from the repository root:

```sh
(cd src-tauri/ui && npm ci && npm run build)
cargo run -p rusty-conduit-gui
```

Run the same checks as CI:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
(cd src-tauri/ui && npm run check && npm test && npm run build)
python3 scripts/check-pure-rust-crypto.py
python3 scripts/validate-release-config.py
```

## Command-line flags

| Flag | Effect |
| --- | --- |
| `--tray` | Start in the tray with no window. Login autostart uses this. |
| `--show` | Open the window even when `--tray` is given. |
| `--safe-rendering` | Turn off WebKitGTK compositing to work around rendering glitches on Linux. |
| `-h`, `--help` | Print usage and exit. |
| `-V`, `--version` | Print the version and exit. |

Launching the app while it is already running opens the existing window, unless the second launch uses `--tray` alone.

## Documentation

- [`docs/MASTER-PLAN.md`](docs/MASTER-PLAN.md): architecture and delivery plan
- [`docs/RELEASING.md`](docs/RELEASING.md): cutting releases, building installers, signing, and smoke tests

## License

BSD-3-Clause. See [`LICENSE`](LICENSE).
