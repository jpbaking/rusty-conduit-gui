# Rusty Conduit SSH GUI — Master Plan

> **Status:** Draft v1 (Architecture & Delivery Plan)  
> **Target Core:** `../rusty-conduit-ssh` (`v1.1.0`, BSD-3-Clause, Rust library + CLI)  
> **Platforms:** Windows (x64/arm64), macOS (Universal Apple Silicon + Intel), Linux (x64/arm64 — XFCE/X11 & Wayland)

---

## 1. Vision & Core Requirements

Build a lightweight, cross-platform desktop **system tray application** and **Manage Window** that lets users save, run, autostart, and auto-reconnect multiple concurrent sessions of `../rusty-conduit-ssh/`.

### Non-Negotiable Requirements

1. **Full Option Coverage:** Configure **every** `rusty-conduit-ssh` option per session from the Manage Window — forward HTTP/HTTPS & SOCKS4/4a/5 listeners, single-port multiplexing, reverse proxy (`-R`), forward/reverse allow/block filters, opt-in HTTPS MITM (PEM & PKCS#12), keepalive & reconnect backoff, logging, and advanced SSH options.
2. **First-Class Multi-Hop Jumphosts:** Convenient visual chain builder (`Local → Jump 1 → Jump 2 → … → Target`) with reusable Host Profiles, per-hop port/user/auth/host-key settings, and step-by-step connection testing.
3. **Saved Password Auth (Targets & Jumphosts):** Support unattended password and keyboard-interactive authentication for both targets and intermediate jumphosts — including at login autostart and during auto-reconnect without any TTY — while preventing server account lockouts on bad credentials.
4. **Zero `~/.ssh/config` (and `~/.ssh/known_hosts`) Dependence:** Never read, write, or implicitly reference `~/.ssh/config`, `/etc/ssh/ssh_config`, `~/.ssh/id_*`, or `~/.ssh/known_hosts`. All connection metadata, keys, and host-key pins are strictly app-managed.
5. **Embedded Isolated `ssh-agent`:** In-app isolated key store and per-hop/per-session scoped agent so key-based authentication works across targets and jumphosts without reading or leaking the user's ambient `SSH_AUTH_SOCK`. No agent is ever forwarded to a remote host (see §3.5).
6. **True Cross-Platform Support:** First-class support for Windows, macOS, and Linux — explicitly covering **XFCE (X11 & Wayland)**, KDE Plasma, GNOME (with/without AppIndicator), and wlroots compositors (Sway/Hyprland/Waybar).

---

## 2. Architecture Decisions (ADR Summary)

| Area | Decision | Rationale |
| :--- | :--- | :--- |
| **SSH Engine** | **Dual-Engine (Architecture C): Pure-Rust `russh` (Default) + Opt-in Isolated OpenSSH Compatibility Engine (Phase 4)** | `russh` natively solves multi-hop per-hop passwords, zero `~/.ssh` isolation, in-memory scoped keys, remote DNS, and Windows/macOS/Linux parity with zero external `ssh` binary. Opt-in OpenSSH covers raw `extra_args`, custom `ProxyCommand`, GSSAPI, and hardware/FIDO2 keys. |
| **Core Integration** | **Embed `rusty_conduit_ssh` as a Rust library crate** (zero upstream changes required for v1) | All required modules (`config`, `net::UpstreamDialer`, `build_engines`, `Server`, `ReverseProxy`, `MitmState`, `FilteredDialer`, `Logger::with_writer`, `AccessLogger::start_with_stdout`) are already public. Bridge `russh` `ChannelStream` into `UpstreamDialer`'s `TcpStream` via a verified per-dial loopback TCP pair. |
| **Process Isolation** | **UI-agnostic Rust Supervisor + Worker isolation** (in-process runtime for `russh` or dedicated `conduit-worker` process; mandatory per-session worker process for OpenSSH engine) | Keeps tunnels and tray completely independent of the webview lifecycle; prevents WebKitGTK/UI crashes from dropping active proxies; isolates child `stdio` and environment variables per session. |
| **Desktop GUI** | **Tauri v2 + Svelte 5 + TypeScript** (destroy webview on close; recreate on demand) | Best fit for form-heavy UX (multi-hop chain builder, CIDR/domain rule editors, cert pickers, virtualized live logs) while keeping idle tray RAM low when the Manage Window is closed. UI-agnostic backend keeps a Slint fallback feasible if Spike 1 hits Linux WebKitGTK blockers. |
| **System Tray** | **`TrayBackend` trait: Tauri tray on Windows/macOS, direct `ksni` (D-Bus SNI) on Linux** | Pure-Rust D-Bus StatusNotifierItem on Linux avoids GTK3/`libappindicator` fragility, works across XFCE 4.15+ Status Tray, KDE, Waybar, and GNOME+AppIndicator, and exposes watcher offline/online state for graceful no-tray fallback. |
| **Secret Vault** | **Hybrid Envelope Encryption (`vault.bin`)** | Random 256-bit vault key; per-record `XChaCha20-Poly1305` (with AAD). Vault key wrapped by OS keyring (`keyring-core` 1.1.0) and/or Master Password (`Argon2id`). Works seamlessly on Windows/macOS/Secret-Service Linux *and* minimal XFCE/Wayland setups without ever falling back to plaintext. |
| **Host Keys** | **App-owned `known_hosts` pinned by `hop_id + host + port`** | Strict TOFU via GUI fingerprint approval dialog; unattended sessions never auto-trust unknown keys; changed host keys are a hard failure with tray alert. |
| **Autostart & Single Instance** | **`tauri-plugin-autostart` (`--tray`) + `tauri-plugin-single-instance` + OS sleep/wake hooks** | Clean per-user login launch (including AppImage `$APPIMAGE` path handling), second launch opens Manage Window, and wake-from-sleep triggers debounced reconnect instead of waiting ~45s for keepalives. |

---

## 3. Core SSH Engine & `rusty-conduit-ssh` Integration

### 3.1 Why Dual-Engine (`russh` Default + Opt-in OpenSSH)

Empirical loopback spikes against `rusty-conduit-ssh` v1.1.0, `russh` 0.65.4, and OpenSSH 10.2p1 established:

- **`russh` Default Engine (Verified on Linux loopback):**
  - Built cleanly with `ring` only (matching `rusty-conduit-ssh`'s pure-Rust `ring` TLS stack; no `aws-lc` or OpenSSL needed).
  - Ran a 3-hop chain (`sshd` encrypted Ed25519 → `russh` password → `sshd` key) driving the real `rusty_conduit_ssh` HTTP and SOCKS5h engines: 20 MiB SHA-256 roundtrip matched in both forward and reverse (`tcpip-forward`) directions.
  - Preserved remote-only DNS (`direct-tcpip` passes hostnames unresolved to the final hop).
  - Detected intermediate hop-1 drop in ~20 ms.
  - Enforced strict host-key pinning and scoped agent forwarding (remote saw exactly 1 assigned key).
- **Why OpenSSH-Only Is Fragile Across Platforms (Empirically Verified Hazards):**
  - OpenSSH `ProxyJump` (`-J`) fails with multi-hop password auth when user/host repeat (identical `SSH_ASKPASS` prompt strings; keyboard-interactive prompts can be arbitrary/localized), inserts `-F` unquoted (breaking paths with spaces such as macOS `Application Support` or `C:\Users\First Last`), and invokes bare `ssh` from `PATH` ignoring `--ssh-bin`.
  - `ssh -N` opens no session channel, so OpenSSH `ForwardAgent` sends **0 `auth-agent-req`** requests in conduit's default tunnel shape.
  - `-F none` still consults `~/.ssh/id_*` and `~/.ssh/known_hosts`; full isolation requires generating a hardened `-F` config per session.
  - Windows OpenSSH requires ≥ 8.4 for `SSH_ASKPASS_REQUIRE=force`, eats single backslashes in `IdentityAgent \\.\pipe\...` config lines, and lacks Unix `SIGTERM` grace.
- **Why Keep Opt-in OpenSSH (Phase 4):**
  - Requirement 1 includes *all* `rusty-conduit-ssh` options; raw `extra_args`, custom `ProxyCommand`, GSSAPI, and hardware/FIDO2 keys cannot be mapped to `russh`. Exposing OpenSSH as an explicit per-session engine option gives 100% option parity without burdening standard users.

### 3.2 Bridging `russh` into `rusty_conduit_ssh` (Zero Upstream Changes)

`rusty_conduit_ssh::net::UpstreamDialer::connect` returns `Pin<Box<dyn Future<Output = io::Result<tokio::net::TcpStream>> + Send + 'a>>`. Because `russh`'s `ChannelStream` is not a `TcpStream`:

- **v1 Bridge (Verified):** `RusshDialer` opens a `direct-tcpip` channel on the final hop, creates a per-dial loopback TCP pair (`127.0.0.1:0` bind → connect → accept → verify peer address == client socket → drop listener), and spawns `tokio::io::copy_bidirectional` between the accepted socket and the SSH channel.
- **Error Mapping:** Map `russh::ChannelOpenFailure` to exact `io::ErrorKind` values (`ConnectFailed` → `ConnectionRefused`, `AdministrativelyProhibited` → `PermissionDenied`, timeout → `TimedOut`) so `rusty_conduit_ssh` emits accurate HTTP `502`/`504` and SOCKS5 reply codes.
- **Optional Future Upstream PRs (Non-Blocking):**
  1. Generalize `UpstreamDialer` to return a boxed `AsyncRead + AsyncWrite + Unpin + Send` stream (eliminates the loopback socket pair per connection).
  2. Add `run_with_events(...)` and typed failure classification (auth vs. host-key vs. network vs. port-bind) to `rusty_conduit_ssh` for cleaner OpenSSH-engine integration.

### 3.3 Session Startup, Reconnect & Shutdown Lifecycle

For each `russh` session:
1. Unlock required secrets from `conduit-vault` into zeroized memory; validate and build `rusty_conduit_ssh::Config`.
2. Start `AccessLogger::start_with_stdout` with an injected writer feeding the session's bounded log ring buffer (and optional file sinks).
3. Start `ReverseProxy::start` (if reverse ports are configured) so local ephemeral `-R` targets are bound once and survive reconnects.
4. Connect hops sequentially (`Hop 0 → Hop 1 → … → Target`):
   - Before sending any credentials on hop `i`, verify its host key in `check_server_key` against app-owned `known_hosts` (keyed by `hop_id + host + port`).
   - Authenticate hop `i` using its configured ordered auth methods (in-memory Key / Password / Keyboard-Interactive / explicit SystemAgent opt-in).
   - Tunnel hop `i+1` over hop `i`'s `direct-tcpip` stream via `russh::client::connect_stream`.
5. Request `tcpip-forward` on the final hop for each `reverse.forwards()` entry; reject any unexpected inbound `forwarded-tcpip` address/port.
6. Wrap `RusshDialer` in `StatsDialer` (for live active connections & bytes in/out), then `FilteredDialer` (if forward allow/block rules exist).
7. Build HTTP/SOCKS/MITM engines via `rusty_conduit_ssh::build_engines` and start `Server`.
8. **Reconnect Behavior:** Keep forward listeners bound while reconnecting (dialer returns `NotConnected`). Reset exponential backoff only after stable uptime (matching `rusty-conduit-ssh`'s 5s `REVERSE_STABLE_UPTIME` when `-R` is active).
9. **Account Lockout Protection:** Immediately halt reconnects and transition to **`NeedsAttention`** on authentication failure (`Permission denied`, rejected password/key) or host-key mismatch. Never blindly retry saved passwords!
10. **Graceful Shutdown:** Drain forward `Server` → tear down SSH chain (and `-R` forwards) → drain `ReverseProxy` → flush `AccessLogger`.

### 3.4 Mandatory `russh` Security Hardening

Override these permissive `russh` defaults in every client handler:
- **`server_channel_open_agent_forward`:** Always reject. The app never forwards an agent.
- **`server_channel_open_forwarded_tcpip`:** Reject any remote address/port not explicitly requested in `reverse.forwards()`.
- **Embedded Agent Server:** Allow only `RequestKeys` and `Sign` after initial session key loading; deny `AddIdentity`, `RemoveIdentity`, `RemoveAll`, and `Lock`.
- **Known Hosts:** Never call `russh`'s default `~/.ssh/known_hosts` helpers; always use app-managed pin storage.

### 3.5 Embedded Isolated `ssh-agent` Design

Clarify and cleanly separate the two distinct key-auth workflows:

1. **Per-Hop Authentication (Default — No Forwarding Needed):**
   - Because the app connects each hop directly through nested `direct-tcpip` channels, private keys **never leave the local machine** and are never exposed to jump hosts.
   - Keys stored in `conduit-vault` (OpenSSH, PEM, PKCS#1/5/8, PuTTY) are decoded in zeroized memory and used directly by the per-hop signer. No socket or external agent is involved.
2. **No Agent Forwarding (removed 2026-11-25):**
   - The app is a forward/reverse proxy. Neither direction needs a remote process to authenticate onward with the user's keys, and per-hop authentication already reaches every jump host and the target.
   - Agent forwarding (an earlier opt-in that ran a remote command on a session channel with a scoped agent) only added risk: root on that host could use the forwarded keys while connected. It was removed. Hops refuse `auth-agent@openssh.com` channels, the OpenSSH engine always writes `ForwardAgent no`, and `-A` / `ForwardAgent` stay in the `extra_args` denylist.
   - Profiles saved with the old `agent_forward*` hop fields still load; the fields are ignored and dropped on the next save.
   - Reading the system `SSH_AUTH_SOCK` is never done.

### 3.6 OpenSSH Compatibility Engine Hardening (Phase 4)

When a session explicitly selects `engine = OpenSsh`:
- Run one dedicated `conduit-worker` subprocess per session (orphan-guarded via Windows Job Object, Linux `PR_SET_PDEATHSIG`, macOS PID sweep).
- Generate a hardened per-session `-F` file in a **short path without spaces** (under `$XDG_RUNTIME_DIR` on Linux, short temp/app-runtime dir on macOS/Windows) specifying `HostKeyAlias`, `UserKnownHostsFile <app>/known_hosts`, `GlobalKnownHostsFile none`, `StrictHostKeyChecking yes`, `IdentitiesOnly yes`, `IdentityAgent <isolated-socket|none>`, `ControlMaster no`, `UpdateHostKeys no`, `NumberOfPasswordPrompts 1`.
- Chain multi-hop targets via a per-hop `ProxyCommand` wrapper (`conduit-worker hop-proxy --session <id> --hop <n> -- %h %p`) with an authenticated local IPC askpass helper — never `ProxyJump` and never prompt-text parsing.
- Enforce an `extra_args` denylist rejecting flags that break isolation (`-F`, `-J`, `-i`, `ProxyCommand`, `ProxyJump`, `IdentityAgent`, `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking`, `ControlPath`, `ControlMaster`, `ForwardAgent`, `Include`).
- Require OpenSSH ≥ 8.4 on Windows (runtime version check with clear guidance).

---

## 4. Desktop GUI, System Tray & Platform Architecture

### 4.1 GUI Stack: Tauri v2 + Svelte 5 + TypeScript

- **Window Lifecycle (Low Idle Footprint):** When the user closes the Manage Window, **destroy the webview completely** (not merely hide it) so WebKitGTK / WebView2 / WKWebView helper processes exit and idle tray memory stays minimal. Recreate the window on demand from the tray or `--show`.
- **UI-Agnostic Backend:** All state, vault, SSH, and session orchestration live in pure-Rust workspace crates (`conduit-core`, `conduit-vault`, `conduit-ssh`, `conduit-runtime`). Tauri commands and events are a thin adapter layer; if Spike 1 reveals an unresolvable Linux WebKitGTK issue, the frontend can be swapped to Slint without touching core logic.
- **macOS Dock Policy:** Use `ActivationPolicy::Accessory` while running tray-only (no Dock icon), switching to `ActivationPolicy::Regular` while the Manage Window is open so standard menus and window focus work naturally. Use a monochrome template icon for the menu bar.

### 4.2 System Tray: Windows, macOS, and Linux (XFCE + Wayland)

Abstract tray operations behind a `TrayBackend` trait:
- **Windows & macOS:** Tauri v2 built-in tray (`tray-icon`).
- **Linux (XFCE X11/Wayland, KDE Plasma, GNOME, Sway/Hyprland):** Direct **`ksni`** (pure-Rust D-Bus `StatusNotifierItem`).
  - Zero GTK3 / `libappindicator` / `libayatana-appindicator` runtime dependency.
  - Native support in XFCE 4.15+ (`xfce4-panel` Status Tray Plugin), KDE Plasma, Waybar (Sway/Hyprland), and GNOME with the AppIndicator extension.
  - Exposes D-Bus watcher online/offline status so the app handles late-starting panels and missing tray hosts cleanly.

#### Linux & Wayland Platform Rules
1. **Menu-First Tray:** Never hide a required action behind left-click (inconsistent across Linux SNI hosts); every action is in the tray menu.
2. **No Tray-Anchored Popups:** Wayland clients cannot position windows globally; always open the standard Manage Window.
3. **No-Tray-Host Fallback (e.g., Vanilla GNOME):**
   - Wait up to 10s at login for panels/Waybar to register `StatusNotifierWatcher`.
   - Keep autostart tunnels running regardless of tray availability.
   - If no tray host appears, open the Manage Window with a dismissible info banner; closing it asks **Keep running in background** vs. **Quit**. Re-launching with `--show` reopens the window.
   - Automatically register the tray icon if a watcher appears later.
4. **Wayland Clipboard Fallback:** Copy-to-clipboard from a windowless Wayland tray menu can fail due to compositor focus rules; fall back to a tiny focusable dialog with the URL pre-selected.
5. **NVIDIA + WebKitGTK Mitigation:** Apply targeted env fixes before GTK init *only* when NVIDIA is detected (`WEBKIT_DISABLE_DMABUF_RENDERER=1` on X11; test `__NV_DISABLE_EXPLICIT_SYNC=1` / DMABUF on Wayland), strip those vars from child/worker processes, and provide a `--safe-rendering` CLI flag (`WEBKIT_DISABLE_COMPOSITING_MODE=1`).

---

## 5. Secret Vault & Security Model

### 5.1 Hybrid Envelope-Encrypted Vault (`vault.bin`)

All sensitive values — hop/target passwords, SSH private keys, key passphrases, and MITM CA passphrases — live exclusively in a single encrypted file (`vault.bin`), referenced from profiles by opaque `SecretRef` / `KeyId` UUIDs.

- **Encryption:** Random 256-bit Data Encryption Key (DEK); each record encrypted with `XChaCha20-Poly1305` and a fresh random nonce, binding `(record_id, record_type, vault_version)` as Associated Data (AAD).
- **Key Wrapping (Hybrid Unlock):**
  - **Primary (Seamless):** DEK wrapped/stored in the OS native keyring via `keyring-core` 1.1.0 (Windows Credential Manager, macOS Keychain, Linux `zbus` Secret Service — serialized on a single worker thread). Avoids Windows' 2,560-byte `CREDENTIALW` blob limit because only the 32-byte DEK lives in the keyring.
  - **Fallback / Portable (Minimal Linux/XFCE without Secret Service, or user opt-in):** DEK wrapped by a user Master Password derived with `Argon2id` (baseline 128 MiB, `t=3`, `p=1`, calibrated parameters stored in vault header).
  - **Never Fall Back to Plaintext:** If neither keyring nor unlocked master password is available at login, sessions requiring secrets enter **`Locked`** state (tray shows *Unlock Vault…*) while sessions not needing secrets still start. If the keyring entry disappears, never silently recreate/overwrite `vault.bin` — prompt for recovery/master password.
- **Atomic Storage:** Write temp file → `fsync` → atomic rename, with `0600` permissions (Unix) or owner-only ACL (Windows).

### 5.2 Memory & Leak Controls

- Hold decrypted secrets in `secrecy::SecretBox` / `zeroize` wrappers.
- **Write-Only WebView Secret Fields:** The Rust backend never sends raw passwords, private keys, or passphrases to the frontend — only metadata (`has_secret: true`, key fingerprint/type). JS strings cannot be zeroized.
- Never pass secrets via CLI `argv`, environment variables, TOML files, or unencrypted temp files.
- Disable core dumps (`PR_SET_DUMPABLE=0` on Linux, `setrlimit(RLIMIT_CORE, 0)`), use best-effort `mlock`, and install a panic hook that never prints secret payloads.
- Redact sensitive fields by type in all logs; config exports strip secrets by default (full backup requires explicit passphrase encryption).

### 5.3 Key Management (Upload, Paste, Generate & Per-Hop Picking)

Private keys are managed as first-class records inside `vault.bin` with **zero reference to `~/.ssh/id_*`**:

- **Add Key Methods (Write-Only in UI):**
  1. **Upload / Import File:** Pick any OpenSSH, PEM, PKCS#1/5/8, or PuTTY (`.ppk`) private key file. The app validates the key in Rust, extracts its public key & SHA-256 fingerprint, and encrypts the private key material directly into `vault.bin` (no ongoing dependency on the original file path).
  2. **Paste Private Key:** Paste raw private key text directly into a dedicated write-only modal in the Manage Window (cleared from UI state immediately after submit).
  3. **Generate New Key:** Optionally generate a fresh `ed25519` (default) or `ecdsa-p256` keypair in-app with one-click **Copy Public Key** (`ssh-ed25519 AAAA...`) for pasting into remote `authorized_keys`.
- **Encrypted Key Passphrases:** If an imported/pasted key is passphrase-protected, the user enters the passphrase once at import time to verify the key; the passphrase (or decrypted key material) is stored strictly encrypted inside `vault.bin` so autostart and auto-reconnect work unattended without re-prompting.
- **Key Vault View & Lifecycle:**
  - Lists every saved key by friendly name, algorithm/size, SHA-256 fingerprint, created/imported date, and a **"Used by N hosts/sessions"** indicator.
  - Supports **Copy Public Key**, **Rename**, and **Delete** (warns and lists affected hosts/sessions before removing a referenced key).
  - Private key material is **never** returned to the frontend WebView after ingestion (write-only).
- **Per-Target & Per-Jumphost Picking:**
  - Every Host Profile and every hop in a session's Jump Chain (`Jump 1 → Jump 2 → … → Target`) gets a clean **Key Vault picker** allowing the user to select one or more vaulted keys (ordered) and/or password auth.
  - At connect time, the embedded isolated `ssh-agent` / signer loads *only* the vaulted keys selected for that specific hop.

### 5.4 Host-Key Verification (Zero `~/.ssh/known_hosts`)

- Stored in `<app-data>/known_hosts.json` (or app-owned OpenSSH-format file for Phase 4), keyed by **`hop_id + host + port`**.
- **First Contact:** Session pauses in `AwaitingHostKey` and opens a verification modal showing hop name, host:port, key algorithm, and SHA-256 fingerprint.
- **Unattended Autostart:** Unknown host keys wait in `NeedsAttention` — never silently trusted on first use.
- **Key Changed:** Hard failure; session stops immediately with a high-priority tray alert. Requires explicit user review and re-approval.
- Optional one-time manual import from a user-selected `known_hosts` file (never automatic).

---

## 6. Autostart, Single-Instance & Session Lifecycle

### 6.1 OS Login Autostart & Single Instance

- **App Autostart:** `tauri-plugin-autostart` launching with `--tray` (Windows per-user Run key; macOS `LaunchAgent` initially, evaluating `SMAppService` later; Linux `~/.config/autostart/rusty-conduit-ssh-gui.desktop`, writing stable `$APPIMAGE` path when running as an AppImage).
- **Single Instance:** `tauri-plugin-single-instance`; launching the app a second time (or running `rusty-conduit-ssh-gui --show`) signals the running instance to open/focus the Manage Window.

### 6.2 Session State Machine & Sleep/Wake Handling

```text
Stopped ──► Starting ──► Connected ◄──► Reconnecting (exponential backoff)
               │              ▲
               ├──► WaitingForNetwork
               ├──► Locked (vault locked at login)
               ├──► AwaitingHostKey ──► NeedsAttention (auth / host-key error; NO auto-retry)
               └──► Failed
```

- **Boot / Login Stagger:** Start autostart sessions with a 250–500 ms stagger after vault unlock and network availability.
- **Sleep / Wake & Network Change:** Subscribe to OS wake events (`logind` `PrepareForSleep(false)`, Windows `PBT_APMRESUMEAUTOMATIC`, macOS `NSWorkspace.didWakeNotification`). Debounce 2–5 seconds, then proactively recycle sessions that were `Connected` or `Reconnecting` instead of waiting ~45s for keepalive expiry. Never auto-start user-stopped sessions or `NeedsAttention` sessions.

---

## 7. Data Model & Workspace Layout

### 7.1 Cargo Workspace Structure

```text
rusty-conduit-ssh-gui/
├── docs/
│   └── MASTER-PLAN.md
├── crates/
│   ├── conduit-core/       # SessionProfile, HostProfile, Hop, validation, mapping to rusty_conduit_ssh::Config
│   ├── conduit-vault/      # vault.bin (XChaCha20-Poly1305 + Argon2id), keyring-core wrapper, zeroized secrets
│   ├── conduit-ssh/        # russh multi-hop chain, HostKeyPolicy, RusshDialer + loopback bridge, reverse, scoped agent
│   ├── conduit-runtime/    # SessionManager, state machine, backoff, wake hooks, bounded log ring buffers, event bus, stats
│   ├── conduit-openssh/    # (Phase 4) hardened -F generator, ProxyCommand/askpass IPC helper, isolated worker
│   └── conduit-tray/       # TrayBackend trait (ksni on Linux, Tauri/tray-icon adapter on Win/macOS)
└── src-tauri/              # Tauri v2 shell, IPC commands, window lifecycle, autostart, single-instance
    └── ui/                 # Svelte 5 + TypeScript frontend
```

### 7.2 Core Data Model

```rust
struct VaultKeyMeta {
    id: KeyId,                       // UUID; private key bytes live only in vault.bin
    name: String,                    // e.g. "Prod Bastion Ed25519"
    algorithm: String,               // ed25519 | ecdsa-p256 | rsa-4096 | ...
    fingerprint_sha256: String,
    public_key_openssh: String,      // safe to display & copy to authorized_keys
    source: KeySource,               // Uploaded | Pasted | Generated
    created_at: Timestamp,
}

struct HostProfile {
    id: Uuid,
    name: String,
    host: String,
    port: u16,                       // default 22
    user: String,
    auth: Vec<AuthMethod>,           // Ordered: Key(KeyId) | Password(SecretRef) | KeyboardInteractive(rules) | SystemAgentOptIn
    host_key_pin: Option<HostKeyPin>,// algorithm, sha256, first_seen, approved_at
}

struct SessionProfile {
    id: Uuid,
    name: String,
    autostart: bool,
    engine: SshEngine,               // Russh (default) | OpenSsh (Phase 4)
    hops: Vec<HopEntry>,             // Ordered chain: [Jump 1, Jump 2, ..., Target] (HostProfileRef or Inline)
    forward: ForwardConfig,          // bind, http_port, socks_port, max_connections, allow/block rules
    reverse: ReverseConfig,          // reverse_bind, reverse_http_port, reverse_socks_port, reverse_allow/block rules
    mitm: Option<MitmConfig>,        // PEM (cert+key) or PKCS#12, SecretRef passphrase, cert_ttl, cache_max, socks_block_web
    tunnel: TunnelConfig,            // ip_version, server_alive_interval/count_max, no_reconnect, initial/max delay, startup_timeout
    logging: LoggingConfig,          // level, format (text|json), http_access_log, socks_log
    openssh_only: OpenSshOptions,    // ssh_bin, ssh_socks_bind/port, extra_args (validated against isolation denylist)
}
```

---

## 8. UX & Information Architecture

### 8.1 System Tray Menu

```text
Rusty Conduit SSH                2 connected · 1 needs attention
────────────────────────────────────────────────────────────────
● Prod Bastion                   Connected  (HTTP :3128 · SOCKS :1080)
    ├── Stop
    ├── Restart
    ├── Copy HTTP Proxy URL      (http://127.0.0.1:3128)
    ├── Copy SOCKS Proxy URL     (socks5h://127.0.0.1:1080)
    └── View Logs
◐ Staging                        Reconnecting (8s)…
! Client VPN                     Auth rejected → Open Manage Window
○ Lab                            Stopped → Start
────────────────────────────────────────────────────────────────
Start All  |  Stop All
Unlock Vault…                    (shown only when locked)
Open Manage Window…
Quit                             (confirms when sessions are active)
```

> Always copy `socks5h://` (never `socks5://`) so client tools keep DNS resolution remote.

### 8.2 Manage Window Layout

- **Left Sidebar:** Searchable session list with live status indicators (`●`, `◐`, `!`, `○`), `+ New Session`, and navigation links to **Host Profiles**, **Key Vault (Embedded Agent)**, and **Settings**.
- **Header Bar:** Session title, live state pill, active connection & byte counters, **`[Test Chain]`**, **`[Save]`**, **`[Start / Stop]`**.
- **7-Tab Session Editor (100% `rusty-conduit-ssh` coverage):**
  1. **Connection & Jump Chain:** Visual chain `[Local] → [Jump 1 ✓] → [Jump 2 !] → [Target]` with drag-and-drop + keyboard reorder, reusable Host Profile picker (with *Save as Profile* promotion), per-hop auth/secret status, host-key fingerprint/reset, IP version, engine selector (`Built-in Rust SSH` vs. `OpenSSH`).
  2. **Forward Proxy:** Bind IP (with non-loopback warning), HTTP port, SOCKS port, single-port mux toggle, `max_connections`, live port-conflict check across saved sessions and OS sockets.
  3. **Reverse Proxy (`-R`):** Remote bind IP (with exposure/GatewayPorts warning), remote HTTP/SOCKS ports, mux indicator.
  4. **Destination Filters:** Forward and reverse Allowlist/Blocklist mode toggle (enforcing mutual exclusivity), IP/CIDR/FQDN/`*.domain` rule editor, bulk paste import, and interactive "Test host against rules" checker.
  5. **HTTPS MITM:** Off / PEM / PKCS#12 selector, file pickers, write-only passphrase stored in vault, cert TTL (`≥ 10s`), cache cap, `socks_block_web_in_mitm` toggle, parsed CA subject & expiry display.
  6. **Keepalive & Reconnect:** `ServerAliveInterval`, `ServerAliveCountMax`, auto-reconnect toggle, initial/max backoff delays, startup timeout, session autostart toggle.
  7. **Logging & Advanced:** Log level (`QUIET`..`VERBOSE`), format (`text`/`json`), file log paths, OpenSSH-only `ssh_bin` / `ssh_socks_bind` / `extra_args` (with isolation validation and redacted preview).
- **Bottom Collapsible Drawer:** Live virtualized diagnostic + access log viewer per session (level filter, text search, pause/autoscroll, copy, clear), backed by a bounded ring buffer in Rust streamed only while the window is open.

---

## 9. Phased Roadmap & Milestones

### Phase 0 — Validation Spikes (Gate Before Full Build)
*Goal: De-risk every platform-specific unknown before committing UI/engine code.*
1. **Spike 0.1 (Cross-Platform `russh` + `ring` CI):** Verify `russh` 0.65.4 + `ring` + `rusty_conduit_ssh` builds and passes the 3-hop forward/reverse loopback test on **Windows, macOS, and Linux** in CI, plus keyboard-interactive auth, encrypted PEM/PKCS8/PuTTY keys, and hung-peer keepalive timeout.
2. **Spike 0.2 (Tauri v2 + Destroy-on-Close + NVIDIA WebKitGTK):** Measure RSS on window open → close → reopen on Windows, macOS, XFCE X11, KDE Wayland, GNOME Wayland, and Sway; confirm WebKit helper processes terminate on window close.
3. **Spike 0.3 (`ksni` Linux Tray Matrix):** Validate `ksni` menu updates, late panel startup, host loss/recovery, and no-tray fallback on XFCE 4.18/4.20 (X11 & Wayland), KDE Plasma, GNOME (with & without AppIndicator), and Sway/Waybar, plus Wayland clipboard fallback.

### Phase 1 — Core Engine, Vault & Multi-Hop Runtime (Headless / CLI-Testable)
- Initialize Cargo workspace (`conduit-core`, `conduit-vault`, `conduit-ssh`, `conduit-runtime`).
- Implement `vault.bin` envelope encryption (`XChaCha20-Poly1305` + `Argon2id` + `keyring-core`).
- Implement `russh` multi-hop chain builder, strict `HostKeyPolicy` (TOFU + changed-key hard stop), `RusshDialer` + loopback bridge, `ReverseProxy` `tcpip-forward` wiring, and lockout-safe auth failure classification.
- Implement `SessionManager` (concurrent sessions, backoff, bounded log ring buffers, live stats dialer, event bus, OS sleep/wake hooks).
- Full integration tests against loopback SSH servers (single-hop, 3-hop mixed password+key, MITM, reverse proxy, filters, reconnect, zero `~/.ssh` access).

### Phase 2 — Tauri v2 Shell, Systray & Core Manage Window
- Wire `conduit-tray` (`ksni` on Linux, Tauri tray on Windows/macOS) + no-tray fallback + macOS `Accessory`/`Regular` policy.
- Implement `tauri-plugin-single-instance`, `tauri-plugin-autostart` (`--tray`), and destroy-webview-on-close lifecycle.
- Build Svelte 5 Manage Window: Session Sidebar, Connection & Multi-Hop Jump Chain Builder, Host Profiles, Key Vault (import/generate/delete keys, write-only secrets), Host-Key Approval modal, Vault Unlock modal, and Live Log Drawer.
- Implement prefix-by-prefix **Test Connection** showing exact failing hop.

### Phase 3 — Full `rusty-conduit-ssh` Option Parity & Embedded Scoped Agent Forwarding
- Complete remaining Session Editor tabs: Forward Proxy (with port conflict detection), Reverse Proxy, Filters (with rule tester), HTTPS MITM (with CA expiry/validation), Keepalive & Reconnect, Logging & Advanced.
- Implement opt-in per-hop **Scoped Agent Forwarding** (in-process read-only agent + signature audit logging + remote-command session channel). *Later removed as out of scope for a proxy; see §3.5.*
- Add encrypted config export/import (secrets omitted by default; optional passphrase-encrypted full backup).

### Phase 4 — Opt-In OpenSSH Compatibility Engine
- Implement `conduit-openssh` worker subprocess (`conduit-worker`) with hardened `-F` generation in short space-free paths, per-hop `ProxyCommand` wrapper + authenticated local IPC askpass, isolated agent socket/named pipe, `extra_args` isolation denylist, and Windows OpenSSH ≥ 8.4 check.
- Run Windows named-pipe & `ProxyCommand` askpass verification suite.

### Phase 5 — Packaging, Signing & Release Automation
- **Windows (x64/arm64):** Signed NSIS `.exe` (per-user, stops workers cleanly before upgrade) + `.msi`.
- **macOS (Universal):** Signed & notarized `.app` / `.dmg` (`lipo` universal binaries).
- **Linux (x64/arm64):** `.deb`, `.rpm`, and `.AppImage` built on oldest supported glibc base (Ubuntu 22.04 / Debian 12). Defer Flatpak/Snap due to sandbox conflicts with host networking/sockets/tray/autostart.
- **CI Gates:** Rust unit/integration tests, frontend typecheck/lint, multi-hop fake-`sshd` E2E on all 3 OSes, automated secret-leak scan of logs & exports, and installer smoke tests.

---

## 10. Open Decisions for User Confirmation

Before starting Phase 0/1 implementation, please confirm your preference on these three product calls:

1. **Default SSH Engine:** Confirm **Pure-Rust `russh` as default** (zero external `ssh` binary, native multi-hop passwords & isolated agent) with **OpenSSH as an opt-in Phase 4 engine** for raw `extra_args` / `ProxyCommand` / FIDO2.
2. **Minimal Linux (No Secret Service) Autostart Policy:** When a Linux desktop (e.g., minimal XFCE/Wayland) has no unlocked OS Secret Service, confirm our default security posture: **require a Master Password unlock** (vault stays `Locked` at login until entered; never fall back to plaintext).
3. **Code Signing Targets:** Confirm whether Apple Developer ID / Windows Authenticode signing certificates will be configured for Phase 5 releases, or if unsigned/ad-hoc builds are fine for initial releases.
