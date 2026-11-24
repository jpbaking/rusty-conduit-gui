# phase-0002 — conduit-openssh core: binary check, hardened -F config, known_hosts & isolated agent socket

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Create `crates/conduit-openssh` (added to workspace `Cargo.toml`) implementing OpenSSH binary discovery & version check, short space-free `0700` runtime directory, app-owned `known_hosts` renderer, hardened per-session `-F` config generator, and isolated local `ssh-agent` server over Unix socket (and `cfg(windows)` named-pipe abstraction).
- Done when: `cargo test -p conduit-openssh && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with passing tests for `ssh -V` parsing (including real `/usr/bin/ssh`), `0700`/`0600` runtime dir & config generation, `HostKeyAlias` `known_hosts` rendering, and Unix-socket `ScopedAgent` wire roundtrips.
- Pattern to follow: `crates/conduit-ssh/src/agent_wire.rs:68-86` (`serve` over `AsyncRead + AsyncWrite + Unpin`), `crates/conduit-core/src/model.rs:463-511` (`OpenSshOptions`, `SessionProfile`), `Cargo.toml:5-14` (workspace members).

## Context
Master Plan Section 3.6 requires every `SshEngine::OpenSsh` session to run completely isolated from `~/.ssh/config`, `/etc/ssh/ssh_config`, `~/.ssh/id_*`, `~/.ssh/known_hosts`, and ambient `SSH_AUTH_SOCK`.
This phase builds the foundational modules of `crates/conduit-openssh`:
- Binary discovery & version check (`binary.rs`): executes `<ssh_bin> -V` (which OpenSSH prints to stderr), parses `OpenSSH_<major>.<minor>` (including `OpenSSH_for_Windows_<major>.<minor>`), enforces `>= 8.4` on Windows (for `SSH_ASKPASS_REQUIRE=force`), and returns a serializable `OpenSshBinaryInfo`.
- Short space-free runtime dir (`runtime_dir.rs`): creates `<base>/rc-<short_hex>` with `0700` permissions on Unix (`$XDG_RUNTIME_DIR` on Linux if space-free and short enough for Unix socket path limits `<= 64` chars, else `/tmp`; short temp dir on macOS/Windows), with RAII `Drop` cleanup.
- App-owned `known_hosts` (`known_hosts.rs`): deterministic `HostKeyAlias` (`rc-<hex>`) per `(hop_id, host, port)` and renderer writing `<alias> <public_key_openssh>\n` (`0600` on Unix) for all approved `HostKeyRecord`s with `public_key_openssh`.
- Hardened `-F` config (`config.rs`): generates per-hop and target `Host` stanzas with `HostKeyAlias`, `UserKnownHostsFile`, `GlobalKnownHostsFile none`, `StrictHostKeyChecking yes`, `IdentitiesOnly yes`, `IdentityAgent <socket|none>`, `ControlMaster no`, `ControlPath none`, `UpdateHostKeys no`, `NumberOfPasswordPrompts 1`, `ServerAliveInterval`, `ServerAliveCountMax`, `AddressFamily`, `ForwardAgent`, and multi-hop `ProxyCommand` invoking `conduit-worker hop-proxy ...` (never `ProxyJump`).
- Isolated local agent server (`agent_server.rs`): serves `conduit_ssh::ScopedAgent` via `conduit_ssh::agent_wire::serve` on a Unix domain socket (`0600` inside runtime dir) on `cfg(unix)` and via `tokio::net::windows::named_pipe::ServerOptions` on `cfg(windows)`.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-openssh/**`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`, `crates/conduit-core/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `src-tauri/**`

## Sub-tasks
1. [done] Add `"crates/conduit-openssh"` to `Cargo.toml` workspace members and create `crates/conduit-openssh/Cargo.toml` (with `[[bin]] name = "conduit-worker" path = "src/bin/conduit-worker.rs"` stub, depending on `conduit-core`, `conduit-ssh`, `rusty-conduit-ssh`, `tokio` with `process`/`net`/`io-util`/`sync`/`time`/`rt`/`macros`, `serde`, `thiserror`, `sha2` or `ring`, `hex` or simple hex helper, `zeroize`, `libc` on unix) and `crates/conduit-openssh/src/lib.rs` — done when: `cargo check -p conduit-openssh` exits 0.
2. [done] Implement `crates/conduit-openssh/src/binary.rs`: `OpenSshBinaryInfo { requested, resolved_path, version_raw, major, minor, supported, message }` (`Serialize`, `Deserialize`, `Clone`, `Debug`, `PartialEq`, `Eq`), `parse_openssh_version(&str) -> Option<(u32, u32)>`, `check_openssh_binary(ssh_bin: &str) -> OpenSshBinaryInfo`, and `check_version_for_platform(major, minor, is_windows)` requiring `>= (8, 4)` on Windows with clear upgrade guidance; add unit tests covering Linux/macOS/Windows OpenSSH version strings (including `8.3` rejected on Windows, `8.4`/`8.6`/`10.2` accepted) and a test invoking `/usr/bin/ssh` on this host — done when: `cargo test -p conduit-openssh binary` passes.
3. [done] Implement `crates/conduit-openssh/src/runtime_dir.rs` (short space-free `0700` directory with RAII cleanup, verified path contains no spaces and is `<= 80` bytes on Unix) and `crates/conduit-openssh/src/known_hosts.rs` (deterministic `host_key_alias(hop_id, host, port) -> String`, `render_known_hosts(&KnownHostsStore, &[(hop_id, host, port)]) -> String`, `write_known_hosts(...)` writing `0600` file, never touching `~/.ssh/known_hosts`) with unit tests — done when: `cargo test -p conduit-openssh runtime_dir && cargo test -p conduit-openssh known_hosts` passes.
4. [done] Implement `crates/conduit-openssh/src/config.rs`: hardened per-session `-F` generator writing `0600` config files for single-hop and multi-hop chains (`HostKeyAlias`, `UserKnownHostsFile`, `GlobalKnownHostsFile none`, `StrictHostKeyChecking yes`, `IdentitiesOnly yes`, `IdentityAgent`, `ControlMaster no`, `ControlPath none`, `UpdateHostKeys no`, `NumberOfPasswordPrompts 1`, `ServerAliveInterval`, `ServerAliveCountMax`, `AddressFamily`, `ForwardAgent`, `ProxyCommand` for multi-hop using `conduit-worker hop-proxy`, never `ProxyJump`, proper Windows backslash escaping for named-pipe `IdentityAgent` paths) with unit tests verifying every directive and asserting zero `~/.ssh` or `ProxyJump` strings — done when: `cargo test -p conduit-openssh config` passes.
5. [done] Implement `crates/conduit-openssh/src/agent_server.rs`: `IsolatedAgentServer::start(runtime_dir, name, Arc<ScopedAgent>)` serving `conduit_ssh::agent_wire::serve` over a `0600` Unix domain socket on `cfg(unix)` and `tokio::net::windows::named_pipe` on `cfg(windows)`, with graceful shutdown handle and `endpoint_path() -> String`; add async tests connecting to the Unix socket and verifying `REQUEST_IDENTITIES`, `SIGN_REQUEST`, and `ADD_IDENTITY` rejection (`SSH_AGENT_FAILURE`) — done when: `cargo test -p conduit-openssh agent_server` passes.

## Verify
```sh
cargo test -p conduit-openssh && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- Adding a new crate dependency would pull in `openssl-sys` or `aws-lc-sys` (violating pure-Rust crypto requirement) → stop, set `Status: needs-human — reason: <dependency name>`
- `ssh -V` is missing or behaves unexpectedly on this host → stop, set `Status: needs-human — reason: <observed output>`

## Log
- (append-only, one line per event)
- sub-task 1: added crates/conduit-openssh to the workspace with manifest, lib.rs and conduit-worker stub
- sub-task 2: implemented binary.rs with version parsing, Windows >= 8.4 gate, timeout-guarded -V check
- sub-task 3: implemented runtime_dir.rs and known_hosts.rs
- sub-task 4: implemented config.rs hardened -F generator with value validation; added IdentityFile lines (none by default) so ssh cannot fall back to ~/.ssh/id_*
- sub-task 5: implemented agent_server.rs with Unix socket and cfg(windows) named pipe; Windows branch not compiled on this host (target not installed)
- phase verified; note for phase-0003: pass each hop's public key path in ConfigHop.identity_files or agent key auth fails
- loopback sshd check of IdentitiesOnly with an isolated agent

## Evidence
- (append-only: command → observed result)
- cargo check -p conduit-openssh → exit 0; Cargo.lock has 0 openssl-sys/aws-lc-sys packages
- cargo test -p conduit-openssh binary → 7 passed, includes real /usr/bin/ssh (OpenSSH_10.2p1)
- cargo test -p conduit-openssh runtime_dir → 5 passed; cargo test -p conduit-openssh known_hosts → 5 passed
- cargo test -p conduit-openssh config → 10 passed, includes real ssh -G parse of generated config
- cargo test -p conduit-openssh agent_server → 6 passed
- cargo test -p conduit-openssh && cargo clippy --workspace --all-targets -- -D warnings → exit 0, 33 tests passed, clippy clean
- throwaway sshd + ssh-agent: IdentityFile none → exit 255 Permission denied (publickey); IdentityFile <key>.pub → exit 0
