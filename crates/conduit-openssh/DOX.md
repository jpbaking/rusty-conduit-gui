# crates/conduit-openssh

Sub-root: Cargo workspace member crate `conduit-openssh`, which also builds the `conduit-worker` binary.

## Purpose
Opt-in OpenSSH compatibility engine, isolated from the user's SSH setup, for cases `russh` cannot cover (raw `extra_args`, custom `ProxyCommand`, GSSAPI, hardware keys).

## Ownership
Owns everything under `crates/conduit-openssh/`. Inherits all root DOX rules and adds the local rules below. The default engine is `../conduit-ssh`; session supervision is `../conduit-runtime`. Staging the worker as a Tauri sidecar is done by `../../scripts/stage-worker.py`.

## Local Contracts
- Never read `~/.ssh/config`, `/etc/ssh/ssh_config`, `~/.ssh/id_*`, `~/.ssh/known_hosts`, or the ambient `SSH_AUTH_SOCK`.
- Every value written to the per-session `ssh -F` file is validated or quoted; a newline must never become a new directive.
- Passwords never appear in argv, the environment, or a file; askpass serves each at most once.
- Child processes start from an empty environment plus the allowlist in `src/env.rs`.
- `ssh` children must not outlive their parent (`src/orphan.rs`).
- Runtime files live in a short, private per-session directory (`src/runtime_dir.rs`).
- `conduit-worker` is a separate binary (`[[bin]]` in `Cargo.toml`); keep its CLI (`askpass`, worker mode) in sync with how `src/supervisor.rs` invokes it.

## Verification
- `cargo test -p conduit-openssh` — `tests/openssh_loopback.rs` needs a real `ssh` client (`/usr/bin/ssh`) but no `sshd`, network, or `~/.ssh`.

## Feature Map
- **OpenSSH session supervisor** — runs one `ssh -N -D` session with app-owned config, keys, and passwords. Start: `src/supervisor.rs`. Files: `src/config.rs`, `src/known_hosts.rs`, `src/runtime_dir.rs`, `src/env.rs`, `src/orphan.rs`.
- **Worker binary and askpass IPC** — per-session worker; answers password prompts over authenticated local IPC. Start: `src/bin/conduit-worker.rs`. Files: `src/askpass.rs`.
- **Isolated agent endpoint** — serves a `ScopedAgent` on a private socket / named pipe for the `ssh` child. Start: `src/agent_server.rs`.
- **OpenSSH binary discovery** — locate `ssh` and check its version. Start: `src/binary.rs`.
- **Tunnel-state dialer** — engine dialer that goes through the `ssh -D` SOCKS port while the tunnel is ready. Start: `src/dialer.rs`.
- **Loopback tests** — real `ssh` against in-process `russh` servers. Start: `tests/openssh_loopback.rs`.

## Child DOX Index
- (none)
