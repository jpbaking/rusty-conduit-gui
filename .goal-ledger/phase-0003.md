# phase-0003 — conduit-openssh: IPC askpass, conduit-worker, orphan guard & supervisor

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Implement authenticated local IPC askpass, child environment sanitization, cross-platform orphan guards, the `conduit-worker` binary (`askpass` & `hop-proxy`), and `OpenSshSupervisor` with real `/usr/bin/ssh` loopback integration tests.
- Done when: `cargo test -p conduit-openssh && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with passing real `/usr/bin/ssh` loopback tests for key auth via isolated agent, password auth via `conduit-worker askpass`, 2-hop `hop-proxy`, auth failure lockout detection, and host-key mismatch hard stop.
- Pattern to follow: `crates/conduit-ssh/tests/common/mod.rs` (in-process `russh` loopback SSH server for tests), `crates/conduit-runtime/src/hardening.rs` (`cfg(target_os = "linux")` `libc::prctl`), `../rusty-conduit-ssh/src/net.rs:34-42` (`TunnelState`).

## Context
OpenSSH's `ProxyJump` (`-J`) breaks multi-hop password auth and paths with spaces. Instead:
- Each session's `OpenSshSupervisor` starts an authenticated local IPC askpass server (Unix socket on Unix or loopback TCP `127.0.0.1:0` with a 256-bit random hex token per hop; passwords are never passed in argv, env, or disk files).
- Each hop's `ssh` process receives a sanitized environment (`env_clear()` + minimal safe allowlist, explicitly stripping `SSH_AUTH_SOCK`, `DISPLAY`, `WEBKIT_*`, `__NV_*`, etc.) with `SSH_ASKPASS=<path to conduit-worker>`, `SSH_ASKPASS_REQUIRE=force`, `DISPLAY=conduit:0`, and its per-hop IPC endpoint + token + hop index.
- `conduit-worker askpass` connects to the askpass IPC, authenticates with the token and hop index, receives the one-shot secret, writes it to stdout, zeroizes it, and exits. Each hop's password is served at most once per connect attempt so bad passwords cannot loop.
- `conduit-worker hop-proxy --config <path> --ssh-bin <path> --hop <n> -- <host> <port>` spawns the inner `ssh -F <hop_config> -W <host>:<port>` with orphan guard and sanitized env.
- Orphan guards: `PR_SET_PDEATHSIG(SIGTERM)` on `cfg(target_os = "linux")`, Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) on `cfg(windows)`, and a parent-PID watcher thread on `cfg(target_os = "macos")`.
- `OpenSshSupervisor` spawns `ssh -F <target_config> -N -D <bind>:<port> [-R ...] <extra_args> <target_alias>`, probes the local `-D` SOCKS5 port for readiness, publishes `watch::Receiver<TunnelState>`, streams stderr diagnostics, classifies auth failures (`Permission denied`) and host-key failures (`Host key verification failed` / `REMOTE HOST IDENTIFICATION HAS CHANGED`), and kills/reaps the child + drops the runtime dir on shutdown.
- Important from phase-0002: because the hardened `-F` config sets `IdentitiesOnly yes`, for every hop that uses vault key auth via `IsolatedAgentServer`, `OpenSshSupervisor` must write each key's public key (`.pub`) into `RuntimeDir` (`0600`) and pass those paths in `ConfigHop.identity_files` (`crates/conduit-openssh/src/config.rs:28`); otherwise `ssh` will not offer the agent's keys. Also expose `reverse_forwards: Vec<String>` (passed as `-R <spec>`) and a stderr/diagnostic log callback on `OpenSshSupervisor` so `phase-0004` can wire `ReverseProxy` and `LogRingBuffer` directly.

## Scope
- In: `crates/conduit-openssh/**`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`, `crates/conduit-core/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `src-tauri/**`

## Sub-tasks
1. [done] Implement `crates/conduit-openssh/src/env.rs` (sanitized child environment builder using `env_clear()` + minimal allowlist, stripping `SSH_AUTH_SOCK`/`WEBKIT_*`/`__NV_*`, setting `SSH_ASKPASS`/`SSH_ASKPASS_REQUIRE=force`/`DISPLAY=conduit:0`/askpass IPC vars) and `crates/conduit-openssh/src/orphan.rs` (`PR_SET_PDEATHSIG(SIGTERM)` in `pre_exec` on `cfg(target_os = "linux")`, Windows Job Object handle on `cfg(windows)`, parent-PID watcher on `cfg(target_os = "macos")`) with unit tests — done when: `cargo test -p conduit-openssh env && cargo test -p conduit-openssh orphan` passes.
2. [done] Implement `crates/conduit-openssh/src/askpass.rs`: authenticated local IPC askpass server (Unix domain socket inside runtime dir on Unix, loopback TCP on Windows) keyed by per-hop random 32-byte hex token + hop index, serving each hop's zeroized password at most once per attempt (subsequent requests for the same hop return denied so `ssh` fails cleanly instead of looping), plus client function `run_askpass_client()` reading endpoint/token/hop from env and printing secret to stdout; add unit tests for valid auth, wrong token rejection, and one-shot exhaustion — done when: `cargo test -p conduit-openssh askpass` passes.
3. [done] Implement `crates/conduit-openssh/src/bin/conduit-worker.rs`: subcommands `askpass` (calls `run_askpass_client()` with core-dump hardening) and `hop-proxy --config <path> --ssh-bin <path> --hop <n> -- <host> <port>` (applies orphan guard, builds sanitized env for hop `n`, execs/spawns `<ssh_bin> -F <config> -W <host>:<port> <hop_alias>` inheriting stdio) — done when: `cargo build -p conduit-openssh --bin conduit-worker` succeeds with 0 warnings.
4. [done] Implement `crates/conduit-openssh/src/supervisor.rs`: `OpenSshSupervisor` + `OpenSshError` (`AuthFailed`, `HostKeyChanged`, `HostKeyUnknown`, `BinaryUnsupported`, `StartupTimeout`, `ProcessExited`, `Io`) that sets up `RuntimeDir`, renders `known_hosts`, starts per-hop `IsolatedAgentServer`s and `AskpassServer`, writes hardened `-F` configs (wiring `conduit-worker` path via `resolve_worker_bin()`), spawns `ssh -F ... -N -D <bind>:<port> [-R ...] <extra_args> <target_alias>` with orphan guard and sanitized env, parses stderr lines into structured failure classification + log callback, waits for `-D` SOCKS5 listener readiness (updating `watch::Sender<TunnelState>`), and cleanly terminates + reaps on shutdown/drop — done when: `cargo test -p conduit-openssh supervisor` passes.
5. [done] Add real `/usr/bin/ssh` loopback integration tests in `crates/conduit-openssh/tests/openssh_loopback.rs` using an in-process `russh` test SSH server (with `direct-tcpip` forwarding): (a) single-hop Ed25519 key auth via isolated agent socket + SOCKS5 TCP roundtrip, (b) single-hop password auth via `conduit-worker askpass`, (c) 2-hop chain via `conduit-worker hop-proxy` (mixed key + password), (d) wrong password classified as `OpenSshError::AuthFailed` (not transient), (e) wrong pinned host key classified as `OpenSshError::HostKeyChanged`, and (f) verifying runtime directory is removed on drop — done when: `cargo test -p conduit-openssh --test openssh_loopback` passes.

## Verify
```sh
cargo test -p conduit-openssh && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- Real `/usr/bin/ssh` rejects a generated `-F` directive or `SSH_ASKPASS_REQUIRE=force` behaves unexpectedly on this Linux host → stop, set `Status: needs-human — reason: <exact ssh -v stderr>`
- `conduit-worker` binary path cannot be located reliably during `cargo test` (check `CARGO_BIN_EXE_conduit-worker` env var first, falling back to sibling of `std::env::current_exe()`) → stop, set `Status: needs-human — reason: <path lookup issue>`

## Log
- (append-only, one line per event)
- sub-task 1: added env.rs (allowlisted child env, per-hop token narrowing) and orphan.rs (PDEATHSIG, Job Object, macOS watcher)
- sub-task 2: added askpass.rs (token-authenticated, one-shot IPC server and client)
- sub-task 3: implemented conduit-worker askpass and hop-proxy; a lone argument is treated as the ssh prompt because SSH_ASKPASS cannot carry a subcommand
- sub-task 4: added supervisor.rs (OpenSshSupervisor, OpenSshError, stderr classification, SOCKS readiness, guarded spawn thread, cleanup)
- sub-task 5: added tests/openssh_loopback.rs with real /usr/bin/ssh for key, password, 2-hop, wrong password, wrong host key, and cleanup
- Verify passed; no ssh or conduit-worker processes or rc-* directories left after 10 loopback runs; cfg(windows) and cfg(target_os=macos) code not compiled on this host

## Evidence
- (append-only: command → observed result)
- cargo test -p conduit-openssh env → 4 passed; cargo test -p conduit-openssh orphan → 3 passed
- cargo test -p conduit-openssh askpass → 8 passed (7 askpass plus 1 env name match)
- cargo build -p conduit-openssh --bin conduit-worker → Finished, 0 warnings
- cargo test -p conduit-openssh supervisor → 5 passed
- cargo test -p conduit-openssh --test openssh_loopback → 6 passed; repeated 10 times → pass=10/10
- cargo test -p conduit-openssh && cargo clippy --workspace --all-targets -- -D warnings → exit 0 (52 unit + 6 loopback tests passed, clippy clean)
