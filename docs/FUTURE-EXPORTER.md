# Future: Docker Compose project exporter

Status: **proposed, not started.** Tracked in [TODO.md](TODO.md).

Export one Proxy, with every Tunnel it routes through, as a zip holding a ready-to-run Docker Compose project and a `README.md` that tells the user how to set it up and run it. Secrets are left out by default, and each one becomes a placeholder file that the README lists. Packaging the real secrets is an explicit opt-in.

The output targets the published CLI images (`ghcr.io/jpbaking/rusty-conduit-switch`, `ghcr.io/jpbaking/rusty-conduit-ssh`) and is for development, testing, and homelabs, like the CLIs themselves.

---

## 1. What the zip contains

```text
<proxy-name>-compose/
├── README.md               # generated per export: what is missing, setup steps, how to run and check
├── compose.yaml
├── .env.example            # only when a profile uses password_env
├── conf/
│   └── config.toml         # rusty-conduit-switch config for the Proxy
├── tunnels/
│   └── <tunnel-name>/
│       ├── config.toml     # rusty-conduit-ssh config (target, reverse proxy, keepalive)
│       ├── ssh_config      # one Host block per hop, chained with ProxyJump
│       └── known_hosts     # from the app's pinned host keys
└── secrets/                # real files with "include secrets", else *.REPLACE_ME placeholders
    ├── <tunnel>-<hop>.key
    ├── <profile>.password
    ├── mitm-ca.pem
    └── mitm-ca.key
```

`compose.yaml` has:

- **`proxy`:** `rusty-conduit-switch` with `--config /etc/rusty-conduit-switch/config.toml --watch-config`, the Proxy's listener ports published on `127.0.0.1`, and `read_only`, `cap_drop: [ALL]`, `no-new-privileges`.
- **`tunnel-<name>`:** one `rusty-conduit-ssh` service per referenced Tunnel, with `-F` pointing at its `ssh_config`. Ports are published only for the Tunnel's own Forward listener or `-L` forwards, if those are enabled.
- **`secrets-init`:** a one-shot service, depended on with `service_completed_successfully`. It copies `secrets/` into a named volume, `chown`s the files to UID `10001`, and sets mode `600`, so the export runs unchanged on Linux hosts as well as Docker Desktop. This is the `keygen` pattern from the workspace examples.

Always export the Proxy as `rusty-conduit-switch`: it covers every Proxy mode, so there is one code path. A Proxy in External TOML mode exports its linked file as `conf/config.toml`.

## 2. Mapping

| App | Compose project |
| :--- | :--- |
| Proxy listeners, network, filter, `socks_block_web`, logging, routing | `conf/config.toml`, from `export_rusty_conduit_switch_toml` |
| Upstream profile, password in the vault | `password_file = "/run/secrets/<profile>"` (packaged or placeholder) |
| Upstream profile, `password_env` / `password_file` | Kept as is, plus a `.env.example` entry or a placeholder file |
| Upstream host `127.0.0.1` / `localhost` | Rewritten to `host.docker.internal`, with `extra_hosts: ["host.docker.internal:host-gateway"]` and a warning |
| `UpstreamKind::Tunnel` profile | `type = "socks5"`, `host = "tunnel-<name>"`, `port = 1080`. Today's switch export writes this as a commented placeholder; the exporter needs a mode that writes it for real. |
| `TunnelForward` target (a `-L` forward with a proxy protocol) | A profile of that protocol at `tunnel-<name>:<forward port>`, and `-L 0.0.0.0:<port>:<dest>` after `--` on the tunnel service |
| Tunnel hops (`HopEntry`) | `ssh_config`: one `Host` block per hop, `ProxyJump` to the previous one, `HostKeyAlias`, `UserKnownHostsFile`, `StrictHostKeyChecking yes`, `BatchMode yes`, `UpdateHostKeys no`. Adapt `conduit-openssh`'s `render_config`, which already renders this chain. |
| Pinned host keys | `known_hosts` via `conduit-openssh`'s `render_known_hosts`, from `HostKeyRecord.public_key_openssh` |
| Tunnel keepalive, IP version | `rusty-conduit-ssh` flags (`--ssh-server-alive-interval`, `--ssh-server-alive-count-max`); `AddressFamily` in `ssh_config` |
| Tunnel reverse proxy | `--reverse-http-port`, `--reverse-socks-port`, `--reverse-bind`, `--reverse-allow` / `--reverse-block` |
| Tunnel port forwards (`-L`, `-R`) | `ssh` arguments after `--`; a local forward binds `0.0.0.0` in the container and is published on `127.0.0.1` |
| MITM CA (vault) | Compose secrets; `RUSTY_CONDUIT_SWITCH_MITM_CA_CERT` / `_KEY` (or `_P12` plus a passphrase file) |
| MITM upstream TLS mode, insecure hosts | `[mitm] insecure_hosts` / `insecure` |
| Tunnel-level MITM, Forward listener, and filters | The same keys in that tunnel's `config.toml` |

## 3. What cannot be exported unattended

A container runs `ssh` with `BatchMode yes`, so nobody can answer a prompt. The exporter checks every referenced hop and reports these before it writes anything:

| Case | Handling |
| :--- | :--- |
| `AuthMethod::Key` | Supported. With "include secrets", the key is written in OpenSSH format; otherwise a placeholder, and the README says which public key the server expects. |
| `AuthMethod::Password` | **Phase 2:** `SSH_ASKPASS` plus `SSH_ASKPASS_REQUIRE=force`, reading a Compose secret; `conduit-openssh/src/askpass.rs` shows the approach. Until then, a blocking warning. |
| `AuthMethod::KeyboardInteractive` (2FA), hardware or FIDO keys | Not exportable. Blocking warning, offering to export the rest with that hop marked for manual setup. |
| `AuthMethod::SystemAgentOptIn` | Not exportable as is. The README explains how to mount an agent socket instead. |
| A pin without `public_key_openssh` (recorded before that field existed) | The README gives the pinned `SHA256:` fingerprint and an `ssh-keyscan` + `ssh-keygen -lf` check. Connecting once in the app fills the field in. Only the first hop can be scanned directly; inner hops need the app to refresh their pins. |
| An unapproved pin | Not exported. Warning. |
| OpenSSH-engine `extra_args` / `ProxyCommand` | Passed through after `--`, with a warning, because they may name paths on this machine. |
| Two services publishing the same host port | Rejected at export, naming both. |

## 4. Secrets

- **Default: placeholders.** Each needed secret becomes `secrets/<name>.REPLACE_ME`, and the README lists every one with what it is for and where it comes from: the key's public half, the upstream's name, or the CA's subject. Placeholders make `secrets-init` fail with a clear message, so the project cannot start half-configured.
- **Opt-in: include secrets.** This needs the vault unlocked in the export flow itself, a confirmation that names each secret by type and owner, and a warning that the zip holds them unencrypted. Files are stored with mode `600` in the zip. The README tells the user to keep the zip out of Git and to delete it once extracted.
- **No encrypted zip.** AES zips need tools many systems lack, and ZipCrypto is weak. If protection at rest is needed later, the better option is an `age`-encrypted `secrets/` archive (pure Rust).
- **Contract change required.** The Project Contract in [`DOX.md`](../DOX.md) says secrets "never appear in logs, exports, or UI state in clear". Opt-in secret packaging contradicts this, so the owner must approve an explicit, narrow exception before Phase 1 ships it. If not approved, ship placeholders only. `src-tauri/tests/secret_leak_scan.rs` must keep passing for every export without the opt-in, and gain a test proving the opt-in writes secrets only into the zip's `secrets/` folder.

## 5. Generated README

Written for the specific export, not generic:

1. What the project runs: the services, which Tunnel each profile uses, and which ports are published.
2. **Before you start:** each missing secret with the exact file to create, keys to add to each server's `authorized_keys`, and any host-key checks from section 3.
3. Check without starting anything: `docker compose run --rm --no-deps proxy validate --config …`, the same for each tunnel, and `test-route` for a few targets taken from the Proxy's rules.
4. Run: `docker compose up -d`, then `curl` lines for HTTP and SOCKS against the published ports.
5. Every export warning, in plain words.
6. Limits: dev and testing use only, no inbound authentication, and keep the published ports on `127.0.0.1`.

## 6. Where the code goes

- **New crate `crates/conduit-compose`.** It depends on `conduit-core`, and on `conduit-openssh` for `render_config` and `render_known_hosts`. It is a pure function from `(Proxy, &[Tunnel], &KnownHostsStore, ExportOptions, &dyn SecretSource)` to `(Vec<ExportFile>, Vec<ExportWarning>)`, where `ExportFile` is a path, bytes, and a mode. It has no vault, Tauri, or filesystem access, so snapshot tests are easy. It is not in `conduit-core`, because that crate must not depend on `conduit-openssh`.
- **Zip writing** happens in the controller with the `zip` crate, `default-features = false, features = ["deflate"]`, pinned in `[workspace.dependencies]`. `python3 scripts/check-pure-rust-crypto.py` must still pass.
- **Controller:** `export_proxy_compose(proxy_id, options, path)` in `src-tauri/src/controller/import_export.rs`, next to `export_proxy_toml`. It resolves secrets from the vault only when the opt-in is set.
- **UI:** an "Export as Docker Compose…" action in the Proxy editor, with a dialog for options, a warnings preview, the secrets confirmation, and a save dialog.

## 7. Phases

| Phase | Scope | Rough size |
| :--- | :--- | :--- |
| **1. Core export** | Managed and External TOML Proxies; key-auth Tunnels with any number of hops; vault upstream passwords; MITM CA (PEM); placeholders; `secrets-init`; generated README; zip; controller command; snapshot tests | About 1 week |
| **2. Full fidelity** | Opt-in secret packaging (after the contract decision); password hops via askpass; `TunnelForward` targets; PKCS#12 CAs; loopback rewrite; the UI warnings preview | 1–2 weeks |
| **3. Drift guard** | A CI job that builds sample exports, unzips them, and runs `docker compose config` plus each CLI's `validate` against the published images. Optionally, run one against a lab sshd, like `examples/smoke-test.sh` in rusty-conduit-series. | 2–3 days |

## 8. Open questions

- Approve the narrow exception for opt-in secret export, or ship placeholders only?
- Export one Proxy at a time, or allow several Proxies in one project (sharing tunnels and ports)?
- Generate an HAProxy scale-out variant (`--scale` for the proxy and tunnels), or leave that to the workspace guides?
- Should tunnel services in an export keep their reverse proxy, when the same Tunnel may also be running in the app and both would claim the same remote port?

## References

- Existing CLI export: `crates/conduit-core/src/toml_io.rs` (`export_rusty_conduit_switch_toml`, `export_rusty_conduit_ssh_toml`, `TomlExport` notes).
- What a Proxy references: `crates/conduit-core/src/v2_mapping.rs` (`proxy_referenced_tunnels`, `proxy_referenced_forwards`, `proxy_vault_secret_refs`).
- OpenSSH renderers: `crates/conduit-openssh/src/config.rs`, `crates/conduit-openssh/src/known_hosts.rs`, `crates/conduit-openssh/src/askpass.rs`.
- Compose patterns to follow: [rusty-conduit-series Docker: advanced](https://github.com/jpbaking/rusty-conduit-series/blob/main/docs/DOCKER-ADVANCED.md) and its [`examples/`](https://github.com/jpbaking/rusty-conduit-series/tree/main/examples), especially `ssh-tunnel` (keys in a volume owned by UID `10001`) and `homelab-stack` (a switch routing to tunnel services).
