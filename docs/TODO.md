# TODO

- **Code signing.** Releases are ad-hoc signed on macOS and unsigned on Windows unless the
  signing secrets in [RELEASING.md](RELEASING.md#4-signing-and-notarization) are set, so
  Gatekeeper and SmartScreen warn users. Decide whether to get an Apple Developer ID and a
  Windows Authenticode certificate.
- **Advanced routing & HTTP/SOCKS split UX.** The Advanced routing drawer (multi-condition
  rules, failover chains, bypass/inbound) and HTTP/SOCKS split override tables in Proxy
  Routing are kept as-is for now. Rework their UX or remove them in a future pass.
- **Unify `MitmConfig.socks_block_web` with top-level `socks_block_web`.** TOML import/export
  already uses top-level `socks_block_web` only, and the editors keep both fields in sync,
  but `MitmConfig.socks_block_web` still exists in `v2_model.rs` alongside `Proxy.socks_block_web`
  and `Tunnel.socks_block_web`. Migrate saved vault data to the top-level field, remove the
  nested field from `MitmConfig` / runtime / mapping, and move the toggle out of `MitmTab`
  before `v0.2.0` stable.
