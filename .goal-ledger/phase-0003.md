# phase-0003 — CLI config.toml drift: error_page, @tunnel/@forward export, socks_block_web merge

- Status: done
- Owner: planner
- Depends on: phase-0002
- Goal: Accept every CLI `config.toml` the three CLIs accept, export v2 Proxies that route through `@tunnel:` / `@forward:` targets, normalize imported Proxies to v2 targets, and keep `socks_block_web` in linked-file mode.
- Done when: every command in `## Verify` exits 0, including the new round-trip tests in sub-tasks 1-4.
- Pattern to follow: `crates/conduit-core/src/toml_io.rs:1361-1394` (the existing commented `socks5` placeholder and note for a legacy `UpstreamKind::Tunnel` profile in the Switch exporter); `crates/conduit-core/src/v2_model.rs:628-660` (`TargetRef::parse`)

## Context
B-04 (1): `ConduitFile`, `SshFile`, and `SwitchFile` are `deny_unknown_fields` and lack `error_page`, so a valid CLI file with `error_page = "..."` is rejected. The app has no custom error page, so import accepts the key and adds the warning `error_page <path> was not imported: the app serves the built-in error page`; export never writes it.
(2) After `migrate_tunnel_profiles` (`v2_model.rs:700-732`), Proxies route to `@tunnel:<uuid>` / `@forward:<tid>:<fid>` instead of `UpstreamKind::Tunnel` profiles. `export_rusty_conduit_ssh_toml` only recognizes the legacy profile, and the Switch exporter writes the raw synthetic targets, which no CLI accepts. Decision: the SSH exporter accepts a default of exactly one `@tunnel:<uuid>` as well as the legacy profile. The Switch exporter gives every synthetic target a profile name (`tunnel-<tunnel uuid>`; `forward-<forward uuid>`), rewrites routing (default, rules, `http`/`socks` tables) and composite slots to those names, and emits a commented placeholder plus a note for each, like the legacy path does: `socks5 127.0.0.1:1080` for a tunnel, and for a forward a profile of its `proxy_protocol` (`http` or `socks5`) at the forward's `bind:port`, with a note to run `ssh -L <listen>:<dest>` for it.
`commit_toml_import` (`src-tauri/src/controller/import_export.rs:342-415`) still saves legacy `UpstreamKind::Tunnel` profiles until the next restart; run `conduit_core::migrate_tunnel_profiles(&mut proxy)` after the tunnel-id fix-up and before `upsert_proxy`.
(3) `merge_external_toml` (`crates/conduit-runtime/src/toml_watcher.rs:154-202`) copies listeners, network, routing, filter, logging, and profiles but drops the file's top-level `socks_block_web`; copy it too and update the doc comment above the function.

## Scope
- In: `crates/conduit-core/src/toml_io.rs`, `crates/conduit-core/src/v2_model.rs` (make `rewrite_target` / `rewrite_table` `pub(crate)` only), `crates/conduit-runtime/src/toml_watcher.rs`, `src-tauri/src/controller/import_export.rs`, `crates/conduit-core/DOX.md`, `docs/` pages that describe TOML import/export notes
- Out: the CLI repos, `src-tauri/ui/`, `crates/conduit-vault/`

## Sub-tasks
1. [done] `error_page: Option<PathBuf>` on all three file structs (serde default, `skip_serializing_if = "Option::is_none"`), the import warning, `None` on export; tests importing each CLI's `config.toml` with `error_page` succeed with the warning — done when: `cargo test -p conduit-core --locked toml_io::tests::error_page` passes.
2. [done] SSH exporter accepts `@tunnel:<uuid>` as the single default target; test: a migrated v2 Proxy (`migrate_tunnel_profiles` applied) exports and re-imports to the same tunnel target and hops — done when: `cargo test -p conduit-core --locked toml_io::tests::ssh_export_v2` passes.
3. [done] Switch exporter rewrite and placeholders as decided in Context; test: a Proxy with `@tunnel:` in default and a rule, an `@forward:` rule, and a composite slot exports to TOML whose uncommented part contains no `@tunnel:` or `@forward:`, and whose placeholders, once uncommented, import with `import_rusty_conduit_switch_toml` without error — done when: `cargo test -p conduit-core --locked toml_io::tests::switch_export_synthetic` passes.
4. [done] `migrate_tunnel_profiles` in `commit_toml_import`, plus a controller test that importing a `rusty-conduit-ssh` file saves a Proxy whose default is `@tunnel:<saved tunnel id>` with no `tunnel` profile — done when: `cargo test -p rusty-conduit-gui --locked commit_toml_import` passes.
5. [done] `socks_block_web` in `merge_external_toml` and its doc comment; extend `merge_keeps_app_fields_and_vaulted_passwords` or add a test with `socks_block_web = true` in the linked file — done when: `cargo test -p conduit-runtime --locked toml_watcher` passes.
6. [done] Docs pass: update `crates/conduit-core/DOX.md` and any `docs/` text that lists export notes or import warnings (`grep -rn 'placeholder\|error_page\|@tunnel' docs crates/conduit-core/DOX.md`) — done when: the grep output was reviewed and every stale statement fixed, recorded in Evidence.
7. [done] (planner, Gate D finding) Rewrap the `merge_external_toml` doc comment and the new test line in `toml_watcher.rs` to ≤ 100 columns — done when: `cargo test -p conduit-runtime --locked toml_watcher` passes.

## Verify
```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p rusty-conduit-gui --test secret_leak_scan --locked
git diff --exit-code -- src-tauri/ui crates/conduit-vault
```

## Escalate when
- An exported placeholder cannot be made to import cleanly in the Switch importer → stop, set Status: needs-human — reason: paste the TOML and the import error.
- Running `migrate_tunnel_profiles` at import changes what an existing controller test asserts → stop, set Status: needs-human — reason: name the test.

## Log
- (append-only, one line per event)
- planner begins phase-0003 (planner-owned)
- sub-task 1: `error_page: Option<PathBuf>` on ConduitFile/SshFile/SwitchFile; `warn_error_page` adds the import warning; exports write `None`
- sub-task 2: SSH exporter resolves the default via `TargetRef::parse` (`@tunnel:<id>`) or a legacy `tunnel` profile; error text keeps "single `tunnel` profile"
- sub-task 3: `synthetic_target_names` + `push_placeholder`; Switch export renames `@tunnel:`/`@forward:` to `tunnel-<id>`/`forward-<id>` in routing (toml_io's own `rewrite_routing`, so v2_model.rs was not touched) and composite slots, with placeholders and notes; legacy tunnel placeholder output unchanged (existing test passes)
- sub-task 4: `migrate_tunnel_profiles` before `upsert_proxy` in `commit_toml_import`; the existing assertion in `ssh_toml_creates_a_tunnel_and_a_proxy_routed_to_it` (legacy Tunnel profile) is exactly the behaviour this sub-task changes, so it now asserts the `@tunnel:` default — not an unexpected test change, so no escalation; new test `commit_toml_import_saves_ssh_proxy_with_a_v2_tunnel_target`
- sub-task 5: `merge_external_toml` copies `socks_block_web`; doc comment updated; test `merge_takes_socks_block_web_from_the_file`
- sub-task 6: docs grep reviewed (see Evidence); updated conduit-core DOX Local Contracts and docs/FUTURE-EXPORTER.md table row
- phase-0003 verified and closed

- Gate D: toml_watcher doc line and new test line exceeded 100 columns; rewrapped (sub-task 7)

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-core --locked toml_io` → 22 passed (incl. `error_page_is_accepted_with_a_warning_and_never_exported`, `ssh_export_v2_tunnel_target_round_trips`, `switch_export_synthetic_targets_become_named_placeholders`, existing `toml_io_switch_export_uses_password_env_and_tunnel_placeholders`)
- `cargo test -p rusty-conduit-gui --locked --lib import_export` → 8 passed (incl. `commit_toml_import_saves_ssh_proxy_with_a_v2_tunnel_target`)
- `cargo test -p conduit-runtime --locked toml_watcher` → 5 passed (incl. `merge_takes_socks_block_web_from_the_file`)
- docs grep `grep -rn 'placeholder\|error_page\|@tunnel' docs crates/conduit-core/DOX.md`: TODO.md:26 and FUTURE-EXPORTER.md (secret placeholders) unaffected; FUTURE-EXPORTER.md:48 updated for synthetic targets; conduit-core DOX gained the error_page and synthetic-target contracts; README.md:16 and RELEASING.md:172 still accurate
- `cargo clippy --workspace --all-targets --locked -- -D warnings` → exit 0; `cargo test --workspace --locked` → 678 passed, 0 failed; secret_leak_scan → 6 passed; `git diff --exit-code -- src-tauri/ui crates/conduit-vault` → exit 0
- Gate D fix-up: `cargo test -p conduit-runtime --locked toml_watcher` → 5 passed
