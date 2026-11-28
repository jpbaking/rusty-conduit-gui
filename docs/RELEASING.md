# Releasing Rusty Conduit GUI

This runbook covers how to cut a release, build installers locally, configure signing, and smoke-test the result.

## Release targets

| Platform | Architectures | Installers | Runner |
| --- | --- | --- | --- |
| Windows | x64, arm64 | Per-user NSIS `.exe`, `.msi` | `windows-latest` |
| macOS | Universal (`lipo`) | `.dmg`, `.app.tar.gz` | `macos-latest` |
| Linux | x64, arm64 | `.deb`, `.rpm`, `.AppImage` | `ubuntu-22.04`, `ubuntu-22.04-arm` |

Every release also includes `SHA256SUMS.txt`.

Every asset is named with the tag's full version, for example `Rusty-Conduit-GUI_0.2.0-beta.6_amd64.deb` or `Rusty-Conduit-GUI-0.2.0-beta.6-1.x86_64.rpm` for tag `v0.2.0-beta.6`.

## 1. Bump the version

Set the same plain `X.Y.Z` in all three files. Never put a label such as `-beta.6` in them: MSI and RPM versions cannot carry one. The label lives only in the tag (see below).

- `src-tauri/Cargo.toml` (`[package]` version)
- `src-tauri/tauri.conf.json`
- `src-tauri/ui/package.json`

Then refresh both lockfiles and check that the versions agree:

```sh
cargo update --workspace
(cd src-tauri/ui && npm install --package-lock-only)
python3 scripts/validate-release-config.py
```

Tags use the format `vX.Y.Z` for a final release or `vX.Y.Z-<label>` for a pre-release, for example `v0.2.0-beta.6`. The tag's `X.Y.Z` must equal the version files, and the tag must point at the commit that contains them. Successive betas of one version keep the same files and only move the tag number (`v0.2.0-beta.6`, `v0.2.0-beta.7`, …).

The release workflow turns the tag into the **release version** with `scripts/release-version.py` (`v0.2.0-beta.6` → `0.2.0-beta.6`) and fails early when the tag's `X.Y.Z` does not match the files. That version, passed to the build as `CONDUIT_RELEASE_VERSION`, appears in:

- the About page and `rusty-conduit-gui --version`;
- every release asset's file name;
- the GitHub Release, which is marked a **pre-release** when the tag has a label.

Builds outside the release workflow (local builds, `npm run dev`, CI) show `X.Y.Z-dev`. A manual dry run shows `X.Y.Z-dev.<short sha>`. Installers and the operating system's app list still show the plain `X.Y.Z`.

To check a tag before pushing it:

```sh
python3 scripts/release-version.py --ref-type tag --ref-name v0.2.0-beta.6
```

## 2. Engine dependency

The workspace `Cargo.toml` pulls the shared engine, `rusty-conduit-engine`, from its pinned Git tag:

```toml
rusty-conduit-engine = { git = "https://github.com/jpbaking/rusty-conduit-engine", tag = "v0.6.0" }
```

No sibling checkout is needed, locally or in CI. Cargo fetches the tag on the first build, and `Cargo.lock` records the exact commit.

- **To move to a new engine release,** change the `tag`, run `cargo update -p rusty-conduit-engine`, and commit both `Cargo.toml` and `Cargo.lock`.
- **Release builds always use a tag,** never a branch, so rebuilding the same app tag later produces the same code.
- The workflows set `CARGO_NET_GIT_FETCH_WITH_CLI=true`, so Cargo fetches the engine with the `git` command line. Set it locally too if Cargo's built-in Git client fails behind a proxy.
- The old `UPSTREAM_REPO` and `UPSTREAM_REF` repository variables are no longer read. You can delete them.

## 3. Build locally

Install the prerequisites:

- Rust stable, Node 22, and Python 3
- Tauri CLI: `cargo install tauri-cli --version 2.12.6 --locked`
- On Debian or Ubuntu:

```sh
sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev \
  librsvg2-dev patchelf libdbus-1-dev libgtk-3-dev rpm
```

Run these from the repository root:

```sh
(cd src-tauri/ui && npm ci && npm run build)
python3 scripts/stage-worker.py --profile release
cargo tauri build --config src-tauri/tauri.bundle.conf.json
python3 scripts/smoke-test-bundle.py --bundle-dir target/release/bundle --platform linux
```

`stage-worker.py` builds `conduit-worker` and copies it to `src-tauri/binaries/`, which Git ignores. The bundle config adds it to the installer as a sidecar (a helper program shipped with the app).

For a specific target, pass the same triple to both build steps. The bundles then land in `target/<triple>/release/bundle`:

```sh
python3 scripts/stage-worker.py --target aarch64-unknown-linux-gnu
cargo tauri build --config src-tauri/tauri.bundle.conf.json --target aarch64-unknown-linux-gnu
```

For a macOS Universal build:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
python3 scripts/stage-worker.py --universal-macos
cargo tauri build --config src-tauri/tauri.bundle.conf.json --target universal-apple-darwin
python3 scripts/smoke-test-bundle.py --bundle-dir target/universal-apple-darwin/release/bundle --platform macos
```

Remove `src-tauri/binaries/` when you finish, so a stale worker cannot be packaged by a later build.

## 4. Signing and notarization

Signing is optional. Add these as GitHub Actions repository secrets.

### macOS

| Secret | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64-encoded Developer ID `.p12` certificate |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the `.p12` file |
| `APPLE_SIGNING_IDENTITY` | Signing identity name |
| `APPLE_ID` | Apple account used for notarization |
| `APPLE_PASSWORD` | App-specific password for that account |
| `APPLE_TEAM_ID` | Apple Developer team ID |

- **No `APPLE_CERTIFICATE`:** the app is ad-hoc signed and the build logs a warning. Gatekeeper (the macOS app check) will warn users.
- **Certificate set, but `APPLE_ID`, `APPLE_PASSWORD`, or `APPLE_TEAM_ID` missing:** the app is signed but not notarized, and the build logs a warning.

### Windows

| Secret | Purpose |
| --- | --- |
| `WINDOWS_CERTIFICATE` | Base64-encoded `.pfx` certificate |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password for the `.pfx` file |

- **No `WINDOWS_CERTIFICATE`:** installers are unsigned and the build logs a warning. SmartScreen (the Windows download check) will warn users.
- **`WINDOWS_CERTIFICATE` set:** the workflow signs both the **x64 and arm64** installers.

## 5. Linux baseline

Linux builds run on Ubuntu 22.04, so the binaries link against its glibc (the core system C library). The supported baseline is **Ubuntu 22.04 / Debian 12** or newer. Do not build release packages on a newer distribution, because the result may not start on the baseline.

**Flatpak and Snap are deferred.** Their sandboxes conflict with what this app needs: host networking, local sockets, the system tray, and autostart.

## 6. Cut the release

1. Merge the version bump and confirm CI is green on `main`.
2. Optional: run the **Release** workflow manually with `dry_run` on. It builds everything without publishing.
3. Tag the release and push the tag:

   ```sh
   git tag -a vX.Y.Z-beta.N -m "vX.Y.Z-beta.N"   # or vX.Y.Z for a final release
   git push origin vX.Y.Z-beta.N
   ```

4. Wait for the workflow. It checks the tag against the version files, runs the CI gates, builds all five targets, smoke-tests them, and creates a **draft** GitHub Release (a pre-release for a labelled tag) whose assets carry the tag's version.
5. Download the draft's files and verify them with `sha256sum --check SHA256SUMS.txt`.
6. Complete the checklist below.
7. Edit the release notes and publish the draft.

## 7. Pre-release smoke-test checklist

Automated checks confirm that the installers exist, contain both binaries, and (for `.deb` and `.rpm`) replace `rusty-conduit-ssh-gui`. They do not launch the app, so test these by hand.

### All platforms

- [ ] The app installs and launches, and **About** and `rusty-conduit-gui --version` show the tag's version (for example `0.2.0-beta.6`, with a **BETA** pill), not `-dev`.
- [ ] A vault can be created, locked, and unlocked.
- [ ] **Upgrade from v0.1.0:** with `rusty-conduit-ssh-gui` installed and holding data, installing v0.2.0 replaces it. The first launch shows the rename banner, and the old vault, sessions, host-key pins, and presets load unchanged.
- [ ] A direct SSH connection works, and an unknown host key prompts for approval.
- [ ] A multi-hop connection works, and **Test Connection** names the failing hop when one is broken.
- [ ] Forward and reverse proxies pass traffic.
- [ ] The Manage Window shows both **Proxies** and **Tunnels**. A Proxy can be created, started, and stopped from each.
- [ ] Each Proxy mode routes traffic: **Direct**, **Forward** (through an upstream profile or a Tunnel), **Auto Switch** (rules and the Route Tester agree), and **External TOML** (edits to the linked file are picked up).
- [ ] Saving a routing change on a running Proxy applies it without dropping open connections.
- [ ] An AirSwitch / ZeroOmega `.bak` file imports through the wizard.
- [ ] A `config.toml` from each CLI (`rusty-conduit`, `rusty-conduit-ssh`, `rusty-conduit-switch`) imports, and export writes one back with no plaintext secrets.
- [ ] A new backup uses format v2 and restores. A v1 backup from v0.1.0 imports and migrates.
- [ ] The tray menu lists **PROXIES** and **TUNNELS** sections, and their start, stop, and mode actions work.
- [ ] The OpenSSH engine starts `conduit-worker` and connects.
- [ ] Closing the window keeps sessions running in the tray.
- [ ] A second launch focuses the existing instance.
- [ ] Autostart launches into the tray after login.
- [ ] Logs and config exports contain no secrets.
- [ ] Uninstalling removes the app and leaves no worker running.

### Windows (x64 and arm64)

- [ ] The NSIS installer works per-user, without an admin prompt.
- [ ] Upgrading over a running app stops the app and `conduit-worker`, then succeeds.
- [ ] With `Rusty Conduit (SSH)` installed, the installer offers to uninstall it, and both answers leave a working install.
- [ ] The `.msi` installs and uninstalls.
- [ ] The signature is valid on signed builds (file Properties, Digital Signatures).
- [ ] OpenSSH askpass and the named-pipe agent work on OpenSSH 8.4 or newer.

### macOS (Apple silicon and Intel)

- [ ] The `.dmg` mounts and the app runs on both architectures.
- [ ] Replacing `Rusty Conduit (SSH).app` with the new app keeps the vault and sessions.
- [ ] `lipo -archs` lists `x86_64 arm64` for the app and `conduit-worker`.
- [ ] `spctl --assess --type execute` accepts signed and notarized builds.
- [ ] The app runs from the tray without a Dock icon, and the Dock icon returns when the window opens.

### Linux (x64 and arm64)

- [ ] The `.deb` installs on Ubuntu 22.04 and Debian 12.
- [ ] The `.rpm` installs on a current Fedora release.
- [ ] `dpkg-deb -f` shows `Replaces` and `Conflicts`, and `rpm -qp --obsoletes` and `--conflicts` show `rusty-conduit-ssh-gui`. Installing over the old package removes it.
- [ ] The `.AppImage` runs on the baseline.
- [ ] The tray works on XFCE.
- [ ] The app works on a Wayland session, including the no-tray fallback where no tray exists.
- [ ] Without an unlocked Secret Service, the vault stays locked until the Master Password is entered, and never falls back to plaintext.

## 8. Upgrading from v0.1.0 (`rusty-conduit-ssh-gui`)

`v0.2.0` renames the app from **Rusty Conduit (SSH)** (`rusty-conduit-ssh-gui`) to **Rusty Conduit GUI** (`rusty-conduit-gui`). The installers handle the switch:

| Platform | What happens |
| --- | --- |
| Linux `.deb` | The package declares `Replaces` and `Conflicts` on `rusty-conduit-ssh-gui`, so installing it removes the old package. |
| Linux `.rpm` | The package declares `Obsoletes` and `Conflicts` on `rusty-conduit-ssh-gui`, so `dnf` replaces the old package. |
| Windows NSIS | Before installing, the installer stops `rusty-conduit-gui.exe`, `rusty-conduit-ssh-gui.exe`, and `conduit-worker.exe`. If `Rusty Conduit (SSH)` is still installed, it offers to uninstall it. Silent installs skip the offer. |
| macOS | The new `.app` has a new name. Users drag it to Applications and delete the old `Rusty Conduit (SSH).app`. The Keychain may ask once to let the renamed app read the vault key. |

On first launch, the app **moves the old data directory** (vault, sessions, host-key pins, presets, and settings) to the new one and moves login autostart to the new name. It refuses to start while the old app is still running.

`scripts/validate-release-config.py` checks this packaging config, and `scripts/smoke-test-bundle.py` checks the metadata inside the built `.deb` and `.rpm` files.
