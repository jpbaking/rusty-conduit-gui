# Releasing Rusty Conduit GUI

This runbook covers how to cut a release, build installers locally, configure signing, and smoke-test the result.

## Release targets

| Platform | Architectures | Installers | Runner |
| --- | --- | --- | --- |
| Windows | x64, arm64 | Per-user NSIS `.exe`, `.msi` | `windows-latest` |
| macOS | Universal (`lipo`) | `.dmg`, `.app.tar.gz` | `macos-latest` |
| Linux | x64, arm64 | `.deb`, `.rpm`, `.AppImage` | `ubuntu-22.04`, `ubuntu-22.04-arm` |

Every release also includes `SHA256SUMS.txt`.

## 1. Bump the version

Set the same `X.Y.Z` in all three files:

- `src-tauri/Cargo.toml` (`[package]` version)
- `src-tauri/tauri.conf.json`
- `src-tauri/ui/package.json`

Then refresh both lockfiles and check that the versions agree:

```sh
cargo update --workspace
(cd src-tauri/ui && npm install --package-lock-only)
python3 scripts/validate-release-config.py
```

Tags use the format `vX.Y.Z`, for example `v0.2.0`. The tag must point at the commit that contains the version bump.

## 2. Sibling repository layout

`Cargo.toml` depends on `rusty-conduit-ssh` by relative path, so both repositories must sit in the same parent directory:

```text
parent/
├── rusty-conduit-ssh/   # upstream engine
└── rusty-conduit-gui/   # this repository
```

CI creates the same layout. Two optional GitHub repository variables choose what it checks out:

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPSTREAM_REPO` | `jpbaking/rusty-conduit-ssh` | Upstream repository |
| `UPSTREAM_REF` | `v1.3.0` | Branch, tag, or commit to build against |

**Pin `UPSTREAM_REF` to a tag or commit for a release.** The default follows `main`, so rebuilding the same tag later can produce different code.

If the upstream repository is private, the workflows also need a checkout credential. They do not configure one today.

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
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. Wait for the workflow. It runs the CI gates, builds all five targets, smoke-tests them, and creates a **draft** GitHub Release.
5. Download the draft's files and verify them with `sha256sum --check SHA256SUMS.txt`.
6. Complete the checklist below.
7. Edit the release notes and publish the draft.

## 7. Pre-release smoke-test checklist

Automated checks confirm that the installers exist and contain both binaries. They do not launch the app, so test these by hand.

### All platforms

- [ ] The app installs and launches, and the version is correct.
- [ ] A vault can be created, locked, and unlocked.
- [ ] A direct SSH connection works, and an unknown host key prompts for approval.
- [ ] A multi-hop connection works, and **Test Connection** names the failing hop when one is broken.
- [ ] Forward and reverse proxies pass traffic.
- [ ] The OpenSSH engine starts `conduit-worker` and connects.
- [ ] Closing the window keeps sessions running in the tray.
- [ ] A second launch focuses the existing instance.
- [ ] Autostart launches into the tray after login.
- [ ] Logs and config exports contain no secrets.
- [ ] Uninstalling removes the app and leaves no worker running.

### Windows (x64 and arm64)

- [ ] The NSIS installer works per-user, without an admin prompt.
- [ ] Upgrading over a running app stops the app and `conduit-worker`, then succeeds.
- [ ] The `.msi` installs and uninstalls.
- [ ] The signature is valid on signed builds (file Properties, Digital Signatures).
- [ ] OpenSSH askpass and the named-pipe agent work on OpenSSH 8.4 or newer.

### macOS (Apple silicon and Intel)

- [ ] The `.dmg` mounts and the app runs on both architectures.
- [ ] `lipo -archs` lists `x86_64 arm64` for the app and `conduit-worker`.
- [ ] `spctl --assess --type execute` accepts signed and notarized builds.
- [ ] The app runs from the tray without a Dock icon, and the Dock icon returns when the window opens.

### Linux (x64 and arm64)

- [ ] The `.deb` installs on Ubuntu 22.04 and Debian 12.
- [ ] The `.rpm` installs on a current Fedora release.
- [ ] The `.AppImage` runs on the baseline.
- [ ] The tray works on XFCE.
- [ ] The app works on a Wayland session, including the no-tray fallback where no tray exists.
- [ ] Without an unlocked Secret Service, the vault stays locked until the Master Password is entered, and never falls back to plaintext.
