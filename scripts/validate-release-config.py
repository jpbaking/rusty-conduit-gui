#!/usr/bin/env python3
"""Validates the Tauri bundle config, icons, installer hooks, versions, and workflows."""

import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAURI = ROOT / "src-tauri"
WORKFLOWS = ROOT / ".github" / "workflows"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_SIZES = {"32x32.png": 32, "128x128.png": 128, "128x128@2x.png": 256}
REQUIRED_JOBS = {
    "ci.yml": {"frontend", "rust-and-e2e"},
    "release.yml": {"verify", "package", "release"},
}
CI_OSES = {"ubuntu-22.04", "macos-latest", "windows-latest"}
FRONTEND_COMMANDS = ("npm ci", "npm run check", "npm test", "npm run build")
CI_COMMANDS = (
    "cargo clippy --workspace --all-targets -- -D warnings",
    "cargo test --workspace",
    "--test secret_leak_scan",
    "scripts/check-pure-rust-crypto.py",
    "scripts/validate-release-config.py",
    '--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests',
)
RELEASE_TARGETS = {
    "linux-x64": ("ubuntu-22.04", "x86_64-unknown-linux-gnu"),
    "linux-arm64": ("ubuntu-22.04-arm", "aarch64-unknown-linux-gnu"),
    "macos-universal": ("macos-latest", "universal-apple-darwin"),
    "windows-x64": ("windows-latest", "x86_64-pc-windows-msvc"),
    "windows-arm64": ("windows-latest", "aarch64-pc-windows-msvc"),
}
PACKAGE_COMMANDS = (
    "scripts/stage-worker.py",
    "tauri build --config src-tauri/tauri.bundle.conf.json",
    "scripts/smoke-test-bundle.py",
)
RELEASE_COMMANDS = ("SHA256SUMS.txt", "gh release create", "--draft")


def load_json(path, errors):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        errors.append(f"{path.relative_to(ROOT)}: {error}")
        return {}


def check_base_config(config, errors):
    bundle = config.get("bundle", {})
    if bundle.get("active") is not False:
        errors.append("tauri.conf.json: bundle.active must stay false for plain builds")
    for field in ("category", "copyright", "license", "shortDescription", "longDescription"):
        if not bundle.get(field):
            errors.append(f"tauri.conf.json: bundle.{field} is required")
    for icon in bundle.get("icon", []):
        if not (TAURI / icon).is_file():
            errors.append(f"tauri.conf.json: icon {icon} does not exist")
    if not bundle.get("icon"):
        errors.append("tauri.conf.json: bundle.icon is required")

    linux = bundle.get("linux", {})
    for package in ("deb", "rpm", "appimage"):
        if package not in linux:
            errors.append(f"tauri.conf.json: bundle.linux.{package} is required")
    if not bundle.get("macOS", {}).get("minimumSystemVersion"):
        errors.append("tauri.conf.json: bundle.macOS.minimumSystemVersion is required")

    nsis = bundle.get("windows", {}).get("nsis", {})
    if nsis.get("installMode") != "currentUser":
        errors.append("tauri.conf.json: NSIS installMode must be currentUser")
    hooks = nsis.get("installerHooks")
    if not hooks:
        errors.append("tauri.conf.json: NSIS installerHooks is required")
    elif (TAURI / hooks).resolve() != (TAURI / "windows" / "nsis-hooks.nsh").resolve():
        errors.append("tauri.conf.json: NSIS installerHooks must be windows/nsis-hooks.nsh")


def check_bundle_overlay(overlay, errors):
    bundle = overlay.get("bundle", {})
    if bundle.get("active") is not True:
        errors.append("tauri.bundle.conf.json: bundle.active must be true")
    if bundle.get("targets") != "all":
        errors.append('tauri.bundle.conf.json: bundle.targets must be "all"')
    if "binaries/conduit-worker" not in bundle.get("externalBin", []):
        errors.append("tauri.bundle.conf.json: externalBin must include binaries/conduit-worker")


def check_nsis_hooks(errors):
    path = TAURI / "windows" / "nsis-hooks.nsh"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"nsis-hooks.nsh: {error}")
        return
    required = (
        "!macro NSIS_HOOK_PREINSTALL",
        "!macro NSIS_HOOK_PREUNINSTALL",
        "rusty-conduit-gui.exe",
        "conduit-worker.exe",
        "taskkill",
    )
    for needle in required:
        if needle not in text:
            errors.append(f"nsis-hooks.nsh: missing {needle}")


def png_size(data):
    if len(data) < 24 or data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", data[16:24])


def check_icons(errors):
    icons = TAURI / "icons"
    for name, size in PNG_SIZES.items():
        path = icons / name
        if not path.is_file():
            errors.append(f"icons/{name} is missing")
        elif png_size(path.read_bytes()) != (size, size):
            errors.append(f"icons/{name} must be a {size}x{size} PNG")

    main = icons / "icon.png"
    if not main.is_file():
        errors.append("icons/icon.png is missing")
    else:
        dimensions = png_size(main.read_bytes())
        if dimensions is None or dimensions[0] != dimensions[1] or dimensions[0] < 256:
            errors.append("icons/icon.png must be a square PNG of at least 256x256")

    ico = icons / "icon.ico"
    if not ico.is_file():
        errors.append("icons/icon.ico is missing")
    else:
        data = ico.read_bytes()
        if len(data) < 6 or data[:4] != b"\x00\x00\x01\x00" or struct.unpack("<H", data[4:6])[0] == 0:
            errors.append("icons/icon.ico has an invalid header")

    icns = icons / "icon.icns"
    if not icns.is_file():
        errors.append("icons/icon.icns is missing")
    else:
        data = icns.read_bytes()
        if len(data) <= 8 or data[:4] != b"icns" or struct.unpack(">I", data[4:8])[0] != len(data):
            errors.append("icons/icon.icns has an invalid header or length")


def cargo_version(errors):
    try:
        text = (TAURI / "Cargo.toml").read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"src-tauri/Cargo.toml: {error}")
        return None
    # Only the [package] table: dependency tables also have `version` keys.
    section = re.search(r"^\[package\]\s*$(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
    match = section and re.search(r'^version\s*=\s*"([^"]+)"', section.group(1), re.MULTILINE)
    if not match:
        errors.append("src-tauri/Cargo.toml: no [package] version")
        return None
    return match.group(1)


def check_versions(config, errors):
    package = load_json(TAURI / "ui" / "package.json", errors)
    versions = {
        "src-tauri/Cargo.toml": cargo_version(errors),
        "src-tauri/tauri.conf.json": config.get("version"),
        "src-tauri/ui/package.json": package.get("version"),
    }
    if None in versions.values() or len(set(versions.values())) != 1:
        errors.append(f"version mismatch: {versions}")


def job_runs(job):
    """Joins a job's shell commands, so a check cannot match a comment or step name."""
    steps = job.get("steps", []) if isinstance(job, dict) else []
    return "\n".join(step.get("run", "") for step in steps if isinstance(step, dict))


def job_uses(job):
    steps = job.get("steps", []) if isinstance(job, dict) else []
    return {step.get("uses", "").split("@")[0] for step in steps if isinstance(step, dict)}


def job_matrix(job):
    strategy = job.get("strategy", {}) if isinstance(job, dict) else {}
    matrix = strategy.get("matrix", {}) if isinstance(strategy, dict) else {}
    return matrix if isinstance(matrix, dict) else {}


def triggers(document):
    # YAML 1.1 reads the bare key `on` as the boolean true.
    value = document.get("on", document.get(True, {}))
    return value if isinstance(value, dict) else {}


def require_commands(name, job_name, job, commands, errors):
    runs = job_runs(job)
    for command in commands:
        if command not in runs:
            errors.append(f"{name}: job {job_name} must run {command}")


def check_ci(document, errors):
    on = triggers(document)
    if "main" not in (on.get("push") or {}).get("branches", []):
        errors.append("ci.yml: must run on push to main")
    if "pull_request" not in on:
        errors.append("ci.yml: must run on pull_request")
    jobs = document["jobs"]
    require_commands("ci.yml", "frontend", jobs.get("frontend"), FRONTEND_COMMANDS, errors)
    rust = jobs.get("rust-and-e2e")
    if set(job_matrix(rust).get("os", [])) != CI_OSES:
        errors.append(f"ci.yml: rust-and-e2e matrix must be exactly {sorted(CI_OSES)}")
    require_commands("ci.yml", "rust-and-e2e", rust, CI_COMMANDS, errors)
    if "actions/checkout" not in job_uses(rust):
        errors.append("ci.yml: rust-and-e2e must check out the repository")
    steps = rust.get("steps", []) if isinstance(rust, dict) else []
    paths = {(step.get("with") or {}).get("path") for step in steps if isinstance(step, dict)}
    if not {"rusty-conduit-gui", "rusty-conduit-ssh"} <= paths:
        errors.append("ci.yml: rust-and-e2e must check out both sibling repositories")


def check_release(document, text, errors):
    on = triggers(document)
    if "v*" not in (on.get("push") or {}).get("tags", []):
        errors.append("release.yml: must run on v* tags")
    dry_run = ((on.get("workflow_dispatch") or {}).get("inputs") or {}).get("dry_run", {})
    if dry_run.get("type") != "boolean" or dry_run.get("default") is not True:
        errors.append("release.yml: workflow_dispatch needs boolean dry_run defaulting to true")

    jobs = document["jobs"]
    verify = jobs.get("verify", {})
    if verify.get("uses") != "./.github/workflows/ci.yml":
        errors.append("release.yml: verify must call ./.github/workflows/ci.yml")

    package = jobs.get("package")
    if not isinstance(package, dict):
        errors.append("release.yml: missing required job package")
        return
    if package.get("needs") != "verify":
        errors.append("release.yml: package must need verify")
    include = job_matrix(package).get("include", [])
    found = {entry.get("name"): (entry.get("os"), entry.get("target")) for entry in include}
    if found != RELEASE_TARGETS:
        errors.append(f"release.yml: package matrix must be exactly {RELEASE_TARGETS}")
    require_commands("release.yml", "package", package, PACKAGE_COMMANDS, errors)
    if not any(entry.get("stage_args") == "--universal-macos" for entry in include):
        errors.append("release.yml: macOS must stage with --universal-macos")
    if "rpm" not in job_runs(package).split():
        errors.append("release.yml: Linux packaging must install rpm")
    for secret in ("secrets.APPLE_CERTIFICATE", "secrets.WINDOWS_CERTIFICATE"):
        if secret not in text:
            errors.append(f"release.yml: conditional signing must use {secret}")

    release = jobs.get("release", {})
    require_commands("release.yml", "release", release, RELEASE_COMMANDS, errors)
    steps = release.get("steps", []) if isinstance(release, dict) else []
    publish = [s for s in steps if isinstance(s, dict) and "gh release create" in s.get("run", "")]
    condition = publish[0].get("if", "") if publish else ""
    for needle in ("startsWith(github.ref, 'refs/tags/v')", "inputs.dry_run"):
        if needle not in condition:
            errors.append(f"release.yml: draft release step condition must include {needle}")


def check_workflows(errors):
    try:
        import yaml
    except ImportError:
        errors.append("PyYAML is required to validate workflows: pip install pyyaml")
        return
    for name in sorted(REQUIRED_JOBS):
        path = WORKFLOWS / name
        try:
            text = path.read_text(encoding="utf-8")
            document = yaml.safe_load(text)
        except OSError as error:
            errors.append(f"{name}: {error}")
            continue
        except yaml.YAMLError as error:
            errors.append(f"{name}: invalid YAML: {error}")
            continue
        jobs = document.get("jobs") if isinstance(document, dict) else None
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"{name}: no jobs defined")
            continue
        missing = sorted(REQUIRED_JOBS[name] - set(jobs))
        for job in missing:
            errors.append(f"{name}: missing required job {job}")
        if missing:
            continue
        if name == "ci.yml":
            check_ci(document, errors)
        else:
            check_release(document, text, errors)


def main():
    errors = []
    config = load_json(TAURI / "tauri.conf.json", errors)
    overlay = load_json(TAURI / "tauri.bundle.conf.json", errors)
    check_base_config(config, errors)
    check_bundle_overlay(overlay, errors)
    check_nsis_hooks(errors)
    check_icons(errors)
    check_versions(config, errors)
    check_workflows(errors)
    if errors:
        for error in errors:
            print(f"release config error: {error}", file=sys.stderr)
        return 1
    print("RELEASE_CONFIG_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
