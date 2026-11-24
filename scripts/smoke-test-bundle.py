#!/usr/bin/env python3
"""Checks that built installers are present, non-empty, and contain both app binaries."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

MAIN = "rusty-conduit-ssh-gui"
WORKER = "conduit-worker"
MAC_ARCHES = {"x86_64", "arm64"}
CHECKSUMS = "SHA256SUMS.txt"


class CheckError(Exception):
    """A bundle failed a check."""


def run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        raise CheckError(f"could not run {command[0]}: {error}") from error
    if result.returncode != 0:
        raise CheckError(f"{' '.join(map(str, command))} failed: {result.stderr.strip()}")
    return result.stdout


def require_non_empty(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise CheckError(f"{path} is missing or empty")


def find(bundle_dir, suffix):
    return sorted(p for p in bundle_dir.rglob(f"*{suffix}") if p.is_file())


def require_binaries(label, names):
    """`names` holds the file names listed in a package."""
    missing = {MAIN, WORKER} - set(names)
    if missing:
        raise CheckError(f"{label} is missing {', '.join(sorted(missing))}")


def deb_names(listing):
    # The path is the last column of `dpkg-deb -c`. Directories end in `/`.
    paths = (line.split()[-1] for line in listing.splitlines() if line.split())
    return [PurePosixPath(p).name for p in paths if not p.endswith("/")]


def rpm_names(listing):
    return [PurePosixPath(line.strip()).name for line in listing.splitlines() if line.strip()]


def check_deb(path):
    require_non_empty(path)
    require_binaries(path.name, deb_names(run(["dpkg-deb", "-c", str(path)])))


def check_rpm(path):
    require_non_empty(path)
    require_binaries(path.name, rpm_names(run(["rpm", "-qlp", str(path)])))


def check_appimage(path):
    require_non_empty(path)
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise CheckError(f"{path} is not executable")


def check_linux(bundle_dir):
    checks = ((".deb", check_deb), (".rpm", check_rpm), (".AppImage", check_appimage))
    for suffix, check in checks:
        paths = find(bundle_dir, suffix)
        if not paths:
            raise CheckError(f"no {suffix} found in {bundle_dir}")
        for path in paths:
            check(path)


def check_mac_binary(path, lipo_info):
    require_non_empty(path)
    missing = MAC_ARCHES - set(lipo_info(path).replace(":", " ").split())
    if missing:
        raise CheckError(f"{path} is missing slices: {', '.join(sorted(missing))}")


def real_lipo_info(path):
    return run(["lipo", "-info", str(path)])


def check_macos(bundle_dir, lipo_info=real_lipo_info):
    apps = sorted(p for p in bundle_dir.rglob("*.app") if p.is_dir())
    if not apps:
        raise CheckError(f"no .app found in {bundle_dir}")
    for app in apps:
        for name in (MAIN, WORKER):
            check_mac_binary(app / "Contents" / "MacOS" / name, lipo_info)
    dmgs = find(bundle_dir, ".dmg")
    if not dmgs:
        raise CheckError(f"no .dmg found in {bundle_dir}")
    for dmg in dmgs:
        require_non_empty(dmg)


def check_windows(bundle_dir):
    installers = find(bundle_dir, ".exe") + find(bundle_dir, ".msi")
    if not installers:
        raise CheckError(f"no NSIS .exe or .msi found in {bundle_dir}")
    for installer in installers:
        require_non_empty(installer)


def check_checksums(bundle_dir):
    """Verifies `SHA256SUMS.txt` when present. Entries may not point outside the bundle."""
    sums = bundle_dir / CHECKSUMS
    if not sums.is_file():
        return
    root = bundle_dir.resolve()
    entries = 0
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise CheckError(f"malformed checksum line: {line!r}")
        expected, name = parts[0].lower(), parts[1].lstrip("*")
        target = (root / name).resolve()
        if root not in target.parents:
            raise CheckError(f"checksum entry escapes the bundle: {name}")
        require_non_empty(target)
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise CheckError(f"checksum mismatch: {name}")
        entries += 1
    if entries == 0:
        raise CheckError(f"{CHECKSUMS} has no entries")


PLATFORMS = {"linux": check_linux, "macos": check_macos, "windows": check_windows}


def verify(bundle_dir, platform):
    if not bundle_dir.is_dir():
        raise CheckError(f"{bundle_dir} is not a directory")
    PLATFORMS[platform](bundle_dir)
    check_checksums(bundle_dir)


def expect_fail(label, check, *args):
    try:
        check(*args)
    except CheckError:
        return
    raise CheckError(f"self-test: {label} should have failed")


def write(path, data=b"data", mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return path


def build_deb(root, name, files):
    tree = root / f"{name}-tree"
    write(
        tree / "DEBIAN" / "control",
        f"Package: {name}\nVersion: 0.0.1\nArchitecture: all\n"
        "Maintainer: Self Test <test@example.invalid>\nDescription: smoke test fixture\n".encode(),
    )
    (tree / "DEBIAN").chmod(0o755)
    for file_name in files:
        write(tree / "usr" / "bin" / file_name, b"#!/bin/sh\n", 0o755)
    output = root / f"{name}.deb"
    run(["dpkg-deb", "--root-owner-group", "--build", str(tree), str(output)])
    return output


def self_test_listings():
    deb = (
        "drwxr-xr-x root/root 0 2026-01-01 00:00 ./usr/bin/\n"
        f"-rwxr-xr-x root/root 9 2026-01-01 00:00 ./usr/bin/{MAIN}\n"
        f"-rwxr-xr-x root/root 9 2026-01-01 00:00 ./usr/bin/{WORKER}\n"
    )
    require_binaries("deb listing", deb_names(deb))
    partial = f"-rwxr-xr-x root/root 9 2026-01-01 00:00 ./usr/bin/{MAIN}\n"
    expect_fail("deb without worker", require_binaries, "deb", deb_names(partial))
    # A directory or longer name that merely contains the worker name is not the worker.
    lookalike = partial + f"drwxr-xr-x root/root 0 2026-01-01 00:00 ./usr/lib/{WORKER}/\n"
    expect_fail("worker directory", require_binaries, "deb", deb_names(lookalike))
    rpm = f"/usr/bin/{MAIN}\n/usr/bin/{WORKER}\n"
    require_binaries("rpm listing", rpm_names(rpm))
    expect_fail("rpm without main", require_binaries, "rpm", rpm_names(f"/usr/bin/{WORKER}-old\n"))


def self_test_deb(root):
    if shutil.which("dpkg-deb") is None:
        print("self-test: dpkg-deb not found, real .deb check skipped")
        return
    check_deb(build_deb(root, "complete", [MAIN, WORKER]))
    expect_fail("real deb without worker", check_deb, build_deb(root, "partial", [MAIN]))


def self_test_directories(root):
    linux = root / "linux"
    expect_fail("empty linux bundle", check_windows, linux.parent / "absent")
    appimage = write(linux / "app.AppImage", b"image", 0o755)
    check_appimage(appimage)
    expect_fail("empty AppImage", check_appimage, write(linux / "empty.AppImage", b"", 0o755))
    if os.name != "nt":
        expect_fail("non-executable AppImage", check_appimage, write(linux / "n.AppImage", b"x", 0o644))

    windows = root / "windows"
    expect_fail("no Windows installer", check_windows, write(windows / "x.txt").parent)
    write(windows / "nsis" / "setup.exe")
    check_windows(windows)
    write(windows / "msi" / "broken.msi", b"")
    expect_fail("empty MSI", check_windows, windows)

    mac = root / "macos"
    macos_dir = mac / "App.app" / "Contents" / "MacOS"
    write(macos_dir / MAIN)
    write(macos_dir / WORKER)
    universal = lambda path: f"Architectures in the fat file: {path} are: x86_64 arm64"
    thin = lambda path: f"Non-fat file: {path} is architecture: arm64"
    expect_fail("macOS without dmg", check_macos, mac, universal)
    write(mac / "dmg" / "App.dmg")
    check_macos(mac, universal)
    expect_fail("thin macOS binary", check_macos, mac, thin)
    (macos_dir / WORKER).unlink()
    expect_fail("macOS without worker", check_macos, mac, universal)


def self_test_checksums(root):
    bundle = root / "sums"
    artifact = write(bundle / "pkg" / "app.deb", b"payload")
    digest = hashlib.sha256(b"payload").hexdigest()
    sums = bundle / CHECKSUMS
    sums.write_text(f"{digest}  pkg/app.deb\n", encoding="utf-8")
    check_checksums(bundle)
    artifact.write_bytes(b"tampered")
    expect_fail("tampered artifact", check_checksums, bundle)
    artifact.write_bytes(b"payload")
    write(root / "outside.bin", b"payload")
    sums.write_text(f"{digest}  ../outside.bin\n", encoding="utf-8")
    expect_fail("path escape", check_checksums, bundle)
    sums.write_text("\n", encoding="utf-8")
    expect_fail("empty checksum file", check_checksums, bundle)


def self_test():
    with tempfile.TemporaryDirectory(prefix="conduit-smoke-") as temp:
        root = Path(temp)
        self_test_listings()
        self_test_deb(root)
        self_test_directories(root)
        self_test_checksums(root)
    print("SMOKE_TEST_SELF_TEST_OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="test this script on fixtures")
    parser.add_argument("--bundle-dir", type=Path, help="directory holding the built bundles")
    parser.add_argument("--platform", choices=sorted(PLATFORMS))
    args = parser.parse_args()
    if not args.self_test and not (args.bundle_dir and args.platform):
        parser.error("use --self-test, or both --bundle-dir and --platform")
    try:
        if args.self_test:
            self_test()
        else:
            verify(args.bundle_dir, args.platform)
            print(f"SMOKE_TEST_OK {args.platform}")
    except CheckError as error:
        print(f"smoke-test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
