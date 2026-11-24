#!/usr/bin/env python3
"""Builds conduit-worker and copies it to where Tauri expects its sidecar binary."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARIES = ROOT / "src-tauri" / "binaries"
MAC_TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
UNIVERSAL = "universal-apple-darwin"


def fail(message):
    sys.exit(f"stage-worker: {message}")


def run(command):
    print("+ " + " ".join(str(part) for part in command), flush=True)
    try:
        subprocess.run(command, cwd=ROOT, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"command failed: {error}")


def host_triple():
    try:
        output = subprocess.run(
            ["rustc", "-vV"], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"could not run rustc: {error}")
    match = re.search(r"^host: (\S+)$", output, re.MULTILINE)
    if not match:
        fail("rustc -vV did not report a host triple")
    return match.group(1)


def target_directory():
    try:
        output = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"could not run cargo metadata: {error}")
    return Path(json.loads(output)["target_directory"])


def exe_suffix(triple):
    return ".exe" if "windows" in triple else ""


def destination(triple):
    return BINARIES / f"conduit-worker-{triple}{exe_suffix(triple)}"


def build(triple, profile, target_dir):
    command = ["cargo", "build", "-p", "conduit-openssh", "--bin", "conduit-worker"]
    command += ["--target", triple]
    if profile == "release":
        command.append("--release")
    run(command)
    built = target_dir / triple / profile / f"conduit-worker{exe_suffix(triple)}"
    if not built.is_file():
        fail(f"build finished but {built} is missing")
    return built


def install(source, dest):
    """Replaces `dest` in one step, so a failed copy never leaves a partial sidecar."""
    BINARIES.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".partial")
    shutil.copy2(source, partial)
    if os.name != "nt":
        partial.chmod(0o755)
    os.replace(partial, dest)
    print(f"staged {dest}")


def stage_single(triple, profile):
    install(build(triple, profile, target_directory()), destination(triple))


def stage_universal(profile):
    if shutil.which("lipo") is None:
        fail("--universal-macos needs lipo, which is only available on macOS")
    target_dir = target_directory()
    slices = []
    # Tauri's per-architecture builds look up these thin sidecars as well as the universal one.
    for triple in MAC_TARGETS:
        built = build(triple, profile, target_dir)
        install(built, destination(triple))
        slices.append(built)
    BINARIES.mkdir(parents=True, exist_ok=True)
    dest = destination(UNIVERSAL)
    partial = dest.with_name(dest.name + ".partial")
    run(["lipo", "-create", *slices, "-output", partial])
    partial.chmod(0o755)
    os.replace(partial, dest)
    print(f"staged {dest}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--target", metavar="TRIPLE", help="Rust target (default: host)")
    choice.add_argument(
        "--universal-macos",
        action="store_true",
        help=f"build {' + '.join(MAC_TARGETS)} and combine them with lipo",
    )
    parser.add_argument("--profile", choices=("debug", "release"), default="release")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and build nothing")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.target and not re.fullmatch(r"[A-Za-z0-9_.]+(-[A-Za-z0-9_.]+)+", args.target):
        fail(f"invalid target triple {args.target!r}")

    triple = UNIVERSAL if args.universal_macos else args.target or host_triple()
    if args.dry_run:
        print(f"target: {triple}")
        print(f"profile: {args.profile}")
        if args.universal_macos:
            for thin in MAC_TARGETS:
                print(f"destination: {destination(thin)}")
        print(f"destination: {destination(triple)}")
        return 0

    if args.universal_macos:
        stage_universal(args.profile)
    else:
        stage_single(triple, args.profile)
    return 0


if __name__ == "__main__":
    sys.exit(main())
