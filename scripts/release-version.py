#!/usr/bin/env python3
"""Prints the release version for a Git ref and checks it against the version files.

The version files (`src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `src-tauri/ui/package.json`)
hold a plain `X.Y.Z`, because MSI and RPM versions cannot carry a pre-release label. The tag
carries the full release version:

  tag v0.2.0-beta.6  ->  0.2.0-beta.6   (needs X.Y.Z = 0.2.0 in the version files)
  tag v0.2.0         ->  0.2.0
  any other ref      ->  0.2.0-dev.<short sha>   (a dry run)

The release workflow builds that version into the app (About page and `--version`, through
`CONDUIT_RELEASE_VERSION`) and into every installer's file name.

Usage: release-version.py --ref-type tag --ref-name v0.2.0-beta.6 [--sha <commit>] [--github-output FILE]
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# SemVer core plus an optional pre-release label such as beta.6 or rc.1 (no build metadata).
TAG = re.compile(r"^v(\d+\.\d+\.\d+)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$")


def base_version():
    return json.loads((ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))["version"]


def release_version(ref_type, ref_name, sha, base):
    """Returns (version, is_prerelease), or raises ValueError."""
    if ref_type != "tag":
        short = (sha or "local")[:7]
        return f"{base}-dev.{short}", True
    match = TAG.match(ref_name)
    if not match:
        raise ValueError(f"tag {ref_name!r} is not vX.Y.Z or vX.Y.Z-<label>, such as v{base}-beta.1")
    if match.group(1) != base:
        raise ValueError(
            f"tag {ref_name} is for {match.group(1)}, but the version files say {base}: "
            "bump them first (docs/RELEASING.md)"
        )
    return ref_name[1:], match.group(2) is not None


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref-type", required=True, help="GITHUB_REF_TYPE: tag or branch")
    parser.add_argument("--ref-name", required=True, help="GITHUB_REF_NAME, such as v0.2.0-beta.6")
    parser.add_argument("--sha", default="", help="GITHUB_SHA, used for dry-run versions")
    parser.add_argument("--github-output", help="append version= and prerelease= to this file")
    args = parser.parse_args()

    try:
        version, prerelease = release_version(args.ref_type, args.ref_name, args.sha, base_version())
    except (OSError, KeyError, ValueError) as error:
        print(f"release version error: {error}", file=sys.stderr)
        return 1

    print(version)
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as out:
            out.write(f"version={version}\nprerelease={'true' if prerelease else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
