// The app version shown on the About page. Release builds get the tag's version through the
// `CONDUIT_RELEASE_VERSION` environment variable (set by `.github/workflows/release.yml`); every
// other build is a development build. The Rust side does the same in `platform::app_version`.

/**
 * The full app version: the release version when one is given, else `<package version>-dev`.
 * Throws when the release version is not the package's `X.Y.Z`, optionally with a label.
 */
export function resolveAppVersion(packageVersion: string, releaseVersion: string | undefined): string {
  if (!releaseVersion) return `${packageVersion}-dev`;
  if (releaseVersion !== packageVersion && !releaseVersion.startsWith(`${packageVersion}-`)) {
    throw new Error(
      `CONDUIT_RELEASE_VERSION ${releaseVersion} does not match package.json version ${packageVersion}`,
    );
  }
  return releaseVersion;
}

/** The pre-release label's name, such as `beta` for `0.2.0-beta.6`, or null for a final release. */
export function releaseStage(version: string): string | null {
  const label = /^\d+\.\d+\.\d+-([0-9A-Za-z]+)/.exec(version);
  return label?.[1]?.toLowerCase() ?? null;
}

/** The release notes page: the tag's own page for a release build, else the releases list. */
export function releaseNotesUrl(repo: string, version: string): string {
  return releaseStage(version) === "dev" ? `${repo}/releases` : `${repo}/releases/tag/v${version}`;
}
