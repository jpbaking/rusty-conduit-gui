//! OpenSSH binary discovery and version check.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Oldest OpenSSH on Windows with `SSH_ASKPASS_REQUIRE=force`.
pub const MIN_WINDOWS_VERSION: (u32, u32) = (8, 4);
/// Oldest OpenSSH elsewhere: the generated config needs `IdentityAgent` (OpenSSH 7.3).
pub const MIN_VERSION: (u32, u32) = (7, 3);
/// Oldest OpenSSH that always uses the app's askpass helper (`SSH_ASKPASS_REQUIRE=force`).
/// Older clients use it only when the app has no controlling terminal.
pub const FORCED_ASKPASS_VERSION: (u32, u32) = (8, 4);

const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The result of checking a configured `ssh` binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenSshBinaryInfo {
    pub requested: String,
    pub resolved_path: Option<String>,
    pub version_raw: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub supported: bool,
    pub message: String,
    /// A limit of a supported version, such as when password prompts may not reach the app.
    #[serde(default)]
    pub note: Option<String>,
}

/// Finds `OpenSSH_<major>.<minor>` or `OpenSSH_for_Windows_<major>.<minor>` in `-V` output.
pub fn parse_openssh_version(output: &str) -> Option<(u32, u32)> {
    const PREFIX: &str = "OpenSSH_";
    output.match_indices(PREFIX).find_map(|(start, _)| {
        let starts_word = output[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        if !starts_word {
            return None;
        }
        let rest = &output[start + PREFIX.len()..];
        let rest = rest.strip_prefix("for_Windows_").unwrap_or(rest);
        let (major, rest) = leading_number(rest)?;
        let (minor, _) = leading_number(rest.strip_prefix('.')?)?;
        Some((major, minor))
    })
}

fn leading_number(input: &str) -> Option<(u32, &str)> {
    let end = input
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(input.len());
    Some((input[..end].parse().ok()?, &input[end..]))
}

/// Whether this version can run here. The error is guidance to show the user.
pub fn check_version_for_platform(major: u32, minor: u32, is_windows: bool) -> Result<(), String> {
    if is_windows {
        let (min_major, min_minor) = MIN_WINDOWS_VERSION;
        if (major, minor) < MIN_WINDOWS_VERSION {
            return Err(format!(
                "OpenSSH {major}.{minor} is too old for Windows. Upgrade to OpenSSH \
                 {min_major}.{min_minor} or newer, for example from the Win32-OpenSSH releases."
            ));
        }
        return Ok(());
    }
    let (min_major, min_minor) = MIN_VERSION;
    if (major, minor) < MIN_VERSION {
        return Err(format!(
            "OpenSSH {major}.{minor} is too old. The OpenSSH engine needs OpenSSH \
             {min_major}.{min_minor} or newer."
        ));
    }
    Ok(())
}

/// A limit of a supported version worth telling the user about, if any.
pub fn version_note(major: u32, minor: u32, is_windows: bool) -> Option<String> {
    let (forced_major, forced_minor) = FORCED_ASKPASS_VERSION;
    (!is_windows && (major, minor) < FORCED_ASKPASS_VERSION).then(|| {
        format!(
            "Password and passphrase prompts may not reach the app when it is started from a \
             terminal. OpenSSH {forced_major}.{forced_minor} or newer avoids this."
        )
    })
}

/// Runs `<ssh_bin> -V` and reports whether the binary can be used.
pub fn check_openssh_binary(ssh_bin: &str) -> OpenSshBinaryInfo {
    let mut info = OpenSshBinaryInfo {
        requested: ssh_bin.to_string(),
        resolved_path: None,
        version_raw: None,
        major: None,
        minor: None,
        supported: false,
        message: String::new(),
        note: None,
    };
    let Some(path) = resolve(ssh_bin) else {
        info.message = format!("OpenSSH binary {ssh_bin:?} was not found.");
        return info;
    };
    info.resolved_path = Some(path.display().to_string());

    let output = match version_output(&path) {
        Ok(output) => output,
        Err(error) => {
            info.message = format!("Could not run {}: {error}", path.display());
            return info;
        }
    };
    let raw = output.trim().to_string();
    let parsed = parse_openssh_version(&raw);
    info.version_raw = (!raw.is_empty()).then_some(raw);
    let Some((major, minor)) = parsed else {
        info.message = format!("{} did not report an OpenSSH version.", path.display());
        return info;
    };
    info.major = Some(major);
    info.minor = Some(minor);
    match check_version_for_platform(major, minor, cfg!(windows)) {
        Ok(()) => {
            info.supported = true;
            info.message = format!("OpenSSH {major}.{minor} is supported.");
            info.note = version_note(major, minor, cfg!(windows));
        }
        Err(message) => info.message = message,
    }
    info
}

fn resolve(ssh_bin: &str) -> Option<PathBuf> {
    if ssh_bin.is_empty() {
        return None;
    }
    let path = Path::new(ssh_bin);
    if path.components().count() > 1 {
        return path.is_file().then(|| path.to_path_buf());
    }
    let search = std::env::var_os("PATH")?;
    std::env::split_paths(&search).find_map(|dir| {
        let candidate = dir.join(ssh_bin);
        if candidate.is_file() {
            return Some(candidate);
        }
        if cfg!(windows) {
            let candidate = dir.join(format!("{ssh_bin}.exe"));
            return candidate.is_file().then_some(candidate);
        }
        None
    })
}

/// OpenSSH prints its version to stderr. A binary that hangs is killed after a timeout.
fn version_output(path: &Path) -> std::io::Result<String> {
    let mut child = Command::new(path)
        .arg("-V")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + VERSION_TIMEOUT;
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for the version",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_macos_and_windows_versions() {
        let cases = [
            ("OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5", (10, 2)),
            ("OpenSSH_9.9p2, LibreSSL 3.3.6", (9, 9)),
            ("OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3", (8, 6)),
            ("OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2", (9, 5)),
            ("warning: noise\nOpenSSH_8.4p1 Debian", (8, 4)),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_openssh_version(text), Some(expected), "{text}");
        }
    }

    #[test]
    fn rejects_text_that_is_not_an_openssh_version() {
        for text in [
            "",
            "ssh: command not found",
            "OpenSSH_",
            "OpenSSH_x.y",
            "OpenSSH_9",
            "NotOpenSSH_9.1",
            "OpenSSH_99999999999.1",
        ] {
            assert_eq!(parse_openssh_version(text), None, "{text}");
        }
    }

    #[test]
    fn windows_requires_8_4() {
        let error = check_version_for_platform(8, 3, true).unwrap_err();
        assert!(error.contains("Upgrade"));
        assert!(check_version_for_platform(7, 9, true).is_err());
        for (major, minor) in [(8, 4), (8, 6), (10, 2)] {
            assert!(check_version_for_platform(major, minor, true).is_ok());
        }
    }

    #[test]
    fn other_platforms_require_7_3() {
        let error = check_version_for_platform(7, 2, false).unwrap_err();
        assert!(error.contains("7.3 or newer"), "{error}");
        assert!(check_version_for_platform(6, 9, false).is_err());
        for (major, minor) in [(7, 3), (8, 3), (8, 4), (10, 5)] {
            assert!(check_version_for_platform(major, minor, false).is_ok());
        }
    }

    #[test]
    fn versions_before_forced_askpass_get_a_note_off_windows() {
        assert!(version_note(8, 3, false).unwrap().contains("8.4 or newer"));
        assert!(version_note(7, 3, false).is_some());
        assert_eq!(version_note(8, 4, false), None);
        assert_eq!(version_note(10, 5, false), None);
        // Windows already requires 8.4.
        assert_eq!(version_note(8, 4, true), None);
    }

    #[cfg(unix)]
    #[test]
    fn checks_the_real_usr_bin_ssh() {
        let info = check_openssh_binary("/usr/bin/ssh");
        assert!(info.supported, "{info:?}");
        assert_eq!(info.resolved_path.as_deref(), Some("/usr/bin/ssh"));
        assert!(info.version_raw.unwrap().contains("OpenSSH_"));
        assert!(info.major.is_some() && info.minor.is_some());
    }

    #[test]
    fn missing_binary_is_reported() {
        let info = check_openssh_binary("/nonexistent/conduit/ssh");
        assert!(!info.supported);
        assert_eq!(info.resolved_path, None);
        assert!(info.message.contains("not found"));
    }

    #[cfg(unix)]
    #[test]
    fn binary_that_is_not_openssh_is_unsupported() {
        let info = check_openssh_binary("/bin/true");
        assert!(!info.supported);
        assert_eq!(info.major, None);
    }
}
