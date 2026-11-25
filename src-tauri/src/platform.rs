//! Process-level platform rules: CLI flags, WebKitGTK rendering mitigations, autostart path
//! resolution, and process hardening. Everything here runs before any window exists.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const FLAG_TRAY: &str = "--tray";
pub const FLAG_SHOW: &str = "--show";
pub const FLAG_SAFE_RENDERING: &str = "--safe-rendering";
pub const FLAG_HELP: &str = "--help";
pub const FLAG_HELP_SHORT: &str = "-h";
pub const FLAG_VERSION: &str = "--version";
pub const FLAG_VERSION_SHORT: &str = "-V";

pub const ENV_DISABLE_DMABUF: &str = "WEBKIT_DISABLE_DMABUF_RENDERER";
pub const ENV_DISABLE_COMPOSITING: &str = "WEBKIT_DISABLE_COMPOSITING_MODE";
pub const ENV_NV_EXPLICIT_SYNC: &str = "__NV_DISABLE_EXPLICIT_SYNC";

/// Rendering workarounds meant only for this app's WebView, never for its child processes.
pub const RENDERING_ENV_VARS: [&str; 3] =
    [ENV_DISABLE_DMABUF, ENV_DISABLE_COMPOSITING, ENV_NV_EXPLICIT_SYNC];

/// The command-line flags this app understands. Unknown arguments are ignored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CliFlags {
    pub tray: bool,
    pub show: bool,
    pub safe_rendering: bool,
    /// `--help` / `-h`: print usage and exit without starting the GUI.
    pub help: bool,
    /// `--version` / `-V`: print the version and exit without starting the GUI.
    pub version: bool,
}

impl CliFlags {
    /// Parses a full argument list. The first element is the program path and is skipped.
    pub fn parse<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut flags = Self::default();
        for arg in args.into_iter().skip(1) {
            let arg = arg.as_ref();
            if arg == FLAG_TRAY {
                flags.tray = true;
            } else if arg == FLAG_SHOW {
                flags.show = true;
            } else if arg == FLAG_SAFE_RENDERING {
                flags.safe_rendering = true;
            } else if arg == FLAG_HELP || arg == FLAG_HELP_SHORT {
                flags.help = true;
            } else if arg == FLAG_VERSION || arg == FLAG_VERSION_SHORT {
                flags.version = true;
            }
        }
        flags
    }

    pub fn from_env() -> Self {
        Self::parse(std::env::args_os())
    }

    /// Whether this launch starts with no window. `--show` wins over `--tray`.
    pub fn starts_hidden(self) -> bool {
        self.tray && !self.show
    }

    /// Whether a second launch with these flags should open the running app's window. A login
    /// autostart (`--tray`) landing on a running instance must not pop a window up.
    pub fn second_launch_opens_window(self) -> bool {
        !self.starts_hidden()
    }
}

/// The `--version` output: the binary name and its version.
pub fn version_text() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// The `--help` output: a usage line and every flag this app understands.
pub fn help_text() -> String {
    format!(
        "{version}
Desktop tray and Manage Window for Rusty Conduit GUI.

Usage: {name} [OPTIONS]

Options:
  {FLAG_TRAY:<18}  Start in the tray with no window (used by login autostart)
  {FLAG_SHOW:<18}  Open the window even when --tray is given
  {FLAG_SAFE_RENDERING:<18}  Turn off WebKitGTK compositing to work around rendering glitches
  {help:<18}  Print this help and exit
  {ver:<18}  Print the version and exit
",
        version = version_text(),
        name = env!("CARGO_PKG_NAME"),
        help = format!("{FLAG_HELP_SHORT}, {FLAG_HELP}"),
        ver = format!("{FLAG_VERSION_SHORT}, {FLAG_VERSION}"),
    )
}

/// Whether the NVIDIA kernel driver is loaded. `root` is `/` outside tests.
pub fn nvidia_detected(root: &Path) -> bool {
    root.join("proc/driver/nvidia/version").exists() || root.join("sys/module/nvidia").exists()
}

/// The variables to set before GTK starts. A value the user already set is never replaced,
/// except that `--safe-rendering` is an explicit request and always applies.
pub fn rendering_env_overrides(
    nvidia: bool,
    safe_rendering: bool,
    is_set: impl Fn(&str) -> bool,
) -> Vec<(&'static str, &'static str)> {
    let mut overrides = Vec::new();
    if nvidia && !is_set(ENV_DISABLE_DMABUF) {
        overrides.push((ENV_DISABLE_DMABUF, "1"));
    }
    if safe_rendering {
        overrides.push((ENV_DISABLE_COMPOSITING, "1"));
    }
    overrides
}

/// Applies the WebKitGTK mitigations. Call on the main thread before any other thread starts
/// and before GTK initializes, because changing the environment later is not thread-safe.
#[cfg(target_os = "linux")]
pub fn apply_rendering_env(flags: CliFlags) {
    let overrides = rendering_env_overrides(nvidia_detected(Path::new("/")), flags.safe_rendering, |name| {
        std::env::var_os(name).is_some()
    });
    for (name, value) in overrides {
        std::env::set_var(name, value);
    }
}

/// WebKitGTK is Linux-only, so other platforms need no mitigation.
#[cfg(not(target_os = "linux"))]
pub fn apply_rendering_env(_flags: CliFlags) {}

/// Removes the WebView rendering workarounds from a child process's environment. Every child
/// or worker process this app spawns must go through this.
pub fn sanitize_child_env(command: &mut Command) -> &mut Command {
    for name in RENDERING_ENV_VARS {
        command.env_remove(name);
    }
    command
}

/// The program a login autostart entry should launch. An AppImage's real executable lives in
/// a temporary mount that changes every run, so the stable `$APPIMAGE` path is used instead.
pub fn resolve_autostart_executable(appimage: Option<&OsStr>, current_exe: &Path) -> PathBuf {
    match appimage {
        Some(path) if cfg!(target_os = "linux") && !path.is_empty() => PathBuf::from(path),
        _ => current_exe.to_path_buf(),
    }
}

/// [`resolve_autostart_executable`] for the running process.
pub fn autostart_executable() -> std::io::Result<PathBuf> {
    let appimage: Option<OsString> = std::env::var_os("APPIMAGE");
    Ok(resolve_autostart_executable(appimage.as_deref(), &std::env::current_exe()?))
}

/// Turns off core dumps so a crash cannot write decrypted secrets to disk.
pub fn harden_process() {
    if let Err(error) = conduit_runtime::disable_core_dumps() {
        eprintln!("could not disable core dumps: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::test_support::TempDir;

    fn parse(args: &[&str]) -> CliFlags {
        CliFlags::parse(std::iter::once("app").chain(args.iter().copied()))
    }

    #[test]
    fn platform_parses_each_flag_and_ignores_unknown_arguments() {
        assert_eq!(parse(&[]), CliFlags::default());
        assert!(parse(&["--tray"]).tray);
        assert!(parse(&["--show"]).show);
        assert!(parse(&["--safe-rendering"]).safe_rendering);
        assert_eq!(parse(&["--nope", "tray", "--tray=1"]), CliFlags::default());
        assert_eq!(
            parse(&["--safe-rendering", "--show", "--tray"]),
            CliFlags { tray: true, show: true, safe_rendering: true, ..CliFlags::default() }
        );
    }

    #[test]
    fn platform_parses_help_flags() {
        assert!(parse(&["-h"]).help);
        assert!(parse(&["--help"]).help);
        assert!(!parse(&["--help"]).version);
        assert!(!parse(&["-help", "help"]).help);
    }

    #[test]
    fn platform_parses_version_flags() {
        assert!(parse(&["-V"]).version);
        assert!(parse(&["--version"]).version);
        assert!(!parse(&["--version"]).help);
        assert!(!parse(&["-v", "version"]).version);
    }

    #[test]
    fn platform_version_text_names_package_and_version() {
        let text = version_text();
        assert_eq!(text, format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")));
        assert!(text.starts_with("rusty-conduit-gui "));
    }

    #[test]
    fn platform_help_text_lists_every_flag() {
        let text = help_text();
        assert!(text.starts_with(&version_text()));
        assert!(text.contains("Usage: rusty-conduit-gui [OPTIONS]"));
        for flag in [
            FLAG_TRAY,
            FLAG_SHOW,
            FLAG_SAFE_RENDERING,
            FLAG_HELP,
            FLAG_HELP_SHORT,
            FLAG_VERSION,
            FLAG_VERSION_SHORT,
        ] {
            assert!(text.contains(flag), "{flag} missing from help text");
        }
    }

    #[test]
    fn platform_skips_the_program_path() {
        assert_eq!(CliFlags::parse(["--tray"]), CliFlags::default());
    }

    #[test]
    fn platform_show_wins_over_tray() {
        assert!(parse(&["--tray"]).starts_hidden());
        assert!(!parse(&[]).starts_hidden());
        assert!(!parse(&["--tray", "--show"]).starts_hidden());
    }

    #[test]
    fn platform_second_launch_opens_window_unless_autostarted() {
        assert!(parse(&[]).second_launch_opens_window());
        assert!(parse(&["--show"]).second_launch_opens_window());
        assert!(!parse(&["--tray"]).second_launch_opens_window());
        assert!(parse(&["--tray", "--show"]).second_launch_opens_window());
    }

    #[test]
    fn platform_detects_nvidia_from_either_path() {
        let none = TempDir::new();
        assert!(!nvidia_detected(none.path()));

        let proc_root = TempDir::new();
        std::fs::create_dir_all(proc_root.path().join("proc/driver/nvidia")).unwrap();
        std::fs::write(proc_root.path().join("proc/driver/nvidia/version"), "NVRM").unwrap();
        assert!(nvidia_detected(proc_root.path()));

        let sys_root = TempDir::new();
        std::fs::create_dir_all(sys_root.path().join("sys/module/nvidia")).unwrap();
        assert!(nvidia_detected(sys_root.path()));
    }

    #[test]
    fn platform_mitigation_applies_only_on_nvidia() {
        assert!(rendering_env_overrides(false, false, |_| false).is_empty());
        assert_eq!(
            rendering_env_overrides(true, false, |_| false),
            vec![(ENV_DISABLE_DMABUF, "1")]
        );
    }

    #[test]
    fn platform_mitigation_keeps_a_user_set_value() {
        let overrides = rendering_env_overrides(true, false, |name| name == ENV_DISABLE_DMABUF);
        assert!(overrides.is_empty());
    }

    #[test]
    fn platform_safe_rendering_sets_compositing_on_any_gpu() {
        assert_eq!(
            rendering_env_overrides(false, true, |_| true),
            vec![(ENV_DISABLE_COMPOSITING, "1")]
        );
        assert_eq!(rendering_env_overrides(true, true, |_| false).len(), 2);
    }

    #[test]
    fn platform_child_env_strips_every_rendering_variable() {
        let mut command = Command::new("true");
        command.env(ENV_DISABLE_DMABUF, "1").env("KEEP_ME", "1");
        sanitize_child_env(&mut command);

        let envs: Vec<_> = command.get_envs().collect();
        for name in RENDERING_ENV_VARS {
            assert!(envs.contains(&(OsStr::new(name), None)), "{name} was not removed");
        }
        assert!(envs.contains(&(OsStr::new("KEEP_ME"), Some(OsStr::new("1")))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_autostart_prefers_the_appimage_path() {
        let exe = Path::new("/tmp/.mount_abc/usr/bin/app");
        let image = OsStr::new("/home/u/Apps/app.AppImage");
        assert_eq!(
            resolve_autostart_executable(Some(image), exe),
            PathBuf::from("/home/u/Apps/app.AppImage")
        );
    }

    #[test]
    fn platform_autostart_falls_back_to_the_current_executable() {
        let exe = Path::new("/usr/bin/app");
        assert_eq!(resolve_autostart_executable(None, exe), exe);
        assert_eq!(resolve_autostart_executable(Some(OsStr::new("")), exe), exe);
    }

    #[test]
    fn platform_hardening_does_not_panic() {
        harden_process();
    }
}
