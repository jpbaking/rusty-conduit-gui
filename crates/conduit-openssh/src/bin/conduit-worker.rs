//! Per-session OpenSSH worker.
//!
//! - `askpass [prompt]` answers one password prompt. `ssh` runs `SSH_ASKPASS` with the prompt as
//!   its only argument, so a single unrecognized argument is also treated as a prompt.
//! - `hop-proxy --config <path> --ssh-bin <path> --hop <n> -- <host> <port>` runs the inner
//!   `ssh -W` for one hop of a chain.

use std::ffi::OsString;
use std::process::{Command, ExitCode};

use conduit_openssh::env::{build_child_env, AskpassEnv};
use conduit_openssh::orphan;
use conduit_openssh::run_askpass_client;

const USAGE: &str = "usage: conduit-worker askpass [prompt]\n       \
    conduit-worker hop-proxy --config <path> --ssh-bin <path> --hop <n> -- <host> <port>";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let first = args.first().and_then(|arg| arg.to_str());
    match (first, args.len()) {
        (Some("hop-proxy"), len) if len > 1 => hop_proxy(&args[1..]),
        (Some("askpass"), 1) => askpass(None),
        (Some("askpass"), 2) => askpass(Some(&args[1])),
        (Some(_), 1) => askpass(Some(&args[0])),
        // A prompt that is not valid UTF-8 is still a single argument.
        (None, 1) => askpass(Some(&args[0])),
        _ => fail(USAGE),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("conduit-worker: {message}");
    ExitCode::from(2)
}

fn askpass(prompt: Option<&OsString>) -> ExitCode {
    if let Err(error) = orphan::disable_core_dumps() {
        return fail(&format!("could not disable core dumps: {error}"));
    }
    let prompt = prompt.map(|p| p.to_string_lossy());
    match run_askpass_client(prompt.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("conduit-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

struct HopProxyArgs {
    config: OsString,
    ssh_bin: OsString,
    hop: usize,
    host: String,
    port: u16,
}

fn parse_hop_proxy(args: &[OsString]) -> Option<HopProxyArgs> {
    let separator = args.iter().position(|arg| arg == "--")?;
    let (flags, rest) = args.split_at(separator);
    let [_, host, port] = rest else {
        return None;
    };
    let (mut config, mut ssh_bin, mut hop) = (None, None, None);
    for pair in flags.chunks(2) {
        let [name, value] = pair else {
            return None;
        };
        match name.to_str()? {
            "--config" => config = Some(value.clone()),
            "--ssh-bin" => ssh_bin = Some(value.clone()),
            "--hop" => hop = Some(value.to_str()?.parse().ok()?),
            _ => return None,
        }
    }
    let host = host.to_str()?.to_string();
    if host.is_empty() || host.starts_with('-') {
        return None;
    }
    Some(HopProxyArgs {
        config: config?,
        ssh_bin: ssh_bin?,
        hop: hop?,
        host,
        port: port.to_str()?.parse().ok()?,
    })
}

/// The alias of the `hop`-th `Host` block in a config this app generated.
fn hop_alias_from_config(text: &str, hop: usize) -> Option<String> {
    let alias = text
        .lines()
        .filter_map(|line| line.strip_prefix("Host "))
        .nth(hop)?;
    alias.starts_with("rc-").then(|| alias.to_string())
}

fn forward_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn hop_proxy(args: &[OsString]) -> ExitCode {
    let Some(args) = parse_hop_proxy(args) else {
        return fail(USAGE);
    };
    if let Err(error) = orphan::guard_current_process() {
        return fail(&format!("could not set the orphan guard: {error}"));
    }
    let Some(askpass) = AskpassEnv::from_process_env().and_then(|env| env.for_hop(args.hop)) else {
        return fail("askpass environment is missing or has no token for this hop");
    };
    let text = match std::fs::read_to_string(&args.config) {
        Ok(text) => text,
        Err(error) => return fail(&format!("could not read the config: {error}")),
    };
    let Some(alias) = hop_alias_from_config(&text, args.hop) else {
        return fail("the config has no such hop");
    };

    let mut command = Command::new(&args.ssh_bin);
    command
        .arg("-F")
        .arg(&args.config)
        .arg("-W")
        .arg(forward_target(&args.host, args.port))
        .arg(alias)
        .env_clear()
        .envs(build_child_env(std::env::vars_os(), &askpass));
    run_inner(command)
}

/// Replaces this process, so the `PR_SET_PDEATHSIG` set above carries over to `ssh`.
#[cfg(target_os = "linux")]
fn run_inner(mut command: Command) -> ExitCode {
    use std::os::unix::process::CommandExt;
    let error = command.exec();
    fail(&format!("could not start ssh: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn run_inner(mut command: Command) -> ExitCode {
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return fail(&format!("could not start ssh: {error}")),
    };
    #[cfg(target_os = "macos")]
    orphan::watch_parent(child.id());
    #[cfg(windows)]
    let _job = {
        use std::os::windows::io::AsRawHandle;
        match orphan::JobGuard::assign(child.as_raw_handle()) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return fail(&format!("could not set the orphan guard: {error}"));
            }
        }
    };
    match child.wait() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => fail(&format!("could not wait for ssh: {error}")),
    }
}
