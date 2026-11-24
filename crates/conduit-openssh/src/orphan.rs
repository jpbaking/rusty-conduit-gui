//! Keeps `ssh` children from outliving the process that started them.
//!
//! - Linux: `PR_SET_PDEATHSIG(SIGTERM)`.
//! - Windows: a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
//! - macOS: a thread in `conduit-worker` that watches the parent PID.
//!
//! Linux delivers the signal when the parent *thread* exits, so the thread that spawns a guarded
//! child must outlive it.

use std::io;
use std::process::Command;

/// Arranges for the spawned child to receive `SIGTERM` when this thread exits (Linux only).
pub fn guard_command(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `getpid` has no preconditions.
        let parent = unsafe { libc::getpid() };
        // SAFETY: the closure only makes async-signal-safe calls and does not allocate.
        unsafe {
            command.pre_exec(move || set_parent_death_signal(parent));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

/// Ties this process to its current parent (Linux only). Survives `exec`.
pub fn guard_current_process() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `getppid` has no preconditions.
        let parent = unsafe { libc::getppid() };
        set_parent_death_signal(parent)?;
    }
    Ok(())
}

/// The check after `prctl` closes the race where the parent died just before it.
#[cfg(target_os = "linux")]
fn set_parent_death_signal(expected_parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: `PR_SET_PDEATHSIG` takes integer arguments and touches no memory.
    let signal = libc::SIGTERM as libc::c_ulong;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, signal, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `getppid` has no preconditions.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

/// Disables core dumps, and on Linux same-user `ptrace`, for this process.
pub fn disable_core_dumps() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes integer arguments and touches no memory.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid `rlimit` that outlives the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Polls the parent PID. When it changes, stops `child_pid` and exits this process.
#[cfg(target_os = "macos")]
pub fn watch_parent(child_pid: u32) {
    // SAFETY: `getppid` has no preconditions.
    let parent = unsafe { libc::getppid() };
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        // SAFETY: `getppid` has no preconditions.
        if unsafe { libc::getppid() } != parent {
            // SAFETY: `kill` takes integer arguments and touches no memory.
            unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGTERM) };
            std::process::exit(1);
        }
    });
}

#[cfg(windows)]
pub use job::JobGuard;

#[cfg(windows)]
mod job {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::RawHandle;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimitInformation {
        basic: BasicLimitInformation,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> *mut c_void;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            information: *const c_void,
            length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    /// Kills the assigned process when this value is dropped or this process dies.
    #[derive(Debug)]
    pub struct JobGuard(*mut c_void);

    // SAFETY: a job handle may be used and closed from any thread.
    unsafe impl Send for JobGuard {}
    // SAFETY: this type exposes no operation through a shared reference.
    unsafe impl Sync for JobGuard {}

    impl JobGuard {
        /// Creates a kill-on-close job and assigns `process` to it.
        pub fn assign(process: RawHandle) -> io::Result<Self> {
            // SAFETY: null attributes and a null name are documented as valid.
            let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let guard = Self(job);
            let mut limits = ExtendedLimitInformation::default();
            limits.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `limits` is a valid structure of the stated size for this class.
            let set = unsafe {
                SetInformationJobObject(
                    guard.0,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&limits as *const ExtendedLimitInformation).cast(),
                    std::mem::size_of::<ExtendedLimitInformation>() as u32,
                )
            };
            if set == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: both handles are valid for the duration of the call.
            if unsafe { AssignProcessToJobObject(guard.0, process.cast()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(guard)
        }
    }

    impl Drop for JobGuard {
        fn drop(&mut self) {
            // SAFETY: this value owns the handle and closes it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn is_running(pid: i32) -> bool {
        // A zombie still has a /proc entry, so read its state.
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let (_, rest) = stat.rsplit_once(") ")?;
                rest.chars().next()
            })
            .is_some_and(|state| state != 'Z' && state != 'X')
    }

    #[test]
    fn orphan_guard_stops_child_when_spawning_thread_exits() {
        let (sender, receiver) = std::sync::mpsc::channel();
        // The child is reaped on this thread after its parent thread has gone.
        let spawner = std::thread::spawn(move || {
            let mut command = Command::new("/bin/sleep");
            command.arg("30").stdin(Stdio::null());
            guard_command(&mut command);
            sender.send(command.spawn().unwrap()).unwrap();
        });
        let mut child = receiver.recv().unwrap();
        spawner.join().unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.and_then(|s| s.signal()), Some(libc::SIGTERM));
        assert!(!is_running(child.id() as i32));
    }

    #[test]
    fn orphan_guard_keeps_child_while_spawning_thread_lives() {
        let mut command = Command::new("/bin/sleep");
        command.arg("30").stdin(Stdio::null());
        guard_command(&mut command);
        let mut child = command.spawn().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn orphan_guard_current_process_succeeds() {
        // Run in a child so the test process keeps its own settings.
        let mut command = Command::new("/bin/true");
        // SAFETY: the closure only makes async-signal-safe calls.
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(guard_current_process);
        }
        assert!(command.status().unwrap().success());
    }
}
