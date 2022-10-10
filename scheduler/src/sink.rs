use anyhow::{anyhow, Context, Result};

use byte_unit::n_mib_bytes;
use fuzztruction_shared::util::try_get_child_exit_reason;
use log::error;

use std::env::set_current_dir;
use std::os::unix::prelude::AsRawFd;
use std::{
    convert::TryFrom,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    ops::*,
    path::PathBuf,
};
use std::{fs, io, mem};
use std::{os::raw::c_char, time::Duration};
use thiserror::Error;

use libc::SIGKILL;
use mktemp::Temp;
use nix::sys::signal::Signal;

use crate::config::Config;
use crate::io_channels::InputChannel;
use crate::sink_bitmap::{Bitmap, BITMAP_DEFAULT_MAP_SIZE};

use filedescriptor;

const FS_OPT_MAPSIZE: u32 = 0x40000000;

// FDs used by the forkserver to communicate with us.
// Hardcoded in AFLs config.h.
const FORKSRV_FD: i32 = 198;
const AFL_READ_FROM_PARENT_FD: i32 = FORKSRV_FD;
const AFL_WRITE_TO_PARENT_FD: i32 = FORKSRV_FD + 1;

const AFL_SHM_ENV_VAR_NAME: &str = "__AFL_SHM_ID";
const AFL_DEFAULT_TIMEOUT: Duration = Duration::from_millis(10000);

fn repeat_on_interrupt<F, R>(f: F) -> R
where
    F: Fn() -> R,
    R: TryInto<libc::c_int> + Clone,
{
    loop {
        let ret = f();
        if ret.clone().try_into().unwrap_or(0) != -libc::EINTR {
            return ret;
        } else {
            log::trace!("Repeating call because of EINTR");
        }
    }
}

/// Type used to represent error conditions of the source.
#[derive(Error, Debug)]
pub enum SinkError {
    #[error("The workdir '{0}' already exists.")]
    WorkdirExists(String),
    #[error("Fatal error occurred: {0}")]
    FatalError(String),
    #[error("Exceeded timeout while waiting for data: {0}")]
    CommunicationTimeoutError(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunResult {
    Terminated(i32),
    Signalled(Signal),
    TimedOut,
}

#[derive(Debug)]
pub struct AflSink {
    /// That file system path to the target binary.
    path: PathBuf,
    /// The arguments passed to the binary.
    args: Vec<String>,
    /// Workdir
    #[allow(unused)]
    workdir: PathBuf,
    /// Description of how the target binary consumes fuzzing input.
    input_channel: InputChannel,
    /// The file that is used to pass input to the target.
    input_file: (File, PathBuf),
    /// The session id of the forkserver we are communicating with.
    forkserver_sid: Option<i32>,
    /// The bitmap used to compute coverage.
    bitmap: Bitmap,
    /// The fd used to send data to the forkserver.
    send_fd: Option<i32>,
    /// Non blocking fd used to receive data from the forkserver.
    receive_fd: Option<i32>,
    #[allow(unused)]
    stdout_file: Option<(File, PathBuf)>,
    #[allow(unused)]
    stderr_file: Option<(File, PathBuf)>,
    /// Whether to log the output written to stdout. If false, the output is discarded.
    log_stdout: bool,
    /// Whether to log the output written to stderr. If false, the output is discarded.
    log_stderr: bool,
    config: Option<Config>,
    bitmap_was_resize: bool,
}

impl AflSink {
    pub fn new(
        path: PathBuf,
        mut args: Vec<String>,
        mut workdir: PathBuf,
        input_channel: InputChannel,
        config: Option<&Config>,
        log_stdout: bool,
        log_stderr: bool,
    ) -> Result<AflSink> {
        workdir.push("sink");

        // Create the file into we write inputdata before execution.
        fs::create_dir_all(&workdir)?;
        set_current_dir(&workdir)?;

        let tmpfile_path = Temp::new_file_in(&workdir).unwrap().to_path_buf();
        let mut input_file_path = String::from(tmpfile_path.to_str().unwrap());
        input_file_path.push_str("_input");
        let input_file_path = PathBuf::from(input_file_path);

        let input_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&input_file_path)?;

        // Replace the @@ marker in the args with the actual file path (if input type is File).
        if input_channel == InputChannel::File {
            if let Some(elem) = args.iter_mut().find(|e| **e == "@@") {
                *elem = input_file_path.to_str().unwrap().to_owned();
            } else {
                return Err(anyhow!(format!("No @@ marker in args, even though the input channel is defined as file. args: {:#?}", args)));
            }
        }

        let mut stdout_file = None;
        if log_stdout {
            // Setup file for stdout logging.
            let mut path = workdir.clone();
            path.push("stdout");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            stdout_file = Some((file, path));
        }

        let mut stderr_file = None;
        if log_stderr {
            // Setup file for stdout logging.
            let mut path = workdir.clone();
            path.push("stderr");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            stderr_file = Some((file, path));
        }

        Ok(AflSink {
            path,
            args,
            workdir,
            input_channel,
            input_file: (input_file, input_file_path),
            forkserver_sid: None,
            bitmap: Bitmap::new_in_shm(BITMAP_DEFAULT_MAP_SIZE, 0x00),
            send_fd: None,
            receive_fd: None,
            log_stdout,
            log_stderr,
            stdout_file,
            stderr_file,
            config: config.cloned(),
            bitmap_was_resize: false,
        })
    }

    pub fn from_config(config: &Config, id: Option<usize>) -> Result<AflSink> {
        let config_new = config.clone();
        let mut workdir = config_new.general.work_dir.clone();
        workdir.push(
            id.map(|id| id.to_string())
                .unwrap_or_else(|| "0".to_owned()),
        );

        let sink = AflSink::new(
            config_new.sink.bin_path,
            config_new.sink.arguments,
            workdir,
            config_new.sink.input_type,
            Some(config),
            config.sink.log_stdout,
            config.sink.log_stderr,
        )?;
        Ok(sink)
    }

    /// Wait for the given duration for the forkserver read fd to become ready.
    /// Returns Ok(true) if data becomes ready during the given `timeout`, else
    /// Ok(false).
    ///
    /// # Error
    ///
    /// Returns an Error if an unexpected error occurs.
    fn wait_for_data(&self, timeout: Duration) -> Result<()> {
        let pollfd = filedescriptor::pollfd {
            fd: self.receive_fd.unwrap(),
            events: filedescriptor::POLLIN,
            revents: 0,
        };
        let mut pollfds = [pollfd];

        let nready = filedescriptor::poll(&mut pollfds, Some(timeout));
        match nready {
            Ok(1) => Ok(()),
            Ok(0) => Err(SinkError::CommunicationTimeoutError(format!(
                "Did not received data after {:?}",
                timeout
            ))
            .into()),
            Ok(n) => {
                unreachable!("Unexpected return value: {}", n);
            }
            Err(ref err) => {
                if let filedescriptor::Error::Poll(err) = err {
                    if err.kind() == io::ErrorKind::Interrupted {
                        return self.wait_for_data(timeout);
                    }
                }
                Err(SinkError::FatalError(format!("Failed to poll fd: {:#?}", err)).into())
            }
        }
    }

    pub fn start(&mut self) -> Result<()> {
        // send_pipe[1](we) -> send_pipe[0](forkserver).
        let send_pipe = [0i32; 2];
        // receive_pipe[1](forkserver) -> receive_pipe[0](we).
        let receive_pipe = [0i32; 2];

        // Create pipe for communicating with the forkserver.
        unsafe {
            let ret = libc::pipe(send_pipe.as_ptr() as *mut i32);
            assert_eq!(ret, 0);
            let ret = libc::pipe(receive_pipe.as_ptr() as *mut i32);
            assert_eq!(ret, 0);
        }

        self.send_fd = Some(send_pipe[1]);
        let child_receive_fd = send_pipe[0];

        self.receive_fd = Some(receive_pipe[0]);
        let child_send_fd = receive_pipe[1];

        let child_pid = unsafe { libc::fork() };
        match child_pid {
            -1 => return Err(anyhow!("Fork failed!")),
            0 => {
                /*
                Child
                Be aware that we are forking a potentially multithreaded application
                here. Since fork() only copies the calling thread, the environment
                might be left in a dirty state because of, e.g., mutexs that where
                locked at the time fork was called.
                Because of this it is only save to call async-signal-safe functions
                (https://man7.org/linux/man-pages/man7/signal-safety.7.html).
                Note that loggin function (debug!...) often internally use mutexes
                to lock the output buffer, thus using logging here is forbidden
                and likely causes deadlocks.
                */
                let map_shm_id = self.bitmap.shm_id();

                unsafe {
                    let ret = libc::setsid();
                    assert!(ret >= 0);
                }

                // Setup args
                let path =
                    self.path.to_str().map(|s| s.to_owned()).ok_or_else(|| {
                        SinkError::Other(anyhow!("Invalid UTF-8 character in path"))
                    })?;
                let mut args = self.args.clone();
                args.insert(0, path.clone());

                let argv_nonref: Vec<CString> = args
                    .iter()
                    .map(|arg| CString::new(arg.as_bytes()).unwrap())
                    .collect();
                let mut argv: Vec<*const c_char> =
                    argv_nonref.iter().map(|arg| arg.as_ptr()).collect();
                argv.push(std::ptr::null());

                // Setup environment
                let mut envp: Vec<*const c_char> = Vec::new();
                let shm_env_var =
                    CString::new(format!("{}={}", AFL_SHM_ENV_VAR_NAME, map_shm_id)).unwrap();
                envp.push(shm_env_var.as_ptr());

                let mut env_from_config = Vec::new();
                if let Some(cfg) = self.config.as_ref() {
                    cfg.sink.env.iter().for_each(|var| {
                        env_from_config
                            .push(CString::new(format!("{}={}", var.0, var.1).as_bytes()).unwrap())
                    })
                }

                let afl_maps_size =
                    CString::new(format!("AFL_MAP_SIZE={}", self.bitmap().size())).unwrap();
                envp.push(afl_maps_size.as_bytes().as_ptr() as *const i8);

                env_from_config.iter().for_each(|e| {
                    envp.push(e.as_bytes().as_ptr() as *const i8);
                });
                envp.push(std::ptr::null());

                let dev_null_fd = unsafe {
                    let path = CString::new("/dev/null".as_bytes()).unwrap();
                    libc::open(path.as_ptr(), libc::O_RDONLY)
                };
                if dev_null_fd < 0 {
                    panic!("Failed to open /dev/null");
                }

                match self.input_channel {
                    InputChannel::Stdin => unsafe {
                        libc::dup2(self.input_file.0.as_raw_fd(), 0);
                    },
                    _ => unsafe {
                        libc::dup2(dev_null_fd, 0);
                    },
                }

                if self.log_stdout {
                    // unsafe {
                    //     let fd = self.stdout_file.as_ref().unwrap().0.as_raw_fd();
                    //     libc::dup2(fd, libc::STDOUT_FILENO);
                    //     libc::close(fd);
                    // }
                } else {
                    unsafe {
                        libc::dup2(dev_null_fd, libc::STDOUT_FILENO);
                    }
                }

                if self.log_stderr {
                    //unsafe {
                    // let fd = self.stderr_file.as_ref().unwrap().0.as_raw_fd();
                    // libc::dup2(fd, libc::STDERR_FILENO);
                    // libc::close(fd);
                    //}
                } else {
                    unsafe {
                        libc::dup2(dev_null_fd, libc::STDERR_FILENO);
                    }
                }

                unsafe {
                    libc::close(dev_null_fd);
                }

                unsafe {
                    // Close the pipe ends used by our parent.
                    libc::close(self.receive_fd.unwrap());
                    libc::close(self.send_fd.unwrap());

                    // Remap fds to the ones used by the forkserver.
                    // The fds might have by chance the correct value, in this case
                    // dup2 & close would actually cause us to close the fd we intended to pass.
                    if child_receive_fd != AFL_READ_FROM_PARENT_FD {
                        let ret = libc::dup2(child_receive_fd, AFL_READ_FROM_PARENT_FD);
                        assert!(ret >= 0);
                        libc::close(child_receive_fd);
                    }

                    if child_send_fd != AFL_WRITE_TO_PARENT_FD {
                        let ret = libc::dup2(child_send_fd, AFL_WRITE_TO_PARENT_FD);
                        assert!(ret >= 0);
                        libc::close(child_send_fd);
                    }
                }

                unsafe {
                    if !self.log_stdout && !self.log_stderr {
                        // if we log stderr or stdout, the limit will cause our
                        // fuzzer to fail after some time.
                        let mut rlim: libc::rlimit = std::mem::zeroed();
                        rlim.rlim_cur = n_mib_bytes!(512).try_into().unwrap();
                        rlim.rlim_max = n_mib_bytes!(512).try_into().unwrap();
                        let ret = libc::setrlimit(libc::RLIMIT_FSIZE, &rlim as *const libc::rlimit);
                        assert_eq!(ret, 0);
                    }

                    // Disable core dumps
                    let limit_val: libc::rlimit = std::mem::zeroed();
                    let ret = libc::setrlimit(libc::RLIMIT_CORE, &limit_val);
                    assert_eq!(ret, 0);

                    // Max AS size.
                    let mut rlim: libc::rlimit = std::mem::zeroed();
                    rlim.rlim_cur = n_mib_bytes!(512).try_into().unwrap();
                    rlim.rlim_max = n_mib_bytes!(512).try_into().unwrap();
                    let ret = libc::setrlimit(libc::RLIMIT_AS, &rlim as *const libc::rlimit);
                    assert_eq!(ret, 0);

                    let ret = libc::personality(libc::ADDR_NO_RANDOMIZE as u64);
                    assert_eq!(ret, 0);
                }

                if let Err(err) = self.drop_privileges() {
                    log::error!("Failed to drop privileges: {:#?}", err);
                    panic!();
                }

                // Make sure that UID == EUID, since if this is not the case,
                // ld will ignore LD_PRELOAD which we need to use for targets
                // that normally load instrumented libraries during runtime.
                assert_eq!(nix::unistd::getuid(), nix::unistd::geteuid());
                assert_eq!(nix::unistd::getegid(), nix::unistd::getegid());

                let prog = CString::new(path.as_bytes()).unwrap();
                unsafe {
                    libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
                }
                unreachable!("Failed to call execve on '{}'", path);
            }
            _ => { /* The parent */ }
        }
        /* The parent */
        log::info!("Forkserver has pid {}", child_pid);

        // Note th sid, thus we can kill the child later.
        // This is a sid since the child calls setsid().
        self.forkserver_sid = Some(child_pid);

        // Close the pipe ends used by the child.
        unsafe {
            libc::close(child_receive_fd);
            libc::close(child_send_fd);
        }

        unsafe {
            libc::fcntl(self.send_fd.unwrap(), libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(self.receive_fd.unwrap(), libc::F_SETFD, libc::FD_CLOEXEC);
        }

        // Wait for for hello from the child.
        self.wait_for_data(AFL_DEFAULT_TIMEOUT)
            .context("Timeout while waiting for forkserver to come up.")?;

        // Read the available data.
        let buffer = [0u8; 4];
        unsafe {
            let ret = libc::read(
                self.receive_fd.unwrap(),
                buffer.as_ptr() as *mut libc::c_void,
                4,
            );
            if ret != 4 {
                return Err(anyhow!(format!(
                    "Failed to do handshake with forkserver. ret={}",
                    ret
                )));
            }

            // Process extended attributes used by AFL++.
            // Sett src/afl-forkserver.c:689 (afl_fsrv_start)
            let status = u32::from_ne_bytes(buffer);
            log::info!("Forkserver status: 0x{:x}", status);
            if status & FS_OPT_MAPSIZE == FS_OPT_MAPSIZE {
                log::info!("Got extended option FS_OPT_MAPSIZE from forkserver");
                let new_map_size = ((status & 0x00fffffe) >> 1) + 1;
                log::info!("Target requests a map of size {} bytes", new_map_size);
                log::info!("Current map size is {} bytes", self.bitmap().size());
                if self.bitmap_was_resize {
                    log::info!("Already resized, skipping....");
                    return Ok(());
                }

                let new_map_size = new_map_size.next_power_of_two() as usize;
                if new_map_size > self.bitmap().size() {
                    log::info!("Resizing bitmap to {} bytes", new_map_size);
                    self.stop();
                    let new_map = Bitmap::new_in_shm(new_map_size, 0x00);
                    let _ = mem::replace(self.bitmap(), new_map);
                    self.bitmap_was_resize = true;
                    return self.start();
                }
            }
        }

        // if self.stdout_file.is_some() {
        //     // Take the the stdout file thus its fd gets dropped.
        //     self.stdout_file.take();
        // }
        // if self.stderr_file.is_some() {
        //     // Take the the stderr file thus its fd gets dropped.
        //     self.stderr_file.take();
        // }

        // We are ready to fuzz!
        Ok(())
    }

    fn drop_privileges(&mut self) -> Result<()> {
        let uid_gid = self
            .config
            .as_ref()
            .map(|config| config.general.jail_uid_gid())
            .unwrap_or(None);
        if uid_gid.is_some() {
            jail::acquire_privileges()?;
        }
        if let Some((uid, gid)) = uid_gid {
            jail::drop_privileges(uid, gid, true)?;
        }
        Ok(())
    }

    /// Stops the forksever. Must be called before calling start() again.
    /// It is save to call this function multiple times.
    pub fn stop(&mut self) {
        if let Some(sid) = self.forkserver_sid.take() {
            unsafe {
                libc::close(self.send_fd.unwrap());
                libc::close(self.receive_fd.unwrap());

                let ret = libc::killpg(sid, SIGKILL);
                assert!(ret == 0);
                // reap it
                libc::waitpid(sid, std::ptr::null_mut() as *mut libc::c_int, 0);
            }
        }
    }

    /// Write the given bytes into the sinks input channel. This function
    /// is only allowed to be called on sinks with InputChannel::Stdin or InputChannel::File
    /// input channel.
    pub fn write(&mut self, data: &[u8]) {
        debug_assert!(
            self.input_channel == InputChannel::Stdin || self.input_channel == InputChannel::File
        );

        self.input_file.0.seek(SeekFrom::Start(0)).unwrap();
        self.input_file.0.set_len(0).unwrap();
        self.input_file.0.write_all(data).unwrap();
        self.input_file.0.seek(SeekFrom::Start(0)).unwrap();
        self.input_file.0.sync_all().unwrap();
    }

    pub fn run(&mut self, timeout: Duration) -> Result<RunResult> {
        self.bitmap().reset();

        let buffer = [0u8; 4];
        let buf_ptr = buffer.as_ptr() as *mut libc::c_void;

        // Tell the forkserver to fork.
        log::trace!("Requesting fork");
        let ret = repeat_on_interrupt(|| unsafe { libc::write(self.send_fd.unwrap(), buf_ptr, 4) });
        if ret != 4 {
            error!("Fork request failed");
            return Err(anyhow!("Failed to write to send_fd: {}", ret));
        }

        log::trace!("Waiting for child pid");
        self.wait_for_data(AFL_DEFAULT_TIMEOUT)
            .context("Failed to retrive child pid from forkserver")?;
        let ret =
            repeat_on_interrupt(|| unsafe { libc::read(self.receive_fd.unwrap(), buf_ptr, 4) });
        if ret != 4 {
            error!("Failed to retrive child pid");
            return Err(anyhow!("Failed to read from receive_non_blocking_fd"));
        }

        let child_pid = i32::from_le_bytes(buffer);
        log::trace!("Got child pid {}", child_pid);

        if child_pid <= 0 {
            log::error!("Child pid '{}' is invalid", child_pid);
            return Err(anyhow!(
                "Failed to parse child_pid. child_pid={}, bytes={:?}",
                child_pid,
                buffer
            ));
        }

        log::trace!("Waiting for child termination");
        match self.wait_for_data(timeout) {
            Ok(_) => (),
            Err(err) => {
                log::trace!("Child timed out: {:#?}", err);
                // Kill the child since it appears to have timed out.
                let kill_ret = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child_pid),
                    nix::sys::signal::SIGKILL,
                );
                if let Err(ref err) = kill_ret {
                    // This might just be caused by the fact that the child won the race
                    // and terminated before we killed it.
                    log::trace!("Failed to kill child: {:#?}", err);
                }
                if let Err(err) = self
                    .wait_for_data(AFL_DEFAULT_TIMEOUT)
                    .context("Child did not acknowledge termination request")
                {
                    let reason = try_get_child_exit_reason(self.forkserver_sid.unwrap());
                    log::error!(
                        "Exit reason: {:#?}, child_pid={:?}, kill_ret={:?}",
                        reason,
                        child_pid,
                        kill_ret
                    );
                    return Err(err.context(format!("child_exit_reason={:#?}", reason)));
                }

                // Consume exit status.
                let ret = unsafe { libc::read(self.receive_fd.unwrap(), buf_ptr, 4) };
                if ret != 4 {
                    log::error!("Expected {} != 4", ret);
                }
                return Ok(RunResult::TimedOut);
            }
        }

        log::trace!("Child terminated, getting exit status");
        let ret =
            repeat_on_interrupt(|| unsafe { libc::read(self.receive_fd.unwrap(), buf_ptr, 4) });
        if ret != 4 {
            error!("Failed to get exit status");
            return Err(anyhow!("Failed to read from receive_non_blocking_fd"));
        }

        let exit_status = i32::from_le_bytes(buffer);

        log::trace!("Child status is {}", exit_status);
        if libc::WIFEXITED(exit_status) {
            Ok(RunResult::Terminated(libc::WEXITSTATUS(exit_status)))
        } else if libc::WIFSIGNALED(exit_status) {
            let signal = libc::WTERMSIG(exit_status);
            let signal = match Signal::try_from(signal) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to parse signal code {}. Error: {:?}. Using dummy signal SIGUSR2",
                        signal, e
                    );
                    // Some dummy signal type.
                    Signal::SIGUSR2
                }
            };
            Ok(RunResult::Signalled(signal))
        } else {
            unreachable!();
        }
    }

    pub fn bitmap(&mut self) -> &mut Bitmap {
        &mut self.bitmap
    }
}

impl Drop for AflSink {
    fn drop(&mut self) {
        self.stop();
    }
}
