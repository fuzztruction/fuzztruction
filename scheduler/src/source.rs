#![allow(clippy::type_complexity)]

use byte_unit::{n_gib_bytes, n_mib_bytes};
use fuzztruction_shared::{
    aux_messages::{AuxStreamMessage, AuxStreamType},
    aux_stream::AuxStreamAssembler,
    constants::{ENV_LOG_LEVEL, ENV_SHM_NAME, PATCH_POINT_SIZE},
    log_utils::LogRecordWrapper,
    messages::{ChildPid, HelloMessage},
    mutation_cache::{MutationCacheEntryFlags, MutationCacheError},
    types::PatchPointID,
    util::current_log_level,
};
use jail::jail::{Jail, JailBuilder};
use llvm_stackmap::LocationType;
use std::{
    collections::HashMap,
    fmt::Debug,
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
// Interface to 'source' component
use mktemp::Temp;
use nix::sys::signal::Signal;
use posixmq::PosixMq;
use proc_maps::{get_process_maps, MapRange};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::os::unix::fs::PermissionsExt;

use anyhow::{anyhow, Context, Result};
use thiserror::Error;

use std::{cell::RefCell, fs, os::unix::io::AsRawFd, rc::Rc};
use std::{collections::HashSet, io::SeekFrom};
use std::{fs::File, path::PathBuf};
use std::{io::Write, process};

use std::io;
use std::{convert::TryFrom, ffi::CString};
use std::{fs::OpenOptions, io::prelude::*};

use log::{error, kv::ToValue};

use lazy_static::lazy_static;
use libc::{self};

use crate::{config::Config, patchpoint};
use crate::{constants::MAX_PATCHPOINT_CNT, llvm_stackmap::StackMap};
use crate::{
    messages::{
        Message, MessageType, MsgHeader, ReceivableMessages, RunMessage, SyncMutations,
        TerminatedMessage, TracePointStat,
    },
    trace::Trace,
};
use crate::{mutation_cache::MutationCache, patchpoint::PatchPoint};

use crate::io_channels::*;

const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_secs(120);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OUTPUT_SIZE: u64 = n_mib_bytes!(1) as u64;

lazy_static! {
    /// Mapping of (binary path, Child PID) to patch point collection if they
    /// have already been parsed once.
    static ref PATCH_POINT_CACHE: RwLock<HashMap<PathBuf, Arc<Vec<PatchPoint>>>> = RwLock::new(HashMap::new());
}

/// Type used to represent error conditions of the source.
#[derive(Error, Debug)]
pub enum SourceError {
    #[error("The workdir '{0}' already exists.")]
    WorkdirExists(String),
    #[error("Fatal error occurred: {0}")]
    FatalError(String),
    #[error("Fatal IO error: {0}")]
    FatalIOError(#[from] io::Error),
    #[error("Missing @@ or $$ or @$ identifier in the provided arguments.")]
    MissingFileIdentifier,
    #[error("Received unexpected message: {0}")]
    UnexpectedMessage(String),
    #[error("Got unexpected argument: {0}")]
    UnexpectedArgument(String),
    #[error("Error during operating on the mutation cache: {0}")]
    MutationCacheError(#[from] MutationCacheError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result of one run of the target application.
#[derive()]
pub enum RunResult {
    /// The target terminated gracefully.
    Terminated {
        /// The exit code provided by the target.
        exit_code: i32,
        /// The messages received before the child terminated.
        msgs: Vec<ReceivableMessages>,
    },
    /// The target was terminated by a signal.
    Signalled {
        /// The signal number that caused the termination (negative).
        signal: Signal,
        /// The messages received before the child terminated.
        msgs: Vec<ReceivableMessages>,
    },
    /// The target did not manage to finish execution during the given
    /// timeout and was forcefully terminated.
    TimedOut {
        /// Messages received before the target was terminated.
        msgs: Vec<ReceivableMessages>,
    },
}

impl Debug for RunResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminated { exit_code, .. } => f
                .debug_struct("Terminated")
                .field("exit_code", exit_code)
                .finish_non_exhaustive(),
            Self::Signalled { signal, .. } => f
                .debug_struct("Signalled")
                .field("signal", signal)
                .finish_non_exhaustive(),
            Self::TimedOut { .. } => f.debug_struct("TimedOut").finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Pid(i32);

impl From<nix::unistd::Pid> for Pid {
    fn from(pid: nix::unistd::Pid) -> Self {
        Pid(pid.as_raw() as i32)
    }
}

impl From<proc_maps::Pid> for Pid {
    fn from(pid: proc_maps::Pid) -> Self {
        Pid(pid as i32)
    }
}

impl From<Pid> for nix::unistd::Pid {
    fn from(pid: Pid) -> Self {
        nix::unistd::Pid::from_raw(pid.into())
    }
}

impl From<Pid> for i32 {
    fn from(pid: Pid) -> Self {
        pid.0 as i32
    }
}

/// The source program that is used to generate seed for the sink.
#[derive(Debug)]
pub struct Source {
    /// Path to the target binary.
    path: PathBuf,
    /// Args passed to the binary (excluding argv[0]).
    args: Vec<String>,
    /// Workdir
    workdir: PathBuf,
    /// Directory containing data related to the sources state.
    state_dir: PathBuf,
    /// The way input is consumed.
    input_channel: InputChannel,
    /// The way output is stored.
    output_channel: OutputChannel,
    /// File used to server inputs.
    input_file: (File, String),
    /// File used to store the sources output..
    output_file: (File, String),
    /// File used to store the sources stdout.
    stdout_file: Option<(File, PathBuf)>,
    /// File used to store the sources stderr.
    stderr_file: Option<(File, PathBuf)>,
    /// POSIX MQ name for the send queue
    mq_send_name: String,
    /// POSIX MQ name for the receive queue
    mq_recv_name: String,
    /// Queue used to send messages to the target agent.
    mq_send: Option<PosixMq>,
    /// Queue used to receive message from the target agent.
    mq_recv: Option<PosixMq>,
    /// The PID of the target's parent (source agent).
    pid: Option<i32>,
    mem_file: Option<File>,
    log_stdout: bool,
    log_stderr: bool,
    mutation_cache: Rc<RefCell<MutationCache>>,
    /// The memory mappings of the target application.
    /// Available after calling `.start()`.
    mappings: Option<Vec<MapRange>>,
    aux_stream_assembler: AuxStreamAssembler,
    config: Option<Config>,
    jail: Option<Jail>,
    /// List of file that are not purged during workdir purging.
    workdir_file_whitelist: Vec<PathBuf>,
}

impl Source {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        mut args: Vec<String>,
        mut workdir: PathBuf,
        input_channel: InputChannel,
        output_channel: OutputChannel,
        _debug: bool,
        log_stdout: bool,
        log_stderr: bool,
        config: Option<&Config>,
    ) -> Result<Source> {
        let mut workdir_file_whitelist = Vec::new();

        workdir.push("source");

        let mut state_dir = workdir.clone();
        state_dir.push("state");

        workdir.push("workdir");
        log::debug!("Creating workdir {:?}", &workdir);
        fs::create_dir_all(&workdir)?;

        log::debug!("Creating state dir {:?}", &state_dir);
        fs::create_dir_all(&state_dir)?;

        Source::check_link_time_deps(&path, config)?;

        let mut rand_suffix: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        rand_suffix += &format!("_tid_{}", unsafe { libc::gettid().to_string() });

        let mq_send_name: String = "/mq_send_".to_owned() + &rand_suffix;
        let mq_recv_name: String = "/mq_recv_".to_owned() + &rand_suffix;

        let tmpfile = Temp::new_file_in(&workdir).expect("Failed to create tempfile.");
        let input_output_prefix_path = tmpfile.to_str().unwrap();

        let mut file_in_name = input_output_prefix_path.to_owned();
        file_in_name.push_str("_input");

        let file_in = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_in_name)
        {
            Err(e) => Err(SourceError::FatalIOError(e))
                .context(format!("Failed to open input file at {:?}", &file_in_name))?,
            Ok(f) => f,
        };

        let mut out_file_path = String::from(input_output_prefix_path);
        out_file_path.push_str("_output");
        config.map(|cfg| {
            cfg.source
                .output_suffix
                .as_ref()
                .map(|suffix| out_file_path.push_str(suffix))
        });
        log::info!("out_file_path={}", out_file_path);

        let file_out = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_file_path)
        {
            Err(e) => Err(SourceError::FatalIOError(e)).context(format!(
                "Failed to open output file at {:?}",
                &out_file_path
            ))?,
            Ok(f) => f,
        };
        let input_file = (file_in, file_in_name);
        let mut output_file = (file_out, out_file_path);

        let stdout_file = None;
        // if log_stdout {
        //     // Setup file for stdout logging.
        //     let mut path = workdir.clone();
        //     path.push("stdout");
        //     workdir_file_whitelist.push(path.clone());

        //     let file = OpenOptions::new()
        //         .read(true)
        //         .write(true)
        //         .create(true)
        //         .truncate(true)
        //         .open(&path)
        //         .unwrap();
        //     stdout_file = Some((file, path));
        // }

        let mut stderr_file = None;
        if log_stderr {
            // Setup file for stdout logging.
            let mut path = workdir.clone();
            path.push("stderr");
            workdir_file_whitelist.push(path.clone());

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            stderr_file = Some((file, path));
        }

        // Check if our input file is the output file, denoted by @$
        if args.contains(&String::from("@$")) {
            // Implicit requirement: Input and output must be files
            assert_eq!(input_channel, InputChannel::File);
            assert_eq!(output_channel, OutputChannel::File);
            if let Some(arg) = args.iter_mut().find(|arg| arg.contains("@$")) {
                *arg = arg.replace("@$", &input_file.1);
                let out_file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&input_file.1)
                {
                    Err(e) => Err(SourceError::FatalIOError(e))
                        .context(format!("Failed to open output file at {:?}", &input_file.1))?,
                    Ok(f) => f,
                };
                let mut new_out_file_path = input_file.1.clone();
                config.map(|cfg| {
                    cfg.source
                        .output_suffix
                        .as_ref()
                        .map(|suffix| new_out_file_path.push_str(suffix))
                });
                output_file = (out_file, new_out_file_path);
            }
        } else {
            // Prepare the argv vector to possibly contain the path to the input file.
            match input_channel {
                InputChannel::File => {
                    if !args.iter().any(|s| s.contains(&String::from("@@"))) {
                        return Err(SourceError::MissingFileIdentifier.into());
                    }
                    for arg in args.iter_mut() {
                        if arg.contains("@@") {
                            // We found the marker; replace it with the actual path
                            // of the input.
                            *arg = arg.replace("@@", &input_file.1);
                        }
                    }
                }
                _ => {}
            }

            // Prepare the argv vector to possibly contain the path to the output file.
            match output_channel {
                OutputChannel::File => {
                    if !args.iter().any(|s| s.contains(&String::from("$$"))) {
                        return Err(SourceError::MissingFileIdentifier.into());
                    }

                    for arg in args.iter_mut() {
                        if arg.contains("$$") {
                            // We found the marker the we are replacing with the actual path
                            // of the output.
                            *arg = arg.replace("$$", &output_file.1);
                            // Programs do not like it if their output file already exists.
                            fs::remove_file(&output_file.1)?;
                        }
                    }
                }
                _ => {
                    for arg in args.iter() {
                        if arg.contains("$$") {
                            return Err(SourceError::UnexpectedArgument(format!(
                                "Found $$ identifier, but output channel is {:?}",
                                output_channel
                            ))
                            .into());
                        }
                    }
                }
            }
        }

        // Replace $$n args with unique paths. If args contained $$, it was already parsed above.
        let output_marker = args
            .iter()
            .filter_map(|arg| {
                if arg.starts_with("$$") {
                    Some(arg.clone())
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();

        output_marker.into_iter().for_each(|current_marker| {
            let path = Temp::new_file_in(&workdir).expect("Failed to create tempfile.");
            let path = path.as_path().to_str().unwrap().to_owned();
            args.iter_mut().for_each(|arg| {
                if *arg == current_marker {
                    *arg = path.clone();
                }
            });
        });

        // Create the mutation cache
        let mc_name = "/ft_shm_".to_owned() + &rand_suffix;
        let mutation_cache =
            MutationCache::new_shm(mc_name).context("Failed to create mutation cache.")?;

        let jail = if let Some(config) = config {
            if let Some((uid, gid)) = config.general.jail_uid_gid() {
                let mut jail = JailBuilder::new();
                jail.drop_privileges(uid, gid);
                // This is an own mount in our mount namespace, thus we need
                // to explicitly mount it.
                jail.bind_rw(&workdir);
                jail.no_random_devices();
                Some(jail.build()?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Source {
            path,
            args,
            workdir,
            state_dir,
            input_channel,
            output_channel,
            input_file,
            output_file,
            stdout_file,
            stderr_file,
            mq_send_name,
            mq_recv_name,
            mq_send: None,
            mq_recv: None,
            pid: None,
            mem_file: None,
            log_stdout,
            log_stderr,
            mutation_cache: Rc::new(RefCell::new(mutation_cache)),
            mappings: None,
            aux_stream_assembler: AuxStreamAssembler::new(),
            config: config.cloned(),
            jail,
            workdir_file_whitelist,
        })
    }

    pub fn check_link_time_deps(path: &Path, config: Option<&Config>) -> Result<()> {
        // Check if path points to an executable and whether it is linked against our runtime agent.
        // FIXME: Handle static binaries?
        let mut cmd = process::Command::new("ldd");
        cmd.args([&path]);

        if let Some(config) = config {
            // Apply environment variables such as LD_LIBRARY_PATH
            for (key, val) in &config.source.env {
                cmd.env(key, val);
            }
        }

        let output = cmd
            .output()
            .unwrap_or_else(|_| panic!("Failed to call ldd on {:#?}", path))
            .stdout;
        let output = String::from_utf8(output).expect("Failed to convert stdout to UTF8.");

        if output.contains("libgenerator_agent.so => not found") {
            Err(SourceError::FatalError(
                "Target failed to find some libraries/library!".to_owned(),
            ))
            .context(output)?;
        }
        Ok(())
    }

    pub fn from_config(config: &Config, id: Option<usize>) -> Result<Source> {
        let config_new = config.clone();
        let mut workdir = config_new.general.work_dir.clone();
        workdir.push(
            id.map(|id| id.to_string())
                .unwrap_or_else(|| "0".to_owned()),
        );

        Source::new(
            config_new.source.bin_path,
            config_new.source.arguments,
            workdir,
            config_new.source.input_type,
            config_new.source.output_type,
            true,
            config.source.log_stdout,
            config.source.log_stderr,
            Some(config),
        )
    }

    pub fn start(&mut self) -> Result<&Source> {
        log::debug!("Starting source");

        log::debug!("Creating POSIX queues");
        log::debug!("Creating sending MQ: {}", self.mq_send_name);
        self.mq_send = Some(
            posixmq::OpenOptions::readwrite()
                .create_new()
                .open(&self.mq_send_name)
                .context("Failed to create send MQ")?,
        );

        log::debug!("Creating receiving MQ: {}", self.mq_recv_name);
        self.mq_recv = Some(
            posixmq::OpenOptions::readwrite()
                .create_new()
                .open(&self.mq_recv_name)
                .context("Failed to create recv MQ")?,
        );

        let child_pid;
        unsafe {
            log::debug!("Forking child");
            child_pid = libc::fork();

            match child_pid {
                -1 => {
                    /* Error case */
                    log::error!("Failed to fork child");
                    return Err(SourceError::FatalError("Failed to fork child".to_owned()).into());
                }
                0 => {
                    /*
                    Child
                    ? Be aware that we are forking a potentially multithreaded application
                    ? here. Since fork() only copies the calling thread, the environment
                    ? might be left in a dirty state because of, e.g., mutexs that where
                    ? locked at the time fork was called.
                    ? Because of this it is only save to call async-signal-safe functions
                    ? (https://man7.org/linux/man-pages/man7/signal-safety.7.html).
                    ? Note that loggin function (debug!...) often internally use mutexes
                    ? to lock the output buffer, thus using logging here is forbidden
                    ? and likely causes deadlocks.
                    */

                    // Move the process into own process session
                    libc::setsid();
                    let path = self.path.to_str().map(|s| s.to_owned()).ok_or_else(|| {
                        SourceError::Other(anyhow!("Invalid UTF-8 character in path"))
                    })?;

                    // Get the args for the source binary.
                    let mut argv: Vec<CString> = self
                        .args
                        .iter()
                        .map(|arg| CString::new(arg.as_bytes()).unwrap())
                        .collect();

                    // Pass the program name as argv[0]
                    argv.insert(0, CString::new(path.as_bytes()).unwrap());

                    // Create the environment pointer array.
                    let mut envp: Vec<CString> = Vec::new();
                    let env_mq_recv = CString::new(
                        format!("FT_MQ_SEND={}", self.mq_recv_name.as_str()).as_bytes(),
                    )
                    .expect("Failed to format FT_MQ_SEND");
                    envp.push(env_mq_recv);

                    let env_mq_send = CString::new(
                        format!("FT_MQ_RECV={}", self.mq_send_name.as_str()).as_bytes(),
                    )
                    .expect("Failed to format FT_MQ_RECV");
                    envp.push(env_mq_send);

                    let env_log_level = CString::new(
                        format!("{}={}", ENV_LOG_LEVEL, current_log_level()).as_bytes(),
                    )
                    .expect("Failed to format FT_LOG_LEVEL");
                    envp.push(env_log_level);

                    let env_shm_name = CString::new(
                        format!(
                            "{}={}",
                            ENV_SHM_NAME,
                            self.mutation_cache().borrow().shm_name().unwrap().as_str()
                        )
                        .as_bytes(),
                    )
                    .expect("Failed to format ENV_FT_SHM_NAME");
                    envp.push(env_shm_name);

                    // Resolve symbols at the start, thus we do not have to do it
                    // after each fork.
                    let ld_bind_now = CString::new("LD_BIND_NOW=1".as_bytes())
                        .expect("Failed to create LD_BIND_NOW string");
                    envp.push(ld_bind_now);

                    let mut env_from_config = Vec::new();
                    if let Some(cfg) = self.config.as_ref() {
                        cfg.source.env.iter().for_each(|var| {
                            env_from_config.push(
                                CString::new(format!("{}={}", var.0, var.1).as_bytes()).unwrap(),
                            )
                        })
                    }

                    // Safety: `env_from_config` must life as long as `envp`.
                    env_from_config.iter().for_each(|e| {
                        envp.push(e.to_owned());
                    });

                    let dev_null_fd = {
                        let path = CString::new("/dev/null".as_bytes()).unwrap();
                        libc::open(path.as_ptr(), libc::O_RDONLY)
                    };
                    if dev_null_fd < 0 {
                        panic!("Failed to open /dev/null");
                    }

                    match self.input_channel {
                        InputChannel::Stdin => {
                            libc::dup2(self.input_file.0.as_raw_fd(), libc::STDIN_FILENO);
                            libc::close(self.input_file.0.as_raw_fd());
                        }
                        _ => {
                            libc::dup2(dev_null_fd, libc::STDIN_FILENO);
                        }
                    }

                    match self.output_channel {
                        OutputChannel::Stdout => {
                            libc::dup2(self.output_file.0.as_raw_fd(), libc::STDOUT_FILENO);
                            libc::close(self.output_file.0.as_raw_fd());
                        }
                        _ => {
                            if !self.log_stdout {
                                libc::dup2(dev_null_fd, libc::STDOUT_FILENO);
                            } else {
                                // let fd = self.stdout_file.as_ref().unwrap().0.as_raw_fd();
                                // libc::dup2(fd, libc::STDOUT_FILENO);
                                // libc::close(fd);
                            }
                        }
                    }

                    if self.log_stderr {
                        // let fd = self.stderr_file.as_ref().unwrap().0.as_raw_fd();
                        // libc::dup2(fd, libc::STDERR_FILENO);
                        // libc::close(fd);
                    } else {
                        libc::dup2(dev_null_fd, libc::STDERR_FILENO);
                    }

                    libc::close(dev_null_fd);
                    libc::close(self.output_file.0.as_raw_fd());
                    libc::close(self.input_file.0.as_raw_fd());

                    // Ressource limits

                    // Limit the maximum size of file created by the process..
                    if !self.log_stdout && !self.log_stderr {
                        // if we log stderr or stdout, the limit will cause our
                        // fuzzer to fail after some time.
                        let mut rlim: libc::rlimit = std::mem::zeroed();
                        rlim.rlim_cur = n_mib_bytes!(16).try_into().unwrap();
                        rlim.rlim_max = n_mib_bytes!(16).try_into().unwrap();
                        let ret = libc::setrlimit(libc::RLIMIT_FSIZE, &rlim as *const libc::rlimit);
                        assert_eq!(ret, 0);
                    }

                    // Limit maximum virtual memory size.
                    let mut rlim: libc::rlimit = std::mem::zeroed();
                    rlim.rlim_cur = n_gib_bytes!(8).try_into().unwrap();
                    rlim.rlim_max = n_gib_bytes!(8).try_into().unwrap();
                    let ret = libc::setrlimit(libc::RLIMIT_AS, &rlim as *const libc::rlimit);
                    assert_eq!(ret, 0);

                    // Disable core dumps
                    let limit_val: libc::rlimit = std::mem::zeroed();
                    let ret = libc::setrlimit(libc::RLIMIT_CORE, &limit_val);
                    assert_eq!(ret, 0);

                    // Disable ASLR since we rely on all instances having the same memory layout.
                    let ret = libc::personality(libc::ADDR_NO_RANDOMIZE as u64);
                    assert_eq!(ret, 0);

                    std::env::set_current_dir(&self.workdir).unwrap();
                    if let Some(ref mut jail) = self.jail {
                        // ! Make sure that the code in `enter()` is async-signal-safe since we
                        // ! are the forked child of a multithreaded application.
                        jail.enter().unwrap();
                    }

                    // Path of the source binary.
                    let source_binary_path = CString::new(path.as_bytes()).unwrap();
                    let prog = &source_binary_path;

                    // ! Make sure that UID == EUID, since if this is not the case,
                    // ! ld will ignore LD_PRELOAD which we need to use for targets
                    // ! that normally load instrumented libraries during runtime.
                    assert_eq!(nix::unistd::getuid(), nix::unistd::geteuid());
                    assert_eq!(nix::unistd::getegid(), nix::unistd::getegid());

                    nix::unistd::execve(prog, &argv, &envp).unwrap();
                    unreachable!();
                }
                _ => { /* Parent */ }
            }
        }; /* unsafe */

        // Take the file, thus their fds get dropped.
        self.stdout_file.take();
        self.stderr_file.take();

        self.pid = Some(child_pid);

        // Dump some info to state dir
        self.dump_state_to_disk(child_pid)?;

        // Wait for the handshake response.
        log::debug!("Waiting for handshake message.");
        let msg = self
            .wait_for_message::<HelloMessage>(HANDSHAKE_TIMEOUT)
            .context("Handshake error. Did the target fail to find libgenerator_agent.so or any other library it depends on? Please check the logs in the work directory. Pass --show-output (not to the subcommand) to print the targets output..")?;
        log::debug!("Got HelloMessage. Agents TID is {:?}", msg.senders_tid);

        // Get the `mem` file of the child thus we can modify the targets addressspace.
        // This must happen after the child dropped the root permissions (if jailing is enabled).
        // This is guranteed after we received the `HelloMessage`, thus do not move this up.
        self.mem_file = Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{}/mem", child_pid))
                .context("Failed to open /proc/<x>/mem")?,
        );

        // Get the mapping of the target memory space.
        // NOTE: This might not include lazily loaded libraries.
        let mut mappings =
            get_process_maps(self.pid.unwrap()).context("Failed to get process maps")?;
        for map in mappings.iter_mut() {
            let pathname = map
                .pathname
                .as_ref()
                .map(|e| self.resolve_path_from_child(&e));
            map.pathname = pathname.map(|v| v.to_str().unwrap().to_owned());
        }
        self.mappings = Some(mappings);

        // Save mapping in state_dir for later use.
        let mut path = self.state_dir.clone();
        path.push("source_maps");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(format!("{:#?}", &self.mappings).as_bytes())
            .unwrap();

        Ok(self)
    }

    #[allow(unused)]
    fn remove_duplicated_vmas(patch_points: &mut Vec<PatchPoint>) {
        let old_size = patch_points.len();

        let mut vma_to_patch_points = HashMap::<u64, Vec<PatchPoint>>::new();
        for pp in patch_points.iter() {
            let entry = vma_to_patch_points.entry(pp.vma()).or_default();
            entry.push(pp.clone());
        }
        // Only keep keys that map to more than one PatchPoint.
        vma_to_patch_points.retain(|_, v| v.len() > 1);
        // Some random sanity check that we are not purging everything.
        assert!(patch_points.len() < 50 || vma_to_patch_points.len() < (patch_points.len() / 2));

        for (vma, mut duplicated_patchpoints) in vma_to_patch_points.into_iter() {
            log::warn!("Duplicated vma 0x{:x}! Enable trace for more details.", vma,);
            duplicated_patchpoints
                .sort_by(|e, other| e.location().loc_size.cmp(&other.location().loc_size));

            for p in duplicated_patchpoints.iter() {
                log::trace!("{:#?}", p);
            }

            // Keep the one with the biggest loc_size, hopeing that it is a
            // "super" location of the other(s) we are removing.
            for p in duplicated_patchpoints.iter().rev().skip(1) {
                patch_points.retain(|other| {
                    other.id() != p.id() || other.location().loc_size != p.location().loc_size
                });
            }
        }

        let removed_cnt = old_size - patch_points.len();
        if removed_cnt > 0 {
            log::warn!("Removed {} patch points during filtering.", removed_cnt);
        }
    }

    /// Remove all patch points that recorded a const live value.
    fn remove_const_types(patch_points: &mut Vec<PatchPoint>) {
        patch_points.retain(|e| {
            e.location().loc_type != LocationType::Constant
                && e.location().loc_type != LocationType::ConstIndex
        });
    }

    /// Remove all patch points that recorded a frame index
    fn remove_direct_types(patch_points: &mut Vec<PatchPoint>) {
        patch_points.retain(|e| e.location().loc_type != LocationType::Direct);
    }

    /// Resolve a path retrived from the child into a local path.
    /// This is only necessary if the child is jailed into another
    /// mount namespace.
    fn resolve_path_from_child(&self, path: &impl AsRef<Path>) -> PathBuf {
        if let Some(ref jail) = self.jail {
            jail.resolve_path_from_child(path)
        } else {
            path.as_ref().to_owned()
        }
    }

    /// Get all patchpoints of the main executable and all libraries mapped
    /// into the executables process memory.
    pub fn get_patchpoints(&self) -> Result<Arc<Vec<PatchPoint>>> {
        let cache = PATCH_POINT_CACHE.read().unwrap();

        if let Some(value) = self.read_from_cache(&cache) {
            return Ok(value);
        }

        drop(cache);
        // Get write access
        let mut cache = PATCH_POINT_CACHE.write().unwrap();
        // Recheck
        if let Some(value) = self.read_from_cache(&cache) {
            return Ok(value);
        }

        // All executable mappings that have a backing file.
        let mappings = self
            .mappings
            .as_ref()
            .unwrap()
            .iter()
            .filter(|e| e.is_exec() && e.filename().is_some())
            .collect::<Vec<_>>();

        let mut patch_points = parse_file_backed_mappings(mappings);

        let pp_before_filtering = patch_points.len();
        Source::remove_const_types(&mut patch_points);
        Source::remove_direct_types(&mut patch_points);
        Source::remove_duplicated_vmas(&mut patch_points);

        self.remove_misaligned(&mut patch_points);

        //Source::remove_overlapps(&mut patch_points);
        // patch_points.retain(|e| e.location().dwarf_regnum != DwarfReg::Rbx as u16);
        // patch_points.retain(|e| e.location().dwarf_regnum != DwarfReg::R13 as u16);
        // patch_points.retain(|e| e.location().dwarf_regnum != DwarfReg::Rax as u16);

        if pp_before_filtering > patch_points.len() {
            log::warn!(
                "We lost {} ({:0.2}%) due to filtering...",
                pp_before_filtering - patch_points.len(),
                (1.0 - patch_points.len() as f64 / pp_before_filtering as f64) * 100.0
            );
        }

        sanity_check_patch_points(&patch_points);

        log::debug!("Found {} patch points in total", patch_points.len());
        //self.dump_patchpoints(&patch_points);
        let patch_points = Arc::new(patch_points);

        // We held the cache lock until here, thus the next one who picks up the
        // lock will get our inserted Vec.
        cache.insert(self.path.clone(), patch_points.clone());

        assert!(patch_points.len() < MAX_PATCHPOINT_CNT);
        Ok(patch_points)
    }

    /// God nows why, but for a few targets the stackmap entries are misaligned.
    /// So, we simply remove those entries that do not contain a nop pattern at their
    /// corresponding vma.
    fn remove_misaligned(&self, patch_points: &mut Vec<PatchPoint>) {
        if let Some(config) = &self.config {
            if config.general.jail_enabled() {
                jail::acquire_privileges().unwrap();
            }
        }
        assert_eq!(PATCH_POINT_SIZE, 32);
        let nop_pattern = b"\x2E\x66\x0F\x1F\x84\x00\x00\x02\x00\x00\x2E\x66\x0F\x1F\x84\x00\x00\x02\x00\x00\x2E\x66\x0F\x1F\x84\x00\x00\x02\x00\x00\x66\x90";
        patch_points.retain(|p| {
            let content = self.read_mem(p.vma() as usize, nop_pattern.len());
            if let Ok(content) = content {
                content == nop_pattern
            } else {
                false
            }
        });
        if let Some(config) = &self.config {
            if config.general.jail_enabled() {
                let (uid, gid) = config.general.jail_uid_gid().unwrap();
                jail::drop_privileges(uid, gid, false).unwrap();
            }
        }
    }

    fn read_from_cache(
        &self,
        cache: &HashMap<PathBuf, Arc<Vec<PatchPoint>>>,
    ) -> Option<Arc<Vec<PatchPoint>>> {
        if let Some(v) = cache.get(&(self.path.clone())) {
            return Some(v.clone());
        }
        None
    }

    pub fn resolve_patch_point_ids<I: Iterator<Item = PatchPointID>>(
        &self,
        ids: I,
    ) -> Result<Vec<PatchPoint>> {
        let ids: Vec<_> = ids.collect();
        let pps = self.get_patchpoints()?;
        let ret = pps
            .iter()
            .filter(|e| ids.contains(&e.id()))
            .cloned()
            .collect();
        Ok(ret)
    }

    /// Dump the patchpoints to the working directory for later analysis.
    #[allow(unused)]
    fn dump_patchpoints(&self, patch_points: &[PatchPoint]) {
        let mut path = self.state_dir.clone();
        path.push("patch_points.json");
        PatchPoint::dump(&path, patch_points);
    }

    /// Try to get the reason why the child process terminated.
    /// If it is still alive, None ist returned.
    /// If is terminated gracefully, `.0` contains the exit code.
    /// If it was terminated by a signal, `.1` contains the signal.
    pub fn try_get_child_exit_reason(&self) -> Option<(Option<i32>, Option<Signal>)> {
        let status: libc::c_int = 0;
        let ret = unsafe {
            let pid = self.pid.unwrap();
            libc::waitpid(pid, status as *mut libc::c_int, libc::WNOHANG)
        };
        if ret > 0 {
            // Child exited
            let mut exit_code = None;
            if libc::WIFEXITED(status) {
                exit_code = Some(libc::WEXITSTATUS(status));
            }
            let mut signal = None;
            if libc::WIFSIGNALED(status) {
                signal = Some(Signal::try_from(libc::WTERMSIG(status)).unwrap_or(Signal::SIGUSR2));
            }
            return Some((exit_code, signal));
        }
        None
    }

    /// Stop the child process.
    pub fn stop(&mut self) -> Result<&Source, SourceError> {
        if let Some(pid) = self.pid.take() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                // reap it
                libc::waitpid(pid, std::ptr::null_mut() as *mut libc::c_int, 0);
            }
        }

        for e in [&self.mq_recv_name, &self.mq_send_name].iter() {
            match posixmq::unlink(e) {
                Err(e) => match e.kind() {
                    /* The file might already be unlinkned to avoid stale queues if the child crashes */
                    io::ErrorKind::NotFound => (),
                    _ => return Err(e.into()),
                },
                _ => (),
            }
        }

        self.mq_send.take();
        self.mq_recv.take();
        Ok(self)
    }

    /// Get the memory mappings of the child process.
    pub fn read_mapping(&mut self) -> Result<Vec<MapRange>> {
        assert!(self.pid.is_some(), "read_mapping: Source's pid not set");
        Ok(get_process_maps(self.pid.unwrap() as proc_maps::Pid)?)
    }

    /// Get all memory mappings of the main executable of the child process.
    pub fn get_main_executable_mappings(&mut self) -> Result<Vec<MapRange>> {
        assert!(
            self.pid.is_some(),
            "get_main_executable_mappings: Source's process not set (expected Popen)"
        );
        let path = self
            .path
            .to_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| SourceError::Other(anyhow!("Invalid UTF-8 character in path")))?;
        let path = PathBuf::from(path);

        let maps: Vec<MapRange> = self
            .read_mapping()?
            .into_iter()
            .filter(|x| {
                path == self
                    .resolve_path_from_child(x.filename().as_ref().unwrap_or(&String::from("")))
            })
            .collect();

        Ok(maps)
    }

    /// Get the .text mapping of the main executable of the child process.
    pub fn get_main_executable_text_mapping(&mut self) -> Result<MapRange> {
        let mappings = self.get_main_executable_mappings()?;
        let exec_mappings: Vec<MapRange> = mappings.into_iter().filter(|e| e.is_exec()).collect();

        match exec_mappings.len() {
            1 => Ok(exec_mappings[0].clone()),
            _ => Err(anyhow!(format!(
                "There are multiple ({}) executable mappings!",
                exec_mappings.len()
            ))),
        }
    }

    /// Read size bytes from address from the targets virtual address space.
    pub fn read_mem(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        let pid = self.pid.unwrap();
        let buf = vec![0; size];

        unsafe {
            let mut local_iovec: libc::iovec = std::mem::zeroed();
            let mut remote_iovec: libc::iovec = std::mem::zeroed();
            local_iovec.iov_base = buf.as_ptr() as *mut libc::c_void;
            local_iovec.iov_len = size;
            remote_iovec.iov_base = address as *mut libc::c_void;
            remote_iovec.iov_len = size;

            let ret = libc::process_vm_readv(
                pid,
                &local_iovec as *const libc::iovec,
                1,
                &remote_iovec as *const libc::iovec,
                1,
                0,
            );
            if ret < 0 || ret as usize != size {
                return Err(anyhow!("Read from address failed"));
            }
        }

        Ok(buf)
    }

    /// Write data bytes to the address `address` in the targets address space..
    pub fn write_mem(&mut self, _address: usize, _data: &[u8]) -> Result<()> {
        unimplemented!();
    }

    /// Wait for `timeout` long for the agent to send an Ok message.
    /// The timeout is reset if a KeepAlive message is received.
    fn wait_for_ok(&mut self, timeout: Duration) -> Result<()> {
        let mq_recv = self.mq_recv.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; mq_recv.attributes().max_msg_len];
        let aux_stream_handler = &mut self.aux_stream_assembler;

        log::trace!(
            "Waiting for MsgIdOk message for {} seconds",
            timeout.as_secs()
        );

        loop {
            Source::receive_message(aux_stream_handler, mq_recv, timeout, &mut buf)
                .context("Failed to receive message while waiting for ok message")?;

            let header = MsgHeader::try_from_bytes(&buf)?;
            match header.id {
                MessageType::KeepAlive => {
                    log::trace!("Got MessageType::KeepAlive message, waiting additional {:?} for ok message ", timeout);
                }
                MessageType::MsgIdOk => {
                    log::trace!("Got MsgIdOk message");
                    break;
                }
                _ => {
                    return Err(SourceError::FatalError(format!(
                        "Unexpected messsage during wait_for_ok(): {:#?}",
                        header
                    ))
                    .into())
                }
            }
        }
        Ok(())
    }

    /// Wait for `timeout` long for a message of type T.
    /// Messages of different type received in between are ignored.
    fn wait_for_message<T: Message>(&mut self, timeout: Duration) -> Result<T> {
        let mq_recv = self.mq_recv.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; mq_recv.attributes().max_msg_len];
        let aux_stream_handler = &mut self.aux_stream_assembler;

        log::trace!("Waiting for message of type {:?}", T::message_type());

        let start_ts = Instant::now();
        let mut timeout_left = timeout;
        loop {
            Source::receive_message(aux_stream_handler, mq_recv, timeout_left, &mut buf)
                .context(format!(
                    "Failed to receive message of type {:?}",
                    T::message_type()
                ))
                .context(format!(
                    "Error while waiting for message {:?}",
                    T::message_type()
                ))?;
            timeout_left = timeout.saturating_sub(start_ts.elapsed());

            let header = MsgHeader::try_from_bytes(&buf)?;
            if header.id == T::message_type() {
                let ret = T::try_from_bytes(&buf)?;
                return Ok(ret);
            } else {
                log::warn!(
                    "Skipping message of type {:?} while waiting for {:?} message.",
                    header.id,
                    T::message_type()
                );
            }
        }
    }

    /// Notify the source agent that we update the content of the mutation cache
    /// and it therefore needs to reprocess it.
    ///
    /// # Errors
    /// All errors returned by this function must be considered fatal.
    pub fn sync_mutations(&mut self) -> Result<()> {
        let mq_send = self.mq_send.as_ref().unwrap();
        let msg = SyncMutations::new();

        log::trace!("Sending SyncMutations message");
        mq_send.send_timeout(0, msg.to_bytes(), DEFAULT_SEND_TIMEOUT)?;
        self.wait_for_ok(DEFAULT_SYNC_TIMEOUT)?;
        log::trace!("SyncMutations acknowledgment received");

        Ok(())
    }

    /// Process a JSON encoded `LogRecordWrapper` object and pass it to the logging backend.
    fn process_log_record_message(msg: String) {
        let record = serde_json::from_str::<LogRecordWrapper>(&msg);
        if let Err(r) = record {
            log::error!("Failed to decode log message: {}. Err({})", msg, r);
            return;
        }

        let record = record.unwrap();
        let mut builder = log::RecordBuilder::new();
        builder.level(record.level);
        let mod_path = record.module_path.as_deref();
        builder.module_path(mod_path);
        builder.line(record.line);
        builder.file(record.file.as_deref());
        builder.target(record.target.as_str());

        let logger = log::logger();
        let kv = (log::kv::Key::from_str("from_agent"), true.to_value());
        builder.key_values(&kv);
        logger.log(&builder.args(format_args!("{}", &record.message)).build());
    }

    /// Process a received AuxStreamMessage.
    fn process_aux_message(assembler: &mut AuxStreamAssembler, msg: AuxStreamMessage) {
        let ret = assembler.process_str_msg(msg);
        match ret {
            Ok(Some((ty, s))) => match ty {
                AuxStreamType::LogRecord => {
                    Source::process_log_record_message(s);
                }
                _ => log::error!("Received message on unsupported channel."),
            },
            Ok(None) => (/* We did not receive all messages jet */),
            Err(err) => log::error!("Error while decoding aux stream: {}", err),
        }
    }

    /// Receive a message from the agent. In case it is a AuxStreamMessage message, it is directly processed.
    /// If not, the function returns and places the received message into `receive_buf`.
    fn receive_message(
        aux_assembler: &mut AuxStreamAssembler,
        mq: &PosixMq,
        timeout: Duration,
        receive_buf: &mut [u8],
    ) -> Result<()> {
        loop {
            mq.receive_timeout(receive_buf, timeout)?;
            let header = MsgHeader::try_from_bytes(receive_buf)?;
            if header.id == MessageType::AuxStreamMessage {
                Source::process_aux_message(
                    aux_assembler,
                    AuxStreamMessage::try_from_bytes(receive_buf)?,
                );
                continue;
            }
            break;
        }
        Ok(())
    }

    /// Execute the target and report the execution result.
    ///
    /// # Errors
    /// All returned errors must be considered as unrecoverable fatal error.
    pub fn run(&mut self, timeout: Duration) -> Result<RunResult> {
        if cfg!(debug) && self.input_file.0.stream_len().unwrap() == 0 {
            log::warn!("Running without input! Is this intentional?");
        }

        // Make sure we do not create huge output files because nobody calls read().
        self.truncate_stdout_output();

        let run_msg = RunMessage::from_millis(timeout.as_millis() as u32);
        let mq_send = self
            .mq_send
            .as_ref()
            .expect("start() must be called first!");
        let mq_recv = self
            .mq_recv
            .as_ref()
            .expect("start() must be called first!");
        let aux_stream_handler = &mut self.aux_stream_assembler;

        // Scratch buffer.
        let mut buf: Vec<u8> = vec![0; mq_recv.attributes().max_msg_len];

        // Vector used to store messages that preceded the termination message.
        let mut msgs: Vec<ReceivableMessages> = Vec::new();

        // Request run
        mq_send
            .send_timeout(0, run_msg.to_bytes(), DEFAULT_SEND_TIMEOUT)
            .context("Failed to send RunMessage")?;

        // Retrive child sid thus we can kill the forked child if it is unresponsive.
        log::trace!("Waiting for the child sid");
        Source::receive_message(
            aux_stream_handler,
            mq_recv,
            DEFAULT_RECEIVE_TIMEOUT,
            &mut buf,
        )
        .context("Failed to receive child pid")?;
        let pid_msg = ChildPid::try_from_bytes(&buf)?;
        log::trace!("Got child sid: {}", pid_msg.pid);

        // Wait for reply
        loop {
            // Get the next message
            match Source::receive_message(aux_stream_handler, mq_recv, timeout, &mut buf) {
                Ok(_) => (),
                Err(_) => {
                    // The child did not terminated in time
                    // => kill it and consume the resulting terminated message.
                    log::trace!(
                        "Did not receive any response in time. Manually killing the child."
                    );
                    let kill_child_ret = kill_child_process_group(&pid_msg);

                    // Consume the TerminatedMessage that might be caused by our
                    // killpg() call, or, if the child won the race be the actual
                    // TerminatedMessage (in other words, we misinterpreted this as a timeout).
                    // Anyways, there should be exactly one TerminatedMessage message. If not,
                    // then this is a fatal error since the agents state becomes unknown.
                    log::trace!("Waiting for termination acknowledgment.");
                    let msg = self.wait_for_message::<TerminatedMessage>(DEFAULT_RECEIVE_TIMEOUT);
                    if let Err(err) = msg {
                        log::error!(
                            "The agent failed to acknowledge our termination request. err={}, child_pid={}, kill_child_ret={:?}",
                            err, pid_msg.pid, kill_child_ret
                        );
                        return Err(err.context("Expected TerminatedMessage after issuing killpg"));
                    }

                    return Ok(RunResult::TimedOut { msgs });
                }
            }

            let header = MsgHeader::try_from_bytes(&buf)?;
            match header.id {
                MessageType::MsgIdTracePointStat => {
                    log::trace!("Got MsgIdTracePointStat message");
                    msgs.push(ReceivableMessages::TracePointStat(
                        TracePointStat::try_from_bytes(&buf)?,
                    ));
                }
                MessageType::MsgIdTerminated => {
                    let msg = TerminatedMessage::try_from_bytes(&buf)?;
                    let exit_code = msg.exit_code;
                    log::trace!("Received MsgIdTerminated message.");
                    if exit_code >= 0 {
                        log::trace!("Child terminated");
                        return Ok(RunResult::Terminated { exit_code, msgs });
                    } else {
                        /* Signals are represented by negative exit codes */
                        log::trace!("Child was signalled");
                        return Ok(RunResult::Signalled {
                            signal: Signal::try_from(libc::WTERMSIG(-exit_code)).unwrap(),
                            msgs,
                        });
                    }
                }
                _ => {
                    let err_msg = format!("Unexpected bytes received: {:#?}", &buf[..64]);
                    log::error!("{}", err_msg);
                    return Err(anyhow!(err_msg).context("Error while processing received message"));
                }
            }
        }
    }

    pub fn mutation_cache_apply_fn<T, U>(&self, f: T) -> U
    where
        T: Fn(&MutationCache) -> U,
    {
        let mc = self.mutation_cache();
        let mc_borrowed = mc.borrow();
        f(&mc_borrowed)
    }

    pub fn mutation_cache_apply_fn_mut<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(&mut MutationCache) -> U,
    {
        let mc = self.mutation_cache();
        let mut mc_borrowed = mc.borrow_mut();
        f(&mut mc_borrowed)
    }

    pub fn mutation_cache(&self) -> Rc<RefCell<MutationCache>> {
        self.mutation_cache.clone()
    }

    pub fn mutation_cache_unchecked(&self) -> *mut MutationCache {
        self.mutation_cache.as_ptr()
    }

    pub fn mutation_cache_replace(&mut self, other: &MutationCache) -> Result<()> {
        self.mutation_cache().borrow_mut().replace(other)
    }

    /// Trace the childs execution.
    ///
    /// # Errors
    /// All returned errors must be considered as unrecoverable fatal error.
    pub fn trace(&mut self, timeout: Duration) -> Result<(RunResult, Trace)> {
        if cfg!(debug) && self.input_file.0.stream_len().unwrap() == 0 {
            log::warn!("Tracing without input! Is this intentional?");
        }

        // Enable tracing for all entries but do not touch the other flags.
        self.mutation_cache().borrow_mut().iter_mut().for_each(|e| {
            e.set_flag(MutationCacheEntryFlags::TracingEnabled);
        });
        self.sync_mutations()
            .context("Failed to sync mce's before tracing")?;

        let res = self
            .run(timeout)
            .context("Unexpected error during execution")?;

        // Clear the tracing flag.
        self.mutation_cache().borrow_mut().iter_mut().for_each(|e| {
            e.unset_flag(MutationCacheEntryFlags::TracingEnabled);
        });
        // Do not sync, since having records without msk and tracing disabled is not
        // allowed!

        // Get received messages independent of whether the child
        // terminated gracefully or not.
        let messages = match res {
            RunResult::Signalled {
                signal: _,
                ref msgs,
            } => msgs,
            RunResult::TimedOut { ref msgs } => msgs,
            RunResult::Terminated {
                exit_code: _,
                ref msgs,
            } => msgs,
        };

        // Convert received messages into a trace.
        let mut trace_stats = Vec::new();
        for m in messages.iter() {
            if let ReceivableMessages::TracePointStat(stat_msg) = m {
                trace_stats.push(stat_msg);
            } else {
                return Err(SourceError::UnexpectedMessage(format!(
                    "Got unexpected messages {:#?} while tracing.",
                    m
                ))
                .into());
            }
        }
        let trace = Trace::from_trace_point_stats(&trace_stats);

        Ok((res, trace))
    }

    // Try to remove all files in the workdir.
    fn _purge_workdir(&self) -> Result<()> {
        let mut delete_ctr = 0usize;
        let dir = fs::read_dir(&self.workdir)?;
        for entry in dir {
            let entry = entry?;
            if !self.workdir_file_whitelist.contains(&entry.path()) && entry.path() != self.workdir
            {
                if entry.path().is_file() {
                    fs::remove_file(entry.path())?;
                    delete_ctr += 1;
                } else if entry.path().is_dir() {
                    fs::remove_dir_all(entry.path())?;
                    delete_ctr += 1;
                }
            }
        }

        log::trace!("Purged {} files from workdir", delete_ctr);
        Ok(())
    }

    /// Try to remove all files in the workdir and recreate it afterwards.
    fn purge_workdir(&self) {
        log::trace!("Purging workdir");
        if let Err(err) = self._purge_workdir() {
            log::warn!("Failed to purge workdir: {:#?}", err);
        }
        let _ = fs::create_dir_all(&self.workdir);
    }

    /// Write `data` to the input channel of the source.
    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.purge_workdir();

        if self.input_channel == InputChannel::None {
            return;
        }

        if self.input_channel == InputChannel::File {
            let (_, path) = &mut self.input_file;
            let path = PathBuf::from_str(path).unwrap();
            set_perms_770_existing(&path);

            let mut new_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .unwrap();
            new_file.write_all(data).unwrap();
            // drop new_file here, we do not need and open fd for this input mode.
        } else if self.input_channel == InputChannel::Stdin {
            self.input_file.0.seek(SeekFrom::Start(0)).unwrap();
            self.input_file.0.set_len(0).unwrap();
            self.input_file.0.write_all(data).unwrap();
            self.input_file.0.seek(SeekFrom::Start(0)).unwrap();
            self.input_file.0.sync_all().unwrap();
        } else {
            unreachable!();
        }
    }

    /// Truncate the stdout output of the source to 0 bytes.
    #[inline]
    fn truncate_stdout_output(&mut self) {
        if self.output_channel == OutputChannel::Stdout {
            self.output_file.0.seek(SeekFrom::Start(0)).unwrap();
            self.output_file.0.set_len(0).unwrap();
        }
    }

    /// Read from the output channel of the source into `data`.
    #[inline]
    pub fn read(&mut self, data: &mut Vec<u8>) {
        data.clear();

        if self.output_channel == OutputChannel::File {
            self.read_from_output_file(data);
        } else if self.output_channel == OutputChannel::Stdout {
            self.read_from_stdout(data);
        } else {
            unreachable!();
        }
    }

    /// Read from the sources stdout into `data`.
    #[inline]
    fn read_from_stdout(&mut self, data: &mut Vec<u8>) {
        if self.output_file.0.stream_position().unwrap() > MAX_OUTPUT_SIZE {
            log::trace!("Discarding too long output");
            self.truncate_stdout_output();
            return;
        }
        self.output_file.0.seek(SeekFrom::Start(0)).unwrap();
        self.output_file.0.read_to_end(data).unwrap();
        self.truncate_stdout_output();
    }

    /// Read from the source output file into `data`.
    #[inline]
    fn read_from_output_file(&mut self, data: &mut Vec<u8>) {
        if let Ok(mut out_file) = File::open(&self.output_file.1) {
            let stream_len = out_file.stream_len();
            if let Ok(len) = stream_len {
                if len <= MAX_OUTPUT_SIZE {
                    // Read all data and ignore errors.
                    let _ = out_file.read_to_end(data);
                } else {
                    log::trace!("Discarding too long output");
                }
            }
            drop(out_file);
        }
        // Delete the output and ignore errors.
        let _ = fs::remove_file(&self.output_file.1);
    }

    /// Dump some information to the sources state directory.
    fn dump_state_to_disk(&self, child_pid: i32) -> Result<()> {
        let mut path = self.state_dir.clone();

        path.push("child_pid");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(format!("{}", child_pid).as_bytes())?;

        let own_pid = unsafe { libc::getpid() };
        let mut path = self.state_dir.clone();
        path.push("own_pid");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(format!("{}", own_pid).as_bytes())?;

        let own_tid = unsafe { libc::gettid() };
        let mut path = self.state_dir.clone();
        path.push("own_tid");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(format!("{}", own_tid).as_bytes())?;

        Ok(())
    }
}

/// The the permission of the existing file/folder `path` to 770.
fn set_perms_770_existing(path: &Path) {
    let parent = path.parent().unwrap();
    let mut perms = parent.metadata().unwrap().permissions();
    perms.set_mode(0o770);
    fs::set_permissions(parent, perms).unwrap();
}

/// Kill the all processes in the child process group.
///
/// # Error:
/// Returns Err if `killpg` fails. However, this might be caused by the process
/// group vanishing before we could kill it.
fn kill_child_process_group(pid_msg: &ChildPid) -> Result<()> {
    let pid = nix::unistd::Pid::from_raw(pid_msg.pid.try_into().unwrap());
    let ret = nix::sys::signal::killpg(pid, nix::sys::signal::SIGKILL);
    if let Err(err) = ret {
        log::trace!("Failed to execute killpg. However, this might just indicate that the child won the race and terminated itself. err={:#?}", err);
        return Err(err.into());
    }
    Ok(())
}

/// Check that some constraints hold for the patch points:
///     - VMAs are unique
///     - PatchPointIDs are unique
///     - Patch point shadows do not overlap
fn sanity_check_patch_points(patch_points: &[PatchPoint]) {
    // Check for duplicated VMAs.
    let vmas = patch_points.iter().map(|e| e.vma()).collect::<HashSet<_>>();
    assert_eq!(vmas.len(), patch_points.len());
    let ids = patch_points.iter().map(|e| e.id()).collect::<HashSet<_>>();
    assert_eq!(ids.len(), patch_points.len());
    let patchpoint_ranges = patch_points
        .iter()
        .map(|e| e.vma_range())
        .collect::<Vec<_>>();
    assert_eq!(patchpoint_ranges.len(), patch_points.len());

    // Check if overlapping
    let mut patchpoint_ranges_sorted_by_start = patchpoint_ranges.clone();
    patchpoint_ranges_sorted_by_start.sort_by_key(|e| e.start);
    let mut patchpoint_ranges_sorted_by_end = patchpoint_ranges;
    patchpoint_ranges_sorted_by_end.sort_by_key(|e| e.end);
    assert_eq!(
        patchpoint_ranges_sorted_by_start,
        patchpoint_ranges_sorted_by_end
    );
}

/// Get all patchpoints of the file backed `mappings`.
fn parse_file_backed_mappings(mappings: Vec<&MapRange>) -> Vec<PatchPoint> {
    let mut processed_paths = HashSet::new();
    let mut patch_points = Vec::new();

    for mapping in mappings.iter() {
        let path = mapping.filename().as_ref().unwrap();
        log::debug!("Processing mapping: {:?} @ {:?}", mapping, path);
        let test_path = PathBuf::from_str(path).unwrap();
        if !test_path.exists() {
            log::warn!("File of mapping not found: {:?}", test_path);
            continue;
        }

        if StackMap::has_stackmap(path) {
            if !processed_paths.insert(path) {
                log::warn!(
                    "Skipping {:?}, because we already loaded its stack map. \
                           Multiple executable sections are currently not supported.",
                    path
                );
                continue;
            }

            let elf_file = match elf::File::open_path(path) {
                Ok(f) => f,
                Err(_) => panic!("File not found"),
            };

            log::info!("Parsing stackmaps...");
            let stack_maps = StackMap::from_path(path).unwrap();
            for stack_map in stack_maps {
                let mut tmp = patchpoint::from_stackmap(&stack_map, mapping, &elf_file);
                patch_points.append(&mut tmp);
            }
        } else {
            log::debug!("Mapping does not have any patch points.")
        }
    }
    patch_points
}

impl Drop for Source {
    /// Stop the child if the Source get dropped.
    fn drop(&mut self) {
        self.stop().unwrap();
    }
}
