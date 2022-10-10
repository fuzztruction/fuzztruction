use fuzztruction_shared::messages;
use fuzztruction_shared::{
    communication_channel::{CommunicationChannel, CommunicationChannelError},
    constants::ENV_LOG_LEVEL,
    dwarf,
    messages::ReceivableMessages,
};
use fuzztruction_shared::{messages::ChildPid, mutation_cache};

use anyhow::Result;
use lazy_static::lazy_static;
use libc::waitpid;
use log::*;
use messages::{Message, RunMessage, SyncMutations, TerminatedMessage};
use mutation_cache::{MutationCache, MutationCacheEntryFlags};
use std::time::Instant;
use std::{
    collections::HashSet,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

use proc_maps;

use crate::{
    jit::{self, Jit, JitError},
    logging, tracing,
};

pub const DEFAULT_TIMEOUT_MS: u64 = 1000 * 300;
pub const HANDSHAKE_TIMEOUT: u64 = 1000 * 300;

/// Was initialization already done?
static INIT_DONE: AtomicBool = AtomicBool::new(false);
// Is this the child running?
pub static IS_CHILD: AtomicBool = AtomicBool::new(false);

/// Map used to trace coverage and execution count of the patch points.
static TRACE_MAP: Mutex<Option<tracing::TraceMap<u64>>> = Mutex::new(None);

lazy_static! {
    /// Mappings of the processes's virtual address space.
    pub static ref PROC_MAPPINGS: Mutex<Option<Vec<proc_maps::MapRange>>> = Mutex::new(None);
    pub static ref COMMUNICATION_CHANNEL: Mutex<Option<CommunicationChannel>> = Mutex::new(None);
}

/// Send the given message to the coordinator.
pub fn send_message(msg: impl Message, timeout_ms: u64) -> Result<()> {
    let mut cc_guard = COMMUNICATION_CHANNEL.try_lock().unwrap();
    let cc = cc_guard.as_mut().unwrap();
    Ok(cc.send_message(msg, timeout_ms)?)
}

/// Receive a message from the coordinator.
pub fn recv_message(timeout_ms: u64) -> Result<ReceivableMessages> {
    let mut cc_guard = COMMUNICATION_CHANNEL.try_lock().unwrap();
    let cc = cc_guard.as_mut().unwrap();
    Ok(cc.recv_message(timeout_ms)?)
}

/// Whether this is the child or the parent process running.
enum ProcessType {
    CHILD,
    PARENT,
}

struct Agent<'a> {
    pub mutation_cache: MutationCache,
    pub jit: jit::Jit<'a>,
}

impl<'a> Agent<'a> {
    pub fn new() -> Agent<'a> {
        let mut mutation_cache = MutationCache::open_shm_from_env().unwrap();
        // Make sure nobody can open it again and mess with, e.g., its size.
        // Additionally, this makes sure the it gets dropped if we die and no one else
        // keeps a reference.
        mutation_cache.unlink();
        Agent {
            mutation_cache,
            jit: jit::Jit::new(),
        }
    }
}

#[no_mangle]
/// Entrypoint of our agent which is called by a stub inserted right at the start
/// of the source's main by our custom compiler pass.
pub extern "C" fn __ft_auto_init() {
    // dbg!("__ft_auto_init");
    if !INIT_DONE.swap(true, Ordering::SeqCst) {
        start_forkserver();
    }
}

/// Update our globally stored mappings in `PROC_MAPPINGS`. Must be called each
/// time after mapping or unmapping memory.
pub fn update_proc_mappings() {
    let mappings = proc_maps::get_process_maps(std::process::id() as i32).unwrap();
    let mut proc_mappings_guard = PROC_MAPPINGS.lock().unwrap();
    proc_mappings_guard.replace(mappings);
    drop(proc_mappings_guard);
}

/// Spin-up the forkserver by setting up communication to the coordinator.
pub fn start_forkserver() {
    let new_cc = CommunicationChannel::from_env();
    match new_cc {
        // Assume that we are not executed by the coordinator, just execute the
        // binary normally.
        Err(CommunicationChannelError::MissingEnvironmentVariables) => return,
        Err(err) => panic!("Unexpected error: {:?}", err),
        Ok(_) => (),
    }

    let mut cc_guard = COMMUNICATION_CHANNEL.try_lock().unwrap();
    *cc_guard = Some(new_cc.unwrap());
    let cc = cc_guard.as_ref().unwrap();
    // Make sure the link dies, if we die.
    cc.unlink();
    drop(cc_guard);

    let level = std::env::var(ENV_LOG_LEVEL).unwrap_or("Debug".to_owned());
    let level = log::Level::from_str(&level).unwrap();
    logging::setup_logger(level).unwrap();
    logging::setup_panic_logging();

    log::info!("Starting forkserver");
    log::info!("Agent log level is {}", level);

    let trace_map = tracing::TraceMap::new();
    let mut trace_map_guard = TRACE_MAP.lock().unwrap();
    let _ = trace_map_guard.insert(trace_map);
    drop(trace_map_guard);

    update_proc_mappings();

    info!("Sending HelloMessage");
    send_message(
        messages::HelloMessage::new(unsafe { libc::gettid() }),
        HANDSHAKE_TIMEOUT,
    )
    .expect("Failed to send HelloMessage.");
    info!("HelloMessage send");

    process_messages();
}

/// This function is called by patch points if execution tracing is enabled.
/// By calling this function and passing the value `id`, the calling patch point
/// reports that it was executed once.
#[no_mangle]
pub unsafe extern "C" fn __tracing_cb(id: u64) {
    // ! NOTE: This code is called in patch point contexts. This might be
    // ! problematic if we trash registers that are expected to be untouched.
    // ! Wether this is an issue depens on the way LLVM treats live values that
    // ! cross a patch point. Right now, each stub called from a patch point
    // ! makes a copy of all  GPR registers. This could be improved by utilizing
    // ! (all) live values recorded  in the patch points.
    let mut trace_map_guard = TRACE_MAP.lock().unwrap();
    trace_map_guard
        .as_mut()
        .expect("Called tracing_cb without initializing TRACE_MAP")
        .report_hit(id);
}

/// Revert all changes applied to the binary and reapply all mutations that are
/// described in the mutation cache.
fn sync_mutations(agent: &mut Agent, _msg: &SyncMutations) {
    let mut entries = agent.mutation_cache.entries();
    entries.retain(|e| !e.is_flag_set(MutationCacheEntryFlags::Disable));
    let entries = entries;

    // Check that all addresses we might patch are unique.
    let vmas = entries.iter().map(|e| e.vma()).collect::<HashSet<_>>();
    debug_assert!(
        vmas.len() == entries.len(),
        "Cache contains duplicated VMAs!"
    );

    // Reset the binary to its unmodified state. This must happen before calling
    // snapshot_patch_point, thus we only snapshot those patch points that are
    // actually modified later on.
    agent.jit.reset();

    // Reset the trace maps state thus we can register new mutation entries
    // for tracing if any entry requests tracing below.
    let mut trace_map_guard = TRACE_MAP.lock().unwrap();
    trace_map_guard.as_mut().unwrap().reset();
    drop(trace_map_guard);

    // We are about to reset all patch points -> make them writeable.
    entries.iter().for_each(|e| {
        Jit::mark_enclosing_mapping_rwx(e.vma() as *const u8).unwrap();
    });

    // Create a snapshot of all patch points that we might modify,
    // thus we can restore the original binary later. This will only snapshot
    // those patch points we never touched before.
    for entry in entries.iter() {
        agent.jit.snapshot_patch_point(entry.clone());
    }

    // The function used to report patch point hits during tracing.
    let tracing_cb_fn = jit::NativeFunction::from_fn(__tracing_cb as usize, 1);

    for entry in entries.iter() {
        //log::trace!("Processing: {:?}", &entry);
        let mut callables = Vec::new();

        // Having no mask and tracing disabled renders a MutationCacheEntry useless.
        debug_assert!(
            entry.is_flag_set(MutationCacheEntryFlags::TracingEnabled) || entry.msk_len() > 0,
            "entry={:#?}",
            entry
        );

        if entry.msk_len() > 0 {
            //log::trace!("Mutations are enabled for {:?}", entry);
            let mutation_stub = agent.jit.gen_mutation(&entry, true);
            let mutation_stub = match mutation_stub {
                Ok(e) => e,
                Err(JitError::UnsupportedMutation(e)) => {
                    log::warn!("Error while generating mutations: {:#?}. Skipping...", e);
                    continue;
                }
            };

            let stub = agent.jit.allocate(mutation_stub).unwrap();
            //log::trace!("Mutation Stub: {:#?}", stub);
            callables.push(stub);
        }

        if entry.is_flag_set(MutationCacheEntryFlags::TracingEnabled) {
            //log:: log::trace!("Tracing is enabled for {:?}", entry);
            // Tracing for this entry was requested.

            // We pass our own id as argument to the callback.
            let id: u64 = entry.id().into();
            let args = vec![jit::FunctionArg::Constant(id)];

            let tracing_stub = agent.jit.gen_call(
                &tracing_cb_fn,
                args,
                true,
                Some(dwarf::GENERAL_PURPOSE_REGISTERS.to_owned()),
            );
            let tracing_stub = agent.jit.allocate(tracing_stub).unwrap();
            callables.push(tracing_stub);

            // Notify the trace map that the given vma might report a execution hit
            // during tracing.
            let mut trace_map_guard = TRACE_MAP.lock().unwrap();
            trace_map_guard
                .as_mut()
                .unwrap()
                .alloc_slot(entry.id().into());
        }

        if !callables.is_empty() {
            // The function that calls all functions generated above.
            if callables.len() > 1 {
                // Generate multiplexer that calls all functions in `callables` one after another.
                let multiplexer = agent.jit.gen_call_multiplexer(callables.iter().collect());
                let multiplexer = agent.jit.allocate(multiplexer).unwrap();

                // Generate call to the multiplexer and write it into the patch point.
                let patchpoint_stub = agent.jit.gen_call(&multiplexer, vec![], false, None);
                unsafe {
                    let mut f = agent.jit.assemble(patchpoint_stub).unwrap();
                    //log::trace!("Writing patch point stub {:#?} @ {:?}", f, entry.vma());
                    f.write(entry.vma().into())
                }
            } else {
                // Generate call to our stub and write it into the patch point.
                let patchpoint_stub =
                    agent
                        .jit
                        .gen_call(&callables.pop().unwrap(), vec![], false, None);
                unsafe {
                    let mut f = agent.jit.assemble(patchpoint_stub).unwrap();
                    //log::trace!("Writing patch point stub {:#?} @ 0x{:x}", f, entry.vma());
                    f.write(entry.vma().into())
                }
            }
        }
    }

    // Make code generated by our JIT as RX, thus nobody messes with our code.
    agent.jit.mark_mappings_rx();
    // Same for the patch points -> RX
    entries.iter().for_each(|e| {
        Jit::mark_enclosing_mapping_rx(e.vma() as *const u8).unwrap();
    });
}

/// Performe an actual execution of the source.
fn run(agent: &mut Agent, _msg: &RunMessage) -> ProcessType {
    let mut terminated_msg = TerminatedMessage::new();
    TRACE_MAP.lock().unwrap().as_mut().map(|m| m.finalize());

    let mut child_status: i32 = 0;
    match unsafe { libc::fork() } {
        0 => {
            IS_CHILD.store(true, Ordering::Relaxed);
            // Child
            unsafe {
                // Get new session.
                libc::setsid();
            }

            // ! Send child pid to coordinator.
            // ! We do this here, because the coordinator uses killpg for killing
            // ! the child and this will only work if the childs pid == pgid.
            // ! Since this depends on whether `setsid` was called before `killpg` is issued,
            // ! we leave this task to the child because it knows when that is the case.
            let pid = nix::unistd::getpid();
            let pid_msg = ChildPid::new(pid.as_raw() as u64);
            send_message(pid_msg, DEFAULT_TIMEOUT_MS).unwrap();

            // Drop the communication channel to prevet child from sending
            // messages.
            COMMUNICATION_CHANNEL.lock().unwrap().take();

            // Prevent the child from messing with the mutation cache. However, keep it mapped,
            // for accessing the mutation masks and updating runtime vars.
            agent.mutation_cache.make_private().unwrap();
            return ProcessType::CHILD;
        }

        pid if pid > 0 => {
            /* Parent */

            unsafe {
                let ret = waitpid(pid, &mut child_status, 0);
                assert!(ret == pid);
            }

            if libc::WIFEXITED(child_status) {
                terminated_msg.exit_code = libc::WEXITSTATUS(child_status);
            } else if libc::WIFSIGNALED(child_status) {
                terminated_msg.exit_code = -libc::WTERMSIG(child_status);
            } else {
                unreachable!();
            }
        }
        _ => panic!("fork failed"),
    }

    // Postprocess execution trace (potentially) generated by the child.
    postprocess_trace_map();

    // Report the child's exit status to the coordinator
    send_message(terminated_msg, DEFAULT_TIMEOUT_MS)
        .expect("Failed to report child status to the coordinator");

    ProcessType::PARENT
}

/// If the last run produced trace data, report them to the parent.
fn postprocess_trace_map() {
    let mut trace_hits = 0;
    let mut trace_map_guard = TRACE_MAP.lock().unwrap();
    trace_map_guard.as_ref().unwrap().hit_map().map(|entries| {
        let start_ts = Instant::now();
        for e in entries.iter() {
            if e.hits > 0 {
                trace_hits += e.hits;
                send_message(
                    messages::TracePointStat::new(e.value.into(), e.hits, e.order),
                    DEFAULT_TIMEOUT_MS,
                )
                .unwrap();
            }
        }
        log::debug!("Processed trace map in {:?}", start_ts.elapsed());
    });
    trace_map_guard.as_mut().unwrap().reset_hits();
}

/// Main loop of the source agent that waits for instructions from the
/// coordinator.
fn process_messages() {
    let mut agent = Agent::new();

    info!("Ready to receive orders. Starting main loop.");
    loop {
        let new_msg = recv_message(DEFAULT_TIMEOUT_MS);
        let new_msg = new_msg.expect("Failed to receive message from parent.");
        log::trace!("Received new message {:?}", &new_msg);

        match new_msg {
            ReceivableMessages::SyncMutations(msg) => {
                log::trace!("Received SyncMutations message");
                let start_ts = Instant::now();
                sync_mutations(&mut agent, &msg);
                log::trace!("Synchronization completed");
                let msg = messages::Ok::new();
                log::trace!(
                    "Synchronization finshed in {:?}. Sending Ok message.",
                    start_ts.elapsed()
                );
                send_message(msg, DEFAULT_TIMEOUT_MS).unwrap();
            }
            ReceivableMessages::RunMessage(msg) => {
                if let ProcessType::CHILD = run(&mut agent, &msg) {
                    std::mem::forget(agent);
                    return;
                }
            }
            _ => panic!("Unhandled message: {:#?}", new_msg),
        }
    }
}
