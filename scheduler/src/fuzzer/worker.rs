use std::{
    collections::HashSet,
    fs, mem,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        mpsc::{self, RecvTimeoutError, TryRecvError},
        Arc, Barrier, Mutex, Once, RwLock,
    },
    thread::{self, JoinHandle},
};

use crate::{
    config::Config,
    sink::AflSink,
    sink_bitmap::{Bitmap, BITMAP_DEFAULT_MAP_SIZE},
    source::Source,
};

use anyhow::{anyhow, Result};

use fuzztruction_shared::types::PatchPointID;
use lazy_static::lazy_static;
use libc::CPU_SET;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{
    event_counter::FuzzerEventCounter,
    queue::{Queue, QueueEntry},
    worker_impl::{Cerebrum, FuzzingPhase, MutatorType},
};

/// An unique identifier for a FuzzingWorker.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WorkerUid(pub usize);

impl std::fmt::Debug for WorkerUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WorkerUid").field(&self.0).finish()
    }
}

impl ToString for WorkerUid {
    fn to_string(&self) -> String {
        format!("WorkerUid({})", self.0)
    }
}

/// The `Source` is not Send because it uses RefCell<MutationCache>.
/// However, the source field of `FuzzingWorker` is None when FuzzingWorker.spawn()
/// is called, thus it is never send.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Source {}

#[derive(Debug, Default)]
pub struct FuzzerState {
    /// The currently fuzzed [QueueEntry].
    entry: Option<Arc<QueueEntry>>,
    /// The current [FuzzingPhase].
    phase: Option<FuzzingPhase>,
    /// The currently fuzzed [PatchPointID]
    patch_point: Option<PatchPointID>,
    /// The currently used [MutatorType].
    mutator: Option<MutatorType>,
    /// Total iterations of the current mutator.
    mutator_total_iterations: Option<usize>,
    /// Number of iterations done so far for the current mutator.
    mutator_iterations: Option<usize>,
    /// Set of all phases finished so far.
    phases_finished: HashSet<FuzzingPhase>,
}

impl FuzzerState {
    pub fn _reset(&mut self) {
        self.entry.take();
        self.phase.take();
        self.patch_point.take();
        self.mutator.take();
        self.mutator_total_iterations.take();
        self.mutator_iterations.take();
    }

    pub fn set_entry(&mut self, entry: Arc<QueueEntry>) {
        self.entry = Some(entry);
    }

    pub fn set_phase(&mut self, phase: FuzzingPhase) {
        self.phase = Some(phase);
    }

    pub fn set_patch_point(&mut self, patch_point: PatchPointID) {
        self.patch_point = Some(patch_point);
    }

    pub fn set_mutator(&mut self, mutator: MutatorType, total_iterations: usize) {
        self.mutator = Some(mutator);
        self.mutator_total_iterations = Some(total_iterations);
    }

    pub fn set_iterations(&mut self, iterations: usize) {
        assert!(self.mutator_total_iterations.unwrap() >= iterations);
        self.mutator_iterations = Some(iterations);
    }

    pub fn mark_phase_as_done(&mut self, phase: FuzzingPhase) {
        self.phases_finished.insert(phase);
    }

    pub fn is_phase_done(&self, phase: FuzzingPhase) -> bool {
        self.phases_finished.contains(&phase)
    }

    pub fn entry(&self) -> Arc<QueueEntry> {
        self.entry.as_ref().unwrap().clone()
    }

    pub fn phase(&self) -> FuzzingPhase {
        self.phase.unwrap()
    }

    pub fn patch_point(&self) -> PatchPointID {
        self.patch_point.unwrap()
    }

    pub fn mutator(&self) -> MutatorType {
        self.mutator.unwrap()
    }

    pub fn _mutator_total_iterations(&self) -> usize {
        self.mutator_total_iterations.unwrap()
    }

    pub fn _mutator_iterations(&self) -> usize {
        self.mutator_iterations.unwrap()
    }
}

pub struct FuzzingWorker {
    /// A unique number that is used for identification.
    pub uid: WorkerUid,
    /// The configuration of this fuzzing instance.
    pub config: Config,
    /// Used to synchronize the decision who is responsible for initializing shared
    /// state.
    pub shared_init_done: Arc<Once>,
    /// Set if the queue initialization failed.
    pub queue_init_failed_flag: Arc<AtomicBool>,
    /// The fuzzing queue.
    pub queue: Arc<Mutex<Queue>>,
    /// The (local) virgin map that is used to test whether a coverage bitmap
    /// represents a neq path.
    pub virgin_map: Bitmap,
    /// Same as `virgin_map`, except that it is shared between all fuzzing instances,
    /// and used to determine whether a new unique path is also globally unique.
    pub shared_virgin_map: Arc<Mutex<Bitmap>>,
    /// Some stats about this workers performance.
    pub stats: Arc<Mutex<FuzzerEventCounter>>,
    /// Data that describes the current state of the fuzzer (i.e., current fuzzing phase, fuzzed queue entry ...)
    pub state: FuzzerState,
    /// Knowledge database used to make decisions during fuzzing.
    pub cerebrum: Arc<RwLock<Option<Cerebrum>>>,
    /// Used by the controlling process to indicate that the work should stop.
    pub stop_channel: (Option<mpsc::Sender<()>>, mpsc::Receiver<()>),
    /// Used to notify the parent the the initialization is finished.
    pub init_done: (mpsc::Sender<bool>, Option<mpsc::Receiver<bool>>),
    /// Channel used to check whether a worker is alive.
    pub alive_channel: (Option<mpsc::Receiver<()>>, mpsc::Sender<()>),
    /// The source that is used during fuzzing.
    pub source: Option<Source>,
    /// The sink that is used during fuzzing.
    pub sink: Option<AflSink>,
    /// Path to the directory in which inputs that yielded new coverage are stored.
    pub interesting_inputs: PathBuf,
    /// Path to the directory in which inputs that caused crashes are stored.
    pub crashing_inputs: PathBuf,
    /// Shared coverage map used to deduplicate crashes.
    pub shared_crash_virgin_map: Arc<Mutex<Bitmap>>,
    /// A local cache that is queried to avoid locking `shared_crash_virgin_map`
    /// each time.
    pub crash_virgin_map: Bitmap,
    /// Whether the worker was requested to terminate.
    pub stop_requested: bool,
    /// Average execution duration over all executions that is used for runtime estimations.
    pub avg_execution_duration: Duration,
    /// Barrier used to block initialized threads until all other threads have
    /// been initialized.
    pub init_shared_barrier: Arc<Barrier>,
}

/// Counter used to allocate unique IDs for each new worker.
static NEXT_WORKER_UID: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    /// Set of all core ids that haven already been pinned.
    static ref PINNED_CORES: Mutex<HashSet<usize>> = Mutex::new(HashSet::new());
}

/// Get the ids of all pinned cores.
fn get_pinned_cores() -> HashSet<usize> {
    let mut pinned_cores = HashSet::new();
    let core_ids = core_affinity::get_core_ids().unwrap();

    // Check status files of all running processes.
    // ! This is racy and might returns pathes to files that are
    // ! vanished at the point we try to access them.
    let status_files = glob::glob("/proc/*/status").unwrap();
    for file in status_files {
        let mut process_pinned_cores = HashSet::new();
        if let Ok(status_path) = file {
            let mut stat_path = status_path.parent().unwrap().to_owned();
            stat_path.push("stat");
            let stat_content = fs::read_to_string(stat_path);
            if let Ok(content) = stat_content {
                if content.split(' ').nth(2).unwrap_or("") == "Z" {
                    // process is dead
                    continue;
                }
            } else {
                // file vanished before we could open it
                continue;
            }

            let content = fs::read_to_string(status_path);
            if let Ok(content) = content {
                // Parse the status file and retrive the Cpus_allowed_list.
                let re = Regex::new(r"Cpus_allowed_list:\s+(.+)").unwrap();
                let content = re.captures(&content).unwrap();
                let content = content.get(1).unwrap().as_str();
                // Parse each element of the Cpus_allowed_list.
                for e in content.split(',') {
                    if let Some((start, end)) = e.split_once('-') {
                        // Parse CPU range entry, e.g., '0-79'
                        // indicating that CPUs 0-79 (inclusive) are allocated.
                        let start = start.parse::<usize>().unwrap();
                        let end = end.parse::<usize>().unwrap();
                        (start..=end).for_each(|i| {
                            process_pinned_cores.insert(i);
                        });
                    } else {
                        // Parse single entry, e.g., '55'
                        // indicating that this process is pinned to core 55.
                        process_pinned_cores.insert(e.parse::<usize>().unwrap());
                    }
                }
                // If this process is not pinned to all available CPUs, we consider
                // it as pinned (i.e., if the process is pinned to a subset of all CPUs).
                if process_pinned_cores.len() != core_ids.len() {
                    pinned_cores.extend(process_pinned_cores.iter());
                }
            } else {
                // Assume that the file vanished because the process terminated.
            }
        } else {
            // Assume that the file vanished because the process terminated
        }
    }
    pinned_cores
}

/// Get the ids of all available cores (independent of whether they're pinned)
fn get_cores() -> HashSet<usize> {
    core_affinity::get_core_ids()
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect()
}

/// Get a CPU id of an unpinned core, if any.
/// ! The returned core might get pinned before the calling thread
/// ! pinned it itself.
fn get_next_unpinned_core() -> Option<usize> {
    let cores = get_cores();
    let pinned_cores = get_pinned_cores();
    let free_cores = &cores - &pinned_cores;
    free_cores.into_iter().min()
}

/// The public interface of the FuzzingWorker.
impl FuzzingWorker {
    /// Create a new FuzzingWorker that must be started via `spawn()`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config,
        shared_init_done: Arc<Once>,
        queue_init_failed_flag: Arc<AtomicBool>,
        queue: Arc<Mutex<Queue>>,
        shared_virgin_map: Arc<Mutex<Bitmap>>,
        shared_crash_virgin_map: Arc<Mutex<Bitmap>>,
        cerebrum: Arc<RwLock<Option<Cerebrum>>>,
        init_shared_barrier: Arc<Barrier>,
    ) -> FuzzingWorker {
        let virgin_map = Bitmap::new_in_mem(BITMAP_DEFAULT_MAP_SIZE, 0xff);
        let crash_virgin_map = Bitmap::new_in_mem(BITMAP_DEFAULT_MAP_SIZE, 0xff);

        let (stop_channel_send, stop_channel_receive) = mpsc::channel();
        let (init_done_channel_sender, init_done_channel_receiver) = mpsc::channel();
        let (alive_channel_send, alive_channel_receive) = mpsc::channel();

        let uid = WorkerUid(NEXT_WORKER_UID.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let config = config.clone();
        let cfg_timeout = config.general.timeout;

        let interesting_inputs = config.general.interesting_path();
        let crashing_inputs = config.general.crashing_path();

        FuzzingWorker {
            uid,
            config,
            shared_init_done,
            queue_init_failed_flag,
            queue,
            virgin_map,
            shared_virgin_map,
            stats: Arc::new(Mutex::new(FuzzerEventCounter::new())),
            cerebrum,
            stop_channel: (Some(stop_channel_send), stop_channel_receive),
            init_done: (init_done_channel_sender, Some(init_done_channel_receiver)),
            alive_channel: (Some(alive_channel_receive), alive_channel_send),
            source: None,
            sink: None,
            interesting_inputs,
            crashing_inputs,
            crash_virgin_map,
            shared_crash_virgin_map,
            stop_requested: false,
            state: Default::default(),
            avg_execution_duration: cfg_timeout.div_f32(2f32),
            init_shared_barrier,
        }
    }

    /// Try to pin the calling thread to a free core if there is one left. If not,
    /// the thread remains unpinned.
    fn try_set_sched_affinity() {
        let free_core = get_next_unpinned_core().expect("No free core left");

        unsafe {
            let mut msk = mem::zeroed::<libc::cpu_set_t>();
            CPU_SET(free_core, &mut msk);
            let ret = libc::sched_setaffinity(0, mem::size_of_val(&msk), &msk);
            assert_eq!(ret, 0, "Failed to bind to free core {}", free_core);
        }

        log::info!("Pinning to core {:?}", free_core);
    }

    /// Spawn the new work and start fuzzing. This will consume self and
    /// return a proxy that can be used to control the spawned instance.
    pub fn spawn(mut self) -> Result<WorkerProxy> {
        let init_done = self.init_done.1.take().unwrap();
        let stop_channel = self.stop_channel.0.take().unwrap();
        let alive_channel = self.alive_channel.0.take();
        let stats = self.stats.clone();
        let uid = self.uid;

        //log::info!("Waiting for worker {:?} to initialize", uid);
        let thread_handle = thread::Builder::new()
            .name(uid.to_string())
            .spawn(move || {
                FuzzingWorker::try_set_sched_affinity();
                self.fuzzing_main_loop()
            })?;

        // ! Wait for the worker to initialize.
        // ! Since we are multithreaded and the worker makes use of fork during
        // ! initialization, we must wait before spawning the next worker.
        // ! This is required for us to be allowed to use non
        // ! async-safe-functions during forking, since this is disallowed in
        // ! a multithreaded program.
        log::info!("Waiting for worker {:?} to initialize", uid);
        loop {
            let ret = init_done.recv_timeout(Duration::from_secs(60));
            match ret {
                Ok(true) => break, /* init finished */
                Ok(false) => (), /* Worker is still initializing, just a signal thus we do not hang up  */
                Err(err) => {
                    if err == RecvTimeoutError::Disconnected {
                        let child_error = thread_handle.join();
                        log::error!("child_error={:#?}", child_error);
                    }

                    let err_msg = format!(
                        "Timeout! Worker {:?} failed to initialize! e={:#?}",
                        uid, err,
                    );
                    log::error!("{}", err_msg);
                    return Err(anyhow!(err_msg));
                }
            }
        }

        log::info!("Worker {:?} initialized successfully", uid);

        Ok(WorkerProxy {
            uid,
            thread_handle: Some(thread_handle),
            stop_channel: Some(stop_channel),
            stats,
            alive_check_channel: alive_channel,
        })
    }

    /// Get the [WorkerUid] that identifies this fuzzing worker.
    pub fn uid(&self) -> WorkerUid {
        self.uid
    }
}

/// A proxy that is used to communicate with a [`FuzzingWorker`] as soon it is
/// executed in its own thread.
#[derive(Debug)]
pub struct WorkerProxy {
    /// An unique identifier for this worker.
    uid: WorkerUid,
    /// The [`JoinHandle`] of the associated [`FuzzingWorker`].
    thread_handle: Option<JoinHandle<Result<()>>>,
    /// A channel that is used to notify the worker that it should terminate.
    stop_channel: Option<mpsc::Sender<()>>,
    /// Some stats that are describing different aspects of the fuzzers performance.
    stats: Arc<Mutex<FuzzerEventCounter>>,
    /// A channel that is solely used used to determine whether the workder died.
    alive_check_channel: Option<mpsc::Receiver<()>>,
}

impl WorkerProxy {
    /// Retrive the [`WorkerUid`] of the proxied [`FuzzingWorker`].
    pub fn uid(&self) -> WorkerUid {
        self.uid
    }

    /// Retrive the fuzzers stats of the proxied [`FuzzingWorker`].
    pub fn stats(&self) -> Arc<Mutex<FuzzerEventCounter>> {
        self.stats.clone()
    }

    pub fn is_alive(&self) -> bool {
        matches!(
            self.alive_check_channel.as_ref().unwrap().try_recv(),
            Err(TryRecvError::Empty) | Ok(_)
        )
    }

    /// Request the worker to stop soon. If this functions fails, the worker
    /// already terminated or paniced. To await termination and to retrive the exit reason
    /// [`join`] can be used.
    pub fn request_stop_soon(&mut self) {
        let result = self.stop_channel.as_mut().unwrap().send(());
        if let Err(e) = result {
            log::warn!(
                "Failed send stop signal to worker {:?}. Seems like it already terminated/crashed. However, this might just indicate that the worker had no work left. e={:#?}",
                self.uid, e
            );
        }
    }

    /// Wait for the worker to terminate. The `request_stop_soon` function must
    /// be called before joining. If not, this function probably blocks forever.
    pub fn join(&mut self) -> Result<()> {
        let handle = self.thread_handle.take().expect("Join called twice?");
        let result = handle.join();

        // Handle thread panics (outer Result is Err)
        if let Err(e) = result {
            log::error!("Worker terminated with an error.\n{:#?}", e);
            match e.downcast_ref::<String>() {
                Some(s) => {
                    log::error!("Thread paniced with following messages: \"{}\"", s);
                    return Err(anyhow!("Worker paniced with an error: {}", s));
                }
                None => {
                    log::error!(
                        "Failed to retrive addition details about the error that occurred."
                    );
                    return Err(anyhow!("Worker paniced with an error: Reason unknown."));
                }
            }
        }

        // The thread did not panic. Lets retrive the actual return value of the thread.
        let result = result.unwrap();
        if let Err(e) = result {
            log::error!(
                "During execution of worker {:?} an error occurred: {}",
                self.uid(),
                e
            );
            return Err(e.context("Error during thread execution"));
        } else {
            log::info!(
                "Successfully joined worker {:?}. No error was reported by the thread.",
                self.uid()
            );
        }

        Ok(())
    }
}
