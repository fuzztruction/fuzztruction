use fuzztruction_shared::types::PatchPointID;
use hex::ToHex;

use rand::prelude::{IteratorRandom, SliceRandom};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self},
    fs::{self, OpenOptions},
    hash,
    io::Write,
    mem,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{atomic::AtomicU64, Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use anyhow::{Context, Result};
use lazy_static::lazy_static;

use crate::{sink_bitmap::Bitmap, trace::Trace};

use super::{
    finite_integer_set::{PatchPointIDSet, QueueIDDSet},
    worker::WorkerUid,
    worker_impl::{FuzzingPhase, MutatorType},
};

use flate2::write::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;

lazy_static! {
    /// Cache used to store all inputs we already saw.
    static ref INPUTS_CACHE: Mutex<HashMap<String, Arc<Input>>> = Mutex::new(HashMap::new());
}
const DEFAULT_FAVOURED_WEIGHT: u32 = 5;

/// A input passed to an application.
#[derive(Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// The bytes that represent the input.
    #[serde(skip)]
    data: Vec<u8>,
    /// The digest of `data`.
    #[serde(skip)]
    sha256_digest: String,
    /// The path this input was created from.
    origin_path: Option<PathBuf>,
}

/// Custom Debug implementation that omits `data` in the output.
impl fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("sha256_digest", &self.sha256_digest)
            .field("origin_path", &self.origin_path)
            .finish_non_exhaustive()
    }
}

impl Input {
    /// Get an Input from the given bytes. If this function was already called
    /// using the same bytes slice, a reference to the cached Input is returned.
    pub fn from_bytes<D: AsRef<[u8]>, T: AsRef<Path>>(
        data: D,
        origin_path: Option<T>,
    ) -> Arc<Self> {
        let mut digest = Sha256::new();
        digest.update(data.as_ref());
        let sha256_digest: String = digest.finalize().encode_hex();

        let ret = Input {
            data: data.as_ref().to_owned(),
            sha256_digest: sha256_digest.clone(),
            origin_path: origin_path.map(|e| e.as_ref().to_owned()),
        };
        let ret = Arc::new(ret);

        let mut cache = INPUTS_CACHE.lock().unwrap();
        cache.entry(sha256_digest).or_insert_with(|| ret.clone());

        ret
    }

    /// Create an input from the given path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Arc<Input>> {
        let path = path.as_ref();
        let data =
            std::fs::read(path).context(format!("Failed to read from {path:#?}", path = path))?;
        let ret = Input::from_bytes(data, Some(&path));
        Ok(ret)
    }

    /// Create a vector of Input from all files found in the given directory
    /// (non recursive).
    pub fn from_dir(input_dir: impl AsRef<Path>) -> Result<Vec<Arc<Input>>> {
        let mut input_paths = Vec::new();
        let input_dir = input_dir.as_ref();
        let inputs = fs::read_dir(input_dir).context("Failed to read from inputs directory ")?;
        for file in inputs {
            let file = file?.path();
            input_paths.push(file);
        }

        let mut res = Vec::new();
        for path in input_paths {
            res.push(Input::from_path(path)?);
        }

        Ok(res)
    }

    /// The bytes make this Input up.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The length of the input.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn digest(&self) -> &str {
        self.sha256_digest.as_str()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Serialize, Deserialize)]
pub struct QueueEntryId(pub u64);

impl From<usize> for QueueEntryId {
    fn from(v: usize) -> Self {
        QueueEntryId(v as u64)
    }
}

impl From<&QueueEntryId> for usize {
    fn from(pp: &QueueEntryId) -> Self {
        pp.0 as usize
    }
}

impl From<QueueEntryId> for usize {
    fn from(pp: QueueEntryId) -> Self {
        pp.0 as usize
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntryStats {
    /// Execution trace of the source.
    trace: Option<Arc<Trace>>,
    /// Some worker is already tracing this entry.
    tracing_in_progress: bool,
    /// Whether this entry was blacklisted because, e.g., tracing failed or
    /// it showed unstable behavior.
    blacklisted: bool,
    /// Phases that where finished.
    phases_done: HashSet<FuzzingPhase>,
    /// Set of all `PatchPointID`s for that discovery was done.
    #[serde(skip)]
    discovery_pending: Option<PatchPointIDSet>,
    #[serde(skip)]
    combine_done: Option<QueueIDDSet>,
    /// Set of Mutators that were already applied.
    mutators_done: HashSet<MutatorType>,
    /// Used to calculate the propability of favoured entries beeing picked.
    favoured_weight: Option<NonZeroU32>,
}

/// See [GlobalStats] for the "counterpart" of the methods below.
impl QueueEntryStats {
    /// Attach a trace the the `QueueEntryStats`. This must be called before
    /// calling any other method.
    pub fn set_trace(&mut self, trace: &Trace) {
        self.trace = Some(Arc::new(trace.clone()));
    }

    /// Get the [Trace] that belongs to the QueueEntry.
    pub fn trace(&self) -> Option<Arc<Trace>> {
        self.trace.as_ref().cloned()
    }

    pub fn blacklisted(&self) -> bool {
        self.blacklisted
    }

    pub fn set_blacklisted(&mut self) {
        self.blacklisted = true;
    }

    pub fn is_phase_done(&self, phase: FuzzingPhase) -> bool {
        self.phases_done.contains(&phase)
    }

    pub fn mark_phase_done(&mut self, phase: FuzzingPhase) {
        self.phases_done.insert(phase);
    }

    pub fn mark_tracing_in_progress(&mut self) {
        assert!(!self.tracing_in_progress);
        self.tracing_in_progress = true;
    }

    pub fn tracing_in_progress(&self) -> bool {
        self.tracing_in_progress
    }

    pub fn discovery_allocate(&mut self, max: usize) -> PatchPointIDSet {
        let mut set = self.discovery_pending.get_or_insert_with(|| {
            PatchPointIDSet::from_iter(self.trace.as_ref().unwrap().covered().iter().copied())
        });
        let selection = set.choose_random(max);
        set -= &selection;
        selection
    }

    pub fn combined_with_mut(&mut self) -> &mut QueueIDDSet {
        self.combine_done.get_or_insert(QueueIDDSet::new())
    }

    /// Mark `mutator` as done and returns `true` if it was not done already.
    pub fn mark_mutator_done(&mut self, mutator: MutatorType) -> bool {
        self.mutators_done.insert(mutator)
    }

    /// Check whether `mutator` was already applied.
    pub fn is_mutator_done(&self, mutator: MutatorType) -> bool {
        self.mutators_done.contains(&mutator)
    }

    /// Check whether this entry is favoured.
    pub fn is_favoured(&self) -> bool {
        self.favoured_weight.is_some()
    }

    // pub fn set_favoured(&mut self, val: u32) {
    //     assert!(val > 0);
    //     assert!(self.favoured_weight().is_none());
    //     self.favoured_weight = NonZeroU32::new(val);
    // }

    pub fn mark_favoured(&mut self) {
        if self.favoured_weight.is_none() {
            self.favoured_weight = NonZeroU32::new(DEFAULT_FAVOURED_WEIGHT)
        }
    }

    /// The propability weight of this entry being picked during "favoured entry selection".
    pub fn favoured_weight(&self) -> Option<u32> {
        self.favoured_weight.map(|val| val.get())
    }

    /// Decrement the `favoured_weight` by one, but never below 1.
    pub fn favoured_weight_decrement(&mut self) {
        self.favoured_weight = match self.favoured_weight {
            Some(old) if old.get() > 1 => NonZeroU32::new(old.get() - 1),
            old => old,
        };
    }
}

/*
Entries are immutable.
*/
#[derive(Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    /// An ID that uniquely identifies the QueueEntry.
    id: QueueEntryId,
    /// The ID of the parent, if this QueueEntry was forked from another QueueEntry.
    /// Entries created via a seed file have no parent.
    parent_id: Option<QueueEntryId>,
    /// The fuzzing phase that was running during discovery.
    phase: Option<FuzzingPhase>,
    /// The mutator that was used.
    mutator: Option<MutatorType>,
    /// The patch point that was mutated.
    patch_point: Option<PatchPointID>,
    /// The finder of this entry.
    finder: Option<WorkerUid>,
    /// The Input that was used as input for the source application.
    input: Arc<Input>,
    /// The Unix timestamp at which the QueueEntry was created.
    creation_ts: chrono::DateTime<chrono::Utc>,
    /// The mutations that need to be enabled to replay this QueueEntry.
    #[serde(skip)]
    mutations: Option<Vec<u8>>,
    /// The hash of the coverage bitmap of the sink.
    bitmap_hash32: u32,
    /// A bitmap that contains a one for each edge covered in the sink.
    covered_edges: Arc<Bitmap>,
    /// The average execution time in micro seconds for this entry.
    avg_exec_duration_raw: Duration,
    /// Stats that might change over time and are updated by multiple workers.
    stats: Arc<RwLock<QueueEntryStats>>,
    /// Whether the sink is unstable,
    /// i.e., produces varing coverage when executed multiple times
    sink_unstable: bool,
    /// Number of ancestors.
    generation: usize,
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for QueueEntry {}

impl hash::Hash for QueueEntry {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Debug for QueueEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueueEntry")
            .field("id", &self.id)
            .field("parent_id", &self.parent_id)
            .field("phase", &self.phase)
            .field("mutator", &self.mutator)
            .field("patch_point", &self.patch_point)
            .field("finder", &self.finder)
            .field("input", &self.input)
            .field("creation_ts", &self.creation_ts)
            .field("bitmap_hash32", &self.bitmap_hash32)
            .field("avg_exec_duration_raw", &self.avg_exec_duration_raw)
            .field("sink_unstable", &self.sink_unstable)
            .field("generation", &self.generation)
            .finish_non_exhaustive() /* mutations skipped */
    }
}

static QUEUE_ENTRY_NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::too_many_arguments)]
impl QueueEntry {
    pub fn new(
        input: Arc<Input>,
        creation_ts: chrono::DateTime<chrono::Utc>,
        mutations: Option<&Vec<u8>>,
        bitmap_hash32: u32,
        avg_exec_duration_raw: Duration,
        sink_unstable: bool,
        coverage_bitmap: &Bitmap,
        finder: Option<WorkerUid>,
        phase: Option<FuzzingPhase>,
        mutator: Option<MutatorType>,
        patch_point: Option<PatchPointID>,
    ) -> Self {
        let next_id = QUEUE_ENTRY_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let stats = QueueEntryStats {
            trace: None,
            blacklisted: false,
            phases_done: Default::default(),
            discovery_pending: None,
            tracing_in_progress: false,
            combine_done: None,
            mutators_done: HashSet::new(),
            favoured_weight: None,
        };
        let stats = Arc::new(RwLock::new(stats));

        QueueEntry {
            id: QueueEntryId(next_id),
            parent_id: None,
            input,
            creation_ts,
            mutations: mutations.cloned(),
            bitmap_hash32,
            avg_exec_duration_raw,
            stats,
            sink_unstable,
            covered_edges: Arc::new(coverage_bitmap.minimize()),
            generation: 0,
            finder,
            phase,
            mutator,
            patch_point,
        }
    }

    pub fn set_parent(&mut self, parent: &QueueEntry) {
        self.parent_id = Some(parent.id());
        self.generation = parent.generation + 1;
    }

    pub fn id(&self) -> QueueEntryId {
        self.id
    }

    pub fn parent_id(&self) -> Option<QueueEntryId> {
        self.parent_id
    }

    pub fn input(&self) -> Arc<Input> {
        self.input.clone()
    }

    pub fn input_as_ref(&self) -> &Input {
        self.input.as_ref()
    }

    pub fn creation_ts(&self) -> chrono::DateTime<chrono::Utc> {
        self.creation_ts
    }

    pub fn mutations(&self) -> Option<&Vec<u8>> {
        self.mutations.as_ref()
    }

    pub fn bitmap_hash32(&self) -> u32 {
        self.bitmap_hash32
    }

    pub fn covered_edges(&self) -> Arc<Bitmap> {
        self.covered_edges.clone()
    }

    pub fn avg_exec_duration_raw(&self) -> Duration {
        self.avg_exec_duration_raw
    }

    pub fn avg_exec_duration_raw_us(&self) -> u128 {
        self.avg_exec_duration_raw.as_micros() as u128
    }

    pub fn sink_unstable(&self) -> bool {
        self.sink_unstable
    }

    pub fn stats_ro(&self) -> RwLockReadGuard<QueueEntryStats> {
        self.stats.read().unwrap()
    }

    pub fn stats_ro_try(&self) -> Option<RwLockReadGuard<QueueEntryStats>> {
        if let Ok(l) = self.stats.try_read() {
            return Some(l);
        }
        None
    }

    pub fn stats_rw(&self) -> RwLockWriteGuard<QueueEntryStats> {
        self.stats.write().unwrap()
    }

    /// The number of ancestors queue entries.
    pub fn generation(&self) -> usize {
        self.generation
    }

    pub fn finder(&self) -> Option<WorkerUid> {
        self.finder
    }

    pub fn patch_point(&self) -> Option<PatchPointID> {
        self.patch_point
    }

    pub fn phase(&self) -> Option<FuzzingPhase> {
        self.phase
    }

    pub fn mutator(&self) -> Option<MutatorType> {
        self.mutator
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Queue {
    entries: Vec<Arc<QueueEntry>>,
}

#[derive(Debug)]
pub struct QueueIterator {
    entries: Vec<Arc<QueueEntry>>,
}

impl Iterator for QueueIterator {
    type Item = Arc<QueueEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.pop()
    }
}

impl Queue {
    pub fn new() -> Queue {
        Default::default()
    }

    /// Push a new QueueEntry to the queue.
    pub fn push(&mut self, entry: &QueueEntry) -> Arc<QueueEntry> {
        let entry = Arc::new(entry.clone());
        self.entries.push(entry.clone());
        entry
    }

    pub fn append(&mut self, entries: impl IntoIterator<Item = QueueEntry>) {
        let iter = entries.into_iter();
        for qe in iter {
            self.push(&qe);
        }
    }

    pub fn entries(&self) -> Vec<Arc<QueueEntry>> {
        self.iter().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, idx: usize) -> Arc<QueueEntry> {
        assert!(
            idx < self.len(),
            "Index {idx} out of range (len={len})",
            idx = idx,
            len = self.len()
        );
        self.entries.get(idx).unwrap().clone()
    }

    pub fn get_id(&self, id: QueueEntryId) -> Arc<QueueEntry> {
        self.iter().find(|entry| entry.id() == id).unwrap()
    }

    pub fn choose_random(&self) -> Arc<QueueEntry> {
        self.iter().choose(&mut rand::thread_rng()).unwrap()
    }

    pub fn choose_random_filtered<F>(&self, f: F) -> Option<Arc<QueueEntry>>
    where
        F: Fn(&QueueEntry) -> bool,
    {
        let mut entries = self.entries();
        entries.shuffle(&mut rand::thread_rng());
        entries.into_iter().find(|entry| f(entry))
    }

    pub fn filter<F>(&self, f: F) -> Vec<Arc<QueueEntry>>
    where
        F: Fn(&QueueEntry) -> bool,
    {
        let mut ret = Vec::new();
        for entry in self.entries() {
            if f(&entry) {
                ret.push(entry.clone())
            }
        }
        ret
    }

    /// Iterate over all queue entries of the queue.
    pub fn iter(&self) -> QueueIterator {
        QueueIterator {
            entries: self.entries.clone(),
        }
    }

    /// Dump the queue into the directory `path`.
    pub fn dump(&self, path: &Path) -> Result<()> {
        log::info!("Dumping queue to {:?}", path);
        fs::create_dir_all(path)?;

        self.entries().par_iter().for_each(|entry| {
            let mut entry_path = path.to_owned();
            entry_path.push(format!("{}.zlib", entry.id().0));

            if entry_path.exists() {
                // Was already dumped.
            } else {
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(entry_path)
                    .unwrap();
                let mut compressor = ZlibEncoder::new(Vec::new(), Compression::default());
                serde_json::to_writer_pretty(&mut compressor, &entry).unwrap();
                let compressed_bytes = compressor.finish().unwrap();
                file.write_all(&compressed_bytes).unwrap();
            }
        });
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Queue> {
        let mut ret = Queue::new();
        let dir = fs::read_dir(path)?;
        for entry in dir {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let content = fs::read(entry.path())?;
                let mut decompressed = Vec::new();
                let mut decompressor = ZlibDecoder::new(&mut decompressed);
                decompressor.write_all(&content).unwrap();
                decompressor.finish().unwrap();

                let qe: QueueEntry = serde_json::from_slice(&decompressed)?;
                log::debug!("QueueEntry size: {}", mem::size_of_val(&qe));
                ret.push(&qe);
            }
        }
        Ok(ret)
    }
}
