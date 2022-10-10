#![allow(unused)]

use fuzztruction_shared::{mutation_cache::MutationCache, types::PatchPointID};
use std::{
    collections::{HashMap, HashSet},
    default, fmt,
    iter::Sum,
    mem,
    ops::SubAssign,
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockWriteGuard},
    time::Instant,
};

use crate::{
    fuzzer::{
        event_counter::FuzzerEventCounter,
        queue::{Queue, QueueEntry, QueueEntryId},
    },
    patchpoint::PatchPoint,
    trace::Trace,
};

use super::{
    cerebrum_query::CerebrumQuery,
    mutators::{Mutator, MutatorType},
    phases::FuzzingPhase,
};

#[derive(Debug, Default, Clone)]
pub(super) struct PatchPointStatsEntry {
    ///Number of coverage yields.
    pub(super) yield_cnt: u64,
    /// Number of source crashes.
    pub(super) source_crash_cnt: u64,
    /// Total number of mutations applied.
    pub(super) mutation_cnt: u64,
    ///Number of times the source timed out.
    pub(super) source_timeout_cnt: u64,
    /// All [QueueEntryId]s of the [QueueEntry]s that are using this [PatchPointID].
    pub(super) used_by: HashSet<QueueEntryId>,
}

impl PatchPointStatsEntry {
    pub fn merge(&mut self, into: &mut PatchPointStatsEntry) {
        // into.yield_cnt += self.yield_cnt;
        // into.crash_cnt += self.crash_cnt;
        // into.mutation_cnt += self.mutation_cnt;
        // into.timeout_cnt += self.timeout_cnt;
        // into.covered_by_trace += self.covered_by_trace;
        // let new_self = Self::default();
        // mem::replace(self, new_self);
    }
}

pub struct FuzzerConfiguration {
    entry: Arc<QueueEntry>,
    phase: FuzzingPhase,
    mutator: MutatorType,
    target_pp_id: PatchPointID,
    counter: FuzzerEventCounter,
}

impl fmt::Debug for FuzzerConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuzzerConfiguration")
            .field("entry", &self.entry)
            .field("phase", &self.phase)
            .field("target_pp_id", &self.target_pp_id)
            .finish_non_exhaustive()
    }
}

impl FuzzerConfiguration {
    pub fn new(
        entry: Arc<QueueEntry>,
        phase: FuzzingPhase,
        mutator: MutatorType,
        target_pp_id: PatchPointID,
        iterations: usize,
        counter: &FuzzerEventCounter,
    ) -> Self {
        FuzzerConfiguration {
            entry,
            phase,
            mutator,
            target_pp_id,
            counter: counter.clone(),
        }
    }

    pub fn finialize(&mut self, other: &FuzzerEventCounter) {
        let mut other = other.clone();
        other -= &self.counter;
        self.counter = other;
    }
}

#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct Cerebrum {
    pub(super) patch_points: HashSet<Arc<PatchPoint>>,
    pub(super) patch_point_stats: HashMap<PatchPointID, PatchPointStatsEntry>,
    pub(super) patch_point_msks: HashMap<PatchPointID, Vec<(QueueEntryId, Arc<[u8]>)>>,
    pub(super) active_configuration: Option<FuzzerConfiguration>,
    pub(super) queue: Arc<Mutex<Queue>>,
    // replace usize with struct?
    //pub(super) phase_mutator_yields: HashMap<(FuzzingPhase, MutatorType), usize>,
}

impl Cerebrum {
    pub fn new(patch_points: &[PatchPoint], queue: Arc<Mutex<Queue>>) -> Cerebrum {
        let patch_points = patch_points
            .iter()
            .cloned()
            .map(Arc::new)
            .collect::<HashSet<_>>();
        let mut patch_point_stats = HashMap::new();
        for patch_point in patch_points.iter() {
            patch_point_stats.insert(patch_point.id(), PatchPointStatsEntry::default());
        }

        Cerebrum {
            patch_points,
            patch_point_stats,
            patch_point_msks: HashMap::new(),
            active_configuration: Default::default(),
            queue,
        }
    }

    pub fn query(&self) -> CerebrumQuery {
        CerebrumQuery::new(self)
    }

    pub(super) fn resolve_pp_id(&self, id: PatchPointID) -> Arc<PatchPoint> {
        self.patch_points
            .iter()
            .find(|e| e.id() == id)
            .cloned()
            .unwrap()
    }

    pub(super) fn pp_stats(&self, id: PatchPointID) -> &PatchPointStatsEntry {
        self.patch_point_stats.get(&id).unwrap()
    }

    pub fn report_new_qe(&mut self, qe: Arc<QueueEntry>) {
        if let Some(mutations) = qe.mutations() {
            /// Update PatchPointID -> QueueEntryId mapping.
            let mut mc = MutationCache::new().unwrap();
            mc.load_bytes(mutations);

            for mc_entry in mc.entries() {
                let value = self.patch_point_stats.get_mut(&mc_entry.id()).unwrap();
                value.used_by.insert(qe.id());
                let key = self
                    .patch_point_msks
                    .entry(mc_entry.id())
                    .or_insert_with(Vec::new);
                if key
                    .iter()
                    .all(|entry| entry.1.as_ref() != mc_entry.get_msk_as_slice())
                {
                    let msk = mc_entry.get_msk_as_slice().to_owned();
                    key.push((qe.id(), msk.into()));
                }
            }
        }
    }

    pub fn report_crash(&mut self) {
        todo!();
    }

    pub fn report_configuration(&mut self, cfg: FuzzerConfiguration) {
        let counter = &cfg.counter;
        let p = self.patch_point_stats.get_mut(&cfg.target_pp_id).unwrap();
        p.source_crash_cnt += counter.source_crashes;
        p.mutation_cnt += counter.execs;
        p.source_timeout_cnt += counter.source_timeout;
        p.yield_cnt += counter.edges_found + counter.hits_found;
        // //TODO: Process phase/mutator/... for, e.g., mutator statstics
    }
}

/*
    - coverage trace

- QE scheduling:
    - Uses a combination of QE stats and Global stats
    - We prefere:
        - new edges in the sink
        - high sink coverage
        - unique pp in the source and high number of pps
            - we need to trace for this every new pp....
            - dedicated tracing core?
        - sources that cover pps in a different order?
        - QEs that cover one sink edge and a maximum of other edges
        - fast execution
        - higher QE depth?

- Phase scheduling

- Decisions we have to make
  - Which phase and duration/propability
  - Which QE and duration/propability
  - Which PP and duration/propability

*/
