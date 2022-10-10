use std::{
    collections::{HashMap, HashSet},
    ops::ControlFlow,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use fuzztruction_shared::mutation_cache::MutationCache;
use rand::{prelude::SliceRandom, thread_rng, Rng};

use super::FuzzingPhase;
use crate::fuzzer::{queue::QueueEntry, worker::FuzzingWorker};

const FAVOURED_RECALCULATION_INTERVAL: u64 = 50;
static RECALCULATION_CTR: AtomicU64 = AtomicU64::new(0);

fn recalculate_favoured_sink_dominator_edges(entries: &[Arc<QueueEntry>]) {
    let mut edge_dominator: HashMap<usize, &Arc<QueueEntry>> = HashMap::new();
    let mut bytes_set_lut = HashMap::<&Arc<QueueEntry>, usize>::new();

    for candidate in entries {
        for edge in candidate.covered_edges().edges() {
            let current_dominator = edge_dominator.get_mut(&edge);
            if let Some(current_dominator) = current_dominator {
                let current_bytes_set = *bytes_set_lut
                    .entry(current_dominator)
                    .or_insert_with(|| current_dominator.covered_edges().count_bytes_set());
                let candidate_bytes_set = *bytes_set_lut
                    .entry(candidate)
                    .or_insert_with(|| candidate.covered_edges().count_bytes_set());
                if current_bytes_set < candidate_bytes_set {
                    edge_dominator.insert(edge, candidate);
                }
            } else {
                edge_dominator.insert(edge, candidate);
            }
        }
    }
    for entry in edge_dominator.values() {
        entry.stats_rw().mark_favoured();
    }
}

fn recalculate_favoured_unique_patch_point_ids(entries: &[Arc<QueueEntry>]) {
    let mut pp_to_entries = HashMap::new();
    let mut mc = MutationCache::new().unwrap();
    for entry in entries {
        if let Some(mc_content) = entry.mutations() {
            mc.load_bytes(mc_content).unwrap();
            for mce in mc.iter() {
                let val = pp_to_entries.entry(mce.id()).or_insert_with(HashSet::new);
                val.insert(entry.clone());
            }
        }
    }
    for (_, qentries) in pp_to_entries.iter() {
        let entry = qentries
            .iter()
            .max_by_key(|entry| entry.covered_edges().count_bytes_set())
            .take()
            .unwrap();
        entry.stats_rw().mark_favoured();
    }
}

impl FuzzingWorker {
    fn recalculate_favoured(&mut self, entries: &mut [Arc<QueueEntry>]) {
        // Only run this function every FAVOURED_RECALCULATION_INTERVAL time
        // it is called.
        let val = RECALCULATION_CTR.fetch_add(1, Ordering::Relaxed);
        if val % FAVOURED_RECALCULATION_INTERVAL != 0 {
            return;
        }
        let start_ts = Instant::now();
        recalculate_favoured_sink_dominator_edges(entries);
        log::info!(
            "recalculate_favoured_sink_dominator_edges took {:?}",
            start_ts.elapsed()
        );
        let start_ts = Instant::now();
        recalculate_favoured_unique_patch_point_ids(entries);
        log::info!(
            "recalculate_favoured_unique_patch_point_ids took {:?}",
            start_ts.elapsed()
        );
    }

    fn schedule_common(&mut self) -> Arc<QueueEntry> {
        let queue = self.queue.lock().unwrap();
        let mut entries = queue.iter().collect::<Vec<_>>();
        drop(queue);

        self.filter_entries(&mut entries);

        let prev_favoured_cnt = entries
            .iter()
            .filter(|entry| entry.stats_ro().is_favoured())
            .count();
        log::info!("#Favoured entries: {}", prev_favoured_cnt);
        self.recalculate_favoured(&mut entries);
        let favoured_cnt = entries
            .iter()
            .filter(|entry| entry.stats_ro().is_favoured())
            .count();
        log::info!(
            "#New favoured entries: {} #Total:{} ",
            favoured_cnt - prev_favoured_cnt,
            favoured_cnt
        );

        let selected_entry = entries
            .choose_weighted(&mut thread_rng(), |entry| {
                entry.stats_ro().favoured_weight().unwrap_or(1)
            })
            .unwrap();

        // Reduce the weight of the chosen entry, those it is less likely
        // to be picked again.
        selected_entry.stats_rw().favoured_weight_decrement();

        Arc::clone(selected_entry)
    }

    /// Remove those entries that should no be fuzzed according to the current fuzzer
    /// configuration.
    fn filter_entries(&mut self, entries: &mut Vec<Arc<QueueEntry>>) {
        #[allow(clippy::type_complexity)]
        let mut filter: Vec<Box<dyn Fn(&QueueEntry) -> bool>> = vec![];

        let generation_ceiling = self.config.phases.generation_ceiling;
        if let Some(generation_ceiling) = generation_ceiling {
            let f = move |entry: &QueueEntry| entry.generation() <= generation_ceiling as usize;
            filter.push(Box::new(f));
        }

        let f = move |entry: &QueueEntry| !entry.stats_ro().blacklisted();
        filter.push(Box::new(f));

        entries.retain(|entry| {
            filter
                .iter()
                .map(|f| f(entry))
                .all(|filter_result| filter_result)
        });
    }

    /// Schedule a [QueueEntry] for the next fuzzer iteration.
    pub fn schedule_next(&mut self) -> ControlFlow<(), Arc<QueueEntry>> {
        let rng = &mut thread_rng();

        loop {
            let entry = match self.state.phase() {
                FuzzingPhase::Discovery => {
                    let queue = self.queue.lock().unwrap();
                    // The worker is in discovery phase.
                    let mut entries = queue.filter(|e| {
                        e.generation() == 0
                            && !e.stats_ro().blacklisted()
                            && !e.stats_ro().is_phase_done(FuzzingPhase::Discovery)
                    });
                    if entries.is_empty() {
                        log::info!("No queue entries that can be processed via {:?} are left. Switching phase.", FuzzingPhase::Discovery);
                        // Discovery is done -> choose next phase
                        self.state.mark_phase_as_done(FuzzingPhase::Discovery);
                        if self.config.phases.discovery.terminate_when_finished {
                            self.state.set_phase(FuzzingPhase::Exit);
                        } else {
                            self.state.set_phase(FuzzingPhase::None);
                        }
                        // Continue with queue entry selection for the next phase.
                        continue;
                    } else {
                        entries.shuffle(rng);
                        entries.pop().unwrap()
                    }
                }
                FuzzingPhase::Exit => {
                    // Stop the worker.
                    return ControlFlow::Break(());
                }
                _ => self.schedule_common(),
            };

            // Make sure that the queue lock (locked at function entry) is not
            // continuously acquired by adding some jitter. Without this, it might
            // be impossible for a thread in another function to lock it if this function
            // is executed by 39 other threads.
            let mut rng = rand::thread_rng();
            thread::sleep(Duration::from_millis(rng.gen_range(0..100)));
            return ControlFlow::Continue(entry);
        }
    }
}
