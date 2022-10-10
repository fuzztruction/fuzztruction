use std::sync::Arc;

use super::FuzzingPhase;
use crate::{
    fuzzer::{
        queue::QueueEntry,
        worker::FuzzingWorker,
        worker_impl::mutators::{self, Mutator},
    },
    mutation_cache_ops::MutationCacheOpsEx,
};

use anyhow::Result;
use fuzztruction_shared::{
    mutation_cache::MutationCache, mutation_cache_entry::MutationCacheEntry,
};
use rand::{
    prelude::{IteratorRandom, SliceRandom},
    thread_rng,
};

const PHASE: FuzzingPhase = FuzzingPhase::Add;

impl FuzzingWorker {
    #[allow(clippy::type_complexity)]
    fn add_phase_prepare_mutations(
        qe: Arc<QueueEntry>,
        candidates: Vec<&'static mut MutationCacheEntry>,
    ) -> Vec<(&mut MutationCacheEntry, Vec<Box<dyn Mutator<Item = ()>>>)> {
        let mut mutations = Vec::<(
            &mut MutationCacheEntry,
            Vec<Box<dyn mutators::Mutator<Item = ()>>>,
        )>::new();
        for candidate in candidates.into_iter() {
            let mut mutators = Vec::new();
            let msk_len = candidate.get_msk_as_slice().len();

            let iterations = match msk_len {
                x if x <= 32 => 128 * x,
                x if x <= 128 => 64 * x,
                _ => 64 * 128,
            };

            let mutator = mutators::RandomByte1::new(candidate.get_msk_as_slice(), iterations);
            if let Some(mutator) = mutator {
                mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            }

            let mutator = mutators::FlipBit::new(candidate.get_msk_as_slice());
            if qe.stats_rw().mark_mutator_done(mutator.mutator_type()) {
                mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            }

            let entry = (unsafe { candidate.alias_mut() }, mutators);
            mutations.push(entry);
        }
        mutations
    }

    fn add_phase_choose_candidates(&mut self) -> Result<Vec<&'static mut MutationCacheEntry>> {
        let entry = self.state.entry();
        self.load_queue_entry_mutations(&entry)?;
        let source = self.source.as_mut().unwrap();
        // MutationCache of the currently loaded QueueEntry.
        let entry_mc = source.mutation_cache();
        let entry_mc_borrow = entry_mc.borrow();
        log::info!("QueueEntry has {} MCE's", entry_mc_borrow.len());

        let all_patch_points = source.get_patchpoints()?;
        let entry_trace = entry.stats_ro().trace().unwrap();
        let covered_ids = entry_trace.covered();

        let mut tmp_mc = MutationCache::from_patchpoints(all_patch_points.iter())?;
        tmp_mc.union_and_replace(&entry_mc_borrow);
        drop(entry_mc_borrow);

        unsafe {
            tmp_mc.remove_uncovered(&entry_trace);
            tmp_mc.resize_covered_entries(&entry_trace);
        }
        let mut candidates = tmp_mc.entries();

        // Make sure that entries that belong to the entry are always selected.
        let mut selection = candidates
            .drain_filter(|entry| !entry.is_nop())
            .collect::<Vec<_>>();

        let config = &self.config.phases.add;
        let batch_size = config.batch_size as f64;
        log::debug!("batch_size={batch_size}");

        let weight_sum = config.weights_sum() as f64;
        let calc_share = |weight: u32| ((weight as f64 / weight_sum) * batch_size) as u32;
        let rng = &mut thread_rng();

        // Select patch points that where never fuzzed by any other worker before.
        // We always select these, because we assume that fuzzing new logic in the source
        // is more likely to lead to now coverage in the sink.
        // FIXME: We should do this always?
        let select_cnt = calc_share(config.select_unfuzzed_weight);
        log::debug!("select_unfuzzed: n={select_cnt}");
        {
            let cerebrum_guard = self.cerebrum.read().unwrap();
            let cerebrum = cerebrum_guard.as_ref().unwrap();
            let query = cerebrum.query();
            let unfuzzed = query.patch_points_unfuzzed();
            drop(cerebrum_guard);

            let unfuzzed = unfuzzed.intersection(&covered_ids);
            // The selected IDs will be cleared by the callback that is executed for each
            // MCE during fuzzing.
            let selected_ids = unfuzzed
                .take(select_cnt as usize)
                .copied()
                .collect::<Vec<_>>();
            let mut selected_candidates = candidates
                .drain_filter(|e| selected_ids.contains(&e.id()))
                .collect::<Vec<_>>();
            log::debug!(
                "select_unfuzzed selected_candidates={}",
                selected_candidates.len()
            );
            selection.append(&mut selected_candidates);
        }

        // // Select patch points that are part of interesting functions. I.e., the functions
        // // contain patch points that yielded new coverage.
        // let select_cnt = calc_share(config.select_from_yielding_functions_weight);
        // log::debug!("select_from_yielding_functions_weight: n={select_cnt}");
        // {

        // }

        // Select patch points that yielded for other entries.
        let select_cnt = calc_share(config.select_yielding_weight);
        log::debug!("select_yielding_weight: n={select_cnt}");
        {
            let cerebrum_guard = self.cerebrum.read().unwrap();
            let cerebrum = cerebrum_guard.as_ref().unwrap();
            let query = cerebrum.query();
            let yielding_ids = query.patch_points_yielded();
            // clear those that we do not cover
            let yielding_ids = yielding_ids.intersection(&covered_ids).copied();
            // select a subset from the covered ones
            let yielding_ids = yielding_ids
                .into_iter()
                .choose_multiple(&mut thread_rng(), select_cnt as usize);

            // Get the MCEs that belong to the select IDs
            let mut selected_candidates = candidates
                .drain_filter(|e| yielding_ids.contains(&e.id()))
                .collect::<Vec<_>>();
            log::debug!(
                "select_yielding selected_candidates={}",
                selected_candidates.len()
            );
            selection.append(&mut selected_candidates);
        }

        // Select random patch points.
        {
            let select_cnt = calc_share(config.select_random_weight);
            log::debug!("select_random_weight: n={select_cnt}");
            // choose `select_cnt` many random elements.
            let elements = candidates.choose_multiple(rng, select_cnt as usize);
            let mut elements: Vec<_> = elements.copied().collect();
            log::debug!(
                "select_random_weight selected_candidates={}",
                elements.len()
            );
            // remove selected elements from the candidates list.
            let elements_ids: Vec<_> = elements.iter().map(|entry| entry.id()).collect();
            candidates.retain(|entry| !elements_ids.contains(&entry.id()));
            // append our selection to the final `selection` list.
            selection.append(&mut elements);
        }

        log::info!("Selected {} candidates", selection.len());
        let new_mc = MutationCache::from_iter(selection.into_iter())?;
        source.mutation_cache_replace(&new_mc)?;
        let mut entries = source.mutation_cache().borrow_mut().entries_mut_static();
        entries.shuffle(&mut thread_rng());
        Ok(entries)
    }

    pub fn do_add_phase(&mut self) -> Result<()> {
        self.state.set_phase(PHASE);
        let qe = self.state.entry();

        let candidates = self.add_phase_choose_candidates()?;
        let mutations = FuzzingWorker::add_phase_prepare_mutations(qe, candidates);

        // FIXME: per MCE timeout?
        self.fuzz_candidates(
            mutations,
            Some(self.config.phases.mutate.entry_cov_timeout),
            false,
        )?;

        Ok(())
    }
}
