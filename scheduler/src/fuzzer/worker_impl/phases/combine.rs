use std::collections::HashMap;

use crate::{
    fuzzer::{worker::FuzzingWorker, worker_impl::mutators},
    mutation_cache_ops::MutationCacheOpsEx,
};

use anyhow::Result;
use fuzztruction_shared::{
    mutation_cache::MutationCache, mutation_cache_entry::MutationCacheEntry,
};
use rand::{prelude::SliceRandom, thread_rng};

use super::FuzzingPhase;

const PHASE: FuzzingPhase = FuzzingPhase::Combine;

impl FuzzingWorker {
    pub fn do_combine_phase(&mut self) -> Result<()> {
        self.state.set_phase(PHASE);

        let qe = self.state.entry();
        self.load_queue_entry_mutations(&qe)?;
        let source = self.source.as_mut().unwrap();

        // MutationCache of the currently loaded QueueEntry.
        let entry_mc = source.mutation_cache();
        let entry_mc_borrow = entry_mc.borrow();
        log::info!("QueueEntry has {} MCE's", entry_mc_borrow.len());

        let all_patch_points = source.get_patchpoints()?;
        let entry_trace = qe.stats_ro().trace().unwrap();

        let mut tmp_mc = MutationCache::from_patchpoints(all_patch_points.iter())?;
        tmp_mc.union_and_replace(&entry_mc_borrow);
        drop(entry_mc_borrow);

        unsafe {
            tmp_mc.remove_uncovered(&entry_trace);
            tmp_mc.resize_covered_entries(&entry_trace);
        }
        let mut candidates = tmp_mc.entries();

        let cerebrum_ro_guard = self.cerebrum.read().unwrap();
        let cerebrum_ro = cerebrum_ro_guard.as_ref().unwrap();
        let cerebrum_query = cerebrum_ro.query();

        // Get all yielding msks for all MCEs.
        let mut mce_to_msks = HashMap::new();
        for entry in candidates.iter() {
            let yielding_msks = cerebrum_query.patch_point_yielding_msks(&qe, entry.id());
            if !yielding_msks.is_empty() {
                mce_to_msks.insert(entry.id(), yielding_msks);
            }
        }
        drop(cerebrum_ro_guard);

        // Keep MCEs if we have a msk to try or if they have a non zero msk.
        candidates.retain(|entry| !entry.is_nop() || mce_to_msks.contains_key(&entry.id()));

        // Create MC that only contains those MCEs for that we have msks to try.
        let new_mc = MutationCache::from_iter(candidates.into_iter())?;
        source.mutation_cache_replace(&new_mc)?;
        let mut entries = source.mutation_cache().borrow_mut().entries_mut_static();
        entries.shuffle(&mut thread_rng());

        let mut mutations = Vec::<(
            &mut MutationCacheEntry,
            Vec<Box<dyn mutators::Mutator<Item = ()>>>,
        )>::new();

        for entry in entries {
            let msks = if let Some(msks) = mce_to_msks.remove(&entry.id()) {
                msks
            } else {
                // Entries for that `entry.is_nop()` is true, do not necessarily have msks candidates.
                continue;
            };

            if entry.is_nop() {
                entry.disable();
            }

            let mut mutators = Vec::new();

            let mutator =
                mutators::CombineMutator::new(entry.get_msk_as_slice(), msks, entry.is_nop());
            mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);

            let entry = (unsafe { entry.alias_mut() }, mutators);
            mutations.push(entry);
        }

        // source.mutation_cache_replace(&new_mc)?;
        // let mut entries = source.mutation_cache().borrow_mut().entries_mut_static();
        // entries.shuffle(&mut thread_rng());

        self.fuzz_candidates(
            mutations,
            Some(self.config.phases.combine.entry_cov_timeout),
            false,
        )?;

        Ok(())
    }
}
