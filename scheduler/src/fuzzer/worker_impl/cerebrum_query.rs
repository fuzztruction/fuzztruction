#![allow(unused)]

use super::cerebrum::Cerebrum;
use crate::{fuzzer::queue::QueueEntry, patchpoint::PatchPoint, trace::Trace};
use fuzztruction_shared::{
    mutation_cache::MutationCache, mutation_cache_entry::MutationCacheEntry, types::PatchPointID,
};
use std::{
    collections::{HashMap, HashSet},
    ops::RangeBounds,
    sync::Arc,
};

pub struct CerebrumQuery<'a> {
    cerebrum: &'a Cerebrum,
}

impl CerebrumQuery<'_> {
    pub fn new(cerebrum: &Cerebrum) -> CerebrumQuery {
        CerebrumQuery { cerebrum }
    }

    /// Get all [PatchPointID]s that have not been reported as fuzzed yet.
    pub fn patch_points_unfuzzed(&self) -> HashSet<PatchPointID> {
        let pp = &self.cerebrum.patch_points;
        pp.iter()
            .filter(|e| {
                let stats = self.cerebrum.pp_stats(e.id());
                stats.mutation_cnt == 0
            })
            .map(|e| e.id())
            .collect()
    }

    pub fn patch_points_yielded(&self) -> HashSet<PatchPointID> {
        let pp = &self.cerebrum.patch_points;
        pp.iter()
            .filter(|e| {
                let stats = self.cerebrum.pp_stats(e.id());
                stats.yield_cnt > 0
            })
            .map(|e| e.id())
            .collect()
    }

    pub fn patch_point_yield_prop(&self) -> HashMap<PatchPointID, f64> {
        todo!();
    }

    pub fn patch_point_to_sink_edge(&self) -> HashMap<PatchPointID, u64> {
        todo!();
    }

    pub fn patch_point_yielding_msks(
        &self,
        entry: &QueueEntry,
        id: PatchPointID,
    ) -> Vec<Arc<[u8]>> {
        let mut entry_rw_guard = entry.stats_rw();
        let already_tried = entry_rw_guard.combined_with_mut();

        let mut res = Vec::new();
        if let Some(msks) = self.cerebrum.patch_point_msks.get(&id) {
            for (qid, msk) in msks {
                if already_tried.insert(qid) {
                    res.push(Arc::clone(msk));
                }
            }
        }
        res
    }

    // pub fn patch_point_yielding_msks(&self, entry: &QueueEntry, id: PatchPointID) -> Vec<Vec<u8>> {
    //     // FIXME: Keep msks in a buffer und hand out Arcs
    //     let stats = self.cerebrum.pp_stats(id);
    //     let qe_entry_ids = &stats.used_by;
    //     let queue_locked = self.cerebrum.queue.lock().unwrap();
    //     let entries = qe_entry_ids.iter().map(move |id| queue_locked.get_id(*id));
    //     let mut res = Vec::new();

    //     let mut entry_rw_guard = entry.stats_rw();
    //     let already_tried = entry_rw_guard.combined_with_mut();

    //     for entry in entries {
    //         if already_tried.contains(entry.id()) {
    //             continue;
    //         }
    //         already_tried.insert(entry.id());

    //         if let Some(mutations) = entry.mutations() {
    //             let mc = MutationCache::load_bytes(mutations).unwrap();
    //             let mc_entries = mc.entries();
    //             let target_mc_entry = mc_entries
    //                 .iter()
    //                 .find(|mc_entry| mc_entry.id() == id)
    //                 .unwrap();
    //             res.push(target_mc_entry.get_msk_as_slice().to_vec());
    //         }
    //     }
    //     res
    // }

    pub fn patch_points_in_same_function(&self, id: PatchPointID) -> HashSet<PatchPointID> {
        let pp = self.cerebrum.resolve_pp_id(id);
        self.cerebrum
            .patch_points
            .iter()
            .filter(|other| other.function_address() == pp.function_address())
            .map(|pp| pp.id())
            .collect()
    }

    pub fn trace_get_functions_ordered(&self, trace: &Trace) -> Vec<u64> {
        let mut result = Vec::new();
        trace.covered_exec_ordered().into_iter().for_each(|pp_id| {
            let pp = self.cerebrum.resolve_pp_id(pp_id);
            if !result.contains(&pp.function_address()) {
                result.push(pp.function_address());
            }
        });

        result
    }

    pub fn patch_point_ids_to_patch_point(&self, ids: &[PatchPointID]) -> Vec<Arc<PatchPoint>> {
        ids.iter()
            .map(|pp_id| self.cerebrum.resolve_pp_id(*pp_id))
            .collect()
    }
}
