use std::collections::{HashMap, HashSet};

use fuzztruction_shared::{messages::TracePointStat, types::PatchPointID};
use serde::{Deserialize, Serialize};

#[allow(unused)]
const TRACE_EXEC_CNT_LIMIT: u64 = 16384;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Trace {
    /// Mapping of PatchPointID to hit cnt. PatchPointID not found in this
    /// map are considered uncovered (i.e., not executed).
    exec_cnt: HashMap<PatchPointID, u64>,
    exec_order: HashMap<PatchPointID, u64>,
}

impl Trace {
    pub fn from_trace_point_stats(msgs: &[&TracePointStat]) -> Trace {
        let mut exec_cnt = HashMap::new();
        let mut exec_order = HashMap::new();

        msgs.iter().for_each(|e| {
            if e.cnt > TRACE_EXEC_CNT_LIMIT {
                log::trace!("Skipping PatchPoint {:?} since it has a pretty high exec cnt: {:#?}", e.patch_point_id, e);
                return;
            }
            if e.execution_index.is_none() {
                log::trace!("Skipping PatchPoint {:?} since it was executed but does not have an exec idx: {:#?}", e.patch_point_id, e);
                return;
            }

            exec_cnt.insert(e.patch_point_id, e.cnt);
            exec_order.insert(e.patch_point_id, e.execution_index.unwrap().get());
        });

        Trace {
            exec_cnt,
            exec_order,
        }
    }

    pub fn is_covered(&self, pp: PatchPointID) -> bool {
        self.covered().contains(&pp)
    }

    pub fn exec_order(&self, pp: PatchPointID) -> Option<u64> {
        self.exec_order.get(&pp).cloned()
    }

    pub fn covered(&self) -> HashSet<PatchPointID> {
        self.exec_cnt.keys().copied().collect()
    }

    pub fn covered_exec_ordered(&self) -> Vec<PatchPointID> {
        let mut covered: Vec<_> = self.covered().into_iter().collect();
        covered.sort_by_key(|pp| self.exec_order(*pp));
        covered
    }

    pub fn hits_mapping(&self) -> &HashMap<PatchPointID, u64> {
        &self.exec_cnt
    }

    pub fn exec_order_mapping(&self) -> &HashMap<PatchPointID, u64> {
        &self.exec_order
    }

    pub fn len(&self) -> usize {
        self.exec_cnt.keys().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
