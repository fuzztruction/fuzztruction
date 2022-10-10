use anyhow::Result;

use fuzztruction_shared::{
    mutation_cache::MutationCache, mutation_cache_entry::MutationCacheEntry,
};

use crate::{patchpoint::PatchPoint, trace::Trace};

pub trait MutationCacheOpsEx {
    /// Construct a `MutationCache` from `PatchPoint`s.
    #[allow(single_use_lifetimes)]
    fn from_patchpoints<'a, I>(patch_points: I) -> Result<MutationCache>
    where
        I: Iterator<Item = &'a PatchPoint>;
    /// Remove `MutationCacheEntry`s that are not covered by `trace`.
    ///
    /// # Safety
    /// This function is only safe if no references into the [MutationCache]
    /// cross this function call.
    unsafe fn remove_uncovered(&mut self, trace: &Trace) -> &mut Self;

    /// Resize `MutationCacheEntry`s according to the hit count in `trace`.
    ///
    /// # Safety
    /// This function is only safe if no references into the [MutationCache]
    /// cross this function call.
    unsafe fn resize_covered_entries(&mut self, trace: &Trace) -> &mut Self;

    /// Only resize those `MutationCacheEntry`s according to the hit count
    /// of `trace` that do not already have a mask.
    ///
    /// # Safety
    /// This function is only safe if no references into the [MutationCache]
    /// cross this function call.
    unsafe fn resize_covered_entries_wo_msk(&mut self, trace: &Trace) -> &mut Self;
}

impl MutationCacheOpsEx for MutationCache {
    #[allow(single_use_lifetimes)]
    fn from_patchpoints<'a, I>(patch_points: I) -> Result<MutationCache>
    where
        I: Iterator<Item = &'a PatchPoint>,
    {
        let mut ret = MutationCache::new()?;
        for p in patch_points {
            let e: Box<MutationCacheEntry> = p.into_mutation_cache_entry();
            ret.push(&e).unwrap();
        }

        Ok(ret)
    }

    unsafe fn remove_uncovered(&mut self, trace: &Trace) -> &mut Self {
        let covered_ids = trace.covered();
        self.retain(|e| covered_ids.contains(&e.id()));
        self
    }

    unsafe fn resize_covered_entries(&mut self, trace: &Trace) -> &mut Self {
        let map = trace.hits_mapping();

        let mut resized_entries = Vec::new();
        for entry in self.iter_mut() {
            if let Some(v) = map.get(&entry.id()) {
                let e = entry.clone_with_new_msk((*v) as u32 * u32::from(entry.loc_size()));
                resized_entries.push(e);
            }
        }

        for e in resized_entries.iter() {
            self.remove(e.id());
        }

        for e in resized_entries.iter() {
            self.push(e);
        }

        self
    }

    unsafe fn resize_covered_entries_wo_msk(&mut self, trace: &Trace) -> &mut Self {
        let map = trace.hits_mapping();

        let mut resized_entries = Vec::new();
        for entry in self.iter_mut() {
            if let Some(v) = map.get(&entry.id()) {
                let e = entry.clone_with_new_msk((*v) as u32 * u32::from(entry.loc_size()));
                resized_entries.push(e);
            }
        }

        for e in resized_entries.iter() {
            self.remove(e.id());
        }

        for e in resized_entries.iter() {
            self.push(e);
        }

        self
    }
}
