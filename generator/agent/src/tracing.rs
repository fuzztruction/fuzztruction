use std::num::NonZeroU64;
use std::slice;
use std::sync::atomic::Ordering;
use std::{collections::HashSet, mem::transmute};

use fuzztruction_shared::util::ExpectNone;
use libc::{self, c_void, MAP_ANONYMOUS, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use std::fmt::Debug;
use std::hash::Hash;

use crate::agent::IS_CHILD;

#[derive(Debug)]
pub struct TraceMap<'a, T> {
    /// A memory mapping that is shared with the traced process.
    data: Option<&'a mut [TraceEntry<T>]>,
    /// Length of `data`.
    len_bytes: Option<usize>,
    /// Set of all Ts for that a hit can be reported during runtime.
    allocated_slots: HashSet<T>,
    /// Total hits recorded so far.
    total_hits: u64,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct TraceEntry<T> {
    /// Some value that is used to map the `TraceEntry` back to another object
    /// after execution (e.g., the VMA).
    pub value: T,
    /// Number of times this entry was hit.
    pub hits: u64,
    /// A value that can be used to order `TraceEntry`s according to their
    /// time of discovery. Odering entries ascending according to their `order`
    /// id allows to determine whether a entry was covered before or after anotherone.
    pub order: Option<NonZeroU64>,
}

impl<T> TraceEntry<T> {
    pub fn new(value: T) -> TraceEntry<T> {
        TraceEntry {
            value,
            hits: 0,
            order: None,
        }
    }
}

impl<'a, T> TraceMap<'a, T>
where
    T: Eq + Hash + Ord + Clone + Debug,
{
    pub fn new() -> TraceMap<'a, T> {
        TraceMap {
            data: None,
            len_bytes: None,
            allocated_slots: HashSet::new(),
            total_hits: 0,
        }
    }

    /// Register a T for which we we want to report tracing events later via `report_hit`.
    pub fn alloc_slot(&mut self, id: T) {
        self.allocated_slots.insert(id);
    }

    /// Create the actual map that can be used to report hits. This function must be
    /// called before calling `report_hit`. After calling `finalize`, `reset` must be
    /// called before calling `finalize` again.
    pub fn finalize(&mut self) {
        if self.allocated_slots.is_empty() {
            return;
        }

        let mem;
        let len = self.allocated_slots.len() * std::mem::size_of::<TraceEntry<T>>();

        unsafe {
            mem = libc::mmap(
                0 as *mut c_void,
                len,
                PROT_WRITE | PROT_READ,
                MAP_SHARED | MAP_ANONYMOUS,
                0,
                0,
            );
            if mem == MAP_FAILED {
                log::error!("Failed to map memory");
                panic!("Failed to creating mapping");
            }
        }
        let mem = unsafe {
            slice::from_raw_parts_mut(mem as *mut TraceEntry<T>, self.allocated_slots.len())
        };

        let mut sorted_ids: Vec<_> = self.allocated_slots.clone().into_iter().collect();
        sorted_ids.sort();

        let wrapped_ids: Vec<_> = sorted_ids
            .iter()
            .map(|e| TraceEntry::new(e.clone()))
            .collect();

        let mut mem_iter = mem.iter_mut();
        for slot in wrapped_ids.into_iter() {
            let _ = std::mem::replace(mem_iter.next().unwrap(), slot);
        }

        self.allocated_slots.clear();
        self.allocated_slots.shrink_to(0);
        self.data
            .replace(mem)
            .expect_none("finalize() was called again before calling reset()");
        self.len_bytes = Some(len);
    }

    /// Get a reference to the map that contains the recorded hits.
    pub fn hit_map(&self) -> Option<&[TraceEntry<T>]> {
        self.data.as_deref()
    }

    /// Increment the count for `id` by one. Id must have been registered with alloc_slot().
    /// If not, this function panics.
    pub fn report_hit(&mut self, id: T) {
        if !IS_CHILD.load(Ordering::Relaxed) {
            return;
        }

        let data = self
            .data
            .as_mut()
            .expect("Calling report_hit without finalizing is not allowed.");
        let idx = data.binary_search_by(|e| e.value.cmp(&id));
        let idx = idx.expect("Trying to report hit for unallocated element");

        self.total_hits += 1;
        let entry = &mut data[idx];
        if entry.order.is_none() {
            entry.order = NonZeroU64::new(self.total_hits);
        }
        data[idx].hits += 1;
    }

    /// Reset that map and all state.
    pub fn reset(&mut self) {
        if self.data.is_some() {
            unsafe {
                let ret = libc::munmap(
                    self.data.as_mut().unwrap().as_ptr() as *mut c_void,
                    self.len_bytes.unwrap(),
                );
                if ret != 0 {
                    panic!("Failed to munmap memory mapping");
                }
            }
        }
        self.total_hits = 0;
        self.data = None;
        self.len_bytes = None;
        self.allocated_slots.clear();
        // Make sure we are not forking pages that we do not need!
        self.allocated_slots.shrink_to(0);
    }

    /// Reset the hit counters.
    pub fn reset_hits(&mut self) {
        self.data.as_mut().map(|map| {
            map.iter_mut().for_each(|entry| {
                entry.hits = 0;
                entry.order = None;
            })
        });
    }
}

impl<'a, T> Drop for TraceMap<'a, T> {
    fn drop(&mut self) {
        eprintln!("Dropping TraceMap");
        if self.data.is_some() {
            unsafe {
                let ret = libc::munmap(
                    transmute(self.data.as_ref().unwrap()),
                    self.len_bytes.unwrap(),
                );
                if ret != 0 {
                    panic!("Failed to munmap memory mapping");
                }
            }
        }
    }
}
