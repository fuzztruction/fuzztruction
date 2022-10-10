use std::{cmp::min, mem, ptr};

use log::warn;

use crate::{mutation_cache_entry::MutationCacheEntry, types::PatchPointID};

const MAX_MUTATION_CACHE_ENTRIES: usize = 200000;
const PENDING_DELETIONS_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy)]
struct EntryDescriptor {
    start_offset: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct MutationCacheContent {
    /// Size of the memory region backing this instance (i.e., the memory &self points to).
    total_size: usize,
    /// The current size of payload data buffer starting at `data`.
    current_data_size: usize,
    /// The index of the next slot in entry_decriptor_tbl that is free.
    next_free_slot: usize,
    ///
    pending_deletions: usize,
    /// Descriptors describing the start and length of all `MutationCacheEntries`
    /// currently in the cache.
    entry_decriptor_tbl: [Option<EntryDescriptor>; MAX_MUTATION_CACHE_ENTRIES],
    /// A dynamically growing buffer that contains all MutationCacheEntries.
    data: [MutationCacheEntry; 0],
}

impl MutationCacheContent {
    fn data(&self) -> &MutationCacheEntry {
        let addr = &self.data as *const MutationCacheEntry as u64;
        unsafe {
            let addr = addr as *const MutationCacheEntry;
            &*addr
        }
    }

    fn data_ptr<T>(&self) -> *const T {
        self.data().as_ptr() as *const T
    }

    unsafe fn entry_ptr(&self, offset: isize) -> *const MutationCacheEntry {
        let addr = self.data_ptr::<u8>();
        let addr = addr.offset(offset);
        addr as *const MutationCacheEntry
    }

    unsafe fn entry_ref(&self, offset: isize) -> &MutationCacheEntry {
        let addr = self.data_ptr::<u8>();
        let addr = addr.offset(offset);
        &*(addr as *const MutationCacheEntry)
    }

    /// Initialize the content.
    /// NOTE: This function must be called before any other!
    pub fn init(&mut self, size: usize) {
        assert!(
            size >= mem::size_of_val(self),
            "The backing memory must be at least {} bytes large.",
            mem::size_of_val(self)
        );

        self.current_data_size = 0;
        self.total_size = size;
        self.next_free_slot = 0;
        self.entry_decriptor_tbl.fill(None);
    }

    /// Must be called if the cache content was serialized and then
    /// deserialized in a backing memory region with different dimensions.
    pub fn update(&mut self, size: usize) {
        self.total_size = size;
    }

    pub fn space_left(&self) -> usize {
        self.total_size - mem::size_of_val(self) - self.current_data_size
    }

    /// Number of total bytes used by metadata and payload (i.e., mutations).
    /// For making a copy of the current state, it is sufficient to copy
    /// `total_used_bytes()` starting at &self.
    pub fn total_used_bytes(&self) -> usize {
        mem::size_of_val(self) + self.current_data_size
    }

    pub fn clear(&mut self) {
        self.current_data_size = 0;
        self.next_free_slot = 0;
        self.entry_decriptor_tbl.fill(None);
    }

    /// NOTE: The returned referencers are only valid as long as no entries are added
    /// or removed.
    fn entries_raw(&self) -> Vec<*const MutationCacheEntry> {
        let mut ret = Vec::new();
        self.entry_decriptor_tbl
            .iter()
            .filter(|e| e.is_some())
            .map(|e| e.as_ref().unwrap())
            .for_each(|e| {
                let mut addr = self.data().as_ptr() as *const u8;
                unsafe {
                    addr = addr.offset(e.start_offset as isize);
                    ret.push(addr as *const MutationCacheEntry);
                };
            });
        ret
    }

    /// NOTE: The returned referencers are only valid as long as no entries are added
    /// or removed.
    pub fn entries(&self) -> Vec<&MutationCacheEntry> {
        self.entries_raw()
            .into_iter()
            .map(|e| unsafe { &*e })
            .collect()
    }

    /// NOTE: The returned referencers are only valid as long as no entries are added
    /// or removed.
    pub fn entries_mut(&mut self) -> Vec<&mut MutationCacheEntry> {
        self.entries_raw()
            .into_iter()
            .map(|e| unsafe { &mut *(e as *mut MutationCacheEntry) })
            .collect()
    }

    pub fn push(&mut self, entry: &MutationCacheEntry) -> Option<&MutationCacheEntry> {
        assert!(self.next_free_slot < self.entry_decriptor_tbl.len());

        if entry.size() > self.space_left() {
            return None;
        }

        let descriptor = Some(EntryDescriptor {
            start_offset: self.current_data_size,
        });

        let max_slot_idx = self.entry_decriptor_tbl.len() - 1;
        if let ref mut slot @ None = self.entry_decriptor_tbl[self.next_free_slot] {
            *slot = descriptor;
            self.next_free_slot = min(self.next_free_slot + 1, max_slot_idx);
        } else {
            return None;
        }

        if let Some(d) = descriptor {
            let dst_addr = unsafe { self.entry_ptr(d.start_offset as isize) };
            let dst_addr = dst_addr as *mut u8;

            unsafe {
                ptr::copy_nonoverlapping(entry.as_ptr() as *const u8, dst_addr, entry.size());
            }

            self.current_data_size += entry.size();
            unsafe {
                return Some(&*(dst_addr as *const MutationCacheEntry));
            };
        } else {
            warn!("Not enough descriptor entries available");
            return None;
        }
    }

    pub fn consolidate(&mut self) {
        // Copy all entries currently contained in the cache.
        let entries = self
            .entries()
            .iter()
            .map(|e| e.clone_into_box())
            .collect::<Vec<_>>();
        // Purge cache data.
        self.clear();
        // Readd all entries (that are now stored in a continues memory region again)
        entries.iter().for_each(|e| {
            self.push(e);
        });
    }

    pub fn remove(&mut self, id: PatchPointID) {
        let mut descriptor = None;
        for (idx, d) in self.entry_decriptor_tbl.iter().enumerate() {
            if let Some(des @ EntryDescriptor { start_offset, .. }) = d {
                let entry = unsafe { self.entry_ref(*start_offset as isize) };
                if entry.id() == id {
                    descriptor = Some((idx, des.clone()));
                    break;
                }
            }
        }

        if let Some(d) = descriptor {
            // Remove entry that belong to the just deleted element.
            self.entry_decriptor_tbl[d.0] = None;
            self.pending_deletions += 1;

            if self.pending_deletions > PENDING_DELETIONS_LIMIT {
                self.pending_deletions = 0;
                self.consolidate();
            }
            return;
        }

        unreachable!("Trying to delete entry {:?} that does not exists!", id);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util;
    use std::assert_matches::assert_matches;

    fn dummy_entry(id: u64) -> Box<MutationCacheEntry> {
        MutationCacheEntry::new(
            id.into(),
            0,
            0,
            llvm_stackmap::LocationType::Constant,
            8,
            crate::dwarf::DwarfReg::Rax,
            0,
            0,
        )
    }

    #[test]
    fn test_push_remove() {
        let size = 1024 * 1024 * 16;
        let mut content: Box<MutationCacheContent> = util::alloc_box_aligned_zeroed(size);
        content.init(size);

        let init_space_left = content.space_left();

        // Test if empty
        let ret = content.entries();
        assert_eq!(ret.len(), 0);

        // Test push e0
        let e0 = dummy_entry(0);
        let _ret = content.push(&e0).unwrap();
        assert_eq!(content.entries().len(), 1);

        // Test push e1
        let e1 = dummy_entry(1);
        let _ret = content.push(&e1).unwrap();
        assert_eq!(content.entries().len(), 2);

        content.remove(e0.id());
        assert_eq!(content.entries().len(), 1);

        content.remove(e1.id());
        assert_eq!(content.entries().len(), 0);
        content.consolidate();
        assert_eq!(content.space_left(), init_space_left);
    }

    #[test]
    fn test_max_entries() {
        let size = 1024 * 1024 * 1024;
        let mut content: Box<MutationCacheContent> = util::alloc_box_aligned_zeroed(size);
        content.init(size);

        for i in 0..MAX_MUTATION_CACHE_ENTRIES {
            assert_ne!(i as u64, u64::MAX);
            let e = dummy_entry(i as u64);
            assert_matches!(content.push(&e), Some(..));
        }

        let e = dummy_entry(u64::MAX);
        assert_matches!(content.push(&e), None);
    }
}
