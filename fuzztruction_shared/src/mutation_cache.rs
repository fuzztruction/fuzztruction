use std::{assert_matches::assert_matches, collections::HashSet, env, ffi::CString, mem, slice};

use anyhow::{Context, Result};
use llvm_stackmap::LocationType;
use log::*;

use byte_unit::n_mib_bytes;
use shared_memory::ShmemError;
use std::alloc;
use thiserror::Error;

use crate::{
    constants::ENV_SHM_NAME, mutation_cache_content::MutationCacheContent,
    mutation_cache_entry::MutationCacheEntry, types::PatchPointID, util,
};

pub const MUTATION_CACHE_DEFAULT_SIZE: usize = n_mib_bytes!(64) as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MutationCacheEntryFlags {
    None = 0,
    /// Count the number of executions of this patch point and report it
    /// to the coordinator on termination.
    TracingEnabled = 1 << 0,
    Disable = 1 << 1,
}

#[derive(Error, Debug)]
pub enum MutationCacheError {
    #[error("Shared memory error: {0}")]
    ShareMemoryError(#[from] ShmemError),
    #[error("The cache can not hold anymore elements.")]
    CacheOverflow,
    #[error("Unable to find shm with the given name: {0}")]
    ShmNotFound(String),
    #[error("Shared memory error: {0}")]
    ShmError(String),
    #[error("Unkown error occurred: {0}")]
    Other(String),
}

mod backing_memory {
    use std::ffi::CString;

    use crate::mutation_cache_content::MutationCacheContent;

    #[derive(Debug)]
    pub struct ShmMemory {
        pub name: String,
        pub shm_fd: i32,
        pub shm_path: CString,
        pub size: usize,
    }

    #[derive(Debug)]
    pub struct HeapMemory {
        pub memory: Box<MutationCacheContent>,
        pub size: usize,
    }

    #[derive(Debug)]
    pub enum Memory {
        ShmMemory(ShmMemory),
        HeapMemory(HeapMemory),
    }

    impl Memory {
        pub fn shm_memory(&self) -> Option<&ShmMemory> {
            if let Memory::ShmMemory(shm) = self {
                Some(shm)
            } else {
                None
            }
        }

        #[allow(unused)]
        pub fn heap_memory(&self) -> Option<&HeapMemory> {
            if let Memory::HeapMemory(heap) = self {
                Some(heap)
            } else {
                None
            }
        }
    }

    impl Drop for Memory {
        fn drop(&mut self) {
            if let Some(s) = self.shm_memory() {
                unsafe {
                    libc::shm_unlink(s.shm_path.as_ptr());
                }
            }
        }
    }
}

#[derive(Debug)]
struct MutationCacheContentRawPtr(*mut MutationCacheContent);

unsafe impl Send for MutationCacheContentRawPtr {}

#[derive(Debug)]
pub struct MutationCache {
    backing_memory: backing_memory::Memory,
    content_size: usize,
    content: MutationCacheContentRawPtr,
}

/// Getter and setter implementation.
impl MutationCache {
    /// Get the name of the backing shared memory if it is allocated
    /// in a shm.
    pub fn shm_name(&self) -> Option<String> {
        self.backing_memory.shm_memory().map(|e| e.name.clone())
    }

    /// Get the size in bytes.
    pub fn total_size(&self) -> usize {
        self.content_size
    }

    pub fn bytes_used(&self) -> usize {
        self.content().total_used_bytes()
    }

    fn content(&self) -> &MutationCacheContent {
        unsafe { &*self.content.0 }
    }

    fn content_mut(&mut self) -> &mut MutationCacheContent {
        unsafe { &mut *(self.content.0 as *mut MutationCacheContent) }
    }

    fn content_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.content.0 as *const u8, self.content_size) }
    }

    fn content_slice_mut(&self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.content.0 as *mut u8, self.content_size) }
    }

    /// Get a vector of references to all entries contained in the cache.
    /// NOTE: The returned referencers are only valid as long as no entries are added
    /// or removed.
    pub fn entries(&self) -> Vec<&MutationCacheEntry> {
        self.content().entries()
    }

    /// Get a vector of mutable references to all entries contained in the cache.
    /// NOTE: The returned referencers are only valid as long as no entries are added
    /// or removed.
    pub fn entries_mut(&mut self) -> Vec<&mut MutationCacheEntry> {
        self.content_mut().entries_mut()
    }

    pub fn entries_mut_static(&mut self) -> Vec<&'static mut MutationCacheEntry> {
        self.content_mut()
            .entries_mut()
            .into_iter()
            .map(|e| unsafe { mem::transmute(e) })
            .collect()
    }

    pub fn entries_mut_ptr(&mut self) -> Vec<*mut MutationCacheEntry> {
        self.entries_mut()
            .into_iter()
            .map(|e| e.as_mut_ptr())
            .collect()
    }
}

/// Implementations realted to creation and lifecycle management of a MutationCache.
impl MutationCache {
    fn shm_open(name: &str, create: bool) -> Result<MutationCache, MutationCacheError> {
        let mut size = MUTATION_CACHE_DEFAULT_SIZE;

        assert!(!create || size >= mem::size_of::<MutationCacheContent>());
        let name_c = CString::new(name).unwrap();
        let fd;

        trace!(
            "shm_open(name={name}, name_c={name_c:#?}, create={create}, size={size:x} ({size_kb}))",
            name = name,
            name_c = name_c,
            create = create,
            size = size,
            size_kb = size / 1024
        );

        unsafe {
            let mut flags = libc::O_RDWR;
            if create {
                flags |= libc::O_CREAT | libc::O_EXCL;
            }

            fd = libc::shm_open(name_c.as_ptr(), flags, 0o777);
            trace!("shm fd={}", fd);
            if fd < 0 {
                let err = format!("Failed to open shm {}", name);
                error!("{}", err);
                return Err(MutationCacheError::ShmError(err));
            }

            if create {
                trace!("Truncating fd {fd} to {bytes} bytes", fd = fd, bytes = size);
                let ret = libc::ftruncate(fd, size as i64);
                if ret != 0 {
                    return Err(MutationCacheError::ShmError(
                        "Failed to ftruncate shm".to_owned(),
                    ));
                }
            } else {
                let mut stat_buffer: libc::stat = std::mem::zeroed();
                let ret = libc::fstat(fd, &mut stat_buffer);
                if ret != 0 {
                    return Err(MutationCacheError::ShmError(
                        "Failed to get shm size".to_owned(),
                    ));
                }
                size = stat_buffer.st_size as usize;
            }

            let mapping = libc::mmap(
                0 as *mut libc::c_void,
                size,
                libc::PROT_WRITE | libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );

            if mapping == libc::MAP_FAILED {
                return Err(MutationCacheError::ShmError(
                    "Failed to map shm into addresspace".to_owned(),
                ));
            }

            // Check alignment. Implment logging and sanitize messages
            let l = alloc::Layout::new::<MutationCacheContent>();
            assert!(mapping as usize % l.align() == 0);

            let ptr = mapping as *mut u8 as *mut MutationCacheContent;
            let mutation_cache_content: &mut MutationCacheContent = ptr.as_mut().unwrap();
            if create {
                mutation_cache_content.init(size);
            }

            return Ok(MutationCache {
                backing_memory: backing_memory::Memory::ShmMemory(backing_memory::ShmMemory {
                    shm_fd: fd,
                    shm_path: name_c,
                    name: name.to_owned(),
                    size,
                }),
                content_size: size,
                content: MutationCacheContentRawPtr(mutation_cache_content),
            });
        };
    }

    pub fn new_shm(name: impl AsRef<str>) -> Result<MutationCache> {
        let mc = MutationCache::shm_open(name.as_ref(), true)?;
        Ok(mc)
    }

    pub fn open_shm(name: impl AsRef<str>) -> Result<MutationCache> {
        let mc = MutationCache::shm_open(name.as_ref(), false)?;
        Ok(mc)
    }

    pub fn open_shm_from_env() -> Result<MutationCache> {
        let send_name = env::var(ENV_SHM_NAME);
        match send_name {
            Err(_) => Err(MutationCacheError::ShmNotFound(format!(
                "Failed to find environment variable {}",
                ENV_SHM_NAME
            )))?,
            Ok(name) => MutationCache::open_shm(&name),
        }
    }

    pub fn unlink(&mut self) {
        if let Some(name) = self.shm_name() {
            let name = CString::new(name).unwrap();
            unsafe {
                libc::shm_unlink(name.as_ptr());
            }
        }
    }

    pub fn new() -> Result<MutationCache> {
        let size = MUTATION_CACHE_DEFAULT_SIZE;

        assert!(size > std::mem::size_of::<MutationCacheContent>());
        let mut memory = util::alloc_box_aligned_zeroed::<MutationCacheContent>(size);

        let mutation_cache_content =
            unsafe { &mut *(memory.as_mut() as *mut MutationCacheContent) };
        mutation_cache_content.init(size);

        return Ok(MutationCache {
            backing_memory: backing_memory::Memory::HeapMemory(backing_memory::HeapMemory {
                memory,
                size,
            }),
            content_size: size,
            content: MutationCacheContentRawPtr(mutation_cache_content),
        });
    }

    /// Make the cache content non shared if it is backed by an shm.
    /// It is not allowed to call this function on caches using any other
    /// backing storage than shm.
    pub fn make_private(&self) -> Result<()> {
        use backing_memory::*;
        assert_matches!(self.backing_memory, Memory::ShmMemory(..));

        let mem_shm_fd;
        if let Memory::ShmMemory(shm) = &self.backing_memory {
            mem_shm_fd = shm.shm_fd;
        } else {
            unreachable!();
        }

        unsafe {
            let ret = libc::mmap(
                self.content.0 as *mut libc::c_void,
                self.content_size,
                libc::PROT_WRITE | libc::PROT_READ,
                libc::MAP_FIXED | libc::MAP_PRIVATE,
                mem_shm_fd,
                0,
            );
            if ret != self.content.0 as *mut libc::c_void {
                return Err(MutationCacheError::Other(format!(
                    "Remapping shm failed (ret={:#?})",
                    ret
                )))?;
            }
        }

        // Make sure that the client does not mess with the shm fd.
        let ret = unsafe { libc::close(mem_shm_fd) };
        if ret != 0 {
            return Err(MutationCacheError::Other(
                "Failed to close shm fd".to_owned(),
            ))?;
        }

        Ok(())
    }

    pub fn try_clone(&self) -> Result<MutationCache> {
        let mut ret = MutationCache::new()?;
        let data = self.content_slice();
        ret.load_bytes(data)?;
        Ok(ret)
    }
}

/// Methods that are working on the actual cache content.
impl MutationCache {
    pub fn push(&mut self, entry: &MutationCacheEntry) -> Option<&MutationCacheEntry> {
        self.content_mut().push(entry)
    }

    /// Remove the [MutationCacheEntry] with the given `di` .
    /// !!! This will invalidate all references to the cached entries !!!
    pub fn remove(&mut self, id: PatchPointID) {
        self.content_mut().remove(id)
    }

    /// Clears the content of the cache.
    pub fn clear(&mut self) {
        self.content_mut().clear();
    }

    /// Get the number of `MutationCacheEntry` elements in this set.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn load_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        assert!(bytes.len() <= self.content_size);

        self.content_slice_mut()[..bytes.len()].copy_from_slice(bytes);
        unsafe {
            // Update the size since we might loaded the content from a differently
            // sized cache.
            (&mut *(self.content.0 as *mut MutationCacheContent)).update(self.content_size);
        }
        Ok(())
    }

    pub fn save_bytes(&mut self) -> Vec<u8> {
        // Remove whiteouts to reduce size
        self.content_mut().consolidate();
        let content_meta = self.content();
        // Only copy bytes that actually contain information.
        self.content_slice()[0..content_meta.total_used_bytes()].to_vec()
    }

    pub fn from_iter<'a>(
        iter: impl Iterator<Item = &'a MutationCacheEntry>,
    ) -> Result<MutationCache> {
        let mut ret = Self::new()?;

        for elem in iter {
            ret.push(elem);
        }

        Ok(ret)
    }

    pub fn replace(&mut self, other: &MutationCache) -> Result<()> {
        if self.content_size < other.content_size {
            Err(MutationCacheError::CacheOverflow)
                .context("Can not replace cache content with content from a larger cache.")?
        }

        // Copy the other content into our content buffer. We checked that
        // the other content is <= our content, thus this is safe.
        let dst = self.content_slice_mut();
        let src = other.content_slice();
        dst[..src.len()].copy_from_slice(src);

        // The copied content might stream from a cache that was smaller than us,
        // hence we need to inform the MutationCacheContent that its backing memory
        // size might have changed.
        let content_size = self.content_size;
        self.content_mut().update(content_size);

        Ok(())
    }

    /// Removes all elements from the cache that are not listed in the passed
    /// whitelist.
    fn retain_whitelisted(&mut self, whitelist: &[PatchPointID]) {
        let remove = self
            .entries()
            .iter()
            .filter(|e| !whitelist.contains(&e.id()))
            .map(|e| e.id())
            .collect::<Vec<_>>();
        remove.iter().for_each(|e| self.content_mut().remove(*e));
    }

    /// Only retain elements for which `f` returns true.
    /// !!! This will invalidate all references to the contained entries !!!
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&MutationCacheEntry) -> bool,
    {
        let mut entries = self.entries();
        entries.retain(|e| f(*e));
        let wl = entries.iter().map(|e| e.id()).collect::<Vec<_>>();
        self.retain_whitelisted(&wl[..]);
        debug_assert_eq!(self.len(), wl.len());
    }

    /// Only retain MutationCacheEntry's that actually affect the execution.
    /// !!! This will invalidate all references to the contained entries !!!
    pub fn purge_nop_entries(&mut self) {
        let mut entries = self.entries();
        entries.retain(|e| e.msk_len() > 0 && e.get_msk_as_slice().iter().any(|e| *e != 0));
        let wl = entries.iter().map(|e| e.id()).collect::<Vec<_>>();
        self.retain_whitelisted(&wl[..]);
        debug_assert_eq!(self.len(), wl.len());
    }

    pub fn iter(&self) -> impl Iterator<Item = &MutationCacheEntry> {
        self.entries().into_iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut MutationCacheEntry> {
        self.entries_mut().into_iter()
    }

    pub fn union_and_replace(&mut self, other: &MutationCache) {
        let other_ids = other.iter().map(|e| e.id()).collect::<HashSet<_>>();
        // Remove entries from self that are also in other.
        self.retain(|e| !other_ids.contains(&e.id()));
        other.iter().for_each(|e| {
            self.push(e);
        })
    }

    /// Set the flags of all mutation cache entries to zero.
    pub fn reset_flags(&mut self) -> &mut Self {
        self.iter_mut().for_each(|e| {
            e.reset_flags();
        });
        self
    }

    /// Set the passed MutationCacheEntryFlags on all mutation cache entries.
    pub fn set_flag(&mut self, flag: MutationCacheEntryFlags) -> &mut Self {
        self.iter_mut().for_each(|e| {
            e.set_flag(flag);
        });
        self
    }

    /// Clear the MutationCacheEntryFlags from all mutation cache entries.
    pub fn unset_flag(&mut self, flag: MutationCacheEntryFlags) -> &mut Self {
        self.iter_mut().for_each(|e| {
            e.unset_flag(flag);
        });
        self
    }

    /// Enable tracing for all mutation entries in this set.
    pub fn enable_tracing(&mut self) -> &mut Self {
        self.set_flag(MutationCacheEntryFlags::TracingEnabled)
    }

    /// Disable tracing for all mutation entries in this set.
    pub fn disable_tracing(&mut self) -> &mut Self {
        self.unset_flag(MutationCacheEntryFlags::TracingEnabled)
    }

    /// Remove all mutation entries that have the passed LocationType.
    pub fn remove_by_location_type(&mut self, loc_type: LocationType) -> &mut Self {
        self.retain(|e| e.loc_type() != loc_type);
        self
    }

    /// Purge all expect `max` elements from the cache.
    pub fn limit(&mut self, max: usize) -> &mut Self {
        let mut limit = max;
        self.retain(|_e| {
            if limit > 0 {
                limit -= 1;
                true
            } else {
                false
            }
        });
        self
    }

    /// Remove all mutation entries that are of type LocationType::Constant and therefore
    /// are not associated to any live value we might mutate.
    pub fn remove_const_type(&mut self) -> &mut Self {
        self.remove_by_location_type(LocationType::Constant);
        self
    }

    /// Panic if any of the contained entries has a zero sized mutation mask.
    pub fn assert_msks_len_not_zero(&mut self) -> &mut Self {
        self.iter().for_each(|e| {
            assert!(e.msk_len() > 0);
        });
        self
    }

    /// The total length (in bytes) of the masks of all entries in this set.
    pub fn total_msk_len(&self) -> usize {
        let mut sum = 0usize;
        self.iter().for_each(|e| {
            sum += e.msk_len() as usize;
        });
        sum
    }
}

mod test {

    #[test]
    fn test() {}
}
