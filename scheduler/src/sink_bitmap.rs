use std::{
    ops::{BitAnd, BitOr, BitXor, Index, Range},
    ptr, slice,
};

use lazy_static::lazy_static;
use libc::c_void;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/* See afl config.h */
const MAP_SIZE_POW2: usize = 18;
pub const BITMAP_DEFAULT_MAP_SIZE: usize = 1 << MAP_SIZE_POW2;
pub const BITMAP_DEFAULT_MINIMIZED_MAP_SIZE: usize = BITMAP_DEFAULT_MAP_SIZE / 8;

lazy_static! {
    static ref X: u32 = 1;
    // this returns the index we have to use into LOOKUP_BUCKET, i.e., the bucket the value is placed into
    static ref LOOKUP_U8_IDX: [Range<u16>; 9] = [(0..1), (1..2), (2..3), (3..4), (4..8), (8..16), (16..32), (32..128), (128..256)];
    static ref LOOKUP_BUCKET: [u8; 9] = [0, 1, 2, 4, 8, 16, 32, 64, 128];
    static ref LOOKUP_U16: [u16; 2usize.pow(16)] = { // [0; 2usize.pow(16)];
        let mut res = [0; 2usize.pow(16)];
        for b1 in 0u8..=255 {
            for b2 in 0u8..=255 {
                let lookup_b1: u16 = u16::from(LOOKUP_U8_IDX.iter().position(|r| r.contains(&u16::from(b1))).map(|idx| LOOKUP_BUCKET[idx]).unwrap());
                let lookup_b2: u16 = u16::from(LOOKUP_U8_IDX.iter().position(|r| r.contains(&u16::from(b2))).map(|idx| LOOKUP_BUCKET[idx]).unwrap());
                res[((b1 as usize) << 8) + (b2 as usize)] = (lookup_b1 << 8) | lookup_b2;
            }
        }
        res
    };
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize)]
pub enum BitmapStatus {
    NoChange,
    NewHit,
    NewEdge,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bitmap {
    shm_id: Option<i32>,
    shm_addr: Option<libc::intptr_t>,
    #[allow(unused)]
    // Needed to keep the heap allocation alive.
    backing_memory: Option<Box<[u8]>>,
    /// The pattern this bitmap is initially filled with.
    fill_pattern: u8,
    size: usize,
}

impl Bitmap {
    pub fn new_in_shm(size: usize, fill_pattern: u8) -> Bitmap {
        assert!(size >= 8 && size.is_power_of_two());

        // Create new shared memory region.
        let shm_id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                size,
                libc::IPC_CREAT | libc::IPC_EXCL | 0o666,
            )
        };
        assert!(shm_id != -1);

        let shm_addr = unsafe { libc::shmat(shm_id, ptr::null() as *const libc::c_void, 0) };
        assert_ne!(shm_addr, -1i32 as *mut libc::c_void);

        // Init with fill pattern.
        let data = unsafe { slice::from_raw_parts_mut(shm_addr as *mut u8, size) };
        data.copy_from_slice(&vec![fill_pattern; size]);

        Bitmap {
            shm_id: Some(shm_id),
            shm_addr: Some(shm_addr as libc::intptr_t),
            backing_memory: None,
            fill_pattern,
            size,
        }
    }

    pub fn new_in_mem(size: usize, fill_pattern: u8) -> Bitmap {
        assert!(size >= 8 && size.is_power_of_two());
        let mem = Box::new_uninit_slice(size);
        let mut mem = unsafe { mem.assume_init() };
        mem.copy_from_slice(&vec![fill_pattern; size]);
        Bitmap {
            shm_id: None,
            shm_addr: None,
            backing_memory: Some(mem),
            fill_pattern,
            size,
        }
    }

    // pub fn resize(self, new_size: usize) -> Bitmap {
    //     if self.shm_id.is_none() {
    //         Bitmap::new_in_mem(new_size, self.fill_pattern)
    //     } else {

    //     }
    // }

    pub fn data(&self) -> &[u8] {
        if self.shm_id.is_some() {
            unsafe { slice::from_raw_parts_mut(self.shm_addr.unwrap() as *mut u8, self.size) }
        } else {
            unsafe {
                slice::from_raw_parts_mut(
                    self.backing_memory.as_ref().unwrap().as_ptr() as *mut u8,
                    self.size,
                )
            }
        }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        if self.shm_id.is_some() {
            unsafe { slice::from_raw_parts_mut(self.shm_addr.unwrap() as *mut u8, self.size) }
        } else {
            unsafe {
                slice::from_raw_parts_mut(
                    self.backing_memory.as_mut().unwrap().as_ptr() as *mut u8,
                    self.size,
                )
            }
        }
    }

    pub fn copy_from(&mut self, other: &Bitmap) {
        self.data_mut().copy_from_slice(other.data());
    }

    pub fn shm_id(&self) -> i32 {
        self.shm_id.unwrap()
    }

    pub fn reset(&mut self) {
        unsafe {
            libc::memset(
                self.data_mut().as_mut_ptr() as *mut c_void,
                i32::from(self.fill_pattern),
                self.data().len(),
            );
        }
    }

    pub fn count_bytes_set(&self) -> usize {
        let mut bytes_set = 0;
        unsafe {
            let chunks = self.data().as_chunks_unchecked::<8>().iter();
            for chunk in chunks {
                let val = chunk.as_ptr() as *const u64;
                let val = *val;
                if val > 0 {
                    // Optimize for sparse map.
                    ((val & 0xff) != 0).then(|| bytes_set += 1);
                    ((val & 0xff << 8) != 0).then(|| bytes_set += 1);
                    ((val & 0xff << 16) != 0).then(|| bytes_set += 1);
                    ((val & 0xff << 24) != 0).then(|| bytes_set += 1);

                    ((val & 0xff << 32) != 0).then(|| bytes_set += 1);
                    ((val & 0xff << 40) != 0).then(|| bytes_set += 1);
                    ((val & 0xff << 48) != 0).then(|| bytes_set += 1);
                    ((val & 0xff << 56) != 0).then(|| bytes_set += 1);
                }
            }
        }
        bytes_set
    }

    pub fn count_bits_set(&self) -> usize {
        unsafe {
            self.data()
                .as_chunks_unchecked::<8>()
                .iter()
                .map(|c| (*(c.as_ptr() as *const u64)).count_ones() as usize)
                .sum()
        }
    }

    pub fn not(&mut self) -> &mut Self {
        unsafe {
            self.data_mut()
                .as_chunks_unchecked_mut::<8>()
                .iter_mut()
                .for_each(|c| {
                    (*(c.as_ptr() as *mut u64)) = !(*(c.as_ptr() as *mut u64));
                });
        }
        self
    }

    // https://github.com/google/AFL/blob/fab1ca5ed7e3552833a18fc2116d33a9241699bc/afl-fuzz.c#L907
    pub fn has_new_bit(&self, virgin: &mut Bitmap) -> BitmapStatus {
        let it = unsafe {
            let self_it = self.data().as_chunks_unchecked::<8>();
            let virgin_it = virgin.data_mut().as_chunks_unchecked_mut::<8>();
            self_it.iter().zip(virgin_it.iter_mut())
        };

        let mut ret = BitmapStatus::NoChange;
        for (se, vi) in it {
            let self_bytes = u64::from_le_bytes(*se);
            let mut virgin_bytes = u64::from_le_bytes(*vi);

            if self_bytes != 0 && (self_bytes & virgin_bytes) != 0 {
                if ret != BitmapStatus::NewEdge {
                    // we found new bits - this must be at least a new hit!
                    ret = BitmapStatus::NewHit;
                    // check if we this is even a new edge
                    for i in 0..8 {
                        // check if the virgin byte is untouched
                        if se[i] != 0 && (vi[i] == 0xff) {
                            ret = BitmapStatus::NewEdge;
                            break;
                        }
                    }
                }
                virgin_bytes &= !self_bytes;
                unsafe {
                    *(vi.as_ptr() as *mut u64) = virgin_bytes;
                }
            }
        }
        ret
    }

    // https://github.com/google/AFL/blob/fab1ca5ed7e3552833a18fc2116d33a9241699bc/afl-fuzz.c#L1175
    pub fn classify_counts(&mut self) -> &mut Self {
        let it = unsafe { self.data_mut().as_chunks_unchecked_mut::<8>() };

        for c in it {
            let chunk_ptr = c.as_ptr() as *mut u64;
            if unsafe { *chunk_ptr != 0 } {
                let chunk_slice = unsafe { slice::from_raw_parts_mut(chunk_ptr as *mut u16, 4) };
                chunk_slice
                    .iter_mut()
                    .for_each(|s| *s = LOOKUP_U16[*s as usize]);
            }
        }
        self
    }

    pub fn clone_as_mem_backed(&self) -> Self {
        let mut bm = Bitmap::new_in_mem(self.size, self.fill_pattern);
        bm.data_mut().copy_from_slice(self.data());
        bm
    }

    pub fn clone_with_pattern(&self, pattern: u8) -> Self {
        Bitmap::new_in_mem(self.size, pattern)
    }

    pub fn sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(self.data());
        let digest = digest.finalize();
        hex::encode(digest)
    }

    // https://github.com/mboehme/aflfast/blob/master/hash.h
    pub fn hash32(&self) -> u32 {
        let seed: u64 = 0xef8e8af80708ef32;
        let len = self.data().len();

        let mut h1: u64 = len as u64 ^ seed;

        unsafe {
            debug_assert!((len % 8) == 0);
            let chunks = self.data().as_chunks_unchecked::<8>();
            for chunk in chunks {
                let mut k1 = *(chunk.as_ptr() as *const u64);
                k1 = k1.wrapping_mul(0x87c37b91114253d5);
                k1 = k1.rotate_left(31);
                k1 = k1.wrapping_mul(0x4cf5ad432745937f);
                h1 ^= k1;
                h1 = h1.rotate_left(27);
                h1 = h1.wrapping_mul(5);
                h1 = h1.wrapping_add(0x52dce729);
            }
        }

        h1 ^= h1 >> 33;
        h1 = h1.wrapping_mul(0xff51afd7ed558ccd);
        h1 ^= h1 >> 33;
        h1 = h1.wrapping_mul(0xc4ceb9fe1a85ec53);
        h1 ^= h1 >> 33;

        h1 as u32
    }

    pub(crate) fn minimize(&self) -> Bitmap {
        let mut new_map = Bitmap::new_in_mem(self.size() / 8, 0x00);
        let new_map_mem = new_map.data_mut();
        let src_map_mem = self.data();

        for (idx, b) in src_map_mem.iter().enumerate() {
            if *b > 0 {
                new_map_mem[idx / 8] |= 1 << (idx % 8);
            }
        }

        new_map
    }

    pub fn edges(&self) -> Vec<usize> {
        let mut ret = Vec::new();
        for (idx, val) in self.data().iter().enumerate() {
            if *val > 0 {
                ret.push(idx)
            }
        }
        ret
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

macro_rules! impl_ops {
    ($op:tt, $trait_name:ty, $func_name:ident) => {
        impl $trait_name for &Bitmap {
            type Output = Bitmap;

            fn $func_name(self, rhs: Self) -> Self::Output {
                let mut ret = self.clone_with_pattern(0x00);
                unsafe {
                    let mut ret_it = ret.data_mut().as_chunks_unchecked_mut::<8>().iter_mut();
                    let self_it = self.data().as_chunks_unchecked::<8>();
                    let rhs_it = rhs.data().as_chunks_unchecked::<8>();

                    let it = self_it.iter().zip(rhs_it.iter());
                    for (b1, b2) in it {
                        let op_val = *(b1.as_ptr() as *const u64) $op *(b2.as_ptr() as *const u64);
                        let op_ref = slice::from_raw_parts(&op_val as *const u64 as *const u8, std::mem::size_of_val(&op_val));
                        ret_it.next().unwrap().copy_from_slice(op_ref);
                    }
                }
                ret
            }
        }
    };
}

impl_ops!(&, BitAnd, bitand);
impl_ops!(|, BitOr, bitor);
impl_ops!(^, BitXor, bitxor);

impl Index<usize> for Bitmap {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data()[index]
    }
}

impl std::ops::IndexMut<usize> for Bitmap {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data_mut()[index]
    }
}

impl Drop for Bitmap {
    fn drop(&mut self) {
        if let Some(_id) = self.shm_id {
            unsafe {
                let ret = libc::shmdt(self.data().as_ptr() as *const libc::c_void);
                assert_eq!(ret, 0);
            }
        }
    }
}

impl Clone for Bitmap {
    fn clone(&self) -> Self {
        self.clone_as_mem_backed()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_mem() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        assert_eq!(&[FILL_PATTERN; SIZE], mem.data());
    }

    #[test]
    fn test_count_bytes_set() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        assert_eq!(mem.count_bytes_set(), SIZE);
        let mem_empty = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!(mem_empty.count_bytes_set(), 0);
    }

    #[test]
    fn test_count_bits_set() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        assert_eq!(mem.count_bits_set(), SIZE * 8);
        let mem_empty = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!(mem_empty.count_bytes_set(), 0);
    }

    #[test]
    fn test_bitand() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        let mem_empty = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!((&mem & &mem_empty).data(), mem_empty.data());
        assert_eq!((&mem & &mem).data(), mem.data());
    }

    #[test]
    fn test_bitor() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        let mem_empty = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!((&mem_empty | &mem_empty).data(), mem_empty.data());
        assert_eq!((&mem | &mem_empty).data(), mem.data());
        assert_eq!((&mem | &mem).data(), mem.data());
    }

    #[test]
    fn test_bitxor() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        let mem_empty = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!((&mem_empty ^ &mem_empty).data(), mem_empty.data());
        assert_eq!((&mem ^ &mem_empty).data(), mem.data());
        assert_eq!((&mem ^ &mem).data(), mem_empty.data());
    }

    #[test]
    fn test_not() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mem = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        let mem_empty = Bitmap::new_in_mem(SIZE, 0);
        let mut mem2 = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        let mut mem_empty2 = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!(mem2.not().data(), mem_empty.data());
        assert_eq!(mem_empty2.not().data(), mem.data());
    }

    #[test]
    fn test_has_new_bits() {
        const FILL_PATTERN: u8 = 0xff;
        const SIZE: usize = 32;
        let mut virgin = Bitmap::new_in_mem(SIZE, FILL_PATTERN);
        let mut bm = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!(bm.has_new_bit(&mut virgin), BitmapStatus::NoChange);

        bm[0] = 1;
        assert_eq!(bm.has_new_bit(&mut virgin), BitmapStatus::NewEdge);
        assert_eq!(virgin[0], 0xfe);
        // once we've seen the edge, we expect no change for the same input
        assert_eq!(bm.has_new_bit(&mut virgin), BitmapStatus::NoChange);

        bm[0] = 2;
        assert_eq!(bm.has_new_bit(&mut virgin), BitmapStatus::NewHit);
        assert_eq!(virgin[0], 0xff & !0b11);
    }

    #[test]
    fn test_classify_counts() {
        const SIZE: usize = 32;
        let expected_bm = Bitmap::new_in_mem(SIZE, 0);
        let mut bm = Bitmap::new_in_mem(SIZE, 0);
        assert_eq!(bm.classify_counts().data(), expected_bm.data());

        let expected_bm = Bitmap::new_in_mem(SIZE, 0x1);
        let mut bm = Bitmap::new_in_mem(SIZE, 0x1);
        assert_eq!(bm.classify_counts().data(), expected_bm.data());

        let expected_bm = Bitmap::new_in_mem(SIZE, 8);
        let mut bm = Bitmap::new_in_mem(SIZE, 5);
        assert_eq!(bm.classify_counts().data(), expected_bm.data());

        let expected_bm = Bitmap::new_in_mem(SIZE, 128);
        let mut bm = Bitmap::new_in_mem(SIZE, 130);
        assert_eq!(bm.classify_counts().data(), expected_bm.data());

        let expected_bm = Bitmap::new_in_mem(SIZE, 16);
        let mut bm = Bitmap::new_in_mem(SIZE, 8);
        assert_eq!(bm.classify_counts().data(), expected_bm.data());

        let expected_bm = Bitmap::new_in_mem(SIZE, 16);
        let mut bm = Bitmap::new_in_mem(SIZE, 15);
        assert_eq!(bm.classify_counts().data(), expected_bm.data());
    }

    #[test]
    fn test_clone_as_mem_backed() {
        const SIZE: usize = 32;
        let bm = Bitmap::new_in_mem(SIZE, 0xff);
        assert_eq!(bm.clone_as_mem_backed().data(), bm.data());
    }
}
