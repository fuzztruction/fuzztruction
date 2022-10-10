use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct PatchPointID(pub u64);

static PATCH_POINT_ID_INVALID: u64 = 0;
lazy_static! {
    static ref PATCH_POINT_ID_CTR: Mutex<u64> = Mutex::new(PATCH_POINT_ID_INVALID + 1);
    static ref PATCH_POINT_ID_MAP: Mutex<HashMap<(usize, usize, usize), PatchPointID>> =
        Mutex::new(HashMap::new());
}

impl PatchPointID {
    pub fn get(base_offset: usize, inode: usize, section_file_offset: usize) -> PatchPointID {
        let mut ctr = PATCH_POINT_ID_CTR.lock().unwrap();
        let mut map = PATCH_POINT_ID_MAP.lock().unwrap();

        let key = (base_offset, inode, section_file_offset);
        if let Some(id) = map.get(&key) {
            id.clone()
        } else {
            let val = PatchPointID(*ctr);
            let had_val = map.insert(key, val.clone());
            assert!(
                had_val.is_none(),
                "There was already an entry for the given key!"
            );

            *ctr = *ctr + 1;
            val
        }
    }

    pub fn invalid() -> PatchPointID {
        PatchPointID(PATCH_POINT_ID_INVALID)
    }
}

impl ToString for PatchPointID {
    fn to_string(&self) -> String {
        format!("PatchPointID({})", self.0)
    }
}

impl From<PatchPointID> for u64 {
    fn from(pp: PatchPointID) -> Self {
        pp.0
    }
}

impl From<u64> for PatchPointID {
    fn from(v: u64) -> Self {
        PatchPointID(v)
    }
}

impl From<usize> for PatchPointID {
    fn from(v: usize) -> Self {
        PatchPointID(v as u64)
    }
}

impl From<&PatchPointID> for usize {
    fn from(pp: &PatchPointID) -> Self {
        pp.0 as usize
    }
}

impl From<PatchPointID> for usize {
    fn from(pp: PatchPointID) -> Self {
        pp.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VAddr(pub u64);

macro_rules! implement_from_for_multiple {
    ($t:ty) => {
        impl From<$t> for VAddr {
            fn from(v: $t) -> Self {
                VAddr(v as u64)
            }
        }
    };
    ($t:ty, $($tt:ty),+) => {
        impl From<$t> for VAddr {
            fn from(v: $t) -> Self {
                VAddr(v as u64)
            }
        }
        implement_from_for_multiple!($($tt),+);
    };
}

implement_from_for_multiple!(u8, u16, u32, u64, usize);
