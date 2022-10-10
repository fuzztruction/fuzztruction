use std::{cmp::Ordering, collections::HashMap, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct BasicBlock {
    pub module_id: u64,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Trace {
    pub path: PathBuf,
    pub timestamp_ms: u64,
    pub basic_blocks: Vec<BasicBlock>,
    pub modules: Vec<Module>,
    pub id_to_name: HashMap<u64, String>,
}

impl PartialOrd for Trace {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.basic_blocks.cmp(&other.basic_blocks))
    }
}

impl Ord for Trace {
    fn cmp(&self, other: &Self) -> Ordering {
        self.basic_blocks.cmp(&other.basic_blocks)
    }
}

impl Trace {
    pub fn len(&self) -> usize {
        self.basic_blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.basic_blocks.is_empty()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Module {
    pub id: u64,
    pub containing_id: u64,
    pub start: u64,
    pub end: u64,
    pub entry: u64,
    pub offset: u64,
    pub preferred_base: u64,
    pub path: String,
}
