use std::{convert::TryInto, fs::OpenOptions, ops::Range, path::Path};

use fuzztruction_shared::{
    constants::PATCH_POINT_SIZE, mutation_cache::MutationCacheEntryFlags,
    mutation_cache_entry::MutationCacheEntry, types::PatchPointID,
};

use proc_maps::{self, MapRange};

use crate::llvm_stackmap::{Location, StackMap};

use serde::{Deserialize, Serialize};

/// See /usr/include/llvm/IR/Instruction.def for further more IDs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum LLVMIns {
    Br = 2,
    Switch = 3,
    IndirectBr = 4,
    ICmp = 53,
    Select = 57,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PatchPoint {
    /// A unique ID that identifies this PatchPoint independent of the address space
    /// it belongs to.
    id: PatchPointID,
    /// The VMA base if this patch point belongs to binary that is position independent.
    base: u64,
    /// The VMA of this patch point. If this belongs to a PIC binary, `address`
    /// is only an offset relative to `base`.
    address: u64,
    /// The patch point ID that was assigned during compilation.
    llvm_ins: u64,
    /// The live value that where recorded by this patch point.
    location: Location,
    /// The memory mapping this patch point belongs to.
    mapping: MapRange,
    /// The VMA of the function that contains this PatchPoint.
    function_address: u64,
}

impl PatchPoint {
    pub fn new(
        base: u64,
        address: u64,
        llvm_id: u64,
        location: Location,
        mapping: MapRange,
        function_address: u64,
    ) -> Self {
        assert!(address + base > 0);

        // For now we only support a single recorded location per patch point.
        PatchPoint {
            id: PatchPointID::get(address as usize, mapping.inode, mapping.offset),
            address,
            llvm_ins: llvm_id,
            location,
            base,
            mapping,
            function_address,
        }
    }

    pub fn id(&self) -> PatchPointID {
        self.id
    }

    pub fn llvm_ins(&self) -> u64 {
        self.llvm_ins
    }

    pub fn mapping(&self) -> &MapRange {
        &self.mapping
    }

    pub fn function_address(&self) -> u64 {
        self.function_address
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn vma(&self) -> u64 {
        self.base + self.address
    }

    pub fn vma_range(&self) -> Range<u64> {
        self.vma()..(self.vma() + PATCH_POINT_SIZE as u64)
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn into_mutation_cache_entry(&self) -> Box<MutationCacheEntry> {
        self.into()
    }

    pub fn load(path: &Path) -> Vec<PatchPoint> {
        let file = OpenOptions::new().read(true).open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn dump(path: &Path, patch_points: &[PatchPoint]) {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        serde_json::to_writer(file, patch_points).unwrap();
    }
}

pub fn from_stackmap(map: &StackMap, mapping: &MapRange, elf_file: &elf::File) -> Vec<PatchPoint> {
    let mut idx: usize = 0;
    let mut patch_points = Vec::new();

    // If it is PIC, the base is the start address of the mapping.
    // If not, the addresses in the stackmap are absolute.
    assert!(matches!(
        elf_file.ehdr.elftype,
        elf::types::ET_DYN | elf::types::ET_EXEC
    ));
    let is_pic = elf_file.ehdr.elftype == elf::types::ET_DYN;
    let base = is_pic.then(|| mapping.start()).unwrap_or(0) as u64;

    //let mut seen_vmas = HashSet::new();

    for function in &map.stk_size_records {
        assert!(function.function_address > 0);
        let records = &map.stk_map_records[idx..(idx + function.record_count as usize)];
        records.iter().for_each(|record| {
            record.locations.iter().for_each(|location| {
                let mut vma = (function.function_address as usize
                    + record.instruction_offset as usize) as u64;
                // Rebased function address
                let mut function_address = base + function.function_address;

                if is_pic {
                    vma -= mapping.offset as u64;
                    function_address -= mapping.offset as u64;

                    // Sanity check
                    let absolute_vma = vma as u64 + mapping.start() as u64;
                    assert!(
                        (mapping.start() as u64 + mapping.size() as u64) > absolute_vma,
                        "vma 0x{:x} is too big for mapping {:#?}! record={:#?}",
                        absolute_vma,
                        mapping,
                        record
                    );
                }

                let pp = PatchPoint::new(
                    base,
                    vma,
                    record.patch_point_id,
                    *location,
                    mapping.clone(),
                    function_address,
                );

                // if !seen_vmas.insert(pp.vma()) {
                //     let other = patch_points.iter().find(|p: &&PatchPoint| p.vma() == pp.vma()).unwrap();
                //     panic!("Duplicated VMA A={:#?}\nB={:#?}", pp, other);
                // }
                patch_points.push(pp);
            })
        });
        idx += function.record_count as usize;
    }

    patch_points
}

pub fn elf_is_pic(path: impl AsRef<Path>) -> Option<bool> {
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(_) => panic!("File not found"),
    };
    Some(file.ehdr.elftype == elf::types::ET_DYN)
}

impl From<&PatchPoint> for Box<MutationCacheEntry> {
    fn from(pp: &PatchPoint) -> Self {
        let l = pp.location();
        MutationCacheEntry::new(
            pp.id(),
            pp.vma(),
            MutationCacheEntryFlags::None as u8,
            l.loc_type,
            l.loc_size,
            l.dwarf_regnum.try_into().unwrap(),
            l.offset_or_constant,
            0,
        )
    }
}
