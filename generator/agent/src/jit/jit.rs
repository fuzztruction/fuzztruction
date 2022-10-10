use crate::mem::MappedMemoryConfig;
use core::panic;
use fuzztruction_shared::constants::PATCH_POINT_SIZE;
use fuzztruction_shared::dwarf::{DwarfReg, XMM_REGISTERS};
use fuzztruction_shared::mutation_cache_entry::{MutationCacheEntry, MutationCacheEntryMetadata};
use fuzztruction_shared::types::VAddr;
use fuzztruction_shared::{abi, dwarf::GENERAL_PURPOSE_REGISTERS};
use keystone::{Arch, Keystone, OptionType};
use llvm_stackmap::LocationType;
use proc_maps::MapRange;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Mutex;

use libc;
use std::{collections::HashMap, slice};

use memoffset::offset_of;

use super::util;
use crate::agent::{update_proc_mappings, PROC_MAPPINGS};
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

macro_rules! MiB {
    ($val:literal) => {
        (1024 * 1024 * ($val))
    };
}

const DEFAULT_CODE_CACHE_SIZE: usize = MiB!(64);
const CALL_DST_REG: DwarfReg = DwarfReg::R11;

#[derive(Debug, Clone, Copy)]
/// An argument that is passed to a function.
pub enum FunctionArg {
    Constant(u64),
    Register(DwarfReg),
}

#[derive(Debug)]
pub enum JitError {
    UnsupportedMutation(String),
}

#[derive(Debug)]
struct PatchableLocation {
    addr: *mut u8,
    size: usize,
    reset_value: [u8; PATCH_POINT_SIZE],
}

impl PatchableLocation {
    pub fn new(addr: VAddr, size: usize) -> PatchableLocation {
        debug_assert!(size == PATCH_POINT_SIZE);
        PatchableLocation {
            addr: addr.0 as *mut u8,
            size,
            reset_value: [0; PATCH_POINT_SIZE],
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.reset_value.as_ptr() as *mut u8,
                self.addr,
                self.size,
            );
        }
    }

    pub fn copy_default_from_addr(&mut self) -> Result<()> {
        unsafe {
            if !util::is_readable_mem_range(self.addr, self.size) {
                let msg = format!(
                    "Target memory range is not readable. vma=0x{:x}",
                    self.addr as u64
                );
                return Err(anyhow!(msg));
            }

            std::ptr::copy_nonoverlapping(
                self.addr,
                self.reset_value.as_ptr() as *mut u8,
                self.size,
            );
        }
        Ok(())
    }
}

/// Provides an allocator to allocate RWX memory slots that can be used to store
/// jitted code.
struct CodeCache<'a> {
    /// The memory allocation that is used to serve all allocation requests.
    buffer: *mut libc::c_void,
    /// The size of `buffer` in bytes.
    size: usize,
    /// The slice that contains all unallocated bytes of buffer.
    unallocated: &'a mut [u8],
}

impl<'a> CodeCache<'a> {
    pub fn new(size: usize) -> CodeCache<'a> {
        let buffer = unsafe {
            libc::mmap(
                0 as *mut libc::c_void,
                size,
                libc::PROT_EXEC | libc::PROT_READ,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                0,
                0,
            )
        };
        assert!(buffer != libc::MAP_FAILED);
        update_proc_mappings();

        let unallocated = unsafe { slice::from_raw_parts_mut::<u8>(buffer as *mut u8, size) };

        CodeCache {
            buffer,
            size: size,
            unallocated,
        }
    }

    /// Allocate a memory slot with length `len`. The returned slice is safe to use
    /// until self is dropped or `reset()` is called.
    pub fn allocate_slot<'b>(&'b mut self, len: usize) -> Option<&'b mut [u8]> {
        Jit::mark_enclosing_mapping_rwx(self.buffer as *const u8).unwrap();

        if self.unallocated.len() < len {
            return None;
        }

        let tmp = std::mem::replace(&mut self.unallocated, &mut []);
        let split: (&'b mut [u8], &'a mut [u8]) = tmp.split_at_mut(len);
        self.unallocated = split.1;

        Some(split.0)
    }

    pub fn make_rx(&mut self) {
        Jit::mark_enclosing_mapping_rx(self.buffer as *const u8).unwrap();
    }

    /// Reset the CodeCache by discarding all allocations made so far.
    /// Safety: This is unsafe, if there is any references alive that was
    /// handed out by allocate_slot().
    pub unsafe fn reset(&mut self) {
        Jit::mark_enclosing_mapping_rwx(self.buffer as *const u8).unwrap();
        self.unallocated = slice::from_raw_parts_mut::<u8>(self.buffer as *mut u8, self.size);
        self.unallocated.fill(0x00);
        Jit::mark_enclosing_mapping_rx(self.buffer as *const u8).unwrap();
    }
}

impl<'a> Drop for CodeCache<'a> {
    fn drop(&mut self) {
        let ret = unsafe { libc::munmap(self.buffer as *mut libc::c_void, self.size) };
        assert!(ret == 0, "Failed to unmap code cache");
    }
}

/// A object that can be called via call and will return via ret.
pub trait CallableFunction: Debug {
    fn args(&self) -> u64;

    fn vma(&self) -> VAddr;

    fn is_dead(&self) -> bool {
        return false;
    }
}

/// A native function that is part of the application.
#[derive(Debug, Clone, Copy)]
pub struct NativeFunction {
    pub vma: VAddr,
    pub nargs: u64,
}

impl NativeFunction {
    pub fn from_fn(function_addr: usize, nargs: u64) -> NativeFunction {
        NativeFunction {
            vma: VAddr(function_addr as u64),
            nargs,
        }
    }

    pub fn to_box(&self) -> Box<NativeFunction> {
        Box::new(*self)
    }
}

impl CallableFunction for NativeFunction {
    fn args(&self) -> u64 {
        self.nargs
    }

    fn vma(&self) -> VAddr {
        self.vma
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct FunctionInstance {
    asm: Vec<String>,
    /// Number of arguments this function expects.
    //arg_cnt: u8,
    /// The machinecode that was produced by assembling the FunctionTemplate.
    machine_code: Vec<u8>,
    vma: Option<VAddr>,
}

impl FunctionInstance {
    pub fn from_assembled_template(asm: Vec<String>, machine_code: Vec<u8>) -> FunctionInstance {
        FunctionInstance {
            asm,
            machine_code: machine_code,
            vma: None,
        }
    }

    pub fn len(&self) -> usize {
        return self.machine_code.len();
    }

    pub unsafe fn write_safe(&mut self, dst: &mut [u8]) {
        assert!(self.machine_code.len() > 0);
        self.vma = Some((dst.as_ptr() as u64).into());

        //eprintln!("write_safe: {:#?}", self);

        dst[0..self.machine_code.len()].copy_from_slice(&self.machine_code)
    }

    pub unsafe fn write(&mut self, dst_addr: VAddr) {
        assert!(
            self.machine_code.len() <= PATCH_POINT_SIZE,
            "len={}\nasm={:#?}",
            self.machine_code.len(),
            self
        );
        assert!(self.machine_code.len() > 0);
        self.vma = Some(dst_addr);
        std::ptr::copy_nonoverlapping(
            [0x90; PATCH_POINT_SIZE].as_ptr(),
            dst_addr.0 as *mut u8,
            PATCH_POINT_SIZE,
        );
        std::ptr::copy_nonoverlapping(
            self.machine_code.as_ptr(),
            dst_addr.0 as *mut u8,
            self.machine_code.len(),
        );
    }
}

impl CallableFunction for FunctionInstance {
    fn args(&self) -> u64 {
        // No args support for now.
        0
    }

    fn vma(&self) -> VAddr {
        self.vma.unwrap()
    }
}

// Our CC:
// - If a function trashes a reg, it is responsible to back it up
// - At a call instruction, all regs. except R11 must have the same values
//   as when the caller was called.

#[derive(Debug)]
pub struct FunctionTemplate {
    /// The assembler code this function is made of.
    asm_body: Vec<String>,
    /// Whether this function might be called and therefore need a ret instruction.
    /// E.g., if a function gets inlined, this must be false.
    is_callee: bool,
}

//asm_body, is_callee
lazy_static! {
    static ref GEN_CALL_CACHE: Mutex<HashSet<Vec<String>>> = Mutex::new(HashSet::new());
}

impl FunctionTemplate {
    pub fn new(asm_body: Vec<String>, is_callee: bool) -> FunctionTemplate {
        FunctionTemplate {
            asm_body: asm_body,
            is_callee,
        }
    }

    fn assemble(self, ks: &Keystone) -> Option<(Vec<String>, Vec<u8>)> {
        let mut asm = self.asm_body;

        if self.is_callee {
            asm.push("ret".to_owned());
        }

        // Assemble
        let asm_str = asm.join("\n");
        //eprintln!("Assembling:\n-----\n{}\n-----", &asm_str);
        let res = ks.asm(asm_str, 0);
        //eprintln!("res={:#?}", res);
        match res {
            Err(e) => {
                log::error!("Error while assembling {}", e);
                None
            }
            Ok(e) => {
                //eprintln!("{:#?}", e);
                Some((asm, e.bytes.clone()))
            }
        }
    }

    // Put into code cache or write to location (e.g., patch point)
}

pub struct Jit<'a> {
    code_cache: CodeCache<'a>,
    keystone_engine: Keystone,
    registered_patch_points: HashMap<VAddr, PatchableLocation>,
}

impl<'a> Jit<'a> {
    pub fn new() -> Jit<'a> {
        let keystone_engine = Keystone::new(Arch::X86, keystone::Mode::MODE_64).unwrap();

        keystone_engine
            .option(OptionType::SYNTAX, keystone::OptionValue::SYNTAX_NASM)
            .unwrap();

        let code_cache = CodeCache::new(DEFAULT_CODE_CACHE_SIZE);
        Jit {
            code_cache,
            keystone_engine,
            registered_patch_points: HashMap::new(),
        }
    }

    /// Must be called for each patch point before it gets modified the first time.
    /// This function make a copy of the patch point that is used during reset()
    /// to restore the original state of the binary.
    pub fn snapshot_patch_point(&mut self, mce: &MutationCacheEntry) {
        let addr = mce.vma().into();
        let value = self.registered_patch_points.get(&addr);
        if value.is_none() {
            let mut value = PatchableLocation::new(addr.clone(), PATCH_POINT_SIZE);
            if let Err(e) = value.copy_default_from_addr() {
                log::error!(
                    "Failed to snapshot patchpoint at address 0x{:x}. mce={:#?} err={}",
                    addr.0,
                    mce,
                    e
                );
                panic!("Failed to snapshot patchpoint!");
            }
            self.registered_patch_points.insert(addr, value);
        }
    }

    fn get_enclosing_mapping(addr: *const u8) -> Option<MapRange> {
        let mappings_guard = PROC_MAPPINGS.lock().unwrap();
        let mappings = mappings_guard.as_ref().unwrap();
        for m in mappings {
            let addr = addr as usize;
            let start = m.start();
            let end = m.start() + m.size();
            if addr >= start && addr < end {
                return Some(m.clone());
            }
        }
        None
    }

    /// Mark the mapping containing `addr` as RWX.
    pub fn mark_enclosing_mapping_rwx(addr: *const u8) -> Result<()> {
        let mapping = Jit::get_enclosing_mapping(addr);
        if mapping.is_none() {
            return Err(anyhow!("Failed to get mapping for addr {:?}", addr));
        }

        let mapping = mapping.unwrap();
        if !mapping.is_write() {
            let start = mapping.start();
            let size = mapping.size();
            MappedMemoryConfig::new(start as usize, size)
                .reset()
                .read(true)
                .write(true)
                .exec(true)
                .commit()
                .unwrap();
            update_proc_mappings();
        }

        Ok(())
    }

    /// Mark the mapping containing `addr` as RX.
    pub fn mark_enclosing_mapping_rx(addr: *const u8) -> Result<()> {
        let mapping = Jit::get_enclosing_mapping(addr);
        if mapping.is_none() {
            return Err(anyhow!("Failed to get mapping for addr {:?}", addr));
        }

        let mapping = mapping.unwrap();
        if mapping.is_write() {
            let start = mapping.start();
            let size = mapping.size();
            MappedMemoryConfig::new(start as usize, size)
                .reset()
                .read(true)
                .write(false)
                .exec(true)
                .commit()
                .unwrap();
            update_proc_mappings();
        }

        Ok(())
    }

    /// Mark all code generated by the JIT as RX.
    pub fn mark_mappings_rx(&mut self) {
        self.code_cache.make_rx();
    }

    /// Restore the state of the binary as if no modifications have been ever applied.
    pub fn reset(&mut self) {
        self.registered_patch_points.values_mut().for_each(|e| {
            Jit::mark_enclosing_mapping_rwx(e.addr as *const u8).unwrap();
            e.reset();
        });

        self.registered_patch_points.values().for_each(|e| {
            Jit::mark_enclosing_mapping_rx(e.addr as *const u8).unwrap();
        });

        self.registered_patch_points.clear();
        // Make sure we are not forking pages that we do not need!
        self.registered_patch_points.shrink_to(0);

        // Reset code cache allocations.
        // Safety: We resetted all patch points (x.reset()) above, thus there are
        // no dangeling pointers into the caches memory.
        unsafe {
            self.code_cache.reset();
        }
    }

    /// Assemble the passed `template` while leaving the task to the caller to
    /// place it in its final memory location via `write_*`.
    pub fn assemble(&self, template: FunctionTemplate) -> Option<FunctionInstance> {
        let machine_code = template.assemble(&self.keystone_engine);
        let machine_code = machine_code.unwrap();

        let ret = FunctionInstance::from_assembled_template(machine_code.0, machine_code.1);
        Some(ret)
    }

    /// Assembles the passed `template` into an allocated memory slot.
    pub fn allocate(&mut self, template: FunctionTemplate) -> Option<FunctionInstance> {
        let instance = self.assemble(template);
        if let Some(mut instance) = instance {
            let slot = self.code_cache.allocate_slot(instance.len()).unwrap();
            unsafe {
                instance.write_safe(slot);
            }
            return Some(instance);
        }
        log::error!("Allocator is OOM");
        None
    }

    /// Generate a stub that consecutively calls all functions listed in `target_fns`.
    /// If the called functions trash any registers, they are responsible of
    /// backing them up.
    pub fn gen_call_multiplexer(
        &self,
        target_fns: Vec<&impl CallableFunction>,
    ) -> FunctionTemplate {
        assert!(target_fns.len() > 0);
        let mut asm_body = Vec::new();

        asm_body.push(format!("push {}", CALL_DST_REG.name()));

        for f in target_fns.iter() {
            asm_body.push(format!("movabs {}, 0x{:x}", CALL_DST_REG.name(), f.vma().0));
            asm_body.push(format!("call {}", CALL_DST_REG.name()));
        }

        asm_body.push(format!("pop {}", CALL_DST_REG.name()));

        let template = FunctionTemplate::new(asm_body, true);
        template
    }

    /// Generates a stub that calls a function located at `to` and
    /// passing the `args` arguments according to the AMD64 ABI.
    pub fn gen_call(
        &self,
        to: &impl CallableFunction,
        args: Vec<FunctionArg>,
        is_callee: bool,
        trashed_regs: Option<Vec<DwarfReg>>,
    ) -> FunctionTemplate {
        let mut asm_body = Vec::new();
        let mut abi_args_order = abi::ARGUMENT_PASSING_ORDER.iter();

        let mut trashed_regs = trashed_regs.unwrap_or(Vec::new());
        // Used below to call `to`.
        trashed_regs.push(CALL_DST_REG);

        // Parse args to the called function, if any.
        for arg in args {
            match arg {
                FunctionArg::Constant(c) => {
                    let reg = abi_args_order
                        .next()
                        .expect("Ran out of registers for passing arguments");
                    trashed_regs.push(*reg);
                    let reg = reg.name();
                    asm_body.push(format!("movabs {}, 0x{:x}", reg, c));
                }
                _ => todo!("Passing registers is currently not supported!"),
            }
        }

        for reg in trashed_regs.iter() {
            // Insert prologe at the start of this function (idx 0).
            asm_body.insert(0, format!("push {}", reg.name()));
        }

        // Place the callee's address into `CALL_DST_REG`.
        asm_body.push(format!(
            "movabs {}, 0x{:x}",
            CALL_DST_REG.name(),
            to.vma().0
        ));

        // The actual call.
        asm_body.push(format!("call {}", CALL_DST_REG.name()));

        // Restore the trashed registers after the call returns.
        for reg in trashed_regs.iter() {
            asm_body.push(format!("pop {}", reg.name()));
        }

        FunctionTemplate::new(asm_body, is_callee)
    }

    /// Generate a mutation stub for a `MutationCacheEntry` that
    /// directly targets a register.
    fn gen_mutation_reg(
        &self,
        mce: &MutationCacheEntry,
        is_callee: bool,
    ) -> Result<FunctionTemplate, JitError> {
        //eprintln!("gen_mutation_gpr_xmm: reg={:#?}, mce: {:#?}", reg, mce);
        let mut asm = Vec::<String>::new();

        let is_xmm = XMM_REGISTERS.contains(&mce.dwarf_regnum());
        let loc_size = mce.loc_size();
        let chunk_size = if loc_size <= 8 { loc_size } else { 8 };

        let msk_reg = DwarfReg::Rdx.name_with_size(chunk_size as u8).unwrap();
        let target_reg = match loc_size {
            4 => {
                // We use the super register (e.g., EAX -> RAX) if we have
                // a 4 byte target, because applying the mask down below with
                // xor EAX, [msk] causes the upper for bytes to be cleared
                // which is not intended. This only works if the msk buffer
                // contain 4 trailing zero bytes that can be "used" as msk for
                // the upper 4 bytes that we actually do not want to mutate.
                mce.dwarf_regnum().name()
            }
            _ => mce
                .dwarf_regnum()
                .name_with_size(mce.loc_size() as u8)
                .unwrap(),
        };

        let offset = offset_of!(MutationCacheEntryMetadata, dwarf_regnum);
        let t = mce as *const MutationCacheEntry as *const u8 as usize;
        let t = t + offset;
        let t = t as *const u16;
        let t = unsafe { std::ptr::read(t) };

        assert!(mce.dwarf_regnum() as u16 == t);

        // Stack slot for spilling the mutation mask.
        if is_xmm {
            asm.push(format!("push 0"));
            asm.push(format!("push 0"));
        } else {
            asm.push(format!("push 0"));
        }

        // Scratch registers
        asm.push(format!("push rax"));
        asm.push(format!("push rbx"));
        asm.push(format!("push rcx"));
        asm.push(format!("push rdx")); // used for msk

        asm.push(format!(
            "mov rax, 0x{:x}",
            mce as *const MutationCacheEntry as u64
        ));

        asm.push(format!(
            "mov ebx, [rax + 0x{:x}]",
            offset_of!(MutationCacheEntryMetadata, read_pos)
        ));

        // Load the mask value into stack slot
        asm.push(format!(
            "mov {}, [rax + rbx + 0x{:x}]",
            &msk_reg,
            offset_of!(MutationCacheEntry, msk)
        ));
        asm.push(format!("mov [rsp+0x20], {}", &msk_reg));

        if is_xmm {
            asm.push(format!(
                "mov {}, [rax + rbx + 0x{:x}]",
                &msk_reg,
                offset_of!(MutationCacheEntry, msk) + 8
            ));
            asm.push(format!("mov [rsp+0x28], {}", &msk_reg));
        }

        // Current register content
        // RAX = base,
        // EBX = read_pos
        // RCX = free
        // RDX = msk_reg

        // increment read_pos
        asm.push(format!("add ebx, 0x{:x}", loc_size));

        // rcx = msk_len
        asm.push(format!(
            "mov ecx, [rax + 0x{:x}]",
            MutationCacheEntry::offsetof_msk_len(),
        ));

        // cmp read_pos, msk_len
        asm.push(format!("cmp ebx, ecx"));

        // set read_pos = msk_len if (read_pos > msk_len)
        asm.push(format!("cmova ebx, ecx"));

        // Update the read_pos in the struct
        asm.push(format!(
            "mov dword [rax + 0x{:x}], ebx",
            offset_of!(MutationCacheEntryMetadata, read_pos),
        ));

        asm.push(format!("pop rdx"));
        asm.push(format!("pop rcx"));
        asm.push(format!("pop rbx"));
        asm.push(format!("pop rax"));

        // We need here all registers in their untouched state, since
        // we possibly mutate a register that we used in the code above.
        // Hence, we store the mask temporarily onto the stack before appling it.
        if is_xmm {
            asm.push(format!("xorps {}, xmmword [rsp]", target_reg));
            asm.push(format!("add rsp, 0x10"));
        } else {
            asm.push(format!("xor {}, [rsp]", target_reg));
            asm.push(format!("add rsp, 0x8"));
        }

        Ok(FunctionTemplate::new(asm, is_callee))
    }

    fn gen_mutation_indirect(
        &self,
        mce: &MutationCacheEntry,
        is_callee: bool,
    ) -> Result<FunctionTemplate, JitError> {
        //log::trace!("gen_mutation_indirect_gpr: {:#?}", mce);
        let mut asm = Vec::<String>::new();

        if mce.loc_size() > 8 && mce.loc_size() != 16 {
            return Err(JitError::UnsupportedMutation(format!(
                "Unsupported size {} for indirect gpr",
                mce.loc_size()
            )));
        }
        let loc_size = mce.loc_size();
        let loc_size_is_16 = loc_size == 16;
        let chunk_size = if loc_size_is_16 { 8 } else { loc_size };

        let msk_reg = DwarfReg::Rdx.name_with_size(chunk_size as u8).unwrap();

        let offset = offset_of!(MutationCacheEntryMetadata, dwarf_regnum);
        let t = mce as *const MutationCacheEntry as *const u8 as usize;
        let t = t + offset;
        let t = t as *const u16;
        let t = unsafe { std::ptr::read(t) };

        assert!(mce.dwarf_regnum() as u16 == t);

        // Stack slot for spilling the mutation mask.
        asm.push(format!("push 0"));

        if loc_size_is_16 {
            asm.push(format!("push 0"));
        }

        // Scratch registers
        asm.push(format!("push rax"));
        asm.push(format!("push rbx"));
        asm.push(format!("push rcx"));
        asm.push(format!("push rdx")); // used for msk

        asm.push(format!(
            "mov rax, 0x{:x}",
            mce as *const MutationCacheEntry as u64
        ));

        asm.push(format!(
            "mov ebx, [rax + 0x{:x}]",
            offset_of!(MutationCacheEntryMetadata, read_pos)
        ));

        // Load the mask value into stack slot
        asm.push(format!(
            "mov {}, [rax + rbx + 0x{:x}]",
            &msk_reg,
            offset_of!(MutationCacheEntry, msk)
        ));
        asm.push(format!("mov [rsp+0x20], {}", &msk_reg));

        if loc_size_is_16 {
            // Load the mask value into stack slot
            asm.push(format!(
                "mov {}, [rax + rbx + 0x{:x}]",
                &msk_reg,
                offset_of!(MutationCacheEntry, msk) + 8
            ));
            asm.push(format!("mov [rsp+0x28], {}", &msk_reg));
        }

        // Current register content
        // RAX = base,
        // EBX = read_pos
        // RCX = free
        // RDX = msk_reg

        // increment read_pos
        asm.push(format!("add ebx, 0x{:x}", loc_size));

        // rcx = msk_len
        asm.push(format!(
            "mov ecx, [rax + 0x{:x}]",
            MutationCacheEntry::offsetof_msk_len(),
        ));

        // cmp read_pos, msk_len
        asm.push(format!("cmp ebx, ecx"));

        // set read_pos = msk_len if (read_pos > msk_len)
        asm.push(format!("cmova ebx, ecx"));

        // Update the read_pos in the struct
        asm.push(format!(
            "mov dword [rax + 0x{:x}], ebx",
            offset_of!(MutationCacheEntryMetadata, read_pos),
        ));

        asm.push(format!("pop rdx"));
        asm.push(format!("pop rcx"));
        asm.push(format!("pop rbx"));
        asm.push(format!("pop rax"));

        // The ptr to the value we want to mutate is at [dwarf_regnum + offset_or_constant].
        let ptr_base_reg = mce.dwarf_regnum();
        let ptr_base_reg8 = ptr_base_reg.name_with_size(8).unwrap();

        let mut useable_regs = GENERAL_PURPOSE_REGISTERS
            .iter()
            .filter(|r| **r != ptr_base_reg && **r != DwarfReg::Rsp)
            .collect::<Vec<_>>();
        let ptr_reg = useable_regs.pop().unwrap();
        let ptr_reg8 = ptr_reg.name_with_size(8).unwrap();
        let msk_reg = useable_regs.pop().unwrap();

        asm.push(format!("push {}", ptr_reg8));
        asm.push(format!("push {}", msk_reg.name_with_size(8).unwrap()));
        asm.push(format!(
            "lea {}, [{} + {}]",
            ptr_reg8, ptr_base_reg8, mce.metadata.offset_or_constant
        ));

        // ! It look like keystone fails to parse 16 instead of 0x10 correctly !
        asm.push(format!(
            "mov {}, [rsp + 0x10]",
            msk_reg.name_with_size(8).unwrap()
        ));
        asm.push(format!(
            "xor [{}], {}",
            ptr_reg8,
            msk_reg.name_with_size(chunk_size as u8).unwrap()
        ));

        if loc_size_is_16 {
            asm.push(format!(
                "mov {}, [rsp + 0x18]",
                msk_reg.name_with_size(8).unwrap()
            ));
            asm.push(format!("add {}, 8", ptr_reg8));
            asm.push(format!(
                "xor [{}], {}",
                ptr_reg8,
                msk_reg.name_with_size(chunk_size as u8).unwrap()
            ));
        }

        asm.push(format!("pop {}", msk_reg.name_with_size(8).unwrap()));
        asm.push(format!("pop {}", ptr_reg8));

        if loc_size_is_16 {
            asm.push(format!("add rsp, 0x10"));
        } else {
            asm.push(format!("add rsp, 0x8"));
        }

        //eprintln!("asm={:#?}", asm);

        Ok(FunctionTemplate::new(asm, is_callee))
    }

    pub fn gen_mutation(
        &self,
        mce: &MutationCacheEntry,
        is_callee: bool,
    ) -> Result<FunctionTemplate, JitError> {
        assert!(mce.msk_len() > 0);

        let reg = mce.dwarf_regnum();

        match mce.loc_type() {
            LocationType::Register => match reg {
                _ if GENERAL_PURPOSE_REGISTERS.contains(&reg) || XMM_REGISTERS.contains(&reg) => {
                    return self.gen_mutation_reg(mce, is_callee)
                }
                _ => {
                    return Err(JitError::UnsupportedMutation(format!(
                        "Unable to handle register: {:#?}",
                        mce
                    )));
                }
            },
            LocationType::Indirect => match reg {
                _ if GENERAL_PURPOSE_REGISTERS.contains(&reg) => {
                    return self.gen_mutation_indirect(mce, is_callee)
                }
                _ => {
                    return Err(JitError::UnsupportedMutation(format!(
                        "Unable to handle register: {:#?}",
                        mce
                    )));
                }
            },
            _ => Err(JitError::UnsupportedMutation(format!(
                "Unsupported location type: {:#?}",
                mce
            ))),
        }
    }
}
