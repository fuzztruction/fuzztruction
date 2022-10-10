use crate::dwarf::DwarfReg;

/// The order in which integer arguments are passed on System V AMD64 ABI.
pub const ARGUMENT_PASSING_ORDER: &[DwarfReg] = &[
    DwarfReg::Rdi,
    DwarfReg::Rsi,
    DwarfReg::Rdx,
    DwarfReg::Rcx,
    DwarfReg::R8,
    DwarfReg::R9,
];

pub const CALLER_SAVED_GP_REGISTERS: &[DwarfReg] = &[
    DwarfReg::Rax,
    DwarfReg::Rdx,
    DwarfReg::Rcx,
    DwarfReg::Rsi,
    DwarfReg::Rdi,
    DwarfReg::R8,
    DwarfReg::R9,
    DwarfReg::R10,
    DwarfReg::R11,
];

pub const CALLEE_SAVED_GP_REGISTERS: &[DwarfReg] = &[
    DwarfReg::Rbx,
    DwarfReg::Rsp,
    DwarfReg::Rbp,
    DwarfReg::R12,
    DwarfReg::R13,
    DwarfReg::R14,
    DwarfReg::R15,
];
