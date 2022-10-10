use core::panic;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use strum_macros::AsRefStr;

// dwarf_regs
// https://github.com/gimli-rs/gimli/pull/328/commits/44bd277080d7bbc14f721ca46f6fc67806c9cad6
// https://stackoverflow.com/questions/42551113/is-it-possible-to-conditionally-enable-an-attribute-like-derive

/// Mapping of dwarf register interger to register name for x86_64.
#[repr(u16)]
#[derive(
    Debug,
    Copy,
    Clone,
    AsRefStr,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    TryFromPrimitive,
)]
pub enum DwarfReg {
    Rax = 0,
    Rdx,
    Rcx,
    Rbx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
    St0,
    St1,
    St2,
    St3,
    St4,
    St5,
    St6,
    St7,
    Mm0,
    Mm1,
    Mm2,
    Mm3,
    Mm4,
    Mm5,
    Mm6,
    Mm7,
    Rflags,
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
    Reserved0,
    Reserved1,
    FsBase,
    GsBase,
    Reserved2,
    Reserved3,
    Tr,
    Ldtr,
    Mxcsr,
    Fcw,
    Fsw,
    Invalid,
}

pub const GENERAL_PURPOSE_REGISTERS: &[DwarfReg] = &[
    DwarfReg::Rax,
    DwarfReg::Rdx,
    DwarfReg::Rcx,
    DwarfReg::Rbx,
    DwarfReg::Rsi,
    DwarfReg::Rdi,
    DwarfReg::Rbp,
    DwarfReg::Rsp,
    DwarfReg::R8,
    DwarfReg::R9,
    DwarfReg::R10,
    DwarfReg::R11,
    DwarfReg::R12,
    DwarfReg::R13,
    DwarfReg::R14,
    DwarfReg::R15,
];

pub const XMM_REGISTERS: &[DwarfReg] = &[
    DwarfReg::Xmm0,
    DwarfReg::Xmm1,
    DwarfReg::Xmm2,
    DwarfReg::Xmm3,
    DwarfReg::Xmm4,
    DwarfReg::Xmm5,
    DwarfReg::Xmm6,
    DwarfReg::Xmm7,
    DwarfReg::Xmm8,
    DwarfReg::Xmm9,
    DwarfReg::Xmm10,
    DwarfReg::Xmm11,
    DwarfReg::Xmm12,
    DwarfReg::Xmm13,
    DwarfReg::Xmm14,
    DwarfReg::Xmm15,
];

impl Default for DwarfReg {
    fn default() -> Self {
        DwarfReg::Invalid
    }
}

macro_rules! reg0 {
    ($size:ident, $infix:literal) => {
        match $size {
            1 => return Some(format!("{}l", $infix)),
            2 => return Some(format!("{}x", $infix)),
            4 => return Some(format!("e{}x", $infix)),
            8 => return Some(format!("r{}x", $infix)),
            _ => panic!("Invalid size {:?} for infix {:?}", $size, $infix),
        }
    };
}

macro_rules! reg1 {
    ($size:ident, $infix:literal) => {
        match $size {
            1 => return Some(format!("{}il", $infix)),
            2 => return Some(format!("{}i", $infix)),
            4 => return Some(format!("e{}i", $infix)),
            8 => return Some(format!("r{}i", $infix)),
            _ => panic!("Invalid size {} for infix {}", $size, $infix),
        }
    };
}

macro_rules! reg2 {
    ($size:ident, $infix:literal) => {
        match $size {
            1 => return Some(format!("{}pl", $infix)),
            2 => return Some(format!("{}p", $infix)),
            4 => return Some(format!("e{}p", $infix)),
            8 => return Some(format!("r{}p", $infix)),
            _ => panic!("Invalid size {} for infix {}", $size, $infix),
        }
    };
}

macro_rules! reg3 {
    ($size:ident, $infix:literal) => {
        match $size {
            1 => return Some(format!("r{}b", $infix)),
            2 => return Some(format!("r{}w", $infix)),
            4 => return Some(format!("r{}d", $infix)),
            8 => return Some(format!("r{}", $infix)),
            _ => panic!("Invalid size {} for infix {}", $size, $infix),
        }
    };
}

impl DwarfReg {
    pub fn name(&self) -> String {
        let s: String = self.as_ref().to_owned();
        s.to_lowercase()
    }

    pub fn name_with_size(&self, size: u8) -> Option<String> {
        // FIXME: We could return &'static str here if we use macros
        // in the macros above to construct strings with static lifetime.

        const XMM0_ID: u16 = DwarfReg::Xmm0 as u16;
        const XMM15_ID: u16 = DwarfReg::Xmm15 as u16;

        match *self as u16 {
            reg @ XMM0_ID..XMM15_ID => match size {
                16 => return Some(format!("xmm{}", reg - XMM0_ID)),
                _ => panic!("Invalid size {} for xmm", size),
            },
            _ => (), // fallthrough
        }

        assert!(
            size == 1 || size == 2 || size == 4 || size == 8,
            "{:?}",
            self
        );
        match self {
            DwarfReg::Rax => {
                reg0!(size, "a");
            }
            DwarfReg::Rbx => {
                reg0!(size, "b");
            }
            DwarfReg::Rcx => {
                reg0!(size, "c");
            }
            DwarfReg::Rdx => {
                reg0!(size, "d");
            }

            DwarfReg::Rsi => {
                reg1!(size, "s");
            }
            DwarfReg::Rdi => {
                reg1!(size, "d");
            }

            DwarfReg::Rbp => {
                reg2!(size, "b");
            }
            DwarfReg::Rsp => {
                reg2!(size, "s");
            }

            DwarfReg::R8 => {
                reg3!(size, "8");
            }
            DwarfReg::R9 => {
                reg3!(size, "9");
            }
            DwarfReg::R10 => {
                reg3!(size, "10");
            }
            DwarfReg::R11 => {
                reg3!(size, "11");
            }
            DwarfReg::R12 => {
                reg3!(size, "12");
            }
            DwarfReg::R13 => {
                reg3!(size, "13");
            }
            DwarfReg::R14 => {
                reg3!(size, "14");
            }
            DwarfReg::R15 => {
                reg3!(size, "15");
            }
            // Unsupported reg.
            _ => return None,
        }
    }
}
