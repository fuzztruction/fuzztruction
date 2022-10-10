/// These values are not exposed via libc, yet.
/// Defined in FreeBSD source: /sys/vm/vm.h

pub const VM_PROT_READ: i32 = 0x01;
pub const VM_PROT_WRITE: i32 = 0x02;
pub const VM_PROT_EXECUTE: i32 = 0x04;
