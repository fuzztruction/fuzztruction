use libc::{c_char, c_int};
use libc::{waitpid, PT_ATTACH, PT_DETACH, PT_VM_ENTRY, WIFSTOPPED};
use std::convert::From;
use std::ffi::{CStr, OsStr};
use std::io;
use std::iter::Iterator;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use super::bindings::{caddr_t, ptrace_vm_entry};
use super::Pid;

const FILE_NAME_BUFFER_LENGTH: usize = 4096;

impl Default for ptrace_vm_entry {
    fn default() -> Self {
        Self {
            pve_entry: 0,
            pve_timestamp: 0,
            pve_start: 0,
            pve_end: 0,
            pve_offset: 0,
            pve_prot: 0,
            pve_pathlen: 0,
            pve_fileid: 0,
            pve_fsid: 0,
            pve_path: ptr::null_mut(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmEntry {
    pub pve_entry: i32,
    pub pve_timestamp: i32,
    pub pve_start: u64,
    pub pve_end: u64,
    pub pve_offset: u64,
    pub pve_prot: u32,
    pub pve_pathlen: u32,
    pub pve_fileid: i64,
    pub pve_fsid: u32,
    pub pve_path: Option<PathBuf>,
}

impl From<ptrace_vm_entry> for VmEntry {
    fn from(vm_entry: ptrace_vm_entry) -> Self {
        Self {
            pve_entry: vm_entry.pve_entry,
            pve_timestamp: vm_entry.pve_timestamp,
            pve_start: vm_entry.pve_start,
            pve_end: vm_entry.pve_end,
            pve_offset: vm_entry.pve_offset,
            pve_prot: vm_entry.pve_prot,
            pve_pathlen: vm_entry.pve_pathlen,
            pve_fileid: vm_entry.pve_fileid,
            pve_fsid: vm_entry.pve_fsid,
            pve_path: string_from_cstr_ptr(vm_entry.pve_path),
        }
    }
}

impl Default for VmEntry {
    fn default() -> Self {
        Self {
            pve_entry: 0,
            pve_timestamp: 0,
            pve_start: 0,
            pve_end: 0,
            pve_offset: 0,
            pve_prot: 0,
            pve_pathlen: 0,
            pve_fileid: 0,
            pve_fsid: 0,
            pve_path: None,
        }
    }
}

#[derive(Default)]
pub struct VmEntryIterator {
    current: c_int,
    pid: Pid,
}

impl VmEntryIterator {
    pub fn new(pid: Pid) -> std::io::Result<Self> {
        attach(pid)?;

        Ok(Self { current: 0, pid })
    }
}

impl Drop for VmEntryIterator {
    fn drop(&mut self) {
        if let Err(e) = detach(self.pid) {
            eprintln!("failed to ptrace detach: {:?}", e);
        }
    }
}

impl Iterator for VmEntryIterator {
    type Item = VmEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let Self { current, pid } = *self;
        // If the region was mapped from a file, `pve_path` contains filename.
        let pve_pathlen = 4096;
        let pve_path: [c_char; FILE_NAME_BUFFER_LENGTH] = [0; FILE_NAME_BUFFER_LENGTH];

        let entry = ptrace_vm_entry {
            pve_entry: current,
            pve_path: &pve_path as *const _ as *mut _,
            pve_pathlen: pve_pathlen,
            ..Default::default()
        };

        let result = read_vm_entry(pid, entry);

        match result {
            Ok(entry) => {
                self.current = entry.pve_entry;

                Some(entry.into())
            }
            _ => None,
        }
    }
}

fn string_from_cstr_ptr(pointer: *const c_char) -> Option<PathBuf> {
    if pointer.is_null() {
        None
    } else {
        unsafe {
            let cstr = CStr::from_ptr(pointer);
            let osstr = OsStr::from_bytes(cstr.to_bytes());

            if osstr.len() > 0 {
                Some(PathBuf::from(osstr))
            } else {
                None
            }
        }
    }
}

extern "C" {
    fn ptrace(request: c_int, pid: Pid, vm_entry: caddr_t, data: c_int) -> c_int;
}

/// Attach to a process `pid` and wait for the process to be stopped.
pub fn attach(pid: Pid) -> io::Result<()> {
    let attach_status = unsafe { ptrace(PT_ATTACH, pid, ptr::null_mut(), 0) };

    if attach_status == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut wait_status = 0;

    let stopped = unsafe {
        waitpid(pid, &mut wait_status as *mut _, 0);
        WIFSTOPPED(wait_status)
    };

    if !stopped {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Detach from the process `pid`.
pub fn detach(pid: Pid) -> io::Result<()> {
    let detach_status = unsafe { ptrace(PT_DETACH, pid, ptr::null_mut(), 0) };

    if detach_status == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Read virtual memory entry
pub fn read_vm_entry(pid: Pid, vm_entry: ptrace_vm_entry) -> io::Result<ptrace_vm_entry> {
    let result = unsafe { ptrace(PT_VM_ENTRY, pid, &vm_entry as *const _ as *mut i8, 0) };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(vm_entry)
    }
}
