#[allow(warnings)]
mod bindings;
mod protection;
mod ptrace;

use libc::{c_int, pid_t};
use std::convert::From;
use std::iter::Iterator;
use std::path::{Path, PathBuf};

use MapRangeImpl;

pub type Pid = pid_t;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MapRange {
    range_start: usize,
    range_end: usize,
    protection: c_int,
    offset: usize,
    vnode: usize,
    pathname: Option<PathBuf>,
}

impl MapRangeImpl for MapRange {
    fn size(&self) -> usize {
        self.range_end - self.range_start
    }
    fn start(&self) -> usize {
        self.range_start
    }
    fn filename(&self) -> Option<&Path> {
        self.pathname.as_deref()
    }
    fn is_read(&self) -> bool {
        self.protection & protection::VM_PROT_READ != 0
    }
    fn is_write(&self) -> bool {
        self.protection & protection::VM_PROT_WRITE != 0
    }
    fn is_exec(&self) -> bool {
        self.protection & protection::VM_PROT_EXECUTE != 0
    }
}

impl From<ptrace::VmEntry> for MapRange {
    fn from(vm_entry: ptrace::VmEntry) -> Self {
        Self {
            range_start: vm_entry.pve_start as usize,
            range_end: vm_entry.pve_end as usize,
            protection: vm_entry.pve_prot as _,
            offset: vm_entry.pve_offset as usize,
            vnode: vm_entry.pve_fileid as usize,
            pathname: vm_entry.pve_path,
        }
    }
}

pub fn get_process_maps(pid: Pid) -> std::io::Result<Vec<MapRange>> {
    let iter = ptrace::VmEntryIterator::new(pid)?;

    Ok(iter.map(MapRange::from).collect())
}

#[test]
fn test_write_xor_execute_policy() -> () {
    use std::process::Command;
    let mut child = Command::new("/bin/cat")
        .spawn()
        .expect("failed to execute /bin/cat");

    let maps = get_process_maps(child.id() as Pid).unwrap();

    child.kill().expect("failed to kill test process");

    assert!(maps.len() > 0, "No process maps were found");

    let write_and_exec_regions = maps.iter().any(|x| x.is_write() && x.is_exec());

    assert!(!write_and_exec_regions, "W^X violation!");
}
