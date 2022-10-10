use libc::mprotect;

pub const PAGE_SIZE: usize = 4096;

macro_rules! align_to_page {
    ($val:expr) => {
        (($val) & !0xfff)
    };
}

#[derive(Debug, Default, Copy, Clone)]
pub struct PermsConfig {
    is_exec: bool,
    is_read: bool,
    is_write: bool,
}

pub struct MappedMemoryConfig {
    start_addr: usize,
    size: usize,
    perms: PermsConfig,
}

impl MappedMemoryConfig {
    pub fn new(start_addr: usize, size: usize) -> MappedMemoryConfig {
        assert!(size > 0);

        MappedMemoryConfig {
            start_addr,
            size,
            perms: PermsConfig::default(),
        }
    }

    pub fn exec(&mut self, state: bool) -> &mut MappedMemoryConfig {
        self.perms.is_exec = state;
        self
    }

    pub fn read(&mut self, state: bool) -> &mut MappedMemoryConfig {
        self.perms.is_read = state;
        self
    }

    pub fn write(&mut self, state: bool) -> &mut MappedMemoryConfig {
        self.perms.is_write = state;
        self
    }

    pub fn reset(&mut self) -> &mut MappedMemoryConfig {
        self.perms = PermsConfig::default();
        self
    }

    pub fn save_perms(&mut self, perms: &mut PermsConfig) -> &mut MappedMemoryConfig {
        *perms = self.perms;
        self
    }

    pub fn load_perms(&mut self, perms: &PermsConfig) -> &mut MappedMemoryConfig {
        self.perms = *perms;
        self
    }

    pub fn commit(&self) -> Result<(), ()> {
        unsafe {
            let addr = align_to_page!(self.start_addr);
            let len = PAGE_SIZE
                + (align_to_page!(self.start_addr + self.size - 1)
                    - align_to_page!(self.start_addr));
            assert!(len > 0 && (len % PAGE_SIZE) == 0);

            let mut perms = libc::PROT_NONE;
            if self.perms.is_exec {
                perms |= libc::PROT_EXEC;
            }

            if self.perms.is_read {
                perms |= libc::PROT_READ;
            }

            if self.perms.is_write {
                perms |= libc::PROT_WRITE;
            }

            let ret = mprotect(addr as *mut libc::c_void, len as usize, perms);

            if ret != 0 {
                return Err(());
            }
        }
        Ok(())
    }
}
