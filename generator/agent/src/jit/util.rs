/// Check whether `len` bytes starting from `addr` are mapped and readable.
pub fn is_readable_mem_range(addr: *const u8, len: usize) -> bool {
    unsafe {
        let mut pipe = [0i32; 2];
        let ret = libc::pipe(pipe.as_mut_ptr());
        if ret != 0 {
            let msg = "Failed to create pipe";
            log::error!("{}", msg);
            panic!("{}", msg);
        }

        let mut bytes_left = len;
        let mut read_ptr = addr;
        while bytes_left > 0 {
            let ret = libc::write(pipe[1], read_ptr as *const libc::c_void, bytes_left);
            if ret < 0 {
                log::warn!(
                    "is_readable_mem_range -> false. err={:?}",
                    std::io::Error::last_os_error()
                );
                libc::close(pipe[0]);
                libc::close(pipe[1]);
                return false;
            }
            read_ptr = read_ptr.offset(ret);
            bytes_left -= ret as usize;
        }
        libc::close(pipe[0]);
        libc::close(pipe[1]);
        return true;
    }
}
