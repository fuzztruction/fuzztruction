use log::log_enabled;
use nix::sys::signal::Signal;
use std::{
    alloc,
    convert::TryInto,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

pub trait ExpectNone {
    /// Whether this value is None.
    fn is_none(&self) -> bool;

    /// Panics with the given message if the value is not None.
    #[track_caller]
    fn expect_none(&self, msg: &str) {
        if !self.is_none() {
            panic!("Expected None: {}", msg);
        }
    }

    /// Panic if the value is not None.
    #[track_caller]
    fn unwrap_none(&self) {
        if !self.is_none() {
            panic!("Expected to unwrap a None, but got Some");
        }
    }
}

impl<E> ExpectNone for Option<E> {
    fn is_none(&self) -> bool {
        self.is_none()
    }
}

pub fn get_layout<T>(size: usize) -> alloc::Layout {
    let layout = alloc::Layout::new::<T>();
    let alignment = layout.align();
    alloc::Layout::from_size_align(size, alignment).unwrap()
}

/// Alloc a Box with the given `size` and with the correct alignment for T.
/// If `size` is smaller than the size if T, this function panics.
pub fn alloc_box_aligned<T>(size: usize) -> Box<T> {
    unsafe {
        let layout = get_layout::<T>(size);
        assert!(size >= layout.size());
        let buf = alloc::alloc(layout);
        Box::from_raw(buf as *mut T)
    }
}

/// Alloc a Box with the given `size` and with the correct alignment for T.
/// Furthermore, the returned memory is initialized to zero.
/// If `size` is smaller than the size if T, this function panics.
pub fn alloc_box_aligned_zeroed<T>(size: usize) -> Box<T> {
    unsafe {
        let layout = get_layout::<T>(size);
        assert!(size >= layout.size());
        let buf = alloc::alloc_zeroed(layout);
        Box::from_raw(buf as *mut T)
    }
}

pub fn current_log_level() -> log::Level {
    if log_enabled!(log::Level::Trace) {
        log::Level::Trace
    } else if log_enabled!(log::Level::Debug) {
        log::Level::Debug
    } else if log_enabled!(log::Level::Info) {
        log::Level::Info
    } else if log_enabled!(log::Level::Warn) {
        log::Level::Warn
    } else if log_enabled!(log::Level::Error) {
        log::Level::Error
    } else {
        unreachable!();
    }
}

pub fn try_get_child_exit_reason(pid: i32) -> Option<(Option<i32>, Option<Signal>)> {
    let status: libc::c_int = 0;
    let ret = unsafe {
        let pid = pid;
        libc::waitpid(pid, status as *mut libc::c_int, libc::WNOHANG)
    };
    log::info!("waitpid={}, status={}", ret, status);
    if ret > 0 {
        // Child exited
        let mut exit_code = None;
        if libc::WIFEXITED(status) {
            exit_code = Some(libc::WEXITSTATUS(status));
        }
        let mut signal = None;
        if libc::WIFSIGNALED(status) {
            signal = Some(libc::WTERMSIG(status).try_into().unwrap());
        }
        return Some((exit_code, signal));
    }
    None
}

pub fn interruptable_sleep(duration: Duration, interrupt_signal: &Arc<AtomicBool>) -> bool {
    let second = Duration::from_secs(1);
    assert!(duration > second);

    let mut duration_left = duration;
    while duration_left > second {
        if interrupt_signal.load(Ordering::Relaxed) {
            return true;
        }
        thread::sleep(second);
        duration_left = duration_left.saturating_sub(second);
    }
    thread::sleep(duration_left);
    false
}

#[cfg(test)]
mod test {
    use super::*;
    use std::slice;

    #[test]
    fn test_alloc_box_aligned() {
        let val: u64 = 5;
        let s = std::mem::size_of_val(&val);
        for _ in 0..256 {
            let b = alloc_box_aligned::<u64>(s);
            drop(b);
        }
    }

    #[test]
    fn test_alloc_box_aligned_zeroed() {
        let size = 4096 * 3 + 5;
        let mut e: Box<u8> = alloc_box_aligned_zeroed(size);

        let s = unsafe { slice::from_raw_parts_mut(e.as_mut() as *mut u8, size) };
        s.fill(0xff);
    }
}
