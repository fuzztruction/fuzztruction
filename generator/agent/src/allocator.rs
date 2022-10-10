use std::alloc::{GlobalAlloc, System};

pub struct MyAllocator;

static ALLOCATION_SIZE_THRESHHOLD: usize = 4096;

unsafe impl GlobalAlloc for MyAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if layout.size() > ALLOCATION_SIZE_THRESHHOLD {
            let buffer = libc::mmap(
                0 as *mut libc::c_void,
                layout.size(),
                libc::PROT_WRITE | libc::PROT_READ,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                0,
                0,
            );
            assert!(buffer != libc::MAP_FAILED);
            return buffer as *mut u8;
        } else {
            System.alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        if layout.size() > ALLOCATION_SIZE_THRESHHOLD {
            libc::munmap(ptr as *mut libc::c_void, layout.size());
        } else {
            System.dealloc(ptr, layout)
        }
    }
}

#[global_allocator]
static A: MyAllocator = MyAllocator;
