//! Get virtual memory maps from another process
//!
//! This crate provides a function—[`get_process_maps`](linux_maps/fn.get_process_maps.html)
//! that returns a Vec of [`MapRange`](linux_maps/struct.MapRange.html) structs.
//!
//! This code works on Linux, OSX and Windows. Each operating system has different
//! implementations, but the functions and struct's for each OS share the same
//! interface - so this can be used generically across operating systems.
//!
//! Note: on OSX this requires root access, and even with root will still not
//! work on processes that have System Integrity Protection enabled
//! (anything in /usr/bin for example).
//!
//! # Example
//!
//! ```rust,no_run
//! use proc_maps::{get_process_maps, MapRange, Pid};
//!
//! let maps = get_process_maps(123456 as Pid).unwrap();
//! for map in maps {
//!    println!("Filename {:?} Address {} Size {}", map.filename(), map.start(), map.size());
//! }
//! ```

extern crate libc;
extern crate serde;

#[cfg(target_os = "macos")]
extern crate anyhow;
#[cfg(target_os = "macos")]
extern crate libproc;
#[cfg(target_os = "macos")]
extern crate mach;
#[cfg(windows)]
extern crate winapi;

#[cfg(target_os = "macos")]
pub mod mac_maps;
#[cfg(target_os = "macos")]
pub use mac_maps::{get_process_maps, MapRange, Pid};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_maps;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use crate::linux_maps::{get_process_maps, MapRange, Pid};

#[cfg(windows)]
pub mod win_maps;
#[cfg(windows)]
pub use win_maps::{get_process_maps, MapRange, Pid};

#[cfg(target_os = "freebsd")]
pub mod freebsd_maps;
#[cfg(target_os = "freebsd")]
pub use freebsd_maps::{get_process_maps, MapRange, Pid};

fn map_contain_addr(map: &MapRange, addr: usize) -> bool {
    let start = map.start();
    (addr >= start) && (addr < (start + map.size()))
}

/// Returns whether or not any MapRange contains the given address
/// Note: this will only work correctly on OSX and Linux.
pub fn maps_contain_addr(addr: usize, maps: &[MapRange]) -> bool {
    maps.iter().any(|map| map_contain_addr(map, addr))
}
