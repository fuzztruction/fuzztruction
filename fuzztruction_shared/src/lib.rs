#![allow(clippy::all)]
#![feature(new_uninit)]
#![feature(assert_matches)]
#![feature(slice_as_chunks)]
#![feature(exclusive_range_pattern)]

pub mod abi;
pub mod alarm_timer;
pub mod communication_channel;
pub mod dwarf;
pub mod messages;
//pub mod mutation_cache;
pub mod mutation_cache;
pub mod mutation_cache_content;
pub mod mutation_cache_entry;
pub mod types;
pub mod util;

pub mod aux_messages;
pub mod aux_stream;

pub mod constants;
pub mod log_utils;

pub mod eval;
