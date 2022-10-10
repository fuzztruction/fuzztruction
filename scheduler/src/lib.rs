// #![allow(
//     clippy::all,
//     clippy::print_literal,
// )]
// #![warn(
//     clippy::perf,
//     variant_size_differences,
//     clippy::redundant_pattern,
// )]
#![allow(clippy::vec_box, clippy::identity_op, clippy::single_match)]
#![deny(
    clippy::correctness,
    clippy::cast_possible_wrap,
    unused_lifetimes,
    unused_unsafe,
    single_use_lifetimes,
    missing_debug_implementations
)]
#![feature(
    hash_drain_filter,
    new_uninit,
    slice_as_chunks,
    seek_stream_len,
    assert_matches,
    drain_filter,
    thread_id_value,
    core_intrinsics
)]

extern crate lazy_static;

pub use fuzztruction_shared::dwarf;
pub use fuzztruction_shared::messages;
pub use fuzztruction_shared::mutation_cache;
pub use llvm_stackmap;

//pub mod mutation;
pub mod checks;
pub mod io_channels;
pub mod mutation_cache_ops;
pub mod patchpoint;
pub mod sink;
pub mod sink_bitmap;
pub mod source;
pub mod trace;

pub mod config;
pub mod error;
pub mod fuzzer;
pub mod logging;

pub mod constants;

pub mod tracer;
pub mod valgrind;

pub mod aflpp;
