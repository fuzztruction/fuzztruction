proc-maps
=========
[![Build Status](https://github.com/acj/proc-maps/actions/workflows/ci.yml/badge.svg)](https://github.com/rbspy/proc-maps/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/proc-maps.svg)](https://crates.io/crates/proc-maps)
[![docs.rs](https://docs.rs/proc-maps/badge.svg)](https://docs.rs/proc-maps)

This crate supports reading virtual memory maps from another process - and supports
Linux, macOS, Windows, and FreeBSD operating systems.

Example:

``` rust
use proc_maps::get_process_maps;

let maps = get_process_maps(pid)?;
for map in maps {
    println!("Filename {:?} Address {} Size {}", map.filename(), map.start(), map.size());
}

```

This code was originally developed by [Julia Evans](https://github.com/jvns) as part of the rbspy project: https://github.com/rbspy/rbspy.

Release under the MIT License.
