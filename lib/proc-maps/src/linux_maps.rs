use libc;
use std;
use std::fs::File;
use std::io::Read;

pub type Pid = libc::pid_t;
use serde::{Deserialize, Serialize};

/// A struct representing a single virtual memory region
/// While this structure only is for Linux, the OSX, Windows, and FreeBSD
/// variants have identical exposed methods
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct MapRange {
    range_start: usize,
    range_end: usize,
    pub offset: usize,
    pub dev: String,
    pub flags: String,
    pub inode: usize,
    pub pathname: Option<String>,
}

impl MapRange {
    /// Returns the size of this MapRange in bytes
    pub fn size(&self) -> usize {
        self.range_end - self.range_start
    }
    /// Returns the address this MapRange starts at
    pub fn start(&self) -> usize {
        self.range_start
    }
    /// Returns the filename of the loaded module
    pub fn filename(&self) -> &Option<String> {
        &self.pathname
    }
    /// Returns whether this range contains executable code
    pub fn is_exec(&self) -> bool {
        &self.flags[2..3] == "x"
    }
    /// Returns whether this range contains writeable memory
    pub fn is_write(&self) -> bool {
        &self.flags[1..2] == "w"
    }
    /// Returns whether this range contains readable memory
    pub fn is_read(&self) -> bool {
        &self.flags[0..1] == "r"
    }
}

/// Gets a Vec of [`MapRange`](linux_maps/struct.MapRange.html) structs for
/// the passed in PID. (Note that while this function is for linux, the OSX,
/// Windows, and FreeBSD variants have the same interface)
pub fn get_process_maps(pid: Pid) -> std::io::Result<Vec<MapRange>> {
    // Parses /proc/PID/maps into a Vec<MapRange>
    let maps_file = format!("/proc/{}/maps", pid);
    let mut file = File::open(maps_file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(parse_proc_maps(&contents))
}

fn parse_proc_maps(contents: &str) -> Vec<MapRange> {
    let mut vec: Vec<MapRange> = Vec::new();
    for line in contents.split('\n') {
        let mut split = line.split_whitespace();
        let range = split.next();
        if range.is_none() {
            break;
        }
        let mut range_split = range.unwrap().split('-');
        let range_start = range_split.next().unwrap();
        let range_end = range_split.next().unwrap();
        let flags = split.next().unwrap();
        let offset = split.next().unwrap();
        let dev = split.next().unwrap();
        let inode = split.next().unwrap();

        vec.push(MapRange {
            range_start: usize::from_str_radix(range_start, 16).unwrap(),
            range_end: usize::from_str_radix(range_end, 16).unwrap(),
            offset: usize::from_str_radix(offset, 16).unwrap(),
            dev: dev.to_string(),
            flags: flags.to_string(),
            inode: str::parse(inode).unwrap(),
            pathname: Some(split.collect::<Vec<&str>>().join(" ")).filter(|x| !x.is_empty()),
        });
    }
    vec
}

#[test]
fn test_parse_maps() {
    let contents = include_str!("../ci/testdata/map.txt");
    let vec = parse_proc_maps(contents);
    let expected = vec![
        MapRange {
            range_start: 0x00400000,
            range_end: 0x00507000,
            offset: 0,
            dev: "00:14".to_string(),
            flags: "r-xp".to_string(),
            inode: 205736,
            pathname: Some("/usr/bin/fish".to_string()),
        },
        MapRange {
            range_start: 0x00708000,
            range_end: 0x0070a000,
            offset: 0,
            dev: "00:00".to_string(),
            flags: "rw-p".to_string(),
            inode: 0,
            pathname: None,
        },
        MapRange {
            range_start: 0x0178c000,
            range_end: 0x01849000,
            offset: 0,
            dev: "00:00".to_string(),
            flags: "rw-p".to_string(),
            inode: 0,
            pathname: Some("[heap]".to_string()),
        },
        MapRange {
            range_start: 0x7f438053b000,
            range_end: 0x7f438053f000,
            offset: 0,
            dev: "fd:01".to_string(),
            flags: "r--p".to_string(),
            inode: 59034409,
            pathname: Some(
                "/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.4200.6 (deleted)".to_string(),
            ),
        },
    ];
    assert_eq!(vec, expected);

    // Also check that maps_contain_addr works as expected
    assert!(super::maps_contain_addr(0x00400000, &vec));
    assert!(!super::maps_contain_addr(0x00300000, &vec));
}
