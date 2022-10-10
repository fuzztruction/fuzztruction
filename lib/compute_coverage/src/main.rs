use flate2::read::ZlibDecoder;

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    fs,
    io::Write,
    mem,
    path::{Path, PathBuf},
    sync::{Arc, RwLock}, process::exit
};

use rand::seq::SliceRandom;
use rand::thread_rng;

use fuzztruction_shared::eval::coverage_trace::{self};
use lazy_static::lazy_static;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct TimestampInS(u64);

impl Display for TimestampInS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}s", self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct BasicBlock {
    module_name: Arc<String>,
    offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BasicBlockWithTs {
    module_name: Arc<String>,
    offset: u64,
    found_ts_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Trace {
    timestamp_ms: u64,
    bbs: Vec<BasicBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Run {
    workdir: PathBuf,
    /// Traces sorted (accending) according to their timestamps.
    sorted_traces: Vec<Trace>,
}

lazy_static! {
    static ref MODULES_SET: RwLock<HashSet<Arc<String>>> = RwLock::new(HashSet::new());
}

fn update_module_names(trace: &coverage_trace::Trace) {
    let module_set_ro = MODULES_SET.read().unwrap();
    let mut missing_module = false;
    for name in trace.id_to_name.values() {
        if !module_set_ro.contains(name) {
            missing_module = true;
            break;
        }
    }
    mem::drop(module_set_ro);

    if missing_module {
        let mut module_set_rw = MODULES_SET.write().unwrap();
        for name in trace.id_to_name.values() {
            if !module_set_rw.contains(name) {
                module_set_rw.insert(Arc::new(name.clone()));
            }
        }
    }
}

fn get_module_name(trace: &coverage_trace::Trace, bb: &coverage_trace::BasicBlock) -> Arc<String> {
    let mod_id = bb.module_id;
    let name = trace
        .id_to_name
        .iter()
        .find(|entry| *entry.0 == mod_id)
        .unwrap()
        .1;
    let module_set_ro = MODULES_SET.read().unwrap();
    let name = module_set_ro.get(name).unwrap();
    Arc::clone(name)
}

impl BasicBlock {
    fn from_trace_bb(trace: &coverage_trace::Trace, bb: &coverage_trace::BasicBlock) -> BasicBlock {
        let module_name = get_module_name(trace, bb);
        let offset = bb.address;
        BasicBlock {
            module_name,
            offset,
        }
    }
}

impl Trace {
    fn from_trace<F>(path: &Path, module_filter: Option<F>) -> Trace
    where
        F: Fn(&str) -> bool + std::marker::Sync,
    {
        let trace = fs::read(path).unwrap();
        let decoder = ZlibDecoder::new(&trace[..]);
        let trace: coverage_trace::Trace = serde_json::from_reader(decoder).unwrap();
        let timestamp_ms = trace.timestamp_ms;

        update_module_names(&trace);

        let mut bbs = Vec::with_capacity(trace.basic_blocks.len());
        for bb in trace.basic_blocks.iter() {
            let parsed_bb = BasicBlock::from_trace_bb(&trace, bb);
            if module_filter
                .as_ref()
                .map(|filter| filter(&parsed_bb.module_name))
                .unwrap_or(true)
            {
                bbs.push(parsed_bb);
            }
        }
        Trace { timestamp_ms, bbs }
    }

    fn basic_blocks(&self) -> &[BasicBlock] {
        &self.bbs[..]
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
}

impl Run {
    fn from_workdir<F>(path: impl AsRef<Path>, module_filter: Option<F>) -> Option<Run>
    where
        F: Fn(&str) -> bool + std::marker::Sync + std::marker::Send + Copy,
    {
        let path_as_string = path.as_ref().to_str().unwrap();
        let path_as_string = format!("{path_as_string}/traces/*");
        let trace_paths = glob::glob(&path_as_string)
            .unwrap()
            .flatten()
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut traces: Vec<Option<Trace>> = vec![None; trace_paths.len()];
        if traces.is_empty() {
            println!("Skipping empty directory");
            return None;
        }

        let _trace_cnt = trace_paths.len();
        //             .progress_count(trace_cnt as u64)
        trace_paths
            .into_iter()
            .zip(&mut traces)
            .par_bridge()
            .into_par_iter()
            .for_each(|e| {
                let trace = Trace::from_trace(&e.0, module_filter);
                e.1.replace(trace);
            });

        let mut traces: Vec<Trace> = traces.into_iter().flatten().collect();
        traces.sort_by_key(|trace| trace.timestamp_ms);

        // remove duplicates, keep the one with the lowest ts
        let mut filtered_traces = Vec::new();
        traces.reverse();
        loop {
            let trace = traces.pop();
            if trace.is_none() {
                break;
            }
            let trace = trace.unwrap();
            traces.retain(|t| t.basic_blocks() != trace.basic_blocks());
            filtered_traces.push(trace);
        }

        Some(Run {
            workdir: path.as_ref().to_owned(),
            sorted_traces: filtered_traces,
        })
    }

    fn covered_bbs(&self) -> Vec<BasicBlockWithTs> {
        let mut ret = HashSet::new();
        let mut bb_to_ts: HashMap<&BasicBlock, u64> = HashMap::new();

        for trace in &self.sorted_traces {
            let bbs = trace.basic_blocks().iter();
            for bb in bbs {
                let entry = bb_to_ts.entry(bb).or_insert_with(|| trace.timestamp_ms());
                if *entry > trace.timestamp_ms() {
                    *entry = trace.timestamp_ms();
                }
                ret.insert(bb);
            }
        }
        let mut ret_with_ts = Vec::new();
        for bb in ret.into_iter() {
            let b = BasicBlockWithTs {
                module_name: bb.module_name.clone(),
                offset: bb.offset,
                found_ts_ms: *bb_to_ts.get(bb).unwrap(),
            };
            ret_with_ts.push(b);
        }

        ret_with_ts
    }

    fn ts_to_bbs_covered(&self) -> HashMap<TimestampInS, HashSet<&BasicBlock>> {
        let mut ret = HashMap::new();
        for trace in self.sorted_traces.iter() {
            let ts = TimestampInS(trace.timestamp_ms() / 1000);
            let bbs = trace.basic_blocks().iter().collect::<HashSet<_>>();
            ret.entry(ts)
                .and_modify(|entry: &mut HashSet<&BasicBlock>| {
                    entry.extend(bbs.iter());
                })
                .or_insert(bbs);
        }
        ret
    }

    fn ts_to_new_covered_bss(&self) -> HashMap<TimestampInS, HashSet<&BasicBlock>> {
        let mut ret = HashMap::new();
        let mut ts_to_bbs = self.ts_to_bbs_covered().into_iter().collect::<Vec<_>>();
        ts_to_bbs.sort_by_key(|e| e.0 .0);

        let mut seen_bbs = HashSet::new();
        for (ts, bbs) in ts_to_bbs.into_iter() {
            let new_bbs = bbs.difference(&seen_bbs).copied().collect::<HashSet<_>>();
            ret.entry(ts)
                .and_modify(|e: &mut HashSet<&BasicBlock>| e.extend(new_bbs.iter()))
                .or_insert_with(|| new_bbs.clone());
            seen_bbs.extend(new_bbs);
        }

        ret
    }

    pub(crate) fn workdir(&self) -> &Path {
        &self.workdir
    }
}

fn module_filter_fn(module_name: &str) -> bool {
    let blacklist = [
        "/lib/x86_64-linux-gnu/libgcc_s.so",
        "/lib/x86_64-linux-gnu/libstdc++",
        "/lib/x86_64-linux-gnu/libc-",
        "/lib/x86_64-linux-gnu/libpthread",
        "/lib/x86_64-linux-gnu/libm-",
        "/lib/x86_64-linux-gnu/libdl",
        "/lib/x86_64-linux-gnu/ld-",
    ];

    for entry in blacklist {
        if module_name.contains(entry) {
            return false;
        }
    }
    true
}

fn compute_coverage_over_time(run: &Run) {
    let workdir = run.workdir();

    let mut report_path = workdir.to_owned();
    report_path.push("coverage.csv");

    if report_path.exists() {
        println!("{:?} already exists, skipping...", &report_path);
        return;
    }

    let ts_to_bbs = run.ts_to_new_covered_bss();
    let mut res = ts_to_bbs.iter().collect::<Vec<_>>();
    res.sort_by_key(|e| e.0);

    let mut report_path = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(report_path)
        .unwrap();
    report_path
        .write_all("ts_in_s;new_bbs_found\n".as_bytes())
        .unwrap();

    for (ts, bbs) in res {
        if !bbs.is_empty() {
            report_path
                .write_all(format!("{};{}\n", ts.0, bbs.len()).as_bytes())
                .unwrap();
        }
    }
}

fn compute_covered_bbs(run: &Run) {
    let workdir = run.workdir();

    let mut bbset_path = workdir.to_owned();
    bbset_path.push("covered_bbs.json");

    if bbset_path.exists() {
        println!("{:?} already exists, skipping...", &bbset_path);
        return;
    }
    let bbs = run.covered_bbs();

    let bbs = serde_json::to_string_pretty(&bbs).unwrap();
    fs::write(bbset_path, bbs.as_bytes()).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target-folder>", args[0]);
        eprintln!("    <target-folder> must contain subfolders that contain a subfolder traces.");
        eprintln!("    This program will generate a .csv that map time to #covered basic blocks");
        eprintln!("    and a .json that maps timestamps to sets of found basic blocks addresses.");
        exit(1);
    }

    let path = format!("{}/*", args[1]);

    let runs = glob::glob(&path).unwrap();
    let mut runs = runs.into_iter().flatten().collect::<Vec<_>>();
    runs.shuffle(&mut thread_rng());

    runs.iter().for_each(|run_workdir| {
        println!("Processing {:?}", run_workdir);

        let mut report_path = run_workdir.to_owned();
        report_path.push("coverage.csv");
        let mut bbset_path = run_workdir.to_owned();
        bbset_path.push("covered_bbs.json");

        if bbset_path.exists() && report_path.exists() {
            println!("Reports already generated, skipping");
            return;
        }

        {
            let run = Run::from_workdir(run_workdir, Some(module_filter_fn));
            if let Some(run) = run {
                compute_coverage_over_time(&run);
                compute_covered_bbs(&run);
            }
        }
    });
}
