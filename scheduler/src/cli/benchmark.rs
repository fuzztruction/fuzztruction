use std::collections::HashSet;
use std::hash::Hasher;
use std::time;
#[allow(clippy::all)]
use std::time::Instant;

use ahash::AHasher;
use scheduler::config::Config;
use scheduler::fuzzer::queue::Input;
use scheduler::mutation_cache::MutationCache;
use scheduler::mutation_cache_ops::MutationCacheOpsEx;

use scheduler::source::RunResult;

use scheduler::sink::{self, AflSink};
use scheduler::source::Source;

use llvm_stackmap::StackMap;
use rand::Rng;

pub fn benchmark_target(
    config: &Config,
    iter_cnt: usize,
    with_mutations: bool,
    max_mutations: Option<usize>,
    sink_exec_prop: f64,
) {
    assert!((0f64..=1f64).contains(&sink_exec_prop));

    let mut tmp_buffer = Vec::<u8>::new();
    let mut source = Source::from_config(config, None).unwrap();
    let mut sink = AflSink::from_config(config, None).unwrap();
    source.start().expect("Failed to start source");
    sink.start().expect("Failed to start sink");

    let inputs = Input::from_dir(&config.general.input_dir).unwrap();
    let first_input = inputs.get(0).unwrap();
    let mut virgin_map = sink.bitmap().clone_with_pattern(0xff);

    let patchpoints = source.get_patchpoints().unwrap();
    println!("Target binary has {:#?} patch points.", patchpoints.len());

    //let patchpoints = patchpoints.iter().cloned().take(5000).collect::<Vec<_>>();

    if with_mutations {
        let mcache = MutationCache::from_patchpoints(patchpoints.iter()).unwrap();
        source.mutation_cache_replace(&mcache).unwrap();

        log::info!("Tracing target, this might take some seconds...");
        log::info!("Timeout is {:?}", config.general.tracing_timeout);
        let tracing_start_ts = time::Instant::now();

        source.write(first_input.data());
        let trace_result = source.trace(config.general.tracing_timeout);
        source.read(&mut tmp_buffer);
        if let Err(err) = trace_result {
            source.stop().unwrap();
            sink.stop();
            log::info!("Logs can be found at {:?}", config.general.work_dir);
            panic!("Failed to trace target: {:#?}", err);
        }
        log::info!("Tracing took {:?}", tracing_start_ts.elapsed());
        let trace_result = trace_result.unwrap();
        log::info!(
            "Tracing result {:#?}. Covered {} patch points",
            trace_result.0,
            trace_result.1.len()
        );

        match trace_result.0 {
            RunResult::Terminated { .. } => (),
            result => {
                source.stop().unwrap();
                sink.stop();
                log::info!("Logs can be found at {:?}", config.general.work_dir);
                panic!("Failed to trace target! run_result={:#?}", result)
            }
        }

        let trace = trace_result.1;
        source.mutation_cache_apply_fn_mut(|m| {
            unsafe {
                m.resize_covered_entries(&trace);
                m.remove_uncovered(&trace);
            }
            m.reset_flags();
        });

        if let Some(max_mutations) = max_mutations {
            log::info!(
                "Limit was set! Removing all but {} mutation entries.",
                max_mutations
            );
            let mc = source.mutation_cache();
            let mut mc_mut = mc.borrow_mut();
            mc_mut.limit(max_mutations);
        }

        let mc = source.mutation_cache();
        let mc_ref = mc.borrow();
        let mc_total_size = mc_ref.total_size();
        let mc_bytes_used = mc_ref.bytes_used();
        log::info!(
            "Mutation Cache: {} bytes of {} used ({:.2}%)",
            mc_bytes_used,
            mc_total_size,
            mc_bytes_used as f64 / mc_total_size as f64 * 100.0
        );

        source.sync_mutations().unwrap();
    }

    for input in inputs {
        log::info!("Benchmarking input {:?}", input);
        let mut source_output_hashes = HashSet::new();
        let mut sink_hashes: HashSet<u32> = HashSet::new();

        let mut rng = rand::thread_rng();
        let now = Instant::now();

        log::info!("Benchmarking over {} iterations...", iter_cnt);
        let mut print_empty_output_once = true;

        for _ in 0..iter_cnt {
            source.write(input.data());

            let run_result = source.run(config.general.timeout).unwrap();
            match run_result {
                ref _x @ RunResult::Terminated { .. } => (),
                _ => {
                    log::error!("Unexpected RunResult: {:?}", run_result);
                    unreachable!();
                }
            }
            source.read(&mut tmp_buffer);
            if tmp_buffer.is_empty() && print_empty_output_once {
                print_empty_output_once = false;
                log::error!("Unmutated source did not produce any output!");
            }

            let mut hasher = AHasher::default();
            hasher.write(&tmp_buffer);
            let digest = hasher.finish();
            source_output_hashes.insert(digest);

            let r = rng.gen_range(0.0..1.0);
            if r < sink_exec_prop {
                sink.write(&tmp_buffer);
                let ret = sink.run(config.general.timeout).unwrap();
                match ret {
                    sink::RunResult::Terminated(..) => {
                        let bm = sink.bitmap();
                        bm.classify_counts();
                        bm.has_new_bit(&mut virgin_map);
                        sink_hashes.insert(bm.hash32());
                    }
                    _ => unreachable!(
                        "Unexpected result during sink execution: {ret:#?}",
                        ret = ret
                    ),
                }
            }
        }

        log::info!("source output #hashes: {:?}", source_output_hashes.len(),);
        if source_output_hashes.len() > 1 {
            log::warn!("Source produces varing outputs!");
        }

        log::info!("sink coverage #hashes: {:?}", sink_hashes.len(),);
        if sink_hashes.len() > 1 {
            log::warn!("Sink produces varying coverage!")
        }

        log::info!(
            "execs/s  : {:.2}",
            iter_cnt as f64 / now.elapsed().as_secs_f64()
        );
    }

    source.stop().unwrap();
    sink.stop();
    log::info!("Logs can be found at {:?}", config.general.work_dir);
}

#[allow(unused)]
pub fn benchmark_stackmap_parser(config: &Config) {
    let target_path = &config.source.bin_path;
    let start_ts = time::Instant::now();
    println!("Starting parsing");
    let sm = StackMap::from_path(target_path).unwrap();
    println!("Parsing took {} seconds", start_ts.elapsed().as_secs());
}
