use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::ArgMatches;
use scheduler::{aflpp::run_aflpp_mode, config::Config, tracer, valgrind};
use std::thread;

use scheduler::fuzzer::campaign::FuzzingCampaign;

use crate::{
    benchmark, drop_privileges_permanently, register_on_termination_flag, test_patchpoints,
    util::CliDuration, CAMPAIN_DUMP_INTERVAL,
};

pub(crate) fn handle_cli_test_patchpoints_subcommand(
    config: &Config,
    test_patch_point_matches: &ArgMatches,
) {
    test_patchpoints::run(
        config,
        test_patch_point_matches.is_present("with-mutations"),
    )
}

pub(crate) fn handle_cli_fuzz_subcommand(
    fuzz_matches: &ArgMatches,
    config: scheduler::config::Config,
    termination_requested_flag: Arc<AtomicBool>,
) {
    let timeout = fuzz_matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .unwrap()
        .0;
    // if timeout.as_secs() > 600
    //     && (config.source.log_stderr
    //         || config.source.log_stdout
    //         || config.sink.log_stderr
    //         || config.sink.log_stdout)
    // {
    //     log::error!(
    //         "Please disable logging for source and sink to avoid filesystem space exhaustion."
    //     );
    //     return;
    // }

    let job_cnt = fuzz_matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();
    let mut campaign = FuzzingCampaign::new(&config).unwrap();
    campaign.start(job_cnt).unwrap();
    log::info!("Fuzzing campaign timeout is set to {:?}", timeout);

    let start_ts = Instant::now();
    let mut last_dump_ts = Instant::now();

    while start_ts.elapsed() < timeout {
        if termination_requested_flag.load(std::sync::atomic::Ordering::Relaxed) {
            log::info!("Termination was requested. Shutting down.");
            break;
        }
        if !campaign.is_any_worker_alive() {
            log::info!("All workers terminated. Shutting down.");
            break;
        }
        if last_dump_ts.elapsed() > CAMPAIN_DUMP_INTERVAL {
            log::info!("Dumping campaign to disk");
            last_dump_ts = Instant::now();
            if let Err(err) = campaign.dump() {
                log::error!("Dumping failed: {:#?}", err);
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    if let Err(err) = campaign.shutdown() {
        log::error!("Error while stopping campaign: {:#?}", err);
    }
    campaign.dump().unwrap();
}

pub(crate) fn handle_cli_benchmark_subcommand(
    benchmark_matches: &ArgMatches,
    config: &scheduler::config::Config,
) {
    let iter_cnt = benchmark_matches
        .value_of("iter-cnt")
        .map(|e| e.parse().unwrap())
        .unwrap();
    let max_mutations = benchmark_matches
        .value_of("max-mutations")
        .map(|v| v.parse().unwrap());
    let sink_exec_prop = benchmark_matches
        .value_of("sink-exec-prop")
        .map(|v| v.parse().unwrap())
        .unwrap();
    benchmark::benchmark_target(
        config,
        iter_cnt,
        benchmark_matches.is_present("with-mutations"),
        max_mutations,
        sink_exec_prop,
    );
}

pub(crate) fn handle_cli_valgrind_subcommand(
    valgrind_matches: &ArgMatches,
    config: &scheduler::config::Config,
    termination_requested_flag: Arc<AtomicBool>,
) -> Result<()> {
    let input_dirs = valgrind_matches.values_of_lossy("input-dirs");
    let input_dirs = input_dirs
        .unwrap_or_default()
        .into_iter()
        .map(|path| path.into())
        .collect();
    drop_privileges_permanently(config)?;

    let job_cnt = valgrind_matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap());

    let mut valgrind = valgrind::ValgrindManager::from_config(
        config,
        input_dirs,
        job_cnt,
        termination_requested_flag,
    )?;
    if valgrind_matches.is_present("once") {
        valgrind.queue_new_inputs()?;
        valgrind.run()?;
    } else {
        valgrind.start()?;
    }
    Ok(())
}

pub(crate) fn handle_cli_aflpp_subcommand(matches: &ArgMatches, config: &Config) -> Result<()> {
    drop_privileges_permanently(config)?;

    let termination_flag = register_on_termination_flag();
    let values = matches.values_of_lossy("i");
    let input_dirs: Option<Vec<String>> = values
        .unwrap_or_default()
        .into_iter()
        .map(|path| path.into())
        .collect();
    let timeout = matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0);
    let job_cnt = matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();
    let symcc_job_cnt = matches
        .value_of("symcc-jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();
    let weizz_job_cnt = matches
        .value_of("weizz-jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();

    let input_dirs = input_dirs.map(|dirs| {
        dirs.into_iter()
            .map(|path| PathBuf::from(&path))
            .collect::<Vec<_>>()
    });

    let runner = run_aflpp_mode(
        config.clone(),
        input_dirs,
        job_cnt,
        symcc_job_cnt,
        weizz_job_cnt,
        termination_flag,
        timeout,
    )?;
    runner.join()?;

    Ok(())
}

pub(crate) fn handle_cli_trace_subcommand(
    trace_matches: &ArgMatches,
    config: &Config,
) -> Result<()> {
    let termination_flag = register_on_termination_flag();
    let values = trace_matches.values_of_lossy("i");
    let input_dirs = values
        .unwrap_or_default()
        .into_iter()
        .map(|path| path.into())
        .collect();
    let timeout = trace_matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0);
    let job_cnt = trace_matches.value_of("jobs").map(|e| e.parse().unwrap());

    tracer::trace_interesting(config, input_dirs, termination_flag, job_cnt, timeout)?;
    Ok(())
}
