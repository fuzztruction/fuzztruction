mod benchmark;
mod handler;
mod stackmap_parser;
mod test_patchpoints;
mod util;

use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use scheduler::logging::{self};

use scheduler::config::{Config, ConfigBuilder};

extern crate clap;
use clap::{Arg, ArgMatches, Command};
use scheduler::checks::{check_config, check_system};

use ansi_term::Colour::Red;

const CAMPAIN_DUMP_INTERVAL: Duration = Duration::from_secs(60);

fn parse_args() -> ArgMatches {
    let matches = Command::new("Fuzztruction")
        .version("1.0")
        .author("Nils Bars <nils.bars@rub.de>")
        .author("Moritz Schloegel <moritz.schloegel@rub.de>")
        .subcommand_required(true)
        .arg(
            Arg::new("config")
                .help("Path to the configuration file specifing the generator and consumer of the fuzzing campaign.")
                .value_name("config")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::new("log-level")
                .help("Log verbosity (alternative to --verbosity)")
                .value_name("trace, debug, info, warn, error, off")
                .long("log-level")
                .conflicts_with("verbosity")
                .takes_value(true)
                .required(false)
                .default_value("debug"),
        )
        .arg(
            Arg::new("verbosity")
                .short('v')
                .long("verbosity")
                .required(false)
                .multiple_occurrences(true)
                .conflicts_with("log-level")
                .help("Sets the level of verbosity (alternative to --log-level)"),
        )
        .arg(
            Arg::new("purge")
                .help("Purge any data from previous runs. Must be provided if the workdir exists")
                .long("purge")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::new("suffix")
                .help("Suffix appended to the workdir path provided via the config file\n(i.e., <WORKDIR>-<SUFFIX>)")
                .long("suffix")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::new("show-output")
                .help("Show stdout and stderr of the generator and the consumer. This becomes handy for debugging not working configurations")
                .long("show-output")
                .takes_value(false)
                .required(false),
        )
        .subcommand(
            Command::new("fuzz")
                .arg(
                    Arg::new("timeout")
                        .help("Timeout")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("60s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent jobs")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("benchmark")
                .arg(
                    Arg::new("iter-cnt")
                        .help("Iteration count")
                        .short('i')
                        .long("iter-cnt")
                        .takes_value(true)
                        .default_value("100"),
                )
                .arg(
                    Arg::new("with-mutations")
                        .long("with-mutations")
                        .help("Trace the source target and create mutations (with \x00 masks) for all covered patch points")
                        .takes_value(false)
                )
                .arg(
                    Arg::new("max-mutations")
                        .long("max-mutations")
                        .help("Limit the number of active mutations if --with-mutations is also passed")
                        .takes_value(true)
                        .requires("with-mutations")
                )
                .arg(
                    Arg::new("sink-exec-prop")
                        .long("sink-exec-prop")
                        .help("Propability that the sink is executed. Used to simulate the case when a duplicated outputs is produced by the source.")
                        .takes_value(true)
                        .default_value("1.0")
                )
        )
        .subcommand(
            Command::new("valgrind")
                .arg(
                    Arg::new("once")
                        .long("once")
                        .help("Run valgrind only once instead of every N seconds")
                        .takes_value(false)
                )
                .arg(Arg::new("input-dirs")
                    .help("Besides processing interesting and crashing inputs, process the provided directory in addition.")
                    .short('i')
                    .takes_value(true)
                    .multiple_occurrences(true)
                    .allow_invalid_utf8(true)
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent valgrind instances")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("tracer")
                .about("Run DynamoRIO-based tracer to generate basic block traces for each insteresting input found.")
                .arg(Arg::new("i")
                    .short('i')
                    .takes_value(true)
                    .multiple_occurrences(true)
                    .allow_invalid_utf8(true)
                )
                .arg(
                    Arg::new("timeout")
                        .help("Timeout after that a testcase is considered hanging and skipped in consequence")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("2m"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent tracing jobs")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("aflpp")
                .about("Use AFL++ for fuzzing the consumer application. This mode provides flags to combine AFL++ with SYMCC or WEIZZ. If Fuzztruction (fuzz mode) is running using the same config as for the aflpp mode, AFL++ is periodically reseeded with inputs found by Fuzztruction.")
                .arg(Arg::new("i")
                    .help("Use the files in the provided directory for seeding in addition to the one specified in the config")
                    .short('i')
                    .takes_value(true)
                    .multiple_occurrences(true)
                    .allow_invalid_utf8(true)
                )
                .arg(
                    Arg::new("timeout")
                        .help("Time after stopping the fuzzing campaign")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("60s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent AFL++ instances. If greater than one, one master is spawned and the remaining workers are slaves")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::new("symcc-jobs")
                        .help("Number of additional SymCC jobs spawned")
                        .long("symcc-jobs")
                        .takes_value(true)
                        .default_value("0"),
                )
                .arg(
                    Arg::new("weizz-jobs")
                        .help("Number of additional WEIZZ jobs spawned")
                        .long("weizz-jobs")
                        .takes_value(true)
                        .default_value("0"),
                )
        )
        .subcommand(
            Command::new("dump-stackmap")
                .about("Dump the LLVM stackmap (e.g., locations and sizes)")
        )
        .subcommand(
            Command::new("test-patchpoints")
            .about("Test the patchpoints of the source application (for debugging)")
            .arg(
                Arg::new("with-mutations")
                    .long("with-mutations")
                    .help("Trace the source target and create mutations (with \x00 masks) for all covered patch points")
                    .takes_value(false)
            )
        )
        .get_matches();
    matches
}

/// Check whether the workdir already exists and raises an error if --purge
/// was not passed. If this function returns `Ok`, the workdir is empty, but
/// exists.
fn check_workdir(config: &mut Config, matches: &ArgMatches) -> Result<()> {
    config.general.purge_workdir = matches.is_present("purge");

    // We only purge if this is the fuzz or benchmark subcommand.
    let expects_empty_dir = matches!(
        matches.subcommand_name().unwrap_or(""),
        "fuzz" | "benchmark"
    );

    // Purge the working directory if requested.
    if config.general.work_dir.exists() && expects_empty_dir {
        if config.general.purge_workdir {
            std::fs::remove_dir_all(&config.general.work_dir).unwrap_or_else(|_| {
                panic!("Failed to remove workdir {:?}", config.general.work_dir)
            });
            std::fs::create_dir_all(&config.general.work_dir)?;
        } else {
            return Err(anyhow!(
                "Workdir {:?} exists and --purge was not provided!",
                config.general.work_dir
            ));
        }
    }
    Ok(())
}

fn setup_jail(config: &scheduler::config::Config) -> Result<()> {
    if let Some((uid, gid)) = config.general.jail_uid_gid() {
        // We only use the privileges when needed. Drop them temporarily.
        // We will regain them after forking the source / sink process.
        if let Err(err) = jail::drop_privileges(uid, gid, false) {
            return Err(anyhow!("Failed to drop privileges: {:#?}", err));
        }
    }
    Ok(())
}

fn setup_logging(matches: &ArgMatches, config: &scheduler::config::Config) {
    let _logfile = PathBuf::from_str("debug.log").unwrap();
    let log_level = match matches.occurrences_of("verbosity") {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    };
    let log_level = log_level.or_else(|| matches.value_of("log-level")).unwrap();
    std::fs::create_dir_all(&config.general.work_dir).unwrap();
    let mut log_path = config.general.work_dir.clone();
    let log_name = format!("{}.txt", matches.subcommand_name().unwrap_or("log"));
    log_path.push(log_name);
    logging::setup_logger(&log_path, log_level).expect("Failed to setup logger");
    logging::setup_panic_logging();
}


/// Returns a `AtomicBool` that is set to `true` when a SIGTERM or SIGINT is received.
fn register_on_termination_flag() -> Arc<AtomicBool> {
    let termination_requested_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(
        signal_hook::consts::SIGTERM,
        Arc::clone(&termination_requested_flag),
    )
    .expect("Failed to register SIGTERM handler.");
    signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        Arc::clone(&termination_requested_flag),
    )
    .expect("Failed to register SIGINT handler.");
    termination_requested_flag
}

pub(crate) fn drop_privileges_permanently(config: &Config) -> Result<()> {
    if let Some((uid, gid)) = config.general.jail_uid_gid() {
        jail::acquire_privileges()?;
        jail::drop_privileges(uid, gid, true)?;
    };
    Ok(())
}

fn main() {
    if let Err(err) = real_main() {
        let err_msg = format!("Unexpected Error: {:?}", err);
        eprintln!("{}", Red.paint(err_msg));
    }
}

fn real_main() -> Result<()> {
    let matches = parse_args();

    let config_file = matches
        .value_of("config")
        .expect("Failed to provide path to config file");
    let mut config = ConfigBuilder::from_path(config_file).expect("Failed to parse config");

    // Drop privileges before doing anything else.
    setup_jail(&config)?;

    // Add suffix to the workdir if requested.
    suffix_workdir(&mut config, &matches);

    // Logging is using the workdir, thus the workdir setup must happen before enabling logging.
    check_workdir(&mut config, &matches)?;

    //Now we have a workdir -> setup logging before doing anything else.
    setup_logging(&matches, &config);
    check_config(&config)?;
    check_system()?;

    if matches.is_present("show-output") {
        config.source.log_stdout = true;
        config.source.log_stderr = true;
        config.sink.log_stdout = true;
        config.sink.log_stderr = true;
    }

    match matches.subcommand() {
        Some(("benchmark", benchmark_matches)) => {
            handler::handle_cli_benchmark_subcommand(benchmark_matches, &config);
        }
        Some(("dump-stackmap", _)) => stackmap_parser::dump_stackmap(&config.source.bin_path),
        Some(("test-patchpoints", test_patch_point_matches)) => {
            handler::handle_cli_test_patchpoints_subcommand(&config, test_patch_point_matches);
        }
        Some(("fuzz", fuzz_matches)) => {
            let termination_requested_flag = register_on_termination_flag();
            handler::handle_cli_fuzz_subcommand(fuzz_matches, config, termination_requested_flag);
        }
        Some(("valgrind", valgrind_matches)) => {
            let termination_requested_flag = register_on_termination_flag();
            handler::handle_cli_valgrind_subcommand(
                valgrind_matches,
                &config,
                termination_requested_flag,
            )
            .expect("Failed to run Valgrind");
        }
        Some(("tracer", tracer_matches)) => {
            handler::handle_cli_trace_subcommand(tracer_matches, &config)
                .expect("Failed to run tracer");
        }
        Some(("aflpp", aflpp_matches)) => {
            handler::handle_cli_aflpp_subcommand(aflpp_matches, &config)
                .expect("Failed to run AFL++ mode");
        }
        _ => {
            println!("No subcommand specified");
        }
    }
    Ok(())
}

fn suffix_workdir(config: &mut Config, matches: &ArgMatches) {
    let suffix = matches.value_of("suffix");
    if let Some(suffix) = suffix {
        let old_workdir = config.general.work_dir.clone();
        let old_filename = old_workdir
            .file_name()
            .unwrap()
            .to_owned()
            .into_string()
            .unwrap();
        let new_filename = format!("{}-{}", old_filename, suffix);

        let mut new_workdir = old_workdir.parent().unwrap().to_owned();
        new_workdir.push(new_filename);
        config.general.work_dir = new_workdir;
    }
}
