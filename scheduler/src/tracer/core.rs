use crate::config::{Config, GeneralConfig, TargetExecutionContext, VanillaConfig};
use crate::valgrind::{backup_input, setup_input_channel, setup_output_channel};
use anyhow::{anyhow, Result};
use byte_unit::n_gib_bytes;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use fuzztruction_shared::eval::coverage_trace;
use lazy_static::lazy_static;
use mktemp::Temp;
use rayon::prelude::*;
use regex::{Captures, Regex};
use std::process::Stdio;
use std::time::Instant;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    os::unix::prelude::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use std::{sync, thread};
use tempfile::TempDir;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
struct TraceParser {}

lazy_static! {
    static ref TRACE_VERSION_REGEX: Regex = Regex::new(r"DRCOV VERSION: (?P<version>\d+)").unwrap();
    static ref MODULE_ENTRY_REGEX: Regex = Regex::new(r"(?P<id>\d+),\s+(?P<containing_id>\d+),\s+(?P<start>0[xX][0-9a-fA-F]+),\s+(?P<end>0[xX][0-9a-fA-F]+),\s+(?P<entry>0[xX][0-9a-fA-F]+),\s+(?P<offset>[0-9a-fA-F]+),\s+(?P<preferred_base>0[xX][0-9a-fA-F]+),\s+(?P<path>.+)").unwrap();
    static ref MODULE_HEADER_REGEX: Regex = Regex::new(r"Module Table: version (?P<version>\d+), count (?P<mod_num>\d+)").unwrap();
    static ref BB_HEADER_REGEX: Regex = Regex::new(r"BB Table: (?P<bbcount>\d+) bbs").unwrap();
    static ref BB_ENTRY_REGEX: Regex = Regex::new(r"module\[\s*(?P<id>\d+)\]: 0x(?P<address>[0-9a-fA-F]+),\s+(?P<size>\d+)").unwrap();
    static ref TS_FILENAME_REGEX: Regex = Regex::new(r"ts:(?P<timestamp>\d+)").unwrap();
}

impl TraceParser {
    fn check_trace_version(line: &str) -> Result<()> {
        let version = TRACE_VERSION_REGEX
            .captures(line)
            .and_then(|c| c.name("version"))
            .and_then(|c| c.as_str().parse::<u64>().ok())
            .expect("Failed to parse DRCOV Version");
        if version != 3 {
            return Err(anyhow!("Unsupported DRCOV version: {}", version));
        }
        Ok(())
    }

    fn parse_module_header(line: &str) -> Result<u64> {
        let captures = MODULE_HEADER_REGEX
            .captures(line)
            .expect("Module Table regex failed");
        let version = captures
            .name("version")
            .map(|m| {
                m.as_str()
                    .parse::<u64>()
                    .expect("Module header version not a number")
            })
            .expect("Failed to parse module header version");
        let num_modules = captures
            .name("mod_num")
            .map(|m| {
                m.as_str()
                    .parse::<u64>()
                    .expect("Number of modules not a number")
            })
            .expect("Failed to parse number of modules");

        if version != 5 {
            return Err(anyhow!("Unsupported module header version: {}", version));
        }

        Ok(num_modules)
    }

    fn parse_int_from_capture(captures: &Captures, name: &str) -> Result<u64> {
        captures
            .name(name)
            .map(|m| {
                m.as_str()
                    .parse::<u64>()
                    .or_else(|_| u64::from_str_radix(m.as_str().trim_start_matches("0x"), 16))
                    .unwrap_or_else(|_| panic!("{} cannot be parsed: {}", name, m.as_str()))
            })
            .ok_or_else(|| anyhow!("Failed to parse {}", name))
    }

    fn parse_module(line: &str) -> Result<coverage_trace::Module> {
        // dbg!("line='{}'", &line);
        let captures = MODULE_ENTRY_REGEX
            .captures(line)
            .expect("Module regex failed");

        let id = TraceParser::parse_int_from_capture(&captures, "id")?;
        let containing_id = TraceParser::parse_int_from_capture(&captures, "containing_id")?;
        let start = TraceParser::parse_int_from_capture(&captures, "start")?;
        let end = TraceParser::parse_int_from_capture(&captures, "end")?;
        let entry = TraceParser::parse_int_from_capture(&captures, "entry")?;
        let offset = TraceParser::parse_int_from_capture(&captures, "offset")?;
        let preferred_base = TraceParser::parse_int_from_capture(&captures, "preferred_base")?;
        let path = captures
            .name("path")
            .map(|m| m.as_str().to_owned())
            .expect("Failed to parse module path");

        let module = coverage_trace::Module {
            id,
            containing_id,
            start,
            end,
            entry,
            offset,
            preferred_base,
            path,
        };

        Ok(module)
    }

    fn parse_bb_header(line: &str) -> Result<u64> {
        let captures = BB_HEADER_REGEX
            .captures(line)
            .expect("bb header regex failed");
        let bbcount = TraceParser::parse_int_from_capture(&captures, "bbcount")?;

        Ok(bbcount)
    }

    fn parse_bb_entry(line: &str) -> Result<coverage_trace::BasicBlock> {
        let captures = BB_ENTRY_REGEX
            .captures(line)
            .expect("bb entry regex failed");
        let module_id = TraceParser::parse_int_from_capture(&captures, "id")?;
        let address = TraceParser::parse_int_from_capture(&captures, "address")?;
        let size = TraceParser::parse_int_from_capture(&captures, "size")?;

        let bb = coverage_trace::BasicBlock {
            module_id,
            address,
            size,
        };

        Ok(bb)
    }

    fn parse_timestamp(path: impl AsRef<Path>) -> Result<u64> {
        let name = path.as_ref().file_name().unwrap().to_str().unwrap();

        let ts_ms = TS_FILENAME_REGEX
            .captures(name)
            .and_then(|c| c.name("timestamp"))
            .and_then(|c| c.as_str().parse::<u64>().ok())
            .unwrap_or_else(|| {
                panic!(
                    "Failed to parse timestamp from filename: {}",
                    &path.as_ref().display()
                )
            });

        Ok(ts_ms)
    }

    pub fn parse_trace(
        input: impl AsRef<Path>,
        trace: impl AsRef<Path>,
    ) -> Result<coverage_trace::Trace> {
        let content = fs::read_to_string(&trace)?;
        let mut lines = content.lines();

        // let version = TraceManager::parse_line(
        //     r"DRCOV VERSION: (?P<match>\d+)\n",
        //     lines
        //         .next()
        //         .expect("Logfile has no line containing version"),
        // )?
        // .parse::<u64>()
        // .expect("Version not a number");

        TraceParser::check_trace_version(lines.next().expect("No version line in logfile"))?;

        // skip DRCOV FLAVOR
        lines
            .next()
            .expect("Logfile has no line containing DRCOV_FLAVOR");

        // parse modules
        let num_modules = TraceParser::parse_module_header(
            lines.next().expect("No module header line in logfile"),
        )?;
        // consume line that describes the columns
        lines
            .next()
            .expect("No module table column description line");
        let mut modules = Vec::new();
        // dbg!("num_modules={}", num_modules);
        for _ in 0..num_modules {
            // dbg!("i={}/{}", i, num_modules);
            modules.push(TraceParser::parse_module(
                lines.next().expect("Missing line for module"),
            )?);
            // dbg!("module={}", &modules.last());
        }

        let mut id_to_name = HashMap::new();
        for module in &modules {
            id_to_name.insert(module.id, module.path.clone());
        }

        let num_bbs = TraceParser::parse_bb_header(lines.next().expect("No BB header line"))?;
        // dbg!("num_bbs={}", num_bbs);

        // consume line that describes the columns
        lines.next().expect("No bb column description line");

        let mut basic_blocks = Vec::new();
        for _ in 0..num_bbs {
            basic_blocks.push(TraceParser::parse_bb_entry(
                lines.next().expect("Missing line for bb entry"),
            )?);
        }

        let timestamp_ms = TraceParser::parse_timestamp(&input)?;

        let trace = coverage_trace::Trace {
            path: input.as_ref().to_owned(),
            timestamp_ms,
            basic_blocks,
            modules,
            id_to_name,
        };

        Ok(trace)
    }
}

#[derive(Debug)]
pub struct TraceManager {
    input_dirs: Vec<PathBuf>,
    exit_requested: Arc<AtomicBool>,
    general_config: GeneralConfig,
    target_config: VanillaConfig,
}

impl TraceManager {
    pub fn new(
        general_config: &GeneralConfig,
        target_config: VanillaConfig,
        input_dirs: Vec<PathBuf>,
        exit_requested: Arc<AtomicBool>,
    ) -> Self {
        log::trace!("Creating new TraceManager");
        TraceManager {
            general_config: general_config.clone(),
            target_config,
            input_dirs,
            exit_requested,
        }
    }

    /// Returns all paths to files that we want to trace
    fn get_trace_targets(&self) -> Vec<PathBuf> {
        log::trace!("Identifying trace targets..");
        let mut files = Vec::new();
        let mut dirs = self.input_dirs.clone();
        dirs.push(self.general_config.interesting_path());
        //dirs.push(self.general_config.crashing_path());

        for dir in dirs {
            let base = dir.to_str().unwrap();
            let pattern = format!("{}/**/*", base);
            for path in glob::glob(&pattern).unwrap() {
                match path {
                    Err(err) => log::warn!("Failed to process glob result: {:?}", err),
                    Ok(path) => {
                        if !path.is_dir() {
                            files.push(path)
                        }
                    }
                }
            }
        }
        files
    }

    fn save_trace(&self, input: impl AsRef<Path>, trace: coverage_trace::Trace) -> Result<()> {
        let name = input.as_ref().file_name().unwrap();

        let mut logfile_path = self.general_config.traces_directory();

        logfile_path.push(format!("trace_{}.json", name.to_str().unwrap()));

        // Use `zlib-flate -uncompress <path>` to decompress.
        let mut compressor = ZlibEncoder::new(Vec::new(), Compression::default());
        serde_json::to_writer_pretty(&mut compressor, &trace).unwrap();
        let compressed_bytes = compressor.finish().unwrap();

        let mut logfile = File::create(logfile_path)?;
        logfile.write_all(&compressed_bytes)?;

        Ok(())
    }

    fn trace_input(&self, input: &Path) -> Result<()> {
        log::trace!("Tracing input: {}", &input.display());
        let tmp_dir = TempDir::new()?;
        log::trace!(
            "Using temporary directory: {:#?}",
            tmp_dir.as_ref().as_os_str()
        );

        let temp_input = backup_input(input, tmp_dir.path().to_str().unwrap())?;
        let output_file = {
            let f = Temp::new_file_in(tmp_dir.path()).expect("Failed to create output file");
            f.to_path_buf()
        };

        // TODO: we deploy a custom drrun wrapper script
        let mut command = Command::new("/home/user/DynamoRIO-Linux-9.0.19078/bin64/drrun");

        // set environment from config
        command.env_clear();
        command.envs(self.target_config.env().to_owned());
        command.env("TRACER_LOGDIR", tmp_dir.as_ref().to_str().unwrap());

        //"LD_LIBRARY_PATH=/home/user/leah/eval-targets/openssl/afl/openssl"

        command.args([
            "-persist",
            "-t",
            "drcov",
            "-logdir",
            tmp_dir.as_ref().to_str().unwrap(),
            "-dump_text",
            "--",
        ]);
        let mut args = vec![self.target_config.bin_path().to_str().unwrap().to_owned()];
        args.extend(self.target_config.arguments().to_owned());
        setup_input_channel(&mut args, &temp_input, &mut command)?;
        setup_output_channel(&mut args, output_file);
        command.args(args);

        unsafe {
            command.pre_exec(|| {
                // Max AS size.
                let mut rlim: libc::rlimit = std::mem::zeroed();
                rlim.rlim_cur = n_gib_bytes!(32).try_into().unwrap();
                rlim.rlim_max = n_gib_bytes!(32).try_into().unwrap();
                let ret = libc::setrlimit(libc::RLIMIT_AS, &rlim as *const libc::rlimit);
                assert_eq!(ret, 0);
                Ok(())
            });
        }

        log::debug!("command args: {:?}", command.get_args());
        log::debug!("command envs: {:?}", command.get_envs());
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let timeout = Duration::from_secs(5);
        let start_ts = Instant::now();
        loop {
            if start_ts.elapsed() > timeout {
                log::warn!(
                    "Tracing for input {:?} timed out after {:?}",
                    input,
                    timeout
                );
                return Ok(());
            } else if let Some(exit_code) = child.try_wait().unwrap() {
                log::debug!("Exited: {:?}", exit_code);
                break;
            }
            // yield
            thread::sleep(Duration::from_millis(5));
        }

        // if let Some((uid, gid)) = uid_gid {
        //     jail::drop_privileges(uid, gid, false)?;
        // }

        // parse logfile
        let base = tmp_dir.as_ref().to_str().unwrap();
        let pattern = format!("{}/drcov.*.log", base);
        log::trace!("Searching pattern: {}", &pattern);
        for path in glob::glob(&pattern).unwrap() {
            match path {
                Err(err) => log::warn!("Failed to process glob result: {:?}", err),
                Ok(path) => {
                    if !path.is_dir() {
                        log::debug!("Logfile is: {}", path.display());
                        let trace = TraceManager::parse_trace(input, path)?;
                        log::debug!("Trace is {} bbs long", trace.len());
                        self.save_trace(input, trace)?;
                        return Ok(());
                    }
                }
            }
        }

        Err(anyhow!("No valid trace created"))
    }

    /// Trace files.
    ///
    /// # Arguments
    ///
    /// * `seeds` - Vector of paths of files to trace.
    /// * `jobs` - Number of jobs to run in parallel (must be > 0)
    /// * `timeout` - If given, the exploration is stopped after `timeout`.
    ///
    fn trace_files(
        &self,
        seeds: Vec<PathBuf>,
        jobs: usize,
        _timeout: Option<Duration>,
    ) -> Result<()> {
        assert!(jobs > 0);
        assert!(
            PathBuf::try_from("/home/user/DynamoRIO-Linux-9.0.19078/bin64/drrun")
                .unwrap()
                .exists()
        );

        let uid_gid = self.general_config.jail_uid_gid();
        if let Some((uid, gid)) = uid_gid {
            jail::acquire_privileges()?;
            jail::drop_privileges(uid, gid, true)?;
        }

        log::trace!("Creating new ThreadPoolBuilder");
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()
            .unwrap();

        seeds.par_iter().try_for_each(|f| {
            let ret = self.trace_input(f);
            if ret.is_err() {
                log::error!("trace_input ret={:?}", ret);
            } else {
                log::debug!("trace_input ret={:?}", ret);
            }
            if self.exit_requested.load(sync::atomic::Ordering::Relaxed) {
                None
            } else {
                Some(())
            }
        });

        Ok(())
    }

    fn parse_trace(
        input: impl AsRef<Path>,
        trace: impl AsRef<Path>,
    ) -> Result<coverage_trace::Trace> {
        TraceParser::parse_trace(input, trace)
    }
}

/// Run the exploration mode for the given `config`.
pub fn trace_interesting(
    config: &Config,
    input_dirs: Vec<PathBuf>,
    exit_requested: Arc<AtomicBool>,
    jobs: Option<usize>,
    timeout: Option<Duration>,
) -> Result<()> {
    log::trace!("Tracing interesting inputs..");
    fs::create_dir_all(config.general.traces_directory())?;

    let tracer = TraceManager::new(
        &config.general,
        config.vanilla.clone(),
        input_dirs,
        exit_requested,
    );

    let files_to_trace = tracer.get_trace_targets();
    log::debug!("Found {} targets to trace", files_to_trace.len());
    let jobs = jobs.unwrap_or(1);
    log::trace!("Using {} jobs", jobs);
    tracer.trace_files(files_to_trace, jobs, timeout)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_trace() {
        let file = PathBuf::from("/home/user/leah/coordinator/src/tracer/test_trace.txt");
        dbg!("file_path={}", &file);
        assert!(file.exists());
        let p = PathBuf::from("/tmp/ts:1234+nothing");
        let trace = TraceManager::parse_trace(p, file).unwrap();
        assert_eq!(trace.len(), 3469);
    }

    #[test]
    fn test_check_trace_version() {
        let valid = "DRCOV VERSION: 3";
        assert!(TraceParser::check_trace_version(valid).is_ok());
        let invalid = "DRCOV VERSION: 4";
        assert!(TraceParser::check_trace_version(invalid).is_err());
    }

    #[test]
    fn test_parse_module_header() {
        let valid = "Module Table: version 5, count 21";
        assert_eq!(TraceParser::parse_module_header(valid).unwrap(), 21);
    }

    #[test]
    fn test_parse_bb_header() {
        let valid = "BB Table: 3469 bbs";
        assert_eq!(TraceParser::parse_bb_header(valid).unwrap(), 3469);
    }

    #[test]
    fn test_parse_bb_entry() {
        let valid = "module[  9]: 0x0000000000000e43,  22";
        let actual = TraceParser::parse_bb_entry(valid).unwrap();
        let expected = coverage_trace::BasicBlock {
            module_id: 9,
            address: 0x0000000000000e43,
            size: 22,
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_module() {
        let module_str = String::from("  0,   0, 0x00007fffb3dcd000, 0x00007fffb3dce000, 0x00007fffb3dce1d0, 0000000000000000, 0x0000000072000000,  /home/user/leah/DynamoRIO-Linux-9.0.19078/tools/lib64/release/libdrcov.so");
        let expected = coverage_trace::Module {
            id: 0,
            containing_id: 0,
            start: 0x00007fffb3dcd000,
            end: 0x00007fffb3dce000,
            entry: 0x00007fffb3dce1d0,
            offset: 0000000000000000,
            preferred_base: 0x0000000072000000,
            path: String::from(
                "/home/user/leah/DynamoRIO-Linux-9.0.19078/tools/lib64/release/libdrcov.so",
            ),
        };

        let actual = TraceParser::parse_module(&module_str).expect("Failed to parse module");

        dbg!("module={:#?}", &actual);

        assert_eq!(actual, expected);
    }
}
