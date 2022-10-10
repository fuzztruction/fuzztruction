use anyhow::{Context, Result};
use byte_unit::n_gib_bytes;
use hex::ToHex;
use mktemp::Temp;

use rayon::prelude::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::hash::Hash;
use std::io::Write;
use std::os::unix::prelude::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lazy_static::lazy_static;

use crate::config::Config;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_SCAN_INTERVAL: Duration = Duration::from_secs(300);

lazy_static! {
    static ref FS_LOCK: Mutex<bool> = Mutex::new(false);
}

type InputHash = String;

fn hash_bytes<T: Hash>(t: &T) -> String
where
    T: AsRef<[u8]>,
{
    let mut digest = Sha256::new();
    digest.update(t);
    digest.finalize().encode_hex()
}

fn hash_iterator<T, E>(t: T) -> String
where
    E: AsRef<[u8]>,
    T: Iterator<Item = E>,
{
    let mut digest = Sha256::new();
    for item in t {
        digest.update(item);
    }
    digest.finalize().encode_hex()
}

#[derive(Debug)]
pub struct ValgrindManager {
    known_inputs: HashSet<InputHash>,
    inputs_queue: Vec<PathBuf>,
    /// Map input hashes to input path
    findings: HashMap<InputHash, PathBuf>,
    save_path: PathBuf,
    scan_interval: Duration,
    input_directories: Vec<PathBuf>,
    valgrind_options: Vec<String>,
    timeout: Duration,
    target_binary: PathBuf,
    target_args: Vec<String>,
    env: Vec<(String, String)>,
    #[allow(unused)]
    config: Option<Config>,
    job_cnt: Option<usize>,
    pool_initialized: bool,
    termination_requested_flag: Arc<AtomicBool>,
}

impl ValgrindManager {
    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn new(
        scan_interval: Duration,
        input_directories: Vec<PathBuf>,
        valgrind_options: Vec<String>,
        timeout: Duration,
        save_path: PathBuf,
        target_binary: PathBuf,
        target_args: Vec<String>,
        env: Vec<(String, String)>,
        job_cnt: Option<usize>,
        termination_requested_flag: Arc<AtomicBool>,
    ) -> ValgrindManager {
        ValgrindManager {
            findings: HashMap::new(),
            known_inputs: HashSet::new(),
            inputs_queue: Vec::new(),
            env,
            save_path,
            scan_interval,
            input_directories,
            timeout,
            valgrind_options,
            target_binary,
            target_args,
            config: None,
            job_cnt,
            pool_initialized: false,
            termination_requested_flag,
        }
    }

    pub fn from_config(
        config: &Config,
        input_dirs: Vec<PathBuf>,
        job_cnt: Option<usize>,
        termination_requested_flag: Arc<AtomicBool>,
    ) -> Result<ValgrindManager> {
        let target_args = config.sink.arguments.clone();
        let target_binary = config.vanilla.bin_path.clone();
        let env = config.vanilla.env.clone();
        if !target_binary.exists() {
            return Err(anyhow::anyhow!("Target binary does not exist!"));
        }
        let scan_interval = DEFAULT_SCAN_INTERVAL;
        let timeout = DEFAULT_TIMEOUT;

        let valgrind_options = vec![
            String::from_str("--error-limit=no").unwrap(),
            String::from_str("--track-origins=yes").unwrap(),
            String::from_str("--trace-children=yes").unwrap(),
            String::from_str("--error-exitcode=44").unwrap(),
        ];

        let save_path = config.general.valgrind_path();
        let mut input_directories = [
            config.general.crashing_path(),
            config.general.interesting_path(),
        ]
        .to_vec();
        input_directories.extend(input_dirs);

        // if available, load known_inputs from disk
        let known_inputs = restore_known_inputs(&save_path);

        fs::create_dir_all(&save_path)?;
        Ok(ValgrindManager {
            findings: HashMap::new(),
            inputs_queue: Vec::new(),
            env,
            save_path,
            known_inputs,
            scan_interval,
            input_directories,
            valgrind_options,
            timeout,
            target_binary,
            target_args,
            config: Some(config.clone()),
            job_cnt,
            pool_initialized: false,
            termination_requested_flag,
        })
    }

    fn sanity_checks(self: &ValgrindManager) -> Result<()> {
        log::trace!("Running sanity checks");
        if !self.target_binary.exists() {
            return Err(anyhow::anyhow!(
                "'{}' - binary not found",
                self.target_binary.display()
            ));
        }
        let valgrind_binary = PathBuf::from("/usr/bin/valgrind");
        if !valgrind_binary.exists() {
            return Err(anyhow::anyhow!("'/usr/bin/valgrind' - binary not found"));
        }
        Ok(())
    }

    fn build_args(self: &ValgrindManager, report_file: &Path) -> Vec<String> {
        let mut cmd = Vec::new();

        // If the target is not terminated by SIGTERM (see below),
        // sig SIGKILL is send after this long.
        cmd.push(format!("--kill-after={}", 5));

        // Timeout after sending SIGTERM to the process.
        cmd.push(format!("{:?}", self.timeout));

        // Valgrind binary
        cmd.push("/usr/bin/valgrind".to_owned());

        // Valgrind options
        let logfile_str = format!("--log-file={}", report_file.as_os_str().to_str().unwrap());
        cmd.push(logfile_str);
        cmd.extend(self.valgrind_options.clone());
        cmd.push("--".to_owned());

        // Target binary
        cmd.push(self.target_binary.as_os_str().to_str().unwrap().to_owned());

        // Target binary arguments
        cmd.extend(self.target_args.clone());

        cmd
    }

    /// Scan for new inputs we have not scanned yet
    pub fn queue_new_inputs(self: &mut ValgrindManager) -> Result<()> {
        for dir in &self.input_directories {
            if !dir.is_dir() {
                log::debug!("Directory not found: '{}'", dir.display());
                continue;
            }
            log::debug!("Scanning inputs in {}", dir.display());
            for input in fs::read_dir(dir).unwrap() {
                let input = input?.path();
                if input.is_dir() {
                    continue;
                }
                let content = fs::read(&input).context("Failed to read file content")?;
                let hash = hash_bytes(&content);
                if !self.known_inputs.contains(&hash) {
                    self.known_inputs.insert(hash);
                    self.inputs_queue.push(input);
                }
            }
        }
        log::info!("Found {} new inputs", self.inputs_queue.len());
        Ok(())
    }

    pub fn get_classification_string(self: &ValgrindManager, report: &str) -> String {
        let sep = '+';
        let mut classification = String::new();
        if report.contains("default action of signal") {
            let re = Regex::new(r"default action of signal \d+ \((.+)\)").unwrap();
            let mut matches = re.captures_iter(report);
            if let Some(cap) = matches.next() {
                classification.push_str(&cap[1]);
                classification.push(sep);
            }
        }
        if report.contains("Invalid write") {
            classification.push_str("invalidwrite");
            classification.push(sep);
        }
        if report.contains("Invalid read") {
            classification.push_str("invalidread");
            classification.push(sep);
        }
        if report.contains("uninitialised value") {
            classification.push_str("uninitval");
            classification.push(sep);
        }
        if !classification.is_empty() {
            // remove last occurence of sep
            classification.pop();
            return classification;
        }
        log::warn!("Could not classify Valgrind's report");
        String::from("unknown")
    }

    fn get_bucket_dir(self: &ValgrindManager, report: &str, hash: &str) -> PathBuf {
        let classification = self.get_classification_string(report);
        let bucket_dir_name = format!("{}_{}", classification, hash);
        let mut bucket_dir = self.save_path.clone();
        bucket_dir.push(bucket_dir_name);
        bucket_dir
    }

    fn get_function_name_bucket_dir(self: &ValgrindManager, report: &str, hash: &str) -> PathBuf {
        let classification = self.get_classification_string(report);
        let bucket_dir_name = format!("{}_{}", classification, hash);
        let mut bucket_dir = self.save_path.clone();
        bucket_dir.push("by_function_name");
        bucket_dir.push(bucket_dir_name);
        bucket_dir
    }

    pub fn function_name_hash(report: &str) -> String {
        let re = Regex::new(r"==.*(?:at|by) (?:0x[0-9a-fA-F]+): (\?\?\?|.+) \((.*)\)\n").unwrap();
        let function_names: HashSet<String> = re
            .captures_iter(report)
            .map(|e| String::from(&e[1]))
            .collect();
        let mut function_names = function_names
            .iter()
            .filter(|e| !(**e == "???" || **e == "(below main)"))
            .collect::<Vec<_>>();
        function_names.sort();
        println!("{:?}", function_names);

        hash_iterator(function_names.iter())
    }

    pub fn get_address_stack_trace(self: &ValgrindManager, report: &str) -> Vec<String> {
        let re = Regex::new(r"==.*by (0x[0-9a-fA-F]+):.*\n").unwrap();
        re.captures_iter(report)
            .map(|e| String::from(&e[1]))
            .collect()
    }

    pub fn hash_report(self: &ValgrindManager, report: &str) -> String {
        // extract hashable elements
        /*
        FIXME: The regex currently does not consider the at ... field in the stack traces.
        However, if we now change the algorithm, this "invalidate" all previously
        hashed (and saved) reports.
        ==2186967== Invalid read of size 8
        ==2186967==    at 0x4A67CB6: FilterStream::getDict() (p... <--- ! not hashed !
        ==2186967==    by 0x4BC54C2: Parser::makeStream(Object&...
        ==2186967==    by 0x4BC40A7: Parser::getObj(bool, unsig...
        ==2186967==    by 0x4B5BB41: Hints::readTables(BaseStre...
        ==2186967==    by 0x4BCB3CF: PDFDoc::checkLinearization...
        ==2186967==    by 0x4BCA97B: PDFDoc::getPage(int) (popp...
        ==2186967==    by 0x4BCA794: PDFDoc::displayPage(Output...
        ==2186967==    by 0x4BCADEC: PDFDoc::displayPages(Outpu...
        ==2186967==    by 0x40639C: main (utils/pdftotext.cc:40...
        ==2186967==  Address 0x600000005dba180 is not stack'd, ...
        */
        let stack_trace = self.get_address_stack_trace(report);
        hash_bytes(&stack_trace.join(" ").as_bytes())
    }

    fn save(self: &ValgrindManager, input: &Path, report: &str, bucket_dir: PathBuf) -> Result<()> {
        let _lock = FS_LOCK.lock().unwrap();

        fs::create_dir_all(&bucket_dir)?;
        // copy input
        let mut input_save_path = bucket_dir;
        input_save_path.push(input.file_name().unwrap());
        fs::copy(input, input_save_path.as_path())?;

        let report_dst = input_save_path.with_extension("report");
        let mut report_file = File::create(report_dst)?;
        report_file.write_all(report.as_bytes())?;

        log::trace!(
            "Saved '{}' to '{}'",
            input.display(),
            input_save_path.display()
        );

        Ok(())
    }

    fn store_address_backtrace(
        self: &ValgrindManager,
        input: &Path,
        report_str: &str,
    ) -> Result<()> {
        let hash = self.hash_report(report_str);
        log::trace!("Address backtrace hash: {}", hash);
        let bucket_dir = self.get_bucket_dir(report_str, &hash);
        log::info!(
            "Found interesting address backtrace {}: {}",
            &bucket_dir.display(),
            &input.display()
        );
        self.save(input, report_str, bucket_dir)?;
        // update mapping of hashed report to input path
        // self.findings
        //     .entry(hash)
        //     .or_insert_with(|| input.to_owned());
        Ok(())
    }

    fn store_function_name_backtrace(
        self: &ValgrindManager,
        input: &Path,
        report_str: &str,
    ) -> Result<()> {
        let hash = ValgrindManager::function_name_hash(report_str);
        log::trace!("Function name hash: {}", hash);
        let bucket_dir = self.get_function_name_bucket_dir(report_str, &hash);
        log::info!(
            "Found interesting function name backtrace {}: {}",
            &bucket_dir.display(),
            &input.display()
        );
        self.save(input, report_str, bucket_dir)?;
        Ok(())
    }

    fn process_potential_finding(
        self: &ValgrindManager,
        input: &Path,
        report: &Path,
    ) -> Result<()> {
        let report_str = fs::read_to_string(report)?;
        // hacky fix: if we cannot find a stack trace, we ignore the report
        if self.get_address_stack_trace(&report_str).is_empty() {
            return Ok(());
        }
        self.store_address_backtrace(input, &report_str)?;
        self.store_function_name_backtrace(input, &report_str)?;
        Ok(())
    }

    fn process_timeout(self: &ValgrindManager, input: &Path, report: &Path) -> Result<()> {
        let mut report_str = format!("Valgrind timeouted after {:?} seconds\n", self.timeout);
        log::info!("{}", &report_str);

        report_str += &fs::read_to_string(report)?;
        let bucket_name = String::from("timeout");
        let mut bucket_dir = self.save_path.clone();
        bucket_dir.push(bucket_name);
        self.save(input, &report_str, bucket_dir)?;
        Ok(())
    }

    pub fn run(self: &mut ValgrindManager) -> Result<()> {
        log::info!("Running Valgrind for {} inputs", self.inputs_queue.len());
        self.sanity_checks()?;

        // Disable core dumps
        let limit_val: libc::rlimit = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit_val) };
        assert_eq!(ret, 0);

        let _num_cur_findings = self.findings.len();

        // We replace self.inputs_queue with the new vector `new_inputs_queue`
        // and in turn take the contents of self.inputs_queue, such that we own the inputs
        let new_inputs_queue = Vec::new();
        let inputs = std::mem::replace(&mut self.inputs_queue, new_inputs_queue);

        if !self.pool_initialized {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.job_cnt.unwrap_or(1))
                .build_global()
                .unwrap();
            self.pool_initialized = true;
        }

        inputs.par_iter().try_for_each(|input| {
            let ret = self.process_input(input);
            if ret.is_err() {
                log::error!("Failed to process input {}. ret={:?}", input.display(), ret);
            }
            if self.termination_requested_flag.load(Ordering::Relaxed) {
                None
            } else {
                Some(())
            }
        });

        // for (idx, input) in inputs.into_iter().enumerate() {
        //     self.process_input(idx, num_inputs, input)?;
        // }
        // log::debug!(
        //     "{} new findings ({} in total)",
        //     self.findings.len() - num_cur_findings,
        //     self.findings.len()
        // );

        // Serialize all known inputs to disk
        store_known_inputs(&self.save_path, &self.known_inputs)?;

        Ok(())
    }

    fn process_input(self: &ValgrindManager, input: &Path) -> Result<()> {
        log::info!("Processing input: {}", input.display());
        let temp_input = backup_input(input, "/tmp")?;
        let report_file = Temp::new_file_in("/tmp").expect("Failed to create tempfile for report.");
        log::trace!("Will place report in {}", &report_file.display());
        let output_file = {
            let f = Temp::new_file_in("/tmp").expect("Failed to create output file");
            f.to_path_buf()
        };
        log::trace!("Created {} as output file", &report_file.display());
        let mut command = Command::new("/usr/bin/timeout");
        command.env_clear();
        command.envs(self.env.clone());
        let mut args = self.build_args(report_file.as_path());
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

        let starts_ts = Instant::now();
        log::trace!("Cmd: {:?}", command);
        let output = command.output().context("Failed to retrive output")?;
        let exit_code = output.status.code();
        log::info!("Execution took {:?}", starts_ts.elapsed());
        log::info!("Exit status: {:?}", exit_code);
        match exit_code {
            Some(0) => (),
            // timeout (sigterm -> 124; sigkill -> 128+9=137)
            Some(124) | Some(137) => self
                .process_timeout(input, report_file.as_path())
                .context("Error while processing timeout")?,
            // Valgrind found something interesting (44) or crashed (None)
            // As Valgrind itself may error out (1), we process everything
            // as a potential finding (and weed out false positives by
            // looking for addresses/stack traces)
            _ => self
                .process_potential_finding(input, report_file.as_path())
                .context("Error while processing finding")?,
        };
        Ok(())
    }

    pub fn start(self: &mut ValgrindManager) -> Result<()> {
        let mut iteration_ctr: usize = 0;
        loop {
            log::debug!("Running iteration {}", iteration_ctr);
            let start_time = Instant::now();
            self.queue_new_inputs()
                .context("Failed to queue new inputs")?;
            if !self.inputs_queue.is_empty() {
                self.run().context("Failed to run Valgrind on inputs")?;
            }
            let elapsed_time = start_time.elapsed();

            if elapsed_time < self.scan_interval {
                let diff = self.scan_interval - elapsed_time;
                log::info!("Waiting for {:?} before scanning for new inputs", diff);
                sleep(diff);
            }
            log::debug!("Iteration {} done", iteration_ctr);
            iteration_ctr = iteration_ctr.wrapping_add(1);
        }
    }
}

fn store_known_inputs(save_path: &Path, known_inputs: &HashSet<String>) -> Result<()> {
    log::trace!("Storing {} known_inputs to disk", &known_inputs.len());
    let mut known_inputs_file = save_path.to_owned();
    known_inputs_file.push("known_inputs");
    fs::write(known_inputs_file, serde_json::to_string(&known_inputs)?)?;
    Ok(())
}

fn restore_known_inputs(save_path: &Path) -> HashSet<String> {
    let mut known_inputs: HashSet<String> = HashSet::new();
    let mut known_inputs_file = save_path.to_owned();
    known_inputs_file.push("known_inputs");
    if known_inputs_file.exists() {
        if let Ok(content) = fs::read_to_string(&known_inputs_file) {
            known_inputs = serde_json::from_str(&content).unwrap();
            log::debug!("Reading {} known_inputs from disk", known_inputs.len());
        } else {
            log::warn!(
                "Failed to read {} file contents",
                &known_inputs_file.display()
            );
        }
    } else {
        log::trace!("No {} file found", &known_inputs_file.display());
    }
    known_inputs
}

pub fn setup_output_channel(args: &mut [String], output_file: PathBuf) {
    if let Some(elem) = args.iter_mut().find(|e| **e == "$$") {
        *elem = output_file.as_path().to_str().unwrap().to_owned();
    }
}

pub fn setup_input_channel(
    args: &mut [String],
    input_file: &Temp,
    command: &mut Command,
) -> Result<()> {
    if let Some(elem) = args.iter_mut().find(|e| **e == "@@") {
        *elem = input_file.as_path().to_str().unwrap().to_owned();
        command.stdin(Stdio::null());
    } else {
        // TODO: check this
        command.stdin(File::open(input_file).context("Unable to prepare stdin")?);
    }
    Ok(())
}

pub fn backup_input(input_path: &Path, dir: &str) -> Result<Temp> {
    let input_clone = Temp::new_file_in(dir).expect("Failed to create tempfile for input backup.");
    fs::copy(input_path, &input_clone).context("Failed to copy input file")?;
    log::trace!("Copied input to {}", &input_clone.display());
    Ok(input_clone)
}

/// Run Valgrind periodically in background thread (convenience wrapper)
pub fn run_valgrind_in_background(
    config: &Config,
    input_dirs: Vec<PathBuf>,
    termination_requested_flag: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    log::debug!("Running Valgrind periodically in background");
    let mut valgrind =
        ValgrindManager::from_config(config, input_dirs, Some(1), termination_requested_flag)?;

    let thread_handle = thread::spawn(move || {
        valgrind.start().expect("Failed to start Valgrind");
    });

    Ok(thread_handle)
}
