use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    aflpp::{symcc::SymccWorker, weizz::WeizzWorker},
    config::Config,
};
use anyhow::anyhow;
use anyhow::{Context, Result};
use fuzztruction_shared::util::interruptable_sleep;
use glob;
use hex::ToHex;
use lazy_static::lazy_static;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::WorkerId;

#[derive(Debug)]
pub struct AflPlusPlus {
    config: Config,
    import_dirs: Option<Vec<PathBuf>>,
    workers: Vec<(WorkerId, JoinHandle<Result<()>>)>,
    sync_worker: Option<JoinHandle<Result<()>>>,
}

#[derive(Debug, Clone)]
struct AflPlusPlusWorker {
    config: Config,
    #[allow(unused)]
    import_dirs: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone)]
struct AflPPQueueFile {
    pub path: PathBuf,
    #[allow(unused)]
    pub id: u64,
    pub ts: u64,
}

impl AflPlusPlusWorker {
    pub fn new(config: Config, import_dirs: Option<Vec<PathBuf>>) -> Self {
        AflPlusPlusWorker {
            config,
            import_dirs,
        }
    }

    fn prepare_env(&self) -> Vec<(String, String)> {
        let mut env = self.config.sink.env.to_owned();
        let has_afl_preload = env.iter().any(|e| e.0 == "AFL_PRELOAD");
        let has_ld_preload = env.iter().any(|e| e.0 == "LD_PRELOAD");
        if has_afl_preload && has_ld_preload {
            // Make sure we are purging LD_PRELOAD if AFL_PRELOAD is set, since
            // instrumented LD_PRELOAD libraries will complain about missing afl_* symbols.
            log::info!("Skipping LD_PRELOAD in config in favour of AFL_PRELOAD");
            env.retain(|e| e.0 != "LD_PRELOAD");
        }
        env
    }

    fn run(
        self,
        worker_id: WorkerId,
        exit_requested: Arc<AtomicBool>,
        init_done: mpsc::Sender<()>,
    ) -> Result<()> {
        let seed_dir = self.config.aflpp.as_ref().unwrap().input_dir.clone();
        let mut workdir = self.config.general.work_dir.clone();
        workdir.push("aflpp-workdir");

        let mut cmd = Command::new("/usr/local/bin/afl-fuzz");

        // set environment from config
        cmd.env_clear();
        cmd.env("AFL_NO_UI", "1");

        let env = self.prepare_env();
        cmd.envs(env);

        cmd.args([
            "-i",
            seed_dir.to_str().unwrap(),
            "-o",
            workdir.to_str().unwrap(),
        ]);

        let id = match worker_id {
            WorkerId::AflMaster => "-Mmaster".to_owned(),
            WorkerId::AflSlave(slave_id) => format!("-Sslave{}", slave_id),
            _ => unreachable!("Unknown worker type {:?}", worker_id),
        };
        cmd.arg(id);
        cmd.arg("--");

        let mut args = vec![self.config.sink.bin_path.to_str().unwrap().to_owned()];
        args.extend(self.config.sink.arguments);
        cmd.args(args);

        log::info!("cmd args: {:?}", cmd.get_args());
        log::info!("cmd env: {:?}", cmd.get_envs());

        let mut child = cmd.spawn()?;
        init_done.send(())?;

        loop {
            // Check if the child terminated even though it should still be running.
            let exit_code = child.try_wait();
            match exit_code {
                Err(err) => {
                    let ctx = anyhow!("Child terminated unexpectedly with an error.");
                    return Err(ctx.context(err));
                }
                Ok(Some(exit_status)) if !exit_status.success() => {
                    let err = anyhow!("Child exited unexpectedly: {:?}", exit_status);
                    return Err(err);
                }
                _ => (),
            }

            if interruptable_sleep(Duration::from_secs(5), &exit_requested) {
                log::info!("Exit of worker {:#?} was requested", worker_id);
                let _ = child.kill();
                break;
            }
        }

        log::info!("Terminating worker {:?}", worker_id);

        Ok(())
    }
}

fn parse_queue_file(path: &Path) -> Option<AflPPQueueFile> {
    log::trace!("Processing {:?}", path);

    if !path.is_file() {
        return None;
    }

    let name = path.file_name().map(|path| path.to_string_lossy());
    let name = match name {
        Some(name) => name,
        _ => return None,
    };

    if name.contains("sync:") {
        // synced from other fuzzer
        return None;
    }

    let id = Regex::new("id:([0-9]+)").unwrap();
    let id = id
        .captures(&name)
        .expect("Expected id: field in filename")
        .get(1)
        .expect("Failed to match id:");
    let id = id.as_str().parse().unwrap();

    let ts = Regex::new("time:([0-9]+)").unwrap();
    let ts = ts.captures(&name);
    let ts = if let Some(ts) = ts {
        ts.get(1)
            .expect("Failed to match time:")
            .as_str()
            .parse()
            .unwrap()
    } else {
        // Use as fallback the file's modification ts and the timestamp
        // when we started fuzzing to calculate the time passed
        // since we started fuzzing. This is need for, e.g., symcc workers,
        // since they do not save timestamps to the queue file name.
        let metadata = fs::metadata(path).unwrap();
        let creation_ts = metadata.modified().unwrap();
        let since_fuzzing_start = unsafe {
            // SAFETY: This variable is only written once before
            // any worker in started.
            START_TS.unwrap().elapsed()
        };
        let since_file_created = creation_ts.elapsed().unwrap();
        since_fuzzing_start
            .saturating_sub(since_file_created)
            .as_millis()
    };

    Some(AflPPQueueFile {
        path: path.to_owned(),
        id,
        ts: ts.try_into().unwrap(),
    })
}

lazy_static! {
    static ref PROCESSED_QUEUE_FILES: Mutex<HashSet<PathBuf>> = Mutex::new(HashSet::new());
    static ref SEEN_HASHES_TO_TS: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    static ref FT_TO_AFL_SEEN_HASHES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref FT_TO_AFL_SYNC_CTR: AtomicUsize = AtomicUsize::new(0);
    static ref AFL_CRASHES_TO_FT_SEEN_HASHES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

static mut START_TS: Option<Instant> = None;

fn hash_file_content(path: &Path) -> String {
    let mut digest = Sha256::new();
    let content = fs::read(path).unwrap_or_else(|_| panic!("Failed to read {:?}", path));
    digest.update(content);
    digest.finalize().encode_hex()
}

impl AflPlusPlus {
    pub fn new(config: Config, import_dirs: Option<Vec<PathBuf>>) -> Self {
        AflPlusPlus {
            config,
            import_dirs,
            workers: Vec::new(),
            sync_worker: None,
        }
    }

    fn sync_to_ft(afl_workdir: &Path, interesting_dir: &Path, crashes_path: &Path) -> Result<()> {
        let interesting_dir_glob =
            format!("{}/*/queue/*", afl_workdir.as_os_str().to_str().unwrap());
        log::info!("Checking {} for new queue files", interesting_dir_glob);
        let res = glob::glob(&interesting_dir_glob)?;

        let mut new_files_ctr = 0;
        for path in res.flatten() {
            // Avoid syncing back files synced from ft.
            if path
                .components()
                .any(|c| c.as_os_str().to_str().unwrap() == "ftsync")
            {
                continue;
            }

            // Make sure we are not processing files twice.
            if !PROCESSED_QUEUE_FILES.lock().unwrap().insert(path.clone()) {
                continue;
            }
            new_files_ctr += 1;

            let qfile = parse_queue_file(&path);
            if qfile.is_none() {
                continue;
            }
            let qfile = qfile.unwrap();

            let file_hash = hash_file_content(&qfile.path);
            let mut entry_ts_guard = SEEN_HASHES_TO_TS.lock().unwrap();
            let entry_ts = entry_ts_guard.get_mut(&file_hash.clone());
            if let Some(entry_ts) = entry_ts {
                if *entry_ts > qfile.ts {
                    // we found a queue file that found the same input earlyer,
                    // so update the ts. Since this is the same hash, we do not need
                    // to copy this file again.
                    *entry_ts = qfile.ts;
                } else {
                    // there is already an entry for the  given hash and it was found
                    // earlyer so just ignore this one.
                }
                continue;
            } else {
                // Never saw this hash before -> so insert it.
                entry_ts_guard.insert(file_hash.clone(), qfile.ts);
            }

            let new_name = format!("ts:{}+hash:{}+aflpp", qfile.ts, file_hash);
            let mut dst_path = interesting_dir.to_owned();
            dst_path.push(new_name);

            let dst_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dst_path);
            match dst_file {
                Ok(mut dst_file) => {
                    let content = fs::read(&path)?;
                    dst_file.write_all(&content)?;
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    // just ignore this case
                }
                Err(ref err) => {
                    log::error!(
                        "Failed to copy file from {:?} to {:?}: {:?}",
                        path,
                        &dst_path,
                        err
                    );
                }
            }
        }
        log::info!(
            "Synced {} new queue files from AFL++ to interesting folder",
            new_files_ctr
        );

        let crashes_glob = format!("{}/*/crashes/*", afl_workdir.as_os_str().to_str().unwrap());
        let crashes_glob = glob::glob(&crashes_glob).unwrap();

        for crash in crashes_glob.flatten() {
            let hash = hash_file_content(&crash);
            let mut seen_hashes = AFL_CRASHES_TO_FT_SEEN_HASHES.lock().unwrap();
            if seen_hashes.insert(hash.clone()) {
                let name = format!("{}-{}", crash.file_name().unwrap().to_str().unwrap(), hash);
                let mut dst = crashes_path.to_owned();
                dst.push(name);
                fs::copy(crash, dst).unwrap();
            }
        }

        Ok(())
    }

    fn sync_from_ft(afl_workdir: &Path, interesting_dir: &Path) -> Result<()> {
        let mut ft_afl_sync_dir = afl_workdir.to_owned();
        ft_afl_sync_dir.push("ftsync");
        ft_afl_sync_dir.push("queue");
        fs::create_dir_all(&ft_afl_sync_dir).unwrap();

        let interesting_glob = format!("{}/*", interesting_dir.to_str().unwrap());
        let from_ft_files = glob::glob(&interesting_glob)?;
        for file in from_ft_files.flatten() {
            // Make sure we are syncing back interesting files we initially pushed from
            // afl to ft's interesting folder.
            if file
                .components()
                .any(|c| c.as_os_str().to_str().unwrap().contains("+aflpp"))
            {
                continue;
            }

            let hash = hash_file_content(&file);

            let mut seen_hashes = FT_TO_AFL_SEEN_HASHES.lock().unwrap();
            if !seen_hashes.insert(hash) {
                continue;
            }

            let id = FT_TO_AFL_SYNC_CTR.fetch_add(1, Ordering::Relaxed);
            let name = format!("id:{:06}", id);
            let mut dst = ft_afl_sync_dir.clone();
            dst.push(name);
            fs::copy(file, dst).unwrap();
        }
        Ok(())
    }

    fn sync_worker(
        exit_requested: Arc<AtomicBool>,
        afl_workdir: PathBuf,
        interesting_dir: PathBuf,
        crashes_dir: PathBuf,
    ) -> Result<()> {
        // Wait for other processes to start up.
        interruptable_sleep(Duration::from_secs(60), &exit_requested);

        loop {
            if exit_requested.load(Ordering::Relaxed) {
                log::info!("Stopping sync worker");
                break;
            }

            log::info!("Running sync worker");
            AflPlusPlus::sync_to_ft(&afl_workdir, &interesting_dir, &crashes_dir)?;
            AflPlusPlus::sync_from_ft(&afl_workdir, &interesting_dir)?;

            interruptable_sleep(Duration::from_secs(30), &exit_requested);
        }

        Ok(())
    }

    pub fn start(
        &mut self,
        afl_workers: usize,
        symcc_job_cnt: usize,
        weizz_job_cnt: usize,
        exit_requested: Arc<AtomicBool>,
    ) -> Result<()> {
        log::info!("Starting {} AFL++ workers", afl_workers);
        let mut workers = Vec::new();
        unsafe {
            START_TS = Some(Instant::now());
        }

        if symcc_job_cnt > 0 {
            assert!(afl_workers > 0);
            // We need to use the AFL binary provided via the SymCC config section
            // because SymCC is incompatible with the AFL++ version
            // (which uses non-collision dynamically sized bitmaps).
            self.config.sink.bin_path = self
                .config
                .symcc
                .as_ref()
                .expect("missing symcc config section")
                .afl_bin_path
                .clone();
            self.config.sink.env = self.config.symcc.as_ref().unwrap().afl_bin_env.clone();
        }

        for i in 0..afl_workers {
            let worker_id = match i {
                0 => WorkerId::AflMaster,
                n => WorkerId::AflSlave(n),
            };
            log::info!("Starting AFL worker {:?}", worker_id);

            let worker = AflPlusPlusWorker::new(self.config.clone(), self.import_dirs.clone());
            {
                let exit_requested = Arc::clone(&exit_requested);
                let (init_done_sender, init_done_receiver) = mpsc::channel();
                let worker_handle =
                    thread::spawn(move || worker.run(worker_id, exit_requested, init_done_sender));
                init_done_receiver
                    .recv_timeout(Duration::from_secs(10))
                    .context("Worker exceeded timeout during startup")?;
                workers.push((worker_id, worker_handle));
            }
        }

        for i in 0..weizz_job_cnt {
            let worker_id = if i == 0 {
                WorkerId::WeizzMaster
            } else {
                WorkerId::WeizzWorker(i)
            };

            log::info!("Starting WEIZZ worker: {:?}", worker_id);
            let worker = WeizzWorker::new(self.config.clone());
            {
                let exit_requested = Arc::clone(&exit_requested);
                let (init_done_sender, init_done_receiver) = mpsc::channel();
                let worker_handle =
                    thread::spawn(move || worker.run(worker_id, exit_requested, init_done_sender));
                init_done_receiver
                    .recv_timeout(Duration::from_secs(10))
                    .context("Worker exceeded timeout during startup")?;
                workers.push((worker_id, worker_handle));
            }

            thread::sleep(Duration::from_millis(250));
        }

        if symcc_job_cnt > 0 {
            // SYMCC expects working directories of AFL++ to exist, thus
            // we give AFL++ some time to spin up.
            let duration = Duration::from_secs(30);
            log::info!(
                "Waiting {:?} for AFL++ workers to spin up, thus SYMCC can use the found inputs.",
                duration
            );
            thread::sleep(duration);
        }

        for i in 0..symcc_job_cnt {
            let worker_id = WorkerId::SymccWorker(i);
            log::info!("Starting SymCC worker: {:?}", worker_id);
            let worker = SymccWorker::new(self.config.clone());
            {
                let exit_requested = Arc::clone(&exit_requested);
                let (init_done_sender, init_done_receiver) = mpsc::channel();
                let worker_handle =
                    thread::spawn(move || worker.run(worker_id, exit_requested, init_done_sender));
                init_done_receiver
                    .recv_timeout(Duration::from_secs(10))
                    .context("Worker exceeded timeout during startup")?;
                workers.push((worker_id, worker_handle));
            }
        }

        self.workers.extend(workers);
        let mut afl_workdir = self.config.general.work_dir.clone();
        afl_workdir.push("aflpp-workdir");

        let interesting_dir = self.config.general.interesting_path();
        let _ = fs::create_dir_all(&interesting_dir);
        let crashes_dir = self.config.general.crashing_path();
        let _ = fs::create_dir_all(&crashes_dir);

        let sync_worker = thread::spawn(move || {
            AflPlusPlus::sync_worker(exit_requested, afl_workdir, interesting_dir, crashes_dir)
        });
        self.sync_worker = Some(sync_worker);

        Ok(())
    }

    pub fn join(self) -> Result<()> {
        for worker in self.workers {
            let join_result = worker.1.join();
            match join_result {
                Err(err) => {
                    log::info!("Failed to join worker {:?}: {:#?}", worker.0, err);
                    return Err(anyhow!("Failed to join worker"));
                }
                Ok(worker_err @ Err(_)) => {
                    log::info!(
                        "Error during execution of worker {:?}: {:?}",
                        worker.0,
                        worker_err
                    );
                    return worker_err;
                }
                _ => {
                    log::info!("Worker {:?} terminated successfully.", worker.0)
                }
            }
        }

        let ret = self.sync_worker.unwrap().join();
        if let Err(err) = ret {
            let err = anyhow!("Failed to stop sync worker {:#?}", err);
            return Err(err);
        }
        log::info!("Sync worker stopped successfully");

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_aflpp_mode(
    config: Config,
    import_dirs: Option<Vec<PathBuf>>,
    aflpp_workers: usize,
    symcc_job_cnt: usize,
    weizz_job_cnt: usize,
    exit_requested: Arc<AtomicBool>,
    timeout: Option<Duration>,
) -> Result<AflPlusPlus> {
    let mut ret = AflPlusPlus::new(config, import_dirs);
    ret.start(
        aflpp_workers,
        symcc_job_cnt,
        weizz_job_cnt,
        Arc::clone(&exit_requested),
    )?;

    if let Some(timeout) = timeout {
        // Set exit_requested to true after exceeding timeout.
        thread::spawn(move || {
            thread::sleep(timeout);
            exit_requested.store(true, Ordering::Relaxed);
        });
    }

    Ok(ret)
}
