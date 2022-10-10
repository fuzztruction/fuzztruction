use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::{atomic::AtomicBool, mpsc, Arc},
    time::Duration,
};

use crate::{
    config::{Config, SymccConfig},
    io_channels::InputChannel,
};
use anyhow::anyhow;
use anyhow::Result;
use fuzztruction_shared::util::interruptable_sleep;

use super::WorkerId;

pub struct SymccWorker {
    config: Config,
    symcc_config: SymccConfig,
}

impl SymccWorker {
    pub fn new(config: Config) -> Self {
        let symcc_config = config
            .symcc
            .as_ref()
            .expect("Missing symcc section in config file")
            .clone();
        SymccWorker {
            symcc_config,
            config,
        }
    }

    pub fn run(
        mut self,
        worker_id: WorkerId,
        exit_requested: Arc<AtomicBool>,
        init_done: mpsc::Sender<()>,
    ) -> Result<()> {
        let mut workdir = self.config.general.work_dir.clone();
        workdir.push("aflpp-workdir");

        let id = match worker_id {
            WorkerId::SymccWorker(id) => id,
            _ => unreachable!(),
        };

        let tmp = tempfile::Builder::new()
            .suffix(&format!("symcc-out-{}", id))
            .tempfile_in("/tmp")
            .unwrap();

        let tmp = tmp.path().to_str().unwrap().to_owned();
        if let Some(arg) = self
            .config
            .sink
            .arguments
            .iter_mut()
            .find(|arg| *arg == "$$")
        {
            *arg = tmp.clone()
        }

        if let Some(arg) = self
            .config
            .sink
            .arguments
            .iter_mut()
            .find(|arg| *arg == "$$")
        {
            *arg = tmp;
        }

        let mut afl_worker_dirs = Vec::new();
        let worker_dirs = glob::glob(&format!("{}/*", workdir.to_str().unwrap())).unwrap();
        for dir in worker_dirs.flatten() {
            if dir.is_file() {
                continue;
            }
            afl_worker_dirs.push(dir);
        }
        assert!(!afl_worker_dirs.is_empty());

        let afl_instance_name = &afl_worker_dirs[id % afl_worker_dirs.len()];
        let instance_name = format!("symcc{}", id);

        assert!(PathBuf::try_from(
            "/symcc/util/symcc_fuzzing_helper/target/release/symcc_fuzzing_helper"
        )
        .unwrap()
        .exists());
        let mut cmd =
            Command::new("/symcc/util/symcc_fuzzing_helper/target/release/symcc_fuzzing_helper");
        cmd.current_dir("/symcc/util/symcc_fuzzing_helper/target/release/");
        cmd.args([
            "-o",
            workdir.to_str().unwrap(),
            "-a",
            afl_instance_name.to_str().unwrap(),
            "-n",
            &instance_name,
            "-v",
        ]);

        cmd.arg("--");

        let mut args = vec![self.symcc_config.bin_path.to_str().unwrap().to_owned()];
        args.extend(self.config.sink.arguments);
        cmd.args(args);

        cmd.env_clear();
        cmd.envs(self.symcc_config.env);

        // Passthrough environment for afl-showmap (called by the symcc fuzzing helper)
        for (k, v) in self.symcc_config.afl_bin_env.iter() {
            let new_name = format!("_AFL_PASSTHROUGH_{}", k);
            log::info!("Passing AFL environment variable {} as {}", k, &new_name);
            cmd.env(new_name, v);
        }

        if !matches!(self.config.sink.input_type, InputChannel::Stdin) {
            cmd.stdin(Stdio::null());
        }

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

        Ok(())
    }
}
