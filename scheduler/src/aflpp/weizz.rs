use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::{atomic::AtomicBool, mpsc, Arc},
    time::Duration,
};

use std::os::unix::process::ExitStatusExt;

use crate::{
    config::{Config, VanillaConfig},
    io_channels::InputChannel,
};
use anyhow::anyhow;
use anyhow::Result;
use fuzztruction_shared::util::interruptable_sleep;

use super::WorkerId;

pub struct WeizzWorker {
    config: Config,
    vanilla_config: VanillaConfig,
}

impl WeizzWorker {
    pub fn new(config: Config) -> Self {
        let vanilla_config = config.vanilla.clone();
        WeizzWorker {
            vanilla_config,
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
            WorkerId::WeizzWorker(id) => Some(id),
            WorkerId::WeizzMaster => None,
            _ => unreachable!(),
        };
        let is_master = id.is_none();
        let suffix = if is_master {
            "master".to_owned()
        } else {
            format!("slave{}", id.unwrap())
        };

        // Set output file path
        let tmp = tempfile::Builder::new()
            .suffix(&format!("weizz-out-{}", suffix))
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
            *arg = tmp;
        }

        assert!(PathBuf::try_from("/weizz-fuzzer/weizz").unwrap().exists());
        let mut cmd = Command::new("/weizz-fuzzer/weizz");
        cmd.current_dir("/tmp");

        let inputs_dir = self.config.aflpp.as_ref().unwrap().input_dir.to_str().unwrap();

        cmd.args([
            "-o",
            workdir.to_str().unwrap(),
            "-i",
            inputs_dir,
            "-d",
            "-w",
            "-h",
            "-Q",
        ]);

        if is_master {
            cmd.arg(format!("-M{}", suffix));
        } else {
            cmd.arg(format!("-S{}", suffix));
        }

        cmd.arg("--");

        let mut args = vec![self.vanilla_config.bin_path.to_str().unwrap().to_owned()];
        args.extend(self.config.sink.arguments);
        cmd.args(args);

        cmd.env_clear();
        cmd.env("WEIZZ_NO_UI", "1");
        cmd.envs(self.vanilla_config.env);

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
                    let err = anyhow!(
                        "Child exited unexpectedly: {:?}, {:?}",
                        exit_status,
                        exit_status.signal()
                    );
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
