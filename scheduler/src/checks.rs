use std::{fs::read_to_string, process::Command};

use anyhow::{anyhow, Context, Result};
use jail::jail::wrap_libc;

use crate::{config::Config, error::CliError, fuzzer::queue::Input};

/// Check whether core_pattern is not set to 'core'. If this is the case, we need
/// to pay the overhead of creating a core image each time we crash during an execution.
fn check_core_pattern_is_core() -> Result<()> {
    let content = read_to_string("/proc/sys/kernel/core_pattern");
    let content = content.expect("Failed to open /proc/sys/kernel/core_pattern.");
    if content.trim() != "core" {
        return Err(anyhow!("Please run\necho core | sudo tee /proc/sys/kernel/core_pattern\nto disabling core dumping on segmentationfaults."));
    }
    Ok(())
}

fn check_fs_suid_dumpable() -> Result<()> {
    let content = read_to_string("/proc/sys/fs/suid_dumpable");
    let content = content.expect("Failed to open /proc/sys/fs/suid_dumpable.");
    if content.trim() != "0" {
        return Err(anyhow!(
            "Please run\necho 0 | sudo tee /proc/sys/fs/suid_dumpable\nto allow the core_pattern 'core'."
        ));
    }
    Ok(())
}

/// Check if the /tmp directory is mounted using tmpfs as filesystem.
/// Since we are reading and writing to this directory with a hight frequency, this
/// gives us a performance boost.
fn check_if_tmp_is_tmpfs() -> Result<()> {
    let content = read_to_string("/proc/mounts");
    let content = content.expect("Failed to open /proc/mounts.");

    let lines = content.split('\n');
    let lines = lines
        .into_iter()
        .filter(|e| e.contains("tmpfs /tmp "))
        .collect::<Vec<_>>();

    if lines.len() > 1 {
        return Err(anyhow!(
            "Found multiple mounts for /tmp:\n{lines:#?}",
            lines = lines
        ));
    } else if lines.is_empty() {
        return Err(anyhow!("Could not find a mount for /tmp."));
    }

    if !lines[0].contains("tmpfs") {
        return Err(anyhow!(
            "Please mount /tmp with tmpfs as filesystem:\nsudo mount -t tmpfs none /tmp"
        ));
    }

    Ok(())
}

/// Check if binaries dynamically linked against the source agent are able to find
/// the source agent shared object during linktime.
fn check_if_agent_is_in_path() -> Result<()> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("ldconfig -p | grep libgenerator_agent.so")
        .output()
        .expect("Failed to run command.");

    if !output.status.success() {
        let mut msg =
            "Failed to find libgenerator_agent.so in ld's path. Please run the following commands:\n"
                .to_owned();
        msg.push_str("echo '/home/user/leah/target/debug' > /etc/ld.so.conf.d/fuzztruction.conf\n");
        msg.push_str("sudo ldconfig");
        return Err(CliError::ConfigurationError(format!("{:#?}", output))).context(msg)?;
    }

    Ok(())
}

/// Check if all requirements to run this software are satisfied.
pub fn check_system() -> Result<()> {
    check_core_pattern_is_core()?;
    check_fs_suid_dumpable()?;
    check_if_tmp_is_tmpfs()?;
    check_if_agent_is_in_path()?;
    Ok(())
}

fn check_jail(config: &Config) -> Result<()> {
    if let Some((uid, _gid)) = config.general.jail_uid_gid() {
        log::info!("Checking whether we have enough permissions to jail the fuzzing process.");
        unsafe {
            let ret = wrap_libc(|| libc::seteuid(0));
            if let Err(err) = ret {
                return Err(anyhow!("Failed to set EUID to 0. If jailing is enable, this process must be run as root: {:#?}", err));
            }
            let ret = wrap_libc(|| libc::seteuid(uid));
            if let Err(err) = ret {
                return Err(anyhow!(
                    "Failed to set EUID to {}. Is the jail-uid valid?: {:#?}",
                    uid,
                    err
                ));
            }
        }
    }
    Ok(())
}

fn check_input_directory(config: &Config) -> Result<()> {
    let input_dir = &config.general.input_dir;
    let inputs = Input::from_dir(input_dir).context("Failed to access inputs directory")?;
    if inputs.is_empty() {
        return Err(anyhow!(
            "No inputs found in input directory {:?}",
            input_dir
        ));
    }
    Ok(())
}

pub fn check_config(config: &Config) -> Result<()> {
    check_jail(config)?;
    check_input_directory(config)?;
    Ok(())
}
