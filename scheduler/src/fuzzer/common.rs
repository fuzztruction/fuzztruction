use std::{
    cmp,
    collections::HashSet,
    hash::Hasher,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Instant,
};

use crate::{
    config::Config,
    mutation_cache_ops::MutationCacheOpsEx,
    sink::{self, AflSink},
    sink_bitmap::Bitmap,
    source::{self, Source},
    trace::Trace,
};

use ahash::AHasher;
use anyhow::Result;
use fuzztruction_shared::{mutation_cache::MutationCache, types::PatchPointID};
use lazy_static::lazy_static;
use log::trace;
use std::time::Duration;
use thiserror::Error;

use super::{
    queue::{Input, QueueEntry},
    worker::WorkerUid,
    worker_impl::{FuzzingPhase, MutatorType},
};

const CALIBRATION_MEASURE_CYCLES: u64 = 50;

/// Different types of input that might be use the create new queue entries.
#[allow(dead_code)]
#[derive(Debug)]
pub enum InputType<'a> {
    Input(&'a Arc<Input>),
    Bytes(&'a [u8]),
    Parent(&'a QueueEntry),
}

impl InputType<'_> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            InputType::Input(i) => i.data(),
            InputType::Bytes(b) => b,
            InputType::Parent(e) => e.input_as_ref().data(),
        }
    }
}

#[derive(Debug, Error)]
#[allow(unused)]
pub enum CalibrationError {
    #[error("The target showed varing behavior during source execution.")]
    SourceUnstable(String),
    #[error("The target showed varing behavior during sink execution.")]
    SinkUnstable(String),
    #[error("Error while executing the source target {0:#?}")]
    SourceExecutionFailed(source::RunResult),
    #[error("Error while executing the sink target {0:#?}")]
    SinkExecutionFailed(sink::RunResult),
    #[error("Source did not produce any output.")]
    NoSourceOutput,
}

#[derive(Debug, Error)]
#[allow(unused)]
pub enum ExecError {
    /// The source failed during execution.
    #[error("Error while executing the source {0:#?}")]
    SourceError(source::RunResult),
    /// The source was successfully executed, but did not produced any output.
    #[error("The source produced no output.")]
    NoSourceOutput,
    /// The source execution was successfull, but we already saw the produced output (hash).
    #[error("Duplicated Output.")]
    DuplicatedOutput,
}

/// Produces a new QueueEntry from an input and mutations (that have been previously configured via the soruces mutation cache).
/// While creating the QueueEntry it is tested whether the input parameters (input, mutations) determenstically produce
/// the same coverage and do not cause, e.g., a crash or timeout.
///
/// # Errors:
///
/// CalibrationError
#[allow(clippy::too_many_arguments)]
pub fn common_calibrate(
    config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    input: &InputType,
    mut virgin_map: Option<&mut Bitmap>,
    finder: Option<WorkerUid>,
    phase: Option<FuzzingPhase>,
    mutator: Option<MutatorType>,
    patch_point: Option<PatchPointID>,
) -> Result<QueueEntry> {
    // Whats about the first observed run result? Pass it as arg?
    let data = input.bytes();

    let mut sink_input = Vec::<u8>::with_capacity(4096);
    let mut coverage_hashes_non_classified = HashSet::new();

    // Get the default timeout value.
    let default_timeout = config.general.timeout;

    let mut exec_durations = Vec::with_capacity(CALIBRATION_MEASURE_CYCLES.try_into().unwrap());

    trace!("Doing {} calibration runs", CALIBRATION_MEASURE_CYCLES);
    for _ in 0..CALIBRATION_MEASURE_CYCLES {
        let cycle_start_ts = Instant::now();

        // This will only return Ok(...) if we made it until execution of the sink.
        let sink_res =
            common_calibration_run(config, source, sink, data, default_timeout, &mut sink_input)?;

        log::trace!("calibration run result: {:?}", sink_res);
        match sink_res {
            sink::RunResult::Terminated(..) => (),
            _ => {
                // Anything else than Terminated is considered a failed calibration.
                return Err(CalibrationError::SinkExecutionFailed(sink_res).into());
            }
        }
        exec_durations.push(cycle_start_ts.elapsed());

        // Note the hash (without classification), thus we can later check for non determinism.
        let cov_hash_non_classified = sink.bitmap().hash32();
        coverage_hashes_non_classified.insert(cov_hash_non_classified);

        sink.bitmap().classify_counts();
        if let Some(virgin_map) = &mut virgin_map {
            sink.bitmap().has_new_bit(virgin_map);
        }
    }

    // Add some offset to account for variations.
    let timeout = cmp::min(
        exec_durations.iter().max().unwrap(),
        &config.general.timeout,
    );

    // Check whether the coverage output is deterministic.
    let mut sink_unstable = false;
    if coverage_hashes_non_classified.len() > 1 {
        if config.sink.allow_unstable_sink {
            log::warn!("Sink is unstable, but this is currently allowed.");
            sink_unstable = true;
        } else {
            return Err(CalibrationError::SinkUnstable("Varying coverage.".to_owned()).into());
        }
    }

    // The runs where deterministic. Thus the last produced bitmap is a representant
    // of all previous runs.
    let bitmap = sink.bitmap();
    bitmap.classify_counts();
    let qe_hash = bitmap.hash32();

    let qe_input = match input {
        InputType::Bytes(b) => Input::from_bytes::<&[u8], PathBuf>(b, None),
        InputType::Input(i) => (*i).clone(),
        InputType::Parent(p) => p.input(),
    };

    let mut mc = source.mutation_cache().borrow().try_clone()?;
    mc.purge_nop_entries();

    let mut qe = QueueEntry::new(
        qe_input,
        chrono::Utc::now(),
        Some(&mc.save_bytes()),
        qe_hash,
        *timeout,
        sink_unstable,
        bitmap,
        finder,
        phase,
        mutator,
        patch_point,
    );

    if let InputType::Parent(parent) = input {
        qe.set_parent(parent);
    }

    log::trace!("Calibration done: {:#?}", qe);
    Ok(qe)
}

//FIXME: Whats about multiple sinks / other sink type?
/// input, source, sink, fn_virgin_map -> RunResult
#[inline]
pub fn common_calibration_run(
    _config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    data: &[u8],
    timeout: Duration,
    sink_input: &mut Vec<u8>,
) -> Result<sink::RunResult> {
    source.write(data);
    let success = source.run(timeout)?;
    match success {
        source::RunResult::Terminated { .. } => (),
        _ => return Err(CalibrationError::SourceExecutionFailed(success).into()),
    }
    source.read(sink_input);
    if sink_input.is_empty() {
        return Err(CalibrationError::NoSourceOutput.into());
    }

    // Run the sink.
    sink.write(sink_input);
    sink.run(timeout)
}

lazy_static! {
    static ref SEEN_OUTPUT_HASHES: RwLock<HashSet<u64>> = RwLock::new(HashSet::new());
}

#[inline]
pub fn common_run(
    _config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    source_input_bytes: &[u8],
    timeout: Duration,
    scratch_buffer: &mut Vec<u8>,
) -> Result<sink::RunResult> {
    source.write(source_input_bytes);
    let success = source.run(timeout)?;
    match success {
        source::RunResult::Terminated { .. } => (),
        _ => return Err(ExecError::SourceError(success).into()),
    }
    source.read(scratch_buffer);
    if scratch_buffer.is_empty() {
        return Err(ExecError::NoSourceOutput.into());
    }

    //? Is 64 bit enough for us?
    let mut hasher = AHasher::default();
    hasher.write(scratch_buffer);
    let h = hasher.finish();

    let seen_hashes_locked_read = SEEN_OUTPUT_HASHES.read().unwrap();
    if seen_hashes_locked_read.contains(&h) {
        return Err(ExecError::DuplicatedOutput.into());
    } else {
        // Upgrade to write lock.
        drop(seen_hashes_locked_read);
        let mut seen_hashes_locked_write = SEEN_OUTPUT_HASHES.write().unwrap();
        seen_hashes_locked_write.insert(h);
    }

    // Run the source.
    sink.write(scratch_buffer);
    sink.run(timeout)
}

#[inline]
pub fn common_trace(
    _config: &Config,
    source: &mut Source,
    data: &[u8],
    timeout: Duration,
    sink_input: &mut Vec<u8>,
) -> Result<Trace> {
    let pp = source.get_patchpoints()?;
    let mut trace_mc = MutationCache::from_patchpoints(pp.iter())?;
    trace_mc.remove_const_type();

    let current_mc = source.mutation_cache();
    let mc_backup = current_mc.borrow_mut().save_bytes();

    trace_mc.union_and_replace(&current_mc.borrow());
    source.mutation_cache_replace(&trace_mc)?;

    source.write(data);
    let res = source.trace(timeout);

    // Restore previous state of the MC.
    let mut old_mc = MutationCache::new()?;
    old_mc.load_bytes(&mc_backup)?;
    source.mutation_cache_replace(&old_mc)?;

    if let Ok((run_result, trace)) = res {
        let trace = match run_result {
            source::RunResult::Terminated { .. } => trace,
            _ => return Err(CalibrationError::SourceExecutionFailed(run_result).into()),
        };

        source.read(sink_input);
        if sink_input.is_empty() {
            return Err(CalibrationError::NoSourceOutput.into());
        }

        Ok(trace)
    } else {
        Err(res.unwrap_err())
    }
}
