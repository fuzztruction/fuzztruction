use std::{
    cell::RefCell,
    fs,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fuzztruction_shared::mutation_cache::MutationCache;
use hex::ToHex;
use nix::sys::signal::Signal;
use sha2::{Digest, Sha256};

use crate::{
    constants::AVG_EXECUTION_TIME_STABILIZATION_VALUE,
    fuzzer::{common::common_trace, queue::QueueEntry, worker::FuzzingWorker},
    sink_bitmap::{Bitmap, BitmapStatus},
    trace::Trace,
};
use anyhow::Result;

use super::FuzzingPhase;

impl FuzzingWorker {
    pub fn report_execution_duration(&mut self, avg_execution_duration: Duration, n: u32) {
        self.avg_execution_duration = self.avg_execution_duration
            * AVG_EXECUTION_TIME_STABILIZATION_VALUE
            + avg_execution_duration * n;
        self.avg_execution_duration /= n + AVG_EXECUTION_TIME_STABILIZATION_VALUE;
    }

    /// Check whether the worker should execute the given phase
    /// or it is finished or was disabled.
    pub fn is_phase_done(&self, phase: FuzzingPhase) -> bool {
        self.state.is_phase_done(phase)
    }

    /// Restore the [MutationCache] state from the state stored in the [QueueEntry].
    /// Using this function and execution the source with the input provided
    /// via [QueueEntry::input()] can be used to reproduce the behavior observed
    /// during creation of `entry`.
    pub(super) fn load_queue_entry_mutations(&mut self, entry: &QueueEntry) -> Result<()> {
        let source = &mut self.source.as_mut().unwrap();
        let mutations = entry.mutations();

        if let Some(data) = mutations {
            let mut new_mc = MutationCache::new()?;
            new_mc.load_bytes(data)?;
            source.mutation_cache_replace(&new_mc)?;
        } else {
            // No mutations attached, just clear the mutation cache content.
            let mc_ref = &source.mutation_cache();
            let mut cache = RefCell::borrow_mut(mc_ref);
            cache.clear();
        }

        Ok(())
    }

    /// Store `sink_input` in the `interesting` directory using its SHA256
    /// hash as its name.
    pub(super) fn maybe_save_interesting_input(&self, sink_input: &[u8]) {
        let mut digest = Sha256::new();
        digest.update(sink_input);
        let sha256_digest: String = digest.finalize().encode_hex();
        let stats_lock = self.stats.lock().unwrap();
        let ts = stats_lock.init_ts;
        let filename = format!(
            "ts:{}+hash:{}",
            ts.unwrap().elapsed().as_millis(),
            sha256_digest
        );

        let mut path = self.interesting_inputs.clone();
        path.push(filename);

        fs::write(&path, sink_input).unwrap();
    }

    /// Store `sink_input` in the `crashing` directory using its SHA256
    /// hash and the signal name as filename.
    pub(super) fn save_crashing_input(&self, sink_input: &[u8], signal: Signal) {
        let mut digest = Sha256::new();
        digest.update(sink_input);
        let sha256_digest: String = digest.finalize().encode_hex();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let mut path = self.crashing_inputs.clone();
        let name = format!("ts:{}+hash:{}+sig:{}", ts.as_secs(), sha256_digest, signal);
        path.push(name);
        fs::write(&path, sink_input).unwrap();
    }

    /// Trace the given `QueueEntry` if it does not contain a trace.
    ///
    /// # Errors:
    /// If tracing fails for known reasons, a `CalibrationError` is returned.
    /// All other error types must be considered fatal.
    pub fn trace_queue_entry(&mut self, entry: &Arc<QueueEntry>) -> Result<Option<Arc<Trace>>> {
        let mut stats_rw_guard = entry.stats_rw();
        if let Some(trace) = stats_rw_guard.trace() {
            log::info!("Entry was already traced.");
            return Ok(Some(trace));
        }

        if stats_rw_guard.tracing_in_progress() {
            log::info!("Entry is already traced by another thread. Skipping");
            return Ok(None);
        }
        stats_rw_guard.mark_tracing_in_progress();
        drop(stats_rw_guard);

        let start_ts = Instant::now();
        self.load_queue_entry_mutations(entry)?;
        let input = entry.input();
        let data = input.data();
        let mut buf = Vec::new();
        let trace = common_trace(
            &self.config,
            self.source.as_mut().unwrap(),
            data,
            self.config.general.tracing_timeout,
            &mut buf,
        );

        log::info!("Tracing took {:?}", start_ts.elapsed());

        match trace {
            Ok(trace) => {
                log::info!("Tracing successfull! #covered={}", trace.len());
                let mut lock = entry.stats_rw();
                lock.set_trace(&trace);
                Ok(Some(lock.trace().unwrap()))
            }
            Err(err) => {
                log::warn!("Error while tracing: {:#?}", err);
                Err(err.context("Error while tracing queue entry"))
            }
        }
    }

    /// Check whether `coverage_map` contains new edges/hits according to the `local_virgin`
    /// and `local_virgin` virgin maps. If this is the case, the corresponding bits are cleared
    /// from both maps. Furthermore, if the local map indicates new coverage, the local
    /// map is synced with the global map.
    pub fn check_virgin_maps(
        coverage_map: &Bitmap,
        local_virgin: &mut Bitmap,
        global_virgin: &Arc<Mutex<Bitmap>>,
    ) -> BitmapStatus {
        let has_new_bits = coverage_map.has_new_bit(local_virgin);
        if matches!(has_new_bits, BitmapStatus::NewEdge | BitmapStatus::NewHit) {
            // New coverage, consult global map.
            let mut global_virgin_map = global_virgin.lock().unwrap();
            // Check whether this is globally a new path (and clear it from the global map).
            let has_new_bits = coverage_map.has_new_bit(&mut global_virgin_map);
            // Sync local map with global map, thus we do not need to grab the log next time
            // if we see an already seen path.
            local_virgin.copy_from(&global_virgin_map);
            drop(global_virgin_map);
            return has_new_bits;
        }
        has_new_bits
    }
}
