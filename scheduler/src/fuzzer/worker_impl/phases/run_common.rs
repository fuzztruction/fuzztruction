use std::time::Instant;

use crate::{
    constants::EXECUTION_TIMEOUT_MULTIPLYER,
    fuzzer::{
        common::{common_calibrate, common_run, CalibrationError, ExecError, InputType},
        event_counter::FuzzerEventCounter,
        worker::FuzzingWorker,
    },
    sink::{self},
    sink_bitmap::BitmapStatus,
    source,
};
use anyhow::Result;
use nix::sys::signal::Signal;

impl FuzzingWorker {
    /// Try to create a new [QueueEntry] from the current fuzzer configuration
    /// (sink input and mutation cache state). While this should be in most cases
    /// successfull, instability of the source or sink might cause this process to
    /// fail. However, this is not considered an error, and still yield Ok(())
    /// as return value.
    ///
    /// # Errors
    ///
    /// All errors returned by this function must be considered fatal.
    fn create_new_queue_entry(&mut self, bitmap_status: BitmapStatus) -> Result<()> {
        let worker_uid = self.uid();
        let entry = self.state.entry();
        let source = self.source.as_mut().unwrap();
        let sink = self.sink.as_mut().unwrap();
        let input = InputType::Parent(&entry);
        let mut virgin_map = sink.bitmap().clone_with_pattern(0xff);

        let calibration_result = common_calibrate(
            &self.config,
            source,
            sink,
            &input,
            Some(&mut virgin_map),
            Some(worker_uid),
            Some(self.state.phase()),
            Some(self.state.mutator()),
            Some(self.state.patch_point()),
        );

        match calibration_result {
            Ok(entry) => {
                if let BitmapStatus::NewEdge = bitmap_status {
                    // Mark the entry as favoured if it is covering a new edge.
                    entry.stats_rw().mark_favoured()
                }

                let mut queue = self.queue.lock().unwrap();
                log::info!("New QueueEntry: {:#?}", &entry);
                let new_entry = queue.push(&entry);
                drop(queue);

                let mut cerebrum_guard = self.cerebrum.write().unwrap();
                cerebrum_guard.as_mut().unwrap().report_new_qe(new_entry);

                virgin_map.not();
                self.virgin_map.has_new_bit(&mut virgin_map);
                let mut shared_virgin_map = self.shared_virgin_map.lock().unwrap();
                virgin_map.has_new_bit(&mut shared_virgin_map);
                drop(shared_virgin_map);
            }
            Err(err) => match err.downcast_ref::<CalibrationError>() {
                Some(err) => {
                    // This is expected, just print the error and return.
                    log::info!("Queue entry calibration failed: {:?}", err);
                }
                None => {
                    log::error!("Unexpected error during calibration!");
                    return Err(err.context("Error while calibrating new queue entry"));
                }
            },
        }

        Ok(())
    }

    /// Handle the case if the iteration failed before reaching the sink.
    #[inline]
    fn handle_source_exec_error(&mut self, stats: &mut FuzzerEventCounter, error: &ExecError) {
        match error {
            ExecError::SourceError(source_error) => match source_error {
                source::RunResult::TimedOut { .. } => {
                    stats.source_timeout += 1;
                }
                source::RunResult::Signalled { .. } => {
                    stats.source_crashes += 1;
                }
                r => {
                    unreachable!("Unexpected run result: {:?}", r);
                }
            },
            ExecError::NoSourceOutput => {
                stats.source_no_output += 1;
            }
            ExecError::DuplicatedOutput => {
                stats.source_duplicated_output += 1;
            }
        }
    }

    #[inline]
    fn handle_run_result_terminated(
        &mut self,
        stats: &mut FuzzerEventCounter,
        sink_input: &[u8],
    ) -> Result<()> {
        let sink = self.sink.as_mut().unwrap();
        let coverage_map = sink.bitmap();
        coverage_map.classify_counts();

        let new_coverage = coverage_map.has_new_bit(&mut self.virgin_map);

        if matches!(new_coverage, BitmapStatus::NewEdge | BitmapStatus::NewHit) {
            // New coverage, consult global map.
            let mut global_virgin_map = self.shared_virgin_map.lock().unwrap();
            // Check whether this is globally a new path (and clear it from the global map).
            let has_new_bits = coverage_map.has_new_bit(&mut global_virgin_map);
            // Sync local map with global map, thus we do not need to grab the log next time
            // if we see an already seen path.
            self.virgin_map.copy_from(&global_virgin_map);
            drop(global_virgin_map);

            match has_new_bits {
                BitmapStatus::NewEdge => {
                    stats.edges_found += 1;
                }
                BitmapStatus::NewHit => {
                    stats.hits_found += 1;
                }
                BitmapStatus::NoChange => return Ok(()),
            }
            stats.last_finding_ts = Some(Instant::now());
            self.maybe_save_interesting_input(sink_input);
            self.create_new_queue_entry(has_new_bits)?;
        }

        Ok(())
    }

    fn handle_run_result_signalled(
        &mut self,
        stats: &mut FuzzerEventCounter,
        sink_input: &[u8],
        signal: Signal,
    ) -> Result<()> {
        let sink = self.sink.as_mut().unwrap();
        let coverage_map = sink.bitmap();
        coverage_map.classify_counts();

        let new_bits = FuzzingWorker::check_virgin_maps(
            coverage_map,
            &mut self.crash_virgin_map,
            &self.shared_crash_virgin_map,
        );

        match new_bits {
            BitmapStatus::NewEdge => {
                stats.sink_unique_crashes += 1;
                stats.last_crash_ts = Some(Instant::now());
                self.save_crashing_input(sink_input, signal);
            }
            BitmapStatus::NewHit => {
                stats.sink_unique_crashes += 1;
                stats.last_crash_ts = Some(Instant::now());
                self.save_crashing_input(sink_input, signal);
            }
            BitmapStatus::NoChange => (),
        }

        Ok(())
    }

    #[inline]
    fn handle_run_result(
        &mut self,
        stats: &mut FuzzerEventCounter,
        run_result: sink::RunResult,
        sink_input: &[u8],
    ) -> Result<()> {
        let _entry = self.state.entry();
        let sink = self.sink.as_mut().unwrap();
        let coverage_map = sink.bitmap();
        coverage_map.classify_counts();

        match run_result {
            sink::RunResult::Terminated(..) => {
                stats.successful_source_execs += 1;
                self.handle_run_result_terminated(stats, sink_input)?;
            }
            sink::RunResult::Signalled(signal) => {
                stats.sink_crashes += 1;
                self.handle_run_result_signalled(stats, sink_input, signal)?;
            }
            sink::RunResult::TimedOut => {
                stats.sink_timeout += 1;
            }
        }

        Ok(())
    }

    #[inline]
    pub fn do_run(
        &mut self,
        stats: &mut FuzzerEventCounter,
        input_bytes: &[u8],
        scratch_buffer: &mut Vec<u8>,
    ) -> Result<()> {
        let entry = self.state.entry();
        let source = self.source.as_mut().unwrap();
        let sink = self.sink.as_mut().unwrap();
        let timeout = entry
            .avg_exec_duration_raw()
            .mul_f64(EXECUTION_TIMEOUT_MULTIPLYER);

        let run_result = common_run(
            &self.config,
            source,
            sink,
            input_bytes,
            timeout,
            scratch_buffer,
        );

        match run_result {
            Ok(run_result) => {
                self.handle_run_result(stats, run_result, scratch_buffer)?;
            }
            Err(err) => {
                match err.downcast_ref::<ExecError>() {
                    Some(exec_error) => {
                        self.handle_source_exec_error(stats, exec_error);
                    }
                    None => {
                        // Unknown error => fatal
                        log::error!(
                            "Got unexpected error: {:#?}. child_exit_reason={:#?}",
                            err,
                            source.try_get_child_exit_reason()
                        );
                        return Err(err.context("Unexpected error while executing source/sink"));
                    }
                }
            }
        }

        Ok(())
    }
}
