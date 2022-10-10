use std::{
    intrinsics::unlikely,
    ops::ControlFlow,
    time::{Duration, Instant},
};

use fuzztruction_shared::mutation_cache_entry::MutationCacheEntry;

use crate::{
    constants::FUZZING_LOOP_UPDATE_INTERVAL,
    fuzzer::{
        event_counter::FuzzerEventCounter,
        worker::FuzzingWorker,
        worker_impl::{cerebrum::FuzzerConfiguration, mutators},
    },
};

use anyhow::Result;

impl FuzzingWorker {
    /// This function is used by all fuzzing phases to do the actual fuzzing.
    /// It expects a mapping of [MutationCacheEntry]'s to a set of mutators via `mutations`.
    /// If `no_new_coverage_timeout` is given, the fuzzing loop will be cancelled, if no mutation
    /// yielded coverage since `no_new_coverage_timeout`.
    /// Setting `skip_mce_after_first_path` causes all remaining [Mutator]s of `mutations`
    /// to be skipped as soon as a mutation yielded a new path for the targets
    /// [MutationCacheEntry].
    ///
    /// # Errors
    ///
    /// Every Error returned by this function must be considered fatal.
    #[allow(clippy::type_complexity)]
    pub fn fuzz_candidates(
        &mut self,
        mutations: Vec<(
            &mut MutationCacheEntry,
            Vec<Box<dyn mutators::Mutator<Item = ()>>>,
        )>,
        iteration_no_new_coverage_timeout: Option<Duration>,
        skip_mce_after_first_path: bool,
    ) -> Result<()> {
        let qe = self.state.entry();
        let qe_input = qe.input();
        let source_input_bytes = qe_input.data();
        let mut scratch_buffer = Vec::<u8>::with_capacity(1024 * 1024);
        let current_phase = self.state.phase();

        if self.should_stop() {
            return Ok(());
        }

        // temporary struct that is used to keep stats without
        // incurring locking overhead.
        let mut iteration_stats = FuzzerEventCounter::new();
        iteration_stats.init();

        let source = self.source.as_mut().unwrap();
        source.sync_mutations()?;

        let mut last_update_ts = Instant::now();

        let mut estimated_runtime = Duration::from_secs(0);
        let mut iteration_total_execs_required = 0;
        for (_, mutators) in mutations.iter() {
            mutators.iter().for_each(|m| {
                estimated_runtime += m.estimate_runtime(self.avg_execution_duration);
                iteration_total_execs_required += m.steps_total();
            })
        }

        log::info!(
            "Fuzzing {} entries in {} executions",
            mutations.len(),
            iteration_total_execs_required
        );
        let fuzz_start_ts = Instant::now();
        let phase_start_successful_execs = iteration_stats.successful_source_execs;
        let mut timeout_exceeded = false;
        let mut iteration_configuration = None;

        // consecutively apply all mutations and check result.
        'exit: for e in mutations {
            let target_mce = e.0;
            let mutators = e.1;
            let is_nop = target_mce.is_nop();
            self.state.set_patch_point(target_mce.id());
            let mce_start_paths_cnt = iteration_stats.paths();

            if target_mce.msk_len() == 0 {
                log::error!("Trying to fuzz mutation entry with zero sized msk.");
                continue;
            }
            let msk_copy = target_mce.get_msk_as_slice().to_vec();
            assert_eq!(msk_copy, target_mce.get_msk_as_slice(),);

            'mce: for mutator in mutators {
                self.state
                    .set_mutator(mutator.mutator_type(), mutator.steps_total());
                let mutator_start_ts = Instant::now();
                let mutator_start_execs = iteration_stats.execs;

                iteration_configuration = Some(FuzzerConfiguration::new(
                    qe.clone(),
                    self.state.phase(),
                    mutator.mutator_type(),
                    target_mce.id(),
                    mutator.steps_total(),
                    &iteration_stats,
                ));

                let one_shot = mutator.one_shot();
                let sync_needed = mutator.needs_sync();

                // Enable once for this fuzzing round.
                one_shot.then(|| target_mce.enable());

                if sync_needed {
                    self.source.as_mut().unwrap().sync_mutations()?;
                }

                let mutator_type = mutator.mutator_type();
                for _ in mutator {
                    iteration_stats.execs += 1;
                    self.do_run(
                        &mut iteration_stats,
                        source_input_bytes,
                        &mut scratch_buffer,
                    )?;

                    if unlikely(skip_mce_after_first_path)
                        && mce_start_paths_cnt != iteration_stats.paths()
                    {
                        one_shot.then(|| target_mce.disable());
                        if sync_needed {
                            self.source.as_mut().unwrap().sync_mutations()?;
                        }
                        break 'mce;
                    }

                    if unlikely(last_update_ts.elapsed() > FUZZING_LOOP_UPDATE_INTERVAL) {
                        // execs done so far while processing the mutator
                        let mutator_execs_done = iteration_stats.execs - mutator_start_execs;
                        self.state.set_iterations(mutator_execs_done as usize);

                        // execs done since start of the iteration (start of the function)
                        let iteration_execs_done = iteration_stats.execs;
                        let execs_left =
                            iteration_total_execs_required - iteration_execs_done as usize;
                        log::debug!(
                            "Completed {} of {} executions (progress={:.02}%, left={}, execs/s={:.02}, time_left={:?}, phase={:?})",
                            iteration_execs_done,
                            iteration_total_execs_required,
                            iteration_execs_done as f64 / iteration_total_execs_required as f64 * 100.0,
                            execs_left,
                            iteration_stats.execs_per_sec().unwrap_or_default(),
                            iteration_stats.execs_per_sec().map(|execs_s| Duration::from_secs(execs_left as u64 / execs_s.ceil() as u64)),
                            current_phase,
                        );

                        last_update_ts = Instant::now();
                        if self.should_stop() {
                            one_shot.then(|| target_mce.disable());
                            // No sync check needed since we exit the loop.
                            break 'exit;
                        }

                        if let ControlFlow::Break(_) = check_if_no_new_coverage_timeout_was_exceeded(
                            iteration_no_new_coverage_timeout,
                            &iteration_stats,
                        ) {
                            timeout_exceeded = true;
                            break 'exit;
                        }
                    }
                }
                if msk_copy != target_mce.get_msk_as_slice() {
                    log::error!(
                        "Mutator {:?} left MCE in a dirty state! {:?}!={:?}",
                        mutator_type,
                        msk_copy,
                        target_mce.get_msk_as_slice()
                    );
                }

                one_shot.then(|| target_mce.disable());
                if sync_needed {
                    // We need to sync here, since the next entry might not have set sync_needed.
                    self.source.as_mut().unwrap().sync_mutations()?;
                }

                {
                    let mut cerebrum_guard = self.cerebrum.write().unwrap();
                    let cerebrum = cerebrum_guard.as_mut().unwrap();
                    iteration_configuration
                        .as_mut()
                        .unwrap()
                        .finialize(&iteration_stats);
                    cerebrum.report_configuration(iteration_configuration.take().unwrap());
                }

                let mutator_execs_done = iteration_stats.execs - mutator_start_execs;
                let time_spend = mutator_start_ts.elapsed();
                self.report_execution_duration(
                    time_spend.div_f64(mutator_execs_done as f64),
                    mutator_execs_done as u32,
                );
            }
            assert_eq!(is_nop, target_mce.is_nop(), "Mutator left ");
        }

        let iteration_execs_done = iteration_stats.execs;
        log::debug!(
            "Iteration finished (execs_done={}, exec_required={}, left={})",
            iteration_execs_done,
            iteration_total_execs_required,
            iteration_total_execs_required - iteration_execs_done as usize
        );

        {
            // This is only true if we had an early exit through the 'exit label.
            if let Some(mut configuration) = iteration_configuration.take() {
                // ??? This will mark patch points as done, even though we did not finished fuzzing it.
                // ??? Is that a problem?
                configuration.finialize(&iteration_stats);
                let mut cerebrum_guard = self.cerebrum.write().unwrap();
                let cerebrum = cerebrum_guard.as_mut().unwrap();
                cerebrum.report_configuration(configuration);
            }
        }

        // Sanity check whether the fuzzer continuously crashes.
        let limit = Duration::from_secs(600);
        if phase_start_successful_execs == iteration_stats.successful_source_execs
            && fuzz_start_ts.elapsed() > limit
        {
            log::error!(
                "Fuzzer had no successful execution since {:?}! iteration_stats={:#?}",
                limit,
                iteration_stats,
            );
        }

        // No point in printing the estimation error if this is an early exit.
        // Same is true if we skip MCE's if we find a path.
        if !timeout_exceeded && !skip_mce_after_first_path {
            let time_spend = fuzz_start_ts.elapsed();
            #[allow(clippy::cast_possible_wrap)]
            let diff_ms = time_spend.as_millis() as i128 - estimated_runtime.as_millis() as i128;
            log::info!(
                "Fuzzing took {} seconds ({} ms). actual-estimated={} ms ({:.02})",
                time_spend.as_secs(),
                time_spend.as_millis(),
                diff_ms,
                diff_ms as f64 / (time_spend.as_millis() as f64 / 100.0),
            );
        }

        // snyc the locally stored [FuzzerEventCounter] to the global one.
        let mut shared_stats = self.stats.lock().unwrap();
        *shared_stats += &iteration_stats;
        log::info!("round   stats: {:#?}", iteration_stats);
        log::info!("overall stats: {:#?}", shared_stats);

        Ok(())
    }
}

/// Check if we did not found a new path or crash during since `no_new_coverage_timeout` long.
/// If `no_new_coverage_timeout` is None, `stats.start_ts` is used instead.
fn check_if_no_new_coverage_timeout_was_exceeded(
    no_new_coverage_timeout: Option<Duration>,
    stats: &FuzzerEventCounter,
) -> ControlFlow<()> {
    if let Some(no_new_coverage_timeout) = no_new_coverage_timeout {
        if stats.init_ts.unwrap().elapsed() < no_new_coverage_timeout {
            // If we are not running for `no_new_coverage_timeout` long there is no
            // point of checking whether we found new coverage.
            return ControlFlow::Continue(());
        }

        // We are running for `no_new_coverage_timeout` long, check if the last
        // finding happend less than `no_new_coverage_timeout` ago.
        if let Some(time_since_last_path) = stats.time_since_last_new_path_or_crash() {
            if time_since_last_path > no_new_coverage_timeout {
                log::warn!(
                    "Iteration timeout {:?} exceeded, canceling iteration.",
                    no_new_coverage_timeout
                );
                return ControlFlow::Break(());
            }
        } else {
            // No new path found so far -> cancel phase.
            log::warn!(
                "Iteration timeout {:?} exceeded, canceling iteration.",
                no_new_coverage_timeout
            );
            return ControlFlow::Break(());
        }
    }
    ControlFlow::Continue(())
}
