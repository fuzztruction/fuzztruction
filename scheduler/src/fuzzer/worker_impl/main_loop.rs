use anyhow::Result;
use rand::{distributions::WeightedIndex, prelude::Distribution, thread_rng};
use std::{ops::ControlFlow, sync::mpsc};

use crate::fuzzer::{
    common::CalibrationError, worker::FuzzingWorker, worker_impl::phases::FuzzingPhase,
};

/// The "private" implementation that contains the logic that is executed after spawn()
/// was called.
impl FuzzingWorker {
    /// The entrypoint into the fuzzer loop. This loop is executed
    /// until the FuzzingWorker is termined.
    pub fn fuzzing_main_loop(mut self) -> Result<()> {
        self.init()?;
        self.init_shared()?;

        // Notify the parent that we finished the initialization
        // and that the next worker can be spawned.
        self.init_done.0.send(true)?;

        // Wait for all threads to finish the initialization.
        self.init_shared_barrier.wait();

        self.stats.lock().unwrap().init();

        let mut ret = Ok(());
        self.state.set_phase(FuzzingPhase::Discovery);

        // Loop until we get stopped by our parent.
        loop {
            let next_entry = self.schedule_next();
            let next_entry = match next_entry {
                ControlFlow::Continue(entry) => entry,
                ControlFlow::Break(_) => break,
            };
            if self.should_stop() {
                break;
            }

            log::info!("Next entry picked for fuzzing: {:#?}", next_entry);

            // Trace the selected entry and on success continue.
            // On error, pick next.
            match self.trace_queue_entry(&next_entry) {
                Err(err) => {
                    match err.downcast_ref::<CalibrationError>() {
                        Some(err) => {
                            log::warn!("Tracing failed: {:#?}. Entry blacklisted.", err);
                            next_entry.stats_rw().set_blacklisted();
                            continue;
                        }
                        None => {
                            // Unknown error (this is fatal) => raise it
                            let msg = "Tracing failed with unexpected error".to_owned();
                            log::error!("{}: {:#?}", msg, err);
                            ret = Err(err.context(msg));
                            break;
                        }
                    }
                }
                Ok(Some(trace)) => {
                    if trace.len() == 0 {
                        log::warn!("Trace length is zero! Entry blacklisted");
                        continue;
                    } else {
                        // Trace contains entries and was successful.
                    }
                }
                Ok(None) => {
                    // Entry is currently not traceable, try next.
                    continue;
                }
            }

            if self.should_stop() {
                break;
            }

            // `next_entry` was successfully traced, lets start fuzzing.
            self.state.set_entry(next_entry);
            self.fuzz_selected_entry()?;
        }

        log::info!("Worker {:?} terminated", self.uid());
        self.tear_down()?;
        ret
    }

    /// Check whether this worker received a stop request from its
    /// controlling thread.
    pub fn should_stop(&mut self) -> bool {
        if self.stop_requested {
            return true;
        }

        let was_stopped = self.stop_channel.1.try_recv();
        let ret = match was_stopped {
            Ok(_) => {
                log::info!("Worker {:?} received a stop signal.", self.uid());
                true
            }
            Err(e) => {
                match e {
                    // No message received so far.
                    mpsc::TryRecvError::Empty => false,
                    _ => {
                        log::error!("Failed to check for stop condition: {e}", e = e);
                        // Instruct the thread to stop if we run into an unknown error condition.
                        true
                    }
                }
            }
        };
        // Make sure as soon this function returns true once, it always does.
        self.stop_requested = ret;
        ret
    }

    /// Fuzz the selected QueueEntry.
    fn fuzz_selected_entry(&mut self) -> Result<()> {
        let _rng = rand::thread_rng();
        let entry = self.state.entry();
        self.load_queue_entry_mutations(&entry)?;

        let source = self.source.as_mut().unwrap();
        let _mc_len = source.mutation_cache_apply_fn(|e| e.len());

        if !self.is_phase_done(FuzzingPhase::Discovery) {
            log::info!("Running {:?} phase", FuzzingPhase::Discovery);
            self.do_discovery_phase()?;
            // During Discovery, no other phase is executed -> return and schedule
            // next QueueEntry.
            return Ok(());
        }

        let choices = self.get_choices();
        let choice = make_choice(&choices);
        self.do_choosen_phase(choice)?;

        Ok(())
    }

    fn do_choosen_phase(
        &mut self,
        choice: Option<(u32, FuzzingPhase)>,
    ) -> Result<(), anyhow::Error> {
        log::info!("Running phase {:?}", choice);
        match choice {
            Some((.., FuzzingPhase::Mutate)) => {
                self.do_mutate_phase()?;
            }
            Some((.., FuzzingPhase::Add)) => {
                self.do_add_phase()?;
            }
            Some((.., FuzzingPhase::Combine)) => {
                self.do_combine_phase()?;
            }
            Some(phase) => panic!("Unknown phase: {:?}", phase),
            None => {
                log::info!("No FuzzingPhases to choose from");
            }
        };
        Ok(())
    }

    fn get_choices(&self) -> Vec<(u32, FuzzingPhase)> {
        let mut choices = Vec::new();
        // Disabled phases have a weight of zero
        if !self.is_phase_done(FuzzingPhase::Add) {
            let choice = (self.config.phases.add.weight, FuzzingPhase::Add);
            choices.push(choice);
        }
        if !self.is_phase_done(FuzzingPhase::Mutate) {
            let choice = (self.config.phases.mutate.weight, FuzzingPhase::Mutate);
            choices.push(choice);
        }
        if !self.is_phase_done(FuzzingPhase::Combine) {
            let choice = (self.config.phases.combine.weight, FuzzingPhase::Combine);
            choices.push(choice);
        }
        choices
    }
}

fn make_choice(choices: &[(u32, FuzzingPhase)]) -> Option<(u32, FuzzingPhase)> {
    let dist = WeightedIndex::new(choices.iter().map(|e| e.0)).ok();
    dist.map(|dist| dist.sample(&mut thread_rng()))
        .map(|choice| choices[choice])
}
