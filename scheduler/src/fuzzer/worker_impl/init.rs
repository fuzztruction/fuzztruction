use anyhow::Result;
use fuzztruction_shared::util::ExpectNone;
use std::{cell::RefCell, fs};

use crate::{
    constants::AVG_EXECUTION_TIME_STABILIZATION_VALUE,
    fuzzer::{
        common::{common_calibrate, InputType},
        queue::{Input, QueueEntry},
        worker::FuzzingWorker,
        worker_impl::Cerebrum,
    },
    sink::AflSink,
    sink_bitmap::Bitmap,
    source::Source,
};
use anyhow::anyhow;

/// The "private" implementation that contains the logic that is executed after spawn()
/// was called.
impl FuzzingWorker {
    /// Do the initial setup after this worker has been started.
    pub fn init(&mut self) -> Result<()> {
        log::info!(
            "Initializing worker {:?}. Thread id is {:?}",
            self.uid(),
            unsafe { libc::gettid() }
        );

        self.source.expect_none("already initialized?");
        self.sink.expect_none("already initialized?");

        fs::create_dir_all(&self.crashing_inputs).unwrap();
        fs::create_dir_all(&self.interesting_inputs).unwrap();

        self.source = Some(Source::from_config(&self.config, Some(self.uid.0))?);
        self.sink = Some(AflSink::from_config(&self.config, Some(self.uid.0))?);

        self.source.as_mut().unwrap().start()?;
        self.sink.as_mut().unwrap().start()?;
        self.resize_bitmaps();

        Ok(())
    }

    /// Resize the bitmaps, if the sink does not use the standard size.
    fn resize_bitmaps(&mut self) {
        let bm_size = self.sink.as_mut().unwrap().bitmap().size();
        let bitmap = &mut self.virgin_map;
        if bitmap.size() != bm_size {
            let new_map = Bitmap::new_in_mem(bm_size, 0xff);
            *bitmap = new_map;
        }
        let bitmap = &mut self.crash_virgin_map;
        if bitmap.size() != bm_size {
            let new_map = Bitmap::new_in_mem(bm_size, 0xff);
            *bitmap = new_map;
        }
        let mut shared_bitmap = self.shared_virgin_map.lock().unwrap();
        if shared_bitmap.size() != bm_size {
            let new_map = Bitmap::new_in_mem(bm_size, 0xff);
            *shared_bitmap = new_map;
        }
        let mut shared_bitmap = self.shared_crash_virgin_map.lock().unwrap();
        if shared_bitmap.size() != bm_size {
            let new_map = Bitmap::new_in_mem(bm_size, 0xff);
            *shared_bitmap = new_map;
        }
    }

    /// Release allocated ressources.
    pub fn tear_down(&mut self) -> Result<()> {
        self.source.as_mut().unwrap().stop()?;
        self.sink.as_mut().unwrap().stop();
        Ok(())
    }

    /// Initialize shared state.
    ///
    /// # Error
    ///
    /// Any error returned by this function can be treaded as an unexpected error
    /// and must lead to the termination of the worker thread.
    pub fn init_shared(&mut self) -> Result<()> {
        let mut error = None;

        // We need to borrow self in the closure again, thus we clone here.
        let shared_init_done = self.shared_init_done.clone();
        // Initialize the queue. This is done by exactly one thread while
        // the others are blocking.
        shared_init_done.call_once(|| {
            log::info!(
                "Worker {:?} has the honor of initializing the shared state",
                self.uid()
            );

            // init cerebrum
            let source = self.source.as_mut().unwrap();
            let patch_points = source.get_patchpoints().unwrap();
            let mut cerebrum_guard = self.cerebrum.write().unwrap();
            let _ = cerebrum_guard.insert(Cerebrum::new(&patch_points, self.queue.clone()));
            drop(cerebrum_guard);

            let success = self.calibrate_seed_files();
            if let Err(e) = success {
                // Notify the other threads that the initialization failed.
                self.queue_init_failed_flag
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                error = Some(e);
            } else {
                let entries = success.unwrap();
                let mut queue = self.queue.lock().unwrap();
                queue.append(entries)
            }
        });

        if let Some(e) = error {
            return Err(e.context("Error while initializing the queue".to_owned()));
        }

        // Check if the worker who successfully grabbed the call_once() lock
        // failed to initialize the queue.
        let init_failed = self
            .queue_init_failed_flag
            .load(std::sync::atomic::Ordering::SeqCst);
        if init_failed {
            return Err(anyhow!(
                "The responsible worker failed to initialize the queue."
            ));
        }

        Ok(())
    }

    /// Run the calibration for all seed files in the input directory and
    /// return a vector of QueueEntries.
    ///
    /// # Error
    ///
    /// If the calibration for one seed file fails, this function returns
    /// [Err] containing a [CalibrationError]. In case of an unexpected error,
    /// the type of the contained value is unspecified.
    fn calibrate_seed_files(&mut self) -> Result<Vec<QueueEntry>> {
        let worker_uid = self.uid();
        let inputs = Input::from_dir(&self.config.general.input_dir)?;
        let mut entries = Vec::new();

        let mut virgin_map = self
            .sink
            .as_mut()
            .unwrap()
            .bitmap()
            .clone_with_pattern(0xff);
        let num_inputs = inputs.len();

        for input in inputs {
            log::info!("Importing {:?} into queue...", &input);
            self.init_done.0.send(false)?;

            let input = InputType::Input(&input);

            // Clear the mutation cache.
            let source = &mut self.source.as_mut().unwrap();
            let mc = source.mutation_cache();
            let mut mc_mut = RefCell::borrow_mut(&mc);
            mc_mut.clear();
            drop(mc_mut);

            let result = common_calibrate(
                &self.config,
                self.source.as_mut().unwrap(),
                self.sink.as_mut().unwrap(),
                &input,
                Some(&mut virgin_map),
                Some(worker_uid),
                None,
                None,
                None,
            );
            log::info!("Import result: {:?}", &result);
            match result {
                Ok(entry) => {
                    self.report_execution_duration(
                        entry.avg_exec_duration_raw(),
                        AVG_EXECUTION_TIME_STABILIZATION_VALUE / num_inputs as u32,
                    );
                    entries.push(entry);
                }
                Err(err) => {
                    log::warn!("Failed to import input seeds file: {:?}", err);
                }
            }
        }

        // Clear the coverage produced by the seed entries from the local and global map.
        virgin_map.not();
        virgin_map.has_new_bit(&mut self.virgin_map);
        let mut global_virgin_map = self.shared_virgin_map.lock().unwrap();
        virgin_map.has_new_bit(&mut global_virgin_map);

        if entries.is_empty() {
            return Err(anyhow!("Import of all import seeds failed"));
        }

        Ok(entries)
    }
}
