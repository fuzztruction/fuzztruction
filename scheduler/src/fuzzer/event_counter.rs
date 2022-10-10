use std::{
    borrow::Borrow,
    iter::Sum,
    ops,
    time::{Duration, Instant},
};

use fuzztruction_shared::util::ExpectNone;

/// Different mercies used to describe the performance of a fuzzer.
#[derive(Default, Clone)]
pub struct FuzzerEventCounter {
    /// The timestamps of when the init() was called.
    pub init_ts: Option<Instant>,
    /// Timestamp of the last path found in the sink.
    pub last_finding_ts: Option<Instant>,
    /// Timestamp of the last sink crash.
    pub last_crash_ts: Option<Instant>,
    /// Number of execution.
    pub execs: u64,
    /// Number of times the source execution did not end in a timeout or crash.
    pub successful_source_execs: u64,
    /// Number of edges found in the coverage bitmap.
    pub edges_found: u64,
    /// Number of hits found (i.e., an increase in the number of times a edge was hit)
    /// in the coverage bitmap.
    pub hits_found: u64,
    /// Number of executions that caused the source to crash.
    pub source_crashes: u64,
    /// Number of executions that caused the source to time out.
    pub source_timeout: u64,
    /// Number executions that did not yield any output on the sources
    /// output channel.
    pub source_no_output: u64,
    /// The source produced output already seen.
    pub source_duplicated_output: u64,
    /// Number of executions that caused the sink to timeout.
    pub sink_timeout: u64,
    /// Number of execution that caused the sink to crash .
    pub sink_crashes: u64,
    /// Number of execution with unique coverage map that caused the sink to crash .
    pub sink_unique_crashes: u64,
}

impl std::fmt::Debug for FuzzerEventCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rel_to_execs = |val: u64| -> String {
            let percentage = val as f64 / self.execs as f64;
            format!("{:#?} ({:.2}%)", val, percentage * 100f64)
        };

        f.debug_struct("FuzzerStats")
            .field("init_ts", &self.init_ts)
            .field("last_finding_ts", &self.last_finding_ts)
            .field(
                "since_last_finding()",
                &self.last_finding_ts.map(|ts| ts.elapsed()),
            )
            .field("last_crash_ts", &self.last_crash_ts)
            .field(
                "since_last_crash()",
                &self.last_crash_ts.map(|ts| ts.elapsed()),
            )
            .field("execs", &rel_to_execs(self.execs))
            .field(
                "successful_source_execs",
                &rel_to_execs(self.successful_source_execs),
            )
            .field("edges_found", &self.edges_found)
            .field("hits_found", &self.hits_found)
            .field("paths()", &self.paths())
            .field("source_crashes", &rel_to_execs(self.source_crashes))
            .field("source_timeout", &rel_to_execs(self.source_timeout))
            .field("source_no_output", &rel_to_execs(self.source_no_output))
            .field(
                "source_duplicated_output",
                &rel_to_execs(self.source_duplicated_output),
            )
            .field("sink_timeout", &rel_to_execs(self.sink_timeout))
            .field("sink_crashes", &rel_to_execs(self.sink_crashes))
            .finish()
    }
}

impl FuzzerEventCounter {
    pub fn new() -> Self {
        FuzzerEventCounter { ..Self::default() }
    }

    /// Initialize timestamps used for stats generation.
    /// This must be called for some function to work properly.
    pub fn init(&mut self) {
        self.init_ts
            .replace(Instant::now())
            .expect_none("Called start() twice");
    }

    /// The duration the fuzzer was executed. Might be None if it was never
    /// started.
    /// NOTE: [init] must have been called for this function to return Some.
    pub fn runtime(&self) -> Option<Duration> {
        self.init_ts.map(|ts| ts.elapsed())
    }

    /// The averaged executions per second so far.
    /// NOTE: [init] must have been called for this function to return Some.
    pub fn execs_per_sec(&self) -> Option<f64> {
        if self.execs == 0 {
            return None;
        }
        self.runtime()
            .map(|runtime| self.execs as f64 / runtime.as_secs_f64())
    }

    pub fn paths(&self) -> u64 {
        self.hits_found + self.edges_found
    }

    pub fn time_since_last_new_path_or_crash(&self) -> Option<Duration> {
        let last_path = vec![self.last_finding_ts, self.last_crash_ts];
        match last_path.iter().filter(|ts| ts.is_some()).max() {
            Some(Some(ts)) => Some(ts.elapsed()),
            _ => None,
        }
    }
}

impl<T> ops::AddAssign<T> for FuzzerEventCounter
where
    T: Borrow<FuzzerEventCounter>,
{
    fn add_assign(&mut self, rhs: T) {
        let rhs = rhs.borrow();
        self.execs += rhs.execs;
        self.successful_source_execs += rhs.successful_source_execs;
        self.edges_found += rhs.edges_found;
        self.hits_found += rhs.hits_found;
        self.source_crashes += rhs.source_crashes;
        self.source_timeout += rhs.source_timeout;
        self.source_no_output += rhs.source_no_output;
        self.source_duplicated_output += rhs.source_duplicated_output;
        self.sink_timeout += rhs.sink_timeout;
        self.sink_crashes += rhs.sink_crashes;
    }
}

impl<T> ops::Add<T> for FuzzerEventCounter
where
    T: Borrow<FuzzerEventCounter>,
{
    type Output = Self;

    fn add(mut self, rhs: T) -> Self::Output {
        let rhs = rhs.borrow();
        self.execs += rhs.execs;
        self.successful_source_execs += rhs.successful_source_execs;
        self.edges_found += rhs.edges_found;
        self.hits_found += rhs.hits_found;
        self.source_crashes += rhs.source_crashes;
        self.source_timeout += rhs.source_timeout;
        self.source_no_output += rhs.source_no_output;
        self.source_duplicated_output += rhs.source_duplicated_output;
        self.sink_timeout += rhs.sink_timeout;
        self.sink_crashes += rhs.sink_crashes;
        self
    }
}

impl<T> ops::Sub<T> for FuzzerEventCounter
where
    T: Borrow<FuzzerEventCounter>,
{
    type Output = Self;

    fn sub(mut self, rhs: T) -> Self::Output {
        let rhs = rhs.borrow();
        self.execs -= rhs.execs;
        self.successful_source_execs -= rhs.successful_source_execs;
        self.edges_found -= rhs.edges_found;
        self.hits_found -= rhs.hits_found;
        self.source_crashes -= rhs.source_crashes;
        self.source_timeout -= rhs.source_timeout;
        self.source_no_output -= rhs.source_no_output;
        self.source_duplicated_output -= rhs.source_duplicated_output;
        self.sink_timeout -= rhs.sink_timeout;
        self.sink_crashes -= rhs.sink_crashes;
        self
    }
}

impl<T> ops::SubAssign<T> for FuzzerEventCounter
where
    T: Borrow<FuzzerEventCounter>,
{
    fn sub_assign(&mut self, rhs: T) {
        let rhs = rhs.borrow();
        self.execs -= rhs.execs;
        self.successful_source_execs -= rhs.successful_source_execs;
        self.edges_found -= rhs.edges_found;
        self.hits_found -= rhs.hits_found;
        self.source_crashes -= rhs.source_crashes;
        self.source_timeout -= rhs.source_timeout;
        self.source_no_output -= rhs.source_no_output;
        self.source_duplicated_output -= rhs.source_duplicated_output;
        self.sink_timeout -= rhs.sink_timeout;
        self.sink_crashes -= rhs.sink_crashes;
    }
}

impl Sum for FuzzerEventCounter {
    /// Sum up an iterator of [FuzzerStats]. The result will have the [FuzzerStats::start_ts]
    /// of the oldest [FuzzerStats] or None, if no instance has an `start_ts` set.
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut res = FuzzerEventCounter::new();
        for e in iter {
            res += &e;
            // The resulting FuzzerStats will have the timestamp
            // of the oldest FuzzerStats thingy we are summing up.
            if let Some(ts) = e.init_ts {
                if let Some(res_ts) = res.init_ts.as_mut() {
                    if *res_ts < ts {
                        *res_ts = ts;
                    }
                } else {
                    res.init_ts = Some(ts);
                }
            }
        }
        res
    }
}
