use std::time::Duration;

// -----  Global config -----

/// The maximum number of supported patch points. This limit to allow us to
/// efficiently store PatchPointIDs via bitmaps.
/// Programmes containing more than this limit, will raise an assertion.
/// In this case, the limit might simply be raised to the desired value, however,
/// mind that this will increase the overall memory footprint.
pub const MAX_PATCHPOINT_CNT: usize = 200_000;
pub const MAX_QUEUE_ENTRY_CNT: usize = 100000;
pub const EXECUTION_TIMEOUT_MULTIPLYER: f64 = 1.5;
pub const AVG_EXECUTION_TIME_STABILIZATION_VALUE: u32 = 100;
/// Interval between:
///     - checks whether the worker was terminated
///     - state updates (e.g., progress of the current mutator)
pub const FUZZING_LOOP_UPDATE_INTERVAL: Duration = Duration::from_secs(10);
