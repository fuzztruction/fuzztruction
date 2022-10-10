use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Hash, PartialEq, Eq, Deserialize)]
pub enum FuzzingPhase {
    /// Mutate all patch points that are covered by all [QueueEntry] that
    /// do not have an successor, i.e., where generated using the seed files and
    /// therefore have no mutation cache entries attached.
    Discovery,
    /// Apply non-deterministic mutations to all [QueueEntry]s.
    Mutate,
    Add,
    Combine,
    /// Currently there is no phase enabled. This happens to be the state
    /// during scheduling.
    None,
    /// The worker is distined to terminate. This phase can be used to terminate
    /// the fuzzing process during, e.g., testing.
    Exit,
}

impl Display for FuzzingPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}
