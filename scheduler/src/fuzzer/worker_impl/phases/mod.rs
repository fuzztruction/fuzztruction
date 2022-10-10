mod types;
pub use types::FuzzingPhase;

mod run_common;
mod run_phase;
//phases
mod add;
mod combine;
mod discovery;
mod mutate;
