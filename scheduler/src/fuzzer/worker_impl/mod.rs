mod cerebrum;
pub use cerebrum::Cerebrum;
mod cerebrum_query;

mod common;
mod init;
mod main_loop;

mod mutators;
pub use mutators::MutatorType;

mod phases;
pub use phases::FuzzingPhase;
mod scheduling;
