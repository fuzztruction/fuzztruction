#[derive(Debug, Clone, Copy)]
pub enum WorkerId {
    AflMaster,
    AflSlave(usize),
    SymccWorker(usize),
    QsymWorker(usize),
    WeizzMaster,
    WeizzWorker(usize),
}

mod aflpp_core;
mod symcc;
mod weizz;
pub use aflpp_core::run_aflpp_mode;
