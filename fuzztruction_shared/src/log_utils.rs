use serde::{Deserialize, Serialize};
use std::panic;

/// A trait that allows to log panics caused by, e.g., unwrap().
pub trait UnwrapLog<O> {
    /// Same as unwrap(), except that log::error!() is called, before the
    /// application panics.
    #[track_caller]
    fn unwrap_log(self) -> O;
}

impl<O, E: std::fmt::Debug> UnwrapLog<O> for Result<O, E> {
    fn unwrap_log(self) -> O {
        match self {
            Ok(v) => v,
            Err(err) => {
                let msg = format!("Failed to unwrap Result: {:#?}", err);
                let loc = panic::Location::caller();
                log::error!("{} @ {}", loc, &msg);
                panic!("{}", msg);
            }
        }
    }
}

impl<T> UnwrapLog<T> for Option<T> {
    fn unwrap_log(self) -> T {
        match self {
            Some(v) => v,
            None => {
                let loc = panic::Location::caller();
                let msg = format!("Failed to unwrap None @ {}", loc);
                log::error!("{}", &msg);
                panic!("{}", msg);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct LogRecordWrapper {
    pub level: log::Level,
    pub target: String,
    pub message: String,
    pub module_path: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl LogRecordWrapper {
    pub fn from_record(record: &log::Record) -> LogRecordWrapper {
        LogRecordWrapper {
            level: record.level(),
            target: record.metadata().target().to_owned(),
            message: record.args().to_string(),
            module_path: record.module_path().map(|e| e.to_owned()),
            file: record.file().map(|e| e.to_owned()),
            line: record.line(),
        }
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test() {

        // let record = log::RecordBuilder::new().build();
        // let log_record = LogRecordWrapper::from_record(&record);

        // let serialized = serde_json::to_string(&log_record).unwrap();
        // let deserialized = serde_json::from_str::<LogRecordWrapper>(&serialized).unwrap();
    }
}
