use std::{str::FromStr, time};

use regex::Regex;

pub struct CliDuration(pub time::Duration);

impl FromStr for CliDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = Regex::new("([0-9]+)(s|m|h|d)").unwrap();
        let matches = re
            .captures(s)
            .ok_or(format!("Invalid duration format ({})!", s))?;
        if matches.len() != 3 {
            return Err("Failed to match components".to_owned());
        }

        let amount = matches.get(1).unwrap().as_str();
        let suffix = matches.get(2).unwrap().as_str();

        let amount = u64::from_str(amount).unwrap();

        let seconds = match suffix {
            "s" => amount,
            "m" => amount * 60,
            "h" => amount * 3600,
            "d" => amount * 3600 * 24,
            _ => unreachable!(),
        };
        Ok(CliDuration(time::Duration::from_secs(seconds)))
    }
}
