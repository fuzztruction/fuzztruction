use std::convert::TryInto;
use std::path::Path;
use std::{collections::HashSet, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::time::Duration;
use thiserror::Error;

use crate::io_channels::{InputChannel, OutputChannel};
use yaml_rust::{ScanError, Yaml, YamlLoader};

use std::fmt::Debug;

use std::{str::FromStr, time};

use regex::Regex;

#[derive(Debug, Clone, Copy)]
pub struct FromStrDuration(pub time::Duration);

impl FromStr for FromStrDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = Regex::new("([0-9]+)(s|m|h|d|)").unwrap();
        let matches = re
            .captures(s)
            .ok_or(format!("Invalid duration format ({})!", s))?;
        if matches.len() != 3 {
            return Err("Failed to match components".to_owned());
        }

        let amount = matches.get(1).unwrap().as_str();
        let suffix = matches.get(2).unwrap().as_str();

        let amount = u64::from_str(amount).unwrap();

        let millis = match suffix {
            "" => amount,
            "s" => amount * 1000,
            "m" => amount * 1000 * 60,
            "h" => amount * 1000 * 3600,
            "d" => amount * 1000 * 3600 * 24,
            _ => unreachable!(),
        };
        Ok(FromStrDuration(time::Duration::from_millis(millis)))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceConfig {
    pub env: Vec<(String, String)>,
    /// Path to the Source binary.
    pub bin_path: PathBuf,
    pub arguments: Vec<String>,
    /// Type of input consumed by the Source binary.
    pub input_type: InputChannel,
    /// Type of output produced by the Source binary.
    pub output_type: OutputChannel,
    /// Suffix of the output file
    pub output_suffix: Option<String>,
    /// Whether to log stdout during execution.
    pub log_stdout: bool,
    /// Whether to log stderr during execution.
    pub log_stderr: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PhasesConfig {
    /// Only fuzz entries from generation <= `generation_ceiling`
    pub generation_ceiling: Option<u32>,
    /// Parameters of the discovery phase.
    pub discovery: DiscoveryPhaseConfig,
    /// Parameters of the mutate phase.
    pub mutate: MutatePhaseConfig,
    /// Parameters of the add phase.
    pub add: AddPhaseConfig,
    /// Parameters of the combine phase.
    pub combine: CombinePhaseConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryPhaseConfig {
    /// Enable the discovery phase.
    pub enabled: bool,
    /// Number of [PatchPoint]s that are queued by each work each iteration.
    pub batch_size: u32,
    /// Terminate the worker after finishing the phase.
    pub terminate_when_finished: bool,
    /// Skip batch if no coverage was produced for `batch_cov_timeout`.
    pub batch_cov_timeout: Duration,
    /// Skip phase if no coverage was produced for `phase_cov_timeout`.
    pub phase_cov_timeout: Duration,
}

impl Default for DiscoveryPhaseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size: 50,
            terminate_when_finished: false,
            batch_cov_timeout: Duration::from_secs(60 * 5),
            phase_cov_timeout: Duration::from_secs(60 * 15),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MutatePhaseConfig {
    pub weight: u32,
    pub entry_cov_timeout: Duration,
}

impl Default for MutatePhaseConfig {
    fn default() -> Self {
        Self {
            weight: 50,
            entry_cov_timeout: Duration::from_secs(60 * 15),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AddPhaseConfig {
    pub weight: u32,
    pub batch_size: u32,
    pub select_unfuzzed_weight: u32,
    pub select_yielding_weight: u32,
    pub select_random_weight: u32,
    pub entry_cov_timeout: Duration,
}

impl Default for AddPhaseConfig {
    fn default() -> Self {
        Self {
            weight: 1,
            batch_size: 30,
            select_unfuzzed_weight: 1,
            select_yielding_weight: 1,
            select_random_weight: 1,
            entry_cov_timeout: Duration::from_secs(60 * 15),
        }
    }
}

impl AddPhaseConfig {
    pub fn weights_sum(&self) -> u32 {
        let mut ret = 0;
        ret += self.select_unfuzzed_weight;
        ret += self.select_yielding_weight;
        ret += self.select_random_weight;
        assert!(ret > 0);
        ret
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CombinePhaseConfig {
    pub weight: u32,
    pub entry_cov_timeout: Duration,
}

impl Default for CombinePhaseConfig {
    fn default() -> Self {
        Self {
            weight: 5,
            entry_cov_timeout: Duration::from_secs(60 * 10),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AflPlusPlusConfig {
    pub input_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct QSYMConfig {
    input_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct SinkConfig {
    pub env: Vec<(String, String)>,
    /// Path to the Sink binary.
    pub bin_path: PathBuf,
    pub arguments: Vec<String>,
    /// Type of input consumed by the Sink binary.
    pub input_type: InputChannel,
    /// Type of output produced by the Sink binary.
    pub output_type: OutputChannel,
    /// Whether to log stdout during execution.
    pub log_stdout: bool,
    /// Whether to log stderr during execution.
    pub log_stderr: bool,
    /// Allow the sink to produce different coverage maps for the same input.
    pub allow_unstable_sink: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VanillaConfig {
    /// Environment used during binary
    pub env: Vec<(String, String)>,
    /// Path to the vanilla binary
    pub bin_path: PathBuf,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymccConfig {
    /// Environment used during binary
    pub env: Vec<(String, String)>,
    /// Path to the vanilla binary
    pub bin_path: PathBuf,
    /// Binary compiled with plain afl instrumentation
    pub afl_bin_path: PathBuf,
    /// Environment used for the symcc AFL binary
    pub afl_bin_env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneralConfig {
    pub input_dir: PathBuf,
    pub work_dir: PathBuf,
    pub timeout: Duration,
    pub tracing_timeout: Duration,
    pub purge_workdir: bool,
    pub jail_uid: Option<u32>,
    pub jail_gid: Option<u32>,
}

impl GeneralConfig {
    pub fn traces_directory(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("traces");
        ret
    }

    pub fn interesting_path(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("interesting");
        ret
    }

    pub fn valgrind_path(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("valgrind");
        ret
    }

    pub fn crashing_path(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("crashing");
        ret
    }

    pub fn queue_path(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("queue");
        ret
    }

    pub fn patch_points_path(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("0/source/state/patch_points.json");
        ret
    }

    pub fn introspection_path(&self) -> PathBuf {
        let mut ret = self.work_dir.clone();
        ret.push("introspection.json");
        ret
    }

    pub fn jail_enabled(&self) -> bool {
        self.jail_uid.is_some()
    }

    pub fn jail_uid_gid(&self) -> Option<(u32, u32)> {
        self.jail_enabled()
            .then(|| (self.jail_uid.unwrap(), self.jail_gid.unwrap()))
    }
}

/// A config that describes a setup of one specific source and sink application
/// pair.
#[derive(Debug, Clone, Serialize)]
pub struct Config {
    /// Attributes shared between the source and the sink or that are not related
    /// to ether of them.
    pub general: GeneralConfig,
    /// Attributes related to the source application.
    pub source: SourceConfig,
    /// Configuration of the different fuzzing phases.
    pub phases: PhasesConfig,
    /// Attributes related to the sink application.
    pub sink: SinkConfig,
    /// Attributes related to the vanilla application.
    pub vanilla: VanillaConfig,
    /// Attributes related to AFL++ fuzzer
    pub aflpp: Option<AflPlusPlusConfig>,
    /// Attrbiutes realted to the SymCC fuzzer.
    pub symcc: Option<SymccConfig>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    /// The provided config file is malformed.
    #[error("Invalid syntax: '{0}'")]
    InvalidSyntax(#[from] ScanError),
    /// The config lacks a required attribute.
    #[error("Missing attribute: '{0}'")]
    Missingattribute(String),
    /// The passed value violates some constraint. Use a context to add more info.
    #[error("Invalid value '{0}'")]
    InvalidValue(String),
    /// An error occurred during the convertion of value into expected_type.
    #[error("Failed to convert {value} to type {expected_type}")]
    ConvertionFailed {
        value: String,
        expected_type: String,
    },
    /// The section was not found in the configuration.
    #[error("Missing section '{0}'")]
    MissingSection(String),
    /// Attribute that was not matched by any rule.
    #[error("Unexpected attribute '{0}'")]
    UnexpectedAttribute(String),
}

#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    base_dir: PathBuf,
}

pub trait TargetExecutionContext: Debug {
    /// Environment used during binary execution
    fn env(&self) -> &[(String, String)];
    /// Path to the binary
    fn bin_path(&self) -> &Path;
    /// Args passed to the binary
    fn arguments(&self) -> &[String];
}

pub trait AflTargetExecutionContext: TargetExecutionContext {}

impl TargetExecutionContext for VanillaConfig {
    fn env(&self) -> &[(String, String)] {
        self.env.as_slice()
    }
    fn bin_path(&self) -> &Path {
        self.bin_path.as_path()
    }
    fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

impl TargetExecutionContext for SinkConfig {
    fn env(&self) -> &[(String, String)] {
        self.env.as_slice()
    }
    fn bin_path(&self) -> &Path {
        self.bin_path.as_path()
    }
    fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

impl AflTargetExecutionContext for SinkConfig {}

trait Validator {
    /// Run validation on self.
    fn validate(&self) -> Result<(), anyhow::Error>;
}

trait PathValidator {
    fn path_exists(&self) -> Result<(), anyhow::Error>;
    fn not_path_exists(&self) -> Result<(), anyhow::Error>;
}

// TODO: temp fix. sorry :(
// we want attributes in struct
impl PathValidator for PathBuf {
    fn path_exists(&self) -> Result<()> {
        match self.exists() {
            true => Ok(()),
            false => Err(anyhow!(format!(
                "Path '{:#?}' does not exist (or wrong permissions)",
                &self
            ))),
        }
    }

    fn not_path_exists(&self) -> Result<()> {
        match self.exists() {
            false => Ok(()),
            true => Err(anyhow!(format!("Path '{:#?}' already exists", &self))),
        }
    }
}

impl Validator for Config {
    fn validate(&self) -> Result<()> {
        self.general
            .validate()
            .context("Failed to validate GeneralConfig")?;
        self.source
            .validate()
            .context("Failed to validate SourceConfig")?;
        self.sink
            .validate()
            .context("Failed to validate SinkConfig")?;
        self.vanilla
            .validate()
            .context("Failed to validate VanillaConfig")?;
        Ok(())
    }
}

impl Validator for GeneralConfig {
    fn validate(&self) -> Result<()> {
        // self.work_dir
        //     .not_path_exists()
        //     .context("Failed to validate work_dir")?;
        self.input_dir
            .path_exists()
            .context("Failed to validate input_dir")
    }
}

impl Validator for SourceConfig {
    fn validate(&self) -> Result<()> {
        self.bin_path
            .path_exists()
            .context("Failed to validate bin_path")
    }
}

impl Validator for SinkConfig {
    fn validate(&self) -> Result<()> {
        self.bin_path
            .path_exists()
            .context("Failed to validate bin_path")
    }
}

impl Validator for SymccConfig {
    fn validate(&self) -> Result<()> {
        self.bin_path
            .path_exists()
            .context("Failed to validate bin_path")
    }
}

impl Validator for VanillaConfig {
    fn validate(&self) -> Result<()> {
        self.bin_path
            .path_exists()
            .context("Failed to validate bin_path")
    }
}

trait TryFromYaml {
    /// Try to convert the provided yaml value into an instance of Self or
    /// return an error.
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>>;
}

/// Try to convert a yaml attribute value into a String.
impl TryFromYaml for String {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<String>> {
        let ret = yaml.as_str().map(|f| f.to_owned());
        let ret = ret
            .map(Box::new)
            .ok_or_else(|| ConfigError::ConvertionFailed {
                value: format!("{:#?}", yaml),
                expected_type: "String".to_owned(),
            });
        Ok(ret?)
    }
}

/// Try to convert a yaml attribute value into a String.
impl TryFromYaml for Vec<String> {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Vec<String>>> {
        let ret =
            yaml.as_vec()
                .map(|f| f.to_owned())
                .ok_or_else(|| ConfigError::ConvertionFailed {
                    value: format!("{:#?}", yaml),
                    expected_type: "Array".to_owned(),
                })?;
        let mut ret_new = Vec::new();
        for elem in ret {
            let elem_res = elem.as_str().map(|e| e.to_owned()).ok_or_else(|| {
                ConfigError::ConvertionFailed {
                    value: format!("{:#?}", elem),
                    expected_type: "String".to_owned(),
                }
            })?;
            ret_new.push(elem_res);
        }
        Ok(Box::new(ret_new))
    }
}

/// Try to convert a yaml attribute value into a PathBuf.
impl TryFromYaml for PathBuf {
    fn try_from_yaml(builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<PathBuf>> {
        let ret = yaml.as_str().map(|f| f.to_owned());
        let ret =
            ret.map(|f| Box::new(PathBuf::from(f)))
                .ok_or_else(|| ConfigError::ConvertionFailed {
                    value: format!("{:#?}", yaml),
                    expected_type: "PathBuf".to_owned(),
                });
        let path = ret?;
        let path = if path.is_relative() {
            let abs_path = builder.base_dir.join(path.as_path());
            Box::new(abs_path.canonicalize()?)
        } else {
            path
        };
        Ok(path)
    }
}

impl TryFromYaml for bool {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<bool>> {
        let ret = yaml.as_bool().map(|f| f.to_owned());
        let ret = ret
            .map(Box::new)
            .ok_or_else(|| ConfigError::ConvertionFailed {
                value: format!("{:#?}", yaml),
                expected_type: "bool".to_owned(),
            });
        Ok(ret?)
    }
}

macro_rules! for_int_type {
    ($type:ty) => {
        impl TryFromYaml for $type {
            fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
                let ret = yaml
                    .as_i64()
                    .context(format!("Failed to convert {:?} into i64", yaml))?;
                let ret = ret.try_into()?;
                Ok(Box::new(ret))
            }
        }
    };
}
for_int_type!(u8);
for_int_type!(u16);
for_int_type!(u32);
for_int_type!(u64);

for_int_type!(i8);
for_int_type!(i16);
for_int_type!(i32);
for_int_type!(i64);

impl TryFromYaml for f64 {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
        let ret = yaml
            .as_f64()
            .context(format!("Failed to convert {:?} into f64", yaml))?;
        Ok(Box::new(ret))
    }
}

/// Try to convert a yaml string attribute value to a InputChannel enum variant.
impl TryFromYaml for InputChannel {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
        let ret = String::try_from_yaml(_builder, yaml)?;
        let ret = ret.to_lowercase();
        let ret = match &ret[..] {
            "none" => Ok(Box::new(InputChannel::None)),
            "stdin" => Ok(Box::new(InputChannel::Stdin)),
            "file" => Ok(Box::new(InputChannel::File)),
            _ => Err(ConfigError::InvalidValue(ret)),
        }
        .context("Must be one of None, Stdin or File".to_owned())?;
        Ok(ret)
    }
}

/// Try to convert a yaml string attribute value to a OutputChannel enum variant.
impl TryFromYaml for OutputChannel {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
        let ret = String::try_from_yaml(_builder, yaml)?;
        let ret = ret.to_lowercase();
        let ret = match &ret[..] {
            "none" => Ok(Box::new(OutputChannel::None)),
            "stdout" => Ok(Box::new(OutputChannel::Stdout)),
            "file" => Ok(Box::new(OutputChannel::File)),
            _ => Err(ConfigError::InvalidValue(ret)),
        }
        .context("Must be one of None, Stdout or File".to_owned())?;
        Ok(ret)
    }
}

impl TryFromYaml for Vec<(String, String)> {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Vec<(String, String)>>> {
        let ret =
            yaml.as_vec()
                .map(|f| f.to_owned())
                .ok_or_else(|| ConfigError::ConvertionFailed {
                    value: format!("{:#?}", yaml),
                    expected_type: "Array".to_owned(),
                })?;

        let mut ret_new = Vec::new();
        for kv in ret {
            let kv = kv.as_hash().ok_or_else(|| ConfigError::ConvertionFailed {
                value: format!("{:#?}", kv),
                expected_type: "Hash".to_owned(),
            })?;
            if kv.len() != 1 {
                return Err(ConfigError::InvalidValue(format!(
                    "Expected exactly one key value mapping, got {:#?}",
                    kv
                ))
                .into());
            }
            let kv = kv.iter().take(1).collect::<Vec<_>>();
            let k = *String::try_from_yaml(_builder, kv[0].0)?;
            let v = *String::try_from_yaml(_builder, kv[0].1)?;
            ret_new.push((k, v));
        }

        Ok(Box::new(ret_new))
    }
}

/// Try to convert a yaml string attribute value to a OutputChannel enum variant.
impl TryFromYaml for Duration {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
        let ret = String::try_from_yaml(_builder, yaml)?;
        let duration = FromStrDuration::from_str(&ret).map_err(|err| {
            ConfigError::InvalidValue(format!("Invalid duration value {}. e={}", ret, err))
        })?;

        Ok(Box::new(duration.0))
    }
}

impl<T: TryFromYaml> TryFromYaml for Option<T> {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
        // Values is Option and missing -> return None
        if yaml.is_badvalue() || yaml.is_null() {
            return Ok(Box::new(None));
        }

        // Value is the string "none" and Option -> return None
        let as_str = String::try_from_yaml(_builder, yaml);
        if let Ok(as_str) = as_str {
            let as_str = as_str.to_lowercase();
            if matches!(as_str.as_str(), "none") {
                return Ok(Box::new(None));
            }
        }

        // The values is Some -> try to parse it and raise errors if needed.
        let ret = T::try_from_yaml(_builder, yaml)?;
        Ok(Box::new(Some(*ret)))
    }
}

impl TryFromYaml for yaml_rust::yaml::Hash {
    fn try_from_yaml(_builder: &ConfigBuilder, yaml: &Yaml) -> Result<Box<Self>> {
        let hash = yaml.as_hash();
        if hash.is_none() {
            return Err(
                ConfigError::InvalidValue(format!("Expected Hash found {:?}", yaml)).into(),
            );
        }
        Ok(Box::new(hash.unwrap().clone()))
    }
}

impl ConfigBuilder {
    /// Get an attribute from the given `yaml`.
    fn get_attribute<T: TryFromYaml + Debug>(&self, yaml: &Yaml, attr_name: &str) -> Result<T> {
        // Assume that `yaml` is of type Hash and we can get attributes via the index OP.
        let val = &yaml[attr_name];

        // If we are here the attribute exists, but we do not know whether the type is correct yet.

        let ret = *T::try_from_yaml(self, val).context(format!(
            "Failed to convert attribute \"{0}\" to the requested type.",
            attr_name
        ))?;
        Ok(ret)
    }

    #[allow(clippy::redundant_closure)]
    fn get_section(&self, yml: &Yaml, name: &str) -> Result<Yaml> {
        let section: Option<yaml_rust::yaml::Hash> = self.get_attribute(yml, name)?;
        let section = section.map(|s| Yaml::Hash(s));
        if let Some(section) = section {
            Ok(section)
        } else {
            Err(ConfigError::MissingSection(name.to_owned()).into())
        }
    }

    /// Check whether the given yaml dict contains keys that are not in expected_keys.
    /// If this is the case, return ConfigError::UnexpectedAttribute.
    fn check_for_unparsed_keys<T>(yaml: &Yaml, expected_keys: T) -> Result<()>
    where
        T: IntoIterator + Clone,
        T::Item: AsRef<str>,
    {
        let keys = yaml.as_hash().unwrap().keys();
        let keys: HashSet<&str> = keys.into_iter().map(|e| e.as_str().unwrap()).collect();
        let expected_keys: Vec<_> = expected_keys.into_iter().collect();

        for k in keys.into_iter() {
            if !expected_keys.iter().any(|e| e.as_ref() == k) {
                return Err(ConfigError::UnexpectedAttribute(k.to_owned()).into());
            }
        }
        Ok(())
    }

    /// Parse the general section that contains configuration options that are shared
    /// by multiple other sections.
    fn parse_general_section(&self, yaml: &mut Yaml) -> Result<GeneralConfig> {
        let work_dir = self.get_attribute(yaml, "work-directory")?;
        let input_dir = self.get_attribute(yaml, "input-directory")?;
        let timeout: Option<Duration> = self.get_attribute(yaml, "timeout")?;
        let timeout = timeout.unwrap_or_else(|| Duration::from_millis(40));
        let jail_uid = self.get_attribute(yaml, "jail-uid")?;
        let jail_gid = self.get_attribute(yaml, "jail-gid")?;

        match (jail_uid, jail_gid) {
            (Some(..), Some(..)) => (),
            (None, None) => (),
            _ => return Err(anyhow!("Both or non of jail_uid and jail_gid must be set")),
        }

        ConfigBuilder::check_for_unparsed_keys(
            yaml,
            &[
                "work-directory",
                "input-directory",
                "timeout",
                "jail-uid",
                "jail-gid",
                "sink",
                "afl++",
                "source",
                "symcc",
                "vanilla",
                "phases",
            ],
        )?;

        Ok(GeneralConfig {
            work_dir,
            input_dir,
            timeout,
            tracing_timeout: Duration::from_secs(120),
            purge_workdir: false,
            jail_uid,
            jail_gid,
        })
    }

    fn parse_source_section(&self, yaml: &Yaml) -> Result<SourceConfig> {
        let env: Option<Vec<_>> = self.get_attribute(yaml, "env")?;
        let env = env.unwrap_or_default();
        let bin_path = self.get_attribute(yaml, "bin-path")?;
        let arguments = self.get_attribute(yaml, "arguments")?;
        let input_type = self.get_attribute(yaml, "input-type")?;
        let output_type = self.get_attribute(yaml, "output-type")?;
        let output_suffix = self.get_attribute(yaml, "output-suffix")?;
        let log_stdout = self.get_attribute(yaml, "log-stdout")?;
        let log_stderr = self.get_attribute(yaml, "log-stderr")?;

        ConfigBuilder::check_for_unparsed_keys(
            yaml,
            &[
                "env",
                "bin-path",
                "arguments",
                "input-type",
                "output-type",
                "output-suffix",
                "log-stdout",
                "log-stderr",
            ],
        )?;

        Ok(SourceConfig {
            env,
            bin_path,
            arguments,
            input_type,
            output_type,
            output_suffix,
            log_stdout,
            log_stderr,
        })
    }

    fn parse_discovery_phase_section(&self, section: &Yaml) -> Result<DiscoveryPhaseConfig> {
        let enabled: bool = self.get_attribute(section, "enabled")?;
        let batch_size: u32 = self.get_attribute(section, "batch-size")?;
        let terminate_when_finished: bool =
            self.get_attribute(section, "terminate-when-finished")?;
        let batch_cov_timeout = self
            .get_attribute::<Option<Duration>>(section, "batch-cov-timeout")?
            .unwrap_or_else(|| Duration::from_secs(60 * 5));
        let phase_cov_timeout = self
            .get_attribute::<Option<Duration>>(section, "phase-cov-timeout")?
            .unwrap_or_else(|| Duration::from_secs(60 * 10));

        ConfigBuilder::check_for_unparsed_keys(
            section,
            &[
                "enabled",
                "batch-size",
                "terminate-when-finished",
                "batch-cov-timeout",
                "phase-cov-timeout",
            ],
        )?;

        Ok(DiscoveryPhaseConfig {
            enabled,
            batch_size,
            terminate_when_finished,
            batch_cov_timeout,
            phase_cov_timeout,
        })
    }

    fn parse_mutate_phase_section(&self, section: &Yaml) -> Result<MutatePhaseConfig> {
        let weight: u32 = self.get_attribute(section, "weight")?;
        let entry_cov_timeout = self
            .get_attribute::<Option<Duration>>(section, "entry-cov-timeout")?
            .unwrap_or_else(|| Duration::from_secs(60 * 10));

        ConfigBuilder::check_for_unparsed_keys(section, &["weight", "entry-cov-timeout"])?;

        Ok(MutatePhaseConfig {
            weight,
            entry_cov_timeout,
        })
    }

    fn parse_add_phase_section(&self, section: &Yaml) -> Result<AddPhaseConfig> {
        let weight: u32 = self.get_attribute(section, "weight")?;

        let batch_size: u32 = self.get_attribute(section, "batch-size")?;
        let select_unfuzzed_weight: u32 = self.get_attribute(section, "select-unfuzzed-weight")?;
        let select_yielding_weight: u32 = self.get_attribute(section, "select-yielding-weight")?;
        let select_random_weight: u32 = self.get_attribute(section, "select-random-weight")?;
        let entry_cov_timeout = self
            .get_attribute::<Option<Duration>>(section, "entry-cov-timeout")?
            .unwrap_or_else(|| Duration::from_secs(60 * 10));

        ConfigBuilder::check_for_unparsed_keys(
            section,
            &[
                "weight",
                "batch-size",
                "select-unfuzzed-weight",
                "select-yielding-weight",
                "select-random-weight",
                "entry-cov-timeout",
            ],
        )?;

        Ok(AddPhaseConfig {
            weight,
            batch_size,
            select_unfuzzed_weight,
            select_yielding_weight,
            select_random_weight,
            entry_cov_timeout,
        })
    }

    fn parse_combine_phase_section(&self, section: &Yaml) -> Result<CombinePhaseConfig> {
        let weight: u32 = self.get_attribute(section, "weight")?;
        let entry_cov_timeout = self
            .get_attribute::<Option<Duration>>(section, "entry-cov-timeout")?
            .unwrap_or_else(|| Duration::from_secs(60 * 10));

        ConfigBuilder::check_for_unparsed_keys(section, &["weight", "entry-cov-timeout"])?;

        Ok(CombinePhaseConfig {
            weight,
            entry_cov_timeout,
        })
    }

    fn parse_phases_section(&self, phases_section: &Yaml) -> Result<PhasesConfig> {
        let generation_ceiling: Option<u32> =
            self.get_attribute(phases_section, "generation-ceiling")?;

        let section = self.get_section(phases_section, "discovery")?;
        let discovery_config = self
            .parse_discovery_phase_section(&section)
            .context("Failed to parse discovery section")
            .unwrap_or_default();

        let section = self.get_section(phases_section, "mutate")?;
        let mutate_config = self
            .parse_mutate_phase_section(&section)
            .context("Failed to parse mutate section")
            .unwrap_or_default();

        let section = self.get_section(phases_section, "add")?;
        let add_config = self
            .parse_add_phase_section(&section)
            .context("Failed to parse add section")
            .unwrap_or_default();

        let section = self.get_section(phases_section, "combine")?;
        let combine_config = self
            .parse_combine_phase_section(&section)
            .context("Failed to parse combine section")
            .unwrap_or_default();

        ConfigBuilder::check_for_unparsed_keys(
            phases_section,
            &[
                "generation-ceiling",
                "discovery",
                "mutate",
                "add",
                "combine",
            ],
        )?;

        Ok(PhasesConfig {
            generation_ceiling,
            discovery: discovery_config,
            mutate: mutate_config,
            add: add_config,
            combine: combine_config,
        })
    }

    fn parse_afl_plus_section(&self, yaml: &Yaml) -> Result<AflPlusPlusConfig> {
        let input_dir = self.get_attribute(yaml, "input-dir")?;

        ConfigBuilder::check_for_unparsed_keys(yaml, &["input-dir"])?;

        Ok(AflPlusPlusConfig { input_dir })
    }

    fn parse_sink_section(&self, yaml: &Yaml) -> Result<SinkConfig> {
        let env: Option<Vec<_>> = self.get_attribute(yaml, "env")?;
        let env = env.unwrap_or_default();
        let bin_path = self.get_attribute(yaml, "bin-path")?;
        let arguments = self.get_attribute(yaml, "arguments")?;
        let input_type = self.get_attribute(yaml, "input-type")?;
        let output_type = self.get_attribute(yaml, "output-type")?;
        let log_stdout = self.get_attribute(yaml, "log-stdout")?;
        let log_stderr = self.get_attribute(yaml, "log-stderr")?;
        let allow_unstable_sink = self.get_attribute(yaml, "allow-unstable-sink")?;

        ConfigBuilder::check_for_unparsed_keys(
            yaml,
            &[
                "env",
                "bin-path",
                "arguments",
                "input-type",
                "output-type",
                "log-stdout",
                "log-stderr",
                "allow-unstable-sink",
            ],
        )?;

        Ok(SinkConfig {
            bin_path,
            arguments,
            input_type,
            output_type,
            log_stdout,
            log_stderr,
            env,
            allow_unstable_sink,
        })
    }

    fn parse_symcc_section(&self, yaml: &Yaml) -> Result<SymccConfig> {
        let env: Option<Vec<_>> = self.get_attribute(yaml, "env")?;
        let env = env.unwrap_or_default();
        let bin_path = self.get_attribute(yaml, "bin-path")?;
        let afl_bin_path = self.get_attribute(yaml, "afl-bin-path")?;
        let afl_bin_env: Option<Vec<_>> = self.get_attribute(yaml, "afl-bin-env")?;
        let afl_bin_env = afl_bin_env.unwrap_or_default();

        ConfigBuilder::check_for_unparsed_keys(
            yaml,
            &["env", "bin-path", "afl-bin-path", "afl-bin-env"],
        )?;

        Ok(SymccConfig {
            env,
            bin_path,
            afl_bin_path,
            afl_bin_env,
        })
    }

    fn parse_vanilla_section(&self, yaml: &Yaml, arguments: &[String]) -> Result<VanillaConfig> {
        let env: Option<Vec<_>> = self.get_attribute(yaml, "env")?;
        let env = env.unwrap_or_default();
        let bin_path = self.get_attribute(yaml, "bin-path")?;

        ConfigBuilder::check_for_unparsed_keys(yaml, &["env", "bin-path"])?;

        Ok(VanillaConfig {
            env,
            bin_path,
            arguments: arguments.to_owned(),
        })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(&self, config: &str) -> Result<Config> {
        let mut yaml = YamlLoader::load_from_str(config)?;
        let yaml = &mut yaml[0];

        // Parse all sections of the config
        let general_config = self.parse_general_section(yaml)?;

        let source_section = &yaml["source"];
        if source_section.is_badvalue() {
            return Err(ConfigError::MissingSection("source".to_owned()).into());
        }
        let source_config = self.parse_source_section(source_section)?;

        let phases_section = &yaml["phases"];
        let phase_config = if phases_section.is_badvalue() {
            PhasesConfig::default()
        } else {
            self.parse_phases_section(phases_section)?
        };

        let sink_section = &yaml["sink"];
        if sink_section.is_badvalue() {
            return Err(ConfigError::MissingSection("sink".to_owned()).into());
        }
        let sink_config = self.parse_sink_section(sink_section)?;

        let afl_plus_plus_section = &yaml["afl++"];
        let afl_plus_plus_config = if afl_plus_plus_section.is_badvalue() {
            None
        } else {
            Some(self.parse_afl_plus_section(afl_plus_plus_section)?)
        };

        let symcc_section = &yaml["symcc"];
        let symcc_section = if symcc_section.is_badvalue() {
            None
        } else {
            Some(self.parse_symcc_section(symcc_section)?)
        };

        let vanilla_section = &yaml["vanilla"];
        if vanilla_section.is_badvalue() {
            return Err(ConfigError::MissingSection("vanilla".to_owned()).into());
        }
        let vanilla_config =
            self.parse_vanilla_section(vanilla_section, sink_config.arguments())?;

        let config = Config {
            general: general_config,
            source: source_config,
            phases: phase_config,
            sink: sink_config,
            aflpp: afl_plus_plus_config,
            symcc: symcc_section,
            vanilla: vanilla_config,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn from_path(path: &str) -> Result<Config> {
        let config_string = std::fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("Unable to read config file {}", path));
        let builder = ConfigBuilder {
            base_dir: PathBuf::from_str(path)?.parent().unwrap().to_owned(),
        };
        builder.from_str(&config_string)
    }
}

// #[cfg(test)]
// mod test {
//     use crate::{
//         config::ConfigBuilder,
//         io_channels::{InputChannel, OutputChannel},
//     };
//     use std::path::PathBuf;

//     #[test]
//     fn parse() {
//         let yaml = r#"
//         work-directory: "work"
//         input-directory: "input"

//         source:
//             bin-path: "abc"
//             arguments: ["a", "b", "c"]
//             input-type: "stdin"
//             output-type: "file"
//             log-stdout: false
//             log-stderr: true

//         sink:
//             bin-path: "abc"
//             arguments: ["a", "b", "c"]
//             input-type: "None"
//             output-type: "stdout"
//             log-stdout: true
//             log-stderr: false
//             allow-unstable-sink: true

//         vanilla:
//             bin-path: "abc"
//             arguments: ["a", "b", "c"]

//         phases:
//             discovery:
//                 enabled: true
//                 batch-size: 50
//                 terminate-when-finished: false
//                 batch-cov-timeout: 5m
//                 phase-cov-timeout: 15m
//             mutate:
//                 weight: 50
//                 entry-cov-timeout: 15m
//             add:
//                 weight: 1
//                 batch-size: 60
//                 select-unfuzzed-weight: 1
//                 select-yielding-weight: 1
//                 select-random-weight: 1
//                 entry-cov-timeout: 15m
//             combine:
//                 weight: 5
//                 entry-cov-timeout: 10m

//         "#;

//         let config_builder = ConfigBuilder::from_str(yaml).unwrap();
//         let config = config_builder.build();

//         // General
//         assert_eq!(config.general.work_dir, PathBuf::from("work"));
//         assert_eq!(config.general.input_dir, PathBuf::from("input"));

//         // Source
//         assert_eq!(config.source.bin_path, PathBuf::from("abc"));
//         assert_eq!(config.source.input_type, InputChannel::Stdin);
//         assert_eq!(config.source.output_type, OutputChannel::File);
//         assert!(!config.source.log_stdout);
//         assert!(config.source.log_stderr);
//         assert_eq!(config.source.arguments, vec!["a", "b", "c"]);

//         // Sink
//         assert_eq!(config.sink.bin_path, PathBuf::from("abc"));
//         assert_eq!(config.sink.input_type, InputChannel::None);
//         assert_eq!(config.sink.output_type, OutputChannel::Stdout);
//         assert!(config.sink.log_stdout);
//         assert!(!config.sink.log_stderr);
//         assert_eq!(config.sink.arguments, vec!["a", "b", "c"]);

//         // Vanilla
//         assert_eq!(config.vanilla.bin_path, PathBuf::from("abc"));
//         assert_eq!(config.vanilla.arguments, vec!["a", "b", "c"]);
//     }

//     #[test]
//     fn validate_failure() {
//         let yaml = r#"
//         work-directory: "/tmp"
//         input-directory: "input"

//         source:
//             bin-path: "abc"
//             arguments: ["a", "b", "c"]
//             input-type: "stdin"
//             output-type: "file"
//             log-stdout: false
//             log-stderr: true

//         sink:
//             bin-path: "abc"
//             arguments: ["a", "b", "c"]
//             input-type: "None"
//             output-type: "stdout"
//             log-stdout: true
//             log-stderr: false
//             allow-unstable-sink: true

//         vanilla:
//             bin-path: "abc"
//             arguments: ["a", "b", "c"]

//         phases:
//             discovery:
//                 enabled: true
//                 batch-size: 50
//                 terminate-when-finished: false
//                 batch-cov-timeout: 5m
//                 phase-cov-timeout: 15m
//             mutate:
//                 weight: 50
//                 entry-cov-timeout: 15m
//             add:
//                 weight: 1
//                 batch-size: 60
//                 select-unfuzzed-weight: 1
//                 select-yielding-weight: 1
//                 select-random-weight: 1
//                 entry-cov-timeout: 15m
//             combine:
//                 weight: 5
//                 entry-cov-timeout: 10m

//         "#;

//         let config_builder = ConfigBuilder::from_str(yaml).unwrap();

//         assert!(config_builder.validate().is_err());
//     }

//     #[test]
//     fn validate_success() {
//         let yaml = r#"
//         work-directory: "/nonexistingpath_for_work_dir"
//         input-directory: "/tmp"

//         source:
//             bin-path: "/bin/ls"
//             arguments: ["a", "b", "c"]
//             input-type: "stdin"
//             output-type: "file"
//             log-stdout: false
//             log-stderr: true

//         sink:
//             bin-path: "/bin/ls"
//             arguments: ["a", "b", "c"]
//             input-type: "None"
//             output-type: "stdout"
//             log-stdout: true
//             log-stderr: false
//             allow-unstable-sink: true

//         vanilla:
//             bin-path: "/bin/ls"
//             arguments: ["a", "b", "c"]

//         phases:
//             discovery:
//                 enabled: true
//                 batch-size: 50
//                 terminate-when-finished: false
//                 batch-cov-timeout: 5m
//                 phase-cov-timeout: 15m
//             mutate:
//                 weight: 50
//                 entry-cov-timeout: 15m
//             add:
//                 weight: 1
//                 batch-size: 60
//                 select-unfuzzed-weight: 1
//                 select-yielding-weight: 1
//                 select-random-weight: 1
//                 entry-cov-timeout: 15m
//             combine:
//                 weight: 5
//                 entry-cov-timeout: 10m

//         "#;
//         let config_builder = ConfigBuilder::from_str(yaml).unwrap();

//         assert!(config_builder.validate().is_ok());
//     }
// }
