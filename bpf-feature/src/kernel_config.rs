use flate2::bufread::GzDecoder;
use nix::sys::utsname;
use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
};
use thiserror::Error as ThisError;

#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;
#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum KernelConfigError {
    #[error("can't open file")]
    NotFound,
    #[error("file data format unknown")]
    ContentsUnknown,
    #[error("can't read from file")]
    ReadFail,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum ConfigValue {
    Y,
    N,
    M,
    Other(String),
}

impl Display for ConfigValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigValue::Y => write!(f, "y"),
            ConfigValue::N => write!(f, "n"),
            ConfigValue::M => write!(f, "m"),
            ConfigValue::Other(value) => write!(f, "{}", value),
        }
    }
}

pub type KernelConfigValues = HashMap<&'static str, ConfigValue>;

pub const KERNEL_CONFIG_KEYS: [&'static str; 35] = [
    "CONFIG_BPF",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_HAVE_EBPF_JIT",
    "CONFIG_BPF_JIT",
    "CONFIG_BPF_JIT_ALWAYS_ON",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_DEBUG_INFO_BTF_MODULES",
    "CONFIG_CGROUPS",
    "CONFIG_CGROUP_BPF",
    "CONFIG_CGROUP_NET_CLASSID",
    "CONFIG_SOCK_CGROUP_DATA",
    "CONFIG_BPF_EVENTS",
    "CONFIG_KPROBE_EVENTS",
    "CONFIG_UPROBE_EVENTS",
    "CONFIG_TRACING",
    "CONFIG_FTRACE_SYSCALLS",
    "CONFIG_FUNCTION_ERROR_INJECTION",
    "CONFIG_BPF_KPROBE_OVERRIDE",
    "CONFIG_NET",
    "CONFIG_XDP_SOCKETS",
    "CONFIG_LWTUNNEL_BPF",
    "CONFIG_NET_ACT_BPF",
    "CONFIG_NET_CLS_BPF",
    "CONFIG_NET_CLS_ACT",
    "CONFIG_NET_SCH_INGRESS",
    "CONFIG_XFRM",
    "CONFIG_IP_ROUTE_CLASSID",
    "CONFIG_IPV6_SEG6_BPF",
    "CONFIG_BPF_LIRC_MODE2",
    "CONFIG_BPF_STREAM_PARSER",
    "CONFIG_NETFILTER_XT_MATCH_BPF",
    "CONFIG_BPFILTER",
    "CONFIG_BPFILTER_UMH",
    "CONFIG_TEST_BPF",
    "CONFIG_HZ",
];

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KernelConfig {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub values: KernelConfigValues,
}

impl KernelConfig {
    fn probe_kernel_config() -> Result<KernelConfigValues, KernelConfigError> {
        let utsn = utsname::uname();

        let config_reader: Box<dyn BufRead> =
            match File::open(format!("/boot/config-{}", utsn.release())) {
                Err(_) => {
                    let compressed_config =
                        File::open("/proc/config.gz").map_err(|_| KernelConfigError::NotFound)?;
                    let decoder = GzDecoder::new(BufReader::new(compressed_config));
                    Box::new(BufReader::new(decoder))
                }
                Ok(f) => Box::new(BufReader::new(f)),
            };

        let mut lines_iter = config_reader.lines();
        let _ = lines_iter
            .next()
            .transpose()
            .map_err(|_| KernelConfigError::ReadFail)?
            .ok_or(KernelConfigError::ReadFail)?;
        let line = lines_iter
            .next()
            .transpose()
            .map_err(|_| KernelConfigError::ReadFail)?
            .ok_or(KernelConfigError::ReadFail)?;

        if !line.starts_with("# Automatically generated file; DO NOT EDIT.") {
            return Err(KernelConfigError::ContentsUnknown);
        }

        let mut options = HashMap::new();

        for line_item in lines_iter {
            let line = line_item.map_err(|_| KernelConfigError::ReadFail)?;
            if !line.starts_with("CONFIG_") {
                continue;
            }

            let pieces: Vec<_> = line.split("=").collect();
            if pieces.len() < 2 {
                continue;
            }

            for key in KERNEL_CONFIG_KEYS {
                if key != pieces[0] {
                    continue;
                }

                options.insert(
                    key,
                    match pieces[1] {
                        "y" => ConfigValue::Y,
                        "m" => ConfigValue::M,
                        "n" => ConfigValue::N,
                        _ => ConfigValue::Other(pieces[1].to_string()),
                    },
                );
            }
        }

        return Ok(options);
    }
}

pub fn features() -> Result<KernelConfig, KernelConfigError> {
    return Ok(KernelConfig {
        values: KernelConfig::probe_kernel_config()?,
    });
}
