//! Features derived from compile-time kernel configuration
//!
//! The Linux kernel accepts an assortment of flags that can be enabled or disabled
//! at compilation. These configuration flags are used to determine which eBPF
//! features are eventually available on the running kernel.
//!
//! Depending on your distribution, your kernel config can be available in a number
//! of locations such as:
//!
//! - `/proc/config.gz`
//! - `/boot/config`
//! - `/boot/config-$(uname -r)`
//!
//! This module will search for and read your kernel configuration for relevant
//! eBPF flags. If you believe a flag is missing or incorrectly added to
//! the set in [`KERNEL_CONFIG_KEYS`],  please file [an issue](https://github.com/bpfdeploy-io/bpf-rs).
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

/// Entire set of kernel config flags to determine support of
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

/// Possible errors when reading a kernel's config file
#[non_exhaustive]
#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum KernelConfigError {
    /// Kernel config file was not found
    #[error("can't open file")]
    NotFound,
    /// Could not parse contents of config file
    #[error("file data format unknown")]
    ContentsUnknown,
    /// IO error reading the config file
    #[error("can't read from file")]
    ReadFail,
}

/// Variant of possible config values (e.g. `y`, `n`, `m` etc.)
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum ConfigValue {
    /// This kernel feature is available.
    Y,
    /// This kernel feature is **NOT** available.
    ///
    /// This might mean that you need to upgrade your kernel, flag an issue
    /// with your Linux distro or compile your own kernel to get the necessary
    /// functionality.
    N,
    /// This kernel feature is available *as a module only*.
    ///
    /// This means that the feature is available on your system as a kernel
    /// module but might require privileged enabling of it to gain functionality.
    M,
    NotSet,
    /// This kernel flag is an unstructured value determined at compile time
    Other(String),
}

impl Display for ConfigValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigValue::Y => write!(f, "y"),
            ConfigValue::N => write!(f, "n"),
            ConfigValue::M => write!(f, "m"),
            ConfigValue::NotSet => write!(f, "not set"),
            ConfigValue::Other(value) => write!(f, "{}", value),
        }
    }
}

type KernelConfigValues = HashMap<&'static str, ConfigValue>;

/// Primarily just a wrapper for kernel config values
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KernelConfig {
    /// A HashMap of kernel config values with the key being the
    /// flag and the value derived from reading the kernel config file
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

        let mut config = HashMap::from(KERNEL_CONFIG_KEYS.map(|key| {
            return (key, ConfigValue::NotSet);
        }));

        for line_item in lines_iter {
            let line = line_item.map_err(|_| KernelConfigError::ReadFail)?;
            if !line.starts_with("CONFIG_") {
                continue;
            }

            let split_items: Vec<_> = line.split("=").collect();
            if split_items.len() < 2 {
                continue;
            }

            let line_key = split_items[0];
            let line_value = split_items[1];

            for key in KERNEL_CONFIG_KEYS {
                if key != line_key {
                    continue;
                }

                config.insert(
                    key,
                    match line_value {
                        "y" => ConfigValue::Y,
                        "m" => ConfigValue::M,
                        "n" => ConfigValue::N,
                        _ => ConfigValue::Other(line_value.to_string()),
                    },
                );
            }
        }

        return Ok(config);
    }
}

/// This module's main function to read and determine support of kernel config
/// flags
pub fn features() -> Result<KernelConfig, KernelConfigError> {
    return Ok(KernelConfig {
        values: KernelConfig::probe_kernel_config()?,
    });
}
