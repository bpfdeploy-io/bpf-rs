use flate2::bufread::GzDecoder;
use nix::sys::{
    statfs::{statfs, PROC_SUPER_MAGIC},
    utsname,
};
use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use thiserror::Error as ThisError;

pub mod bpf;
pub mod misc;

#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;
#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "serde")]
mod serde_ext;

#[derive(ThisError, Debug)]
pub enum DetectError {
    #[error("failed to access capabilities")]
    CapAccess,
    #[error("missing CAP_SYS_ADMIN for full feature probe")]
    CapSysAdmin,
}

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
    pub fn features() -> Result<KernelConfig, KernelConfigError> {
        return Ok(KernelConfig {
            values: Self::probe_kernel_config()?,
        });
    }

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

#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum RuntimeError {
    #[error("procfs at /proc was not detected")]
    ProcfsNonExistent,
    #[error("std::num::ParseIntError: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("std::io::Error: {0}")]
    IO(#[from] std::io::Error),
}

type ProcfsResult = Result<usize, RuntimeError>;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Runtime {
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub unprivileged_disabled: ProcfsResult,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub jit_enable: ProcfsResult,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub jit_harden: ProcfsResult,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub jit_kallsyms: ProcfsResult,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub jit_limit: ProcfsResult,
}

impl Runtime {
    pub fn features() -> Result<Runtime, RuntimeError> {
        Self::verify_procfs_exists()?;

        Ok(Runtime {
            unprivileged_disabled: Self::procfs_read(Path::new(
                "/proc/sys/kernel/unprivileged_bpf_disabled",
            )),
            jit_enable: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_enable")),
            jit_harden: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_harden")),
            jit_kallsyms: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_kallsyms")),
            jit_limit: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_limit")),
        })
    }

    fn verify_procfs_exists() -> Result<(), RuntimeError> {
        match statfs("/proc") {
            Err(_) => Err(RuntimeError::ProcfsNonExistent),
            Ok(stat) => {
                if stat.filesystem_type() != PROC_SUPER_MAGIC {
                    Err(RuntimeError::ProcfsNonExistent)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn procfs_read(path: &Path) -> ProcfsResult {
        Ok(std::fs::read_to_string(path)?.trim().parse()?)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Features {
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub runtime: Result<Runtime, RuntimeError>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub kernel_config: Result<KernelConfig, KernelConfigError>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub bpf: Result<bpf::Bpf, bpf::BpfError>,
    pub misc: misc::Misc,
}

pub struct DetectOpts {
    privileged: bool,
    full_helpers: bool,
}

impl Default for DetectOpts {
    fn default() -> Self {
        Self {
            privileged: true,
            full_helpers: false,
        }
    }
}

pub fn detect(opts: DetectOpts) -> Result<Features, DetectError> {
    use caps::{CapSet, Capability::CAP_SYS_ADMIN};
    if opts.privileged {
        match caps::has_cap(None, CapSet::Effective, CAP_SYS_ADMIN) {
            Ok(is_capable) => {
                if !is_capable {
                    return Err(DetectError::CapSysAdmin);
                }
            }
            Err(_) => return Err(DetectError::CapAccess),
        }
    } else {
        match caps::clear(None, CapSet::Effective) {
            Ok(_) => {}
            Err(_) => return Err(DetectError::CapAccess),
        }
    }

    Ok(Features {
        runtime: Runtime::features(),
        kernel_config: KernelConfig::features(),
        bpf: bpf::features(bpf::BpfFeaturesOpts {
            full_helpers: opts.full_helpers,
        }),
        misc: misc::features(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
