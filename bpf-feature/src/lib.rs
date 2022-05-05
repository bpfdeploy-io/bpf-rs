use nix::sys::statfs::{statfs, PROC_SUPER_MAGIC};
use std::path::Path;
use thiserror::Error as ThisError;

pub mod bpf;
pub mod kernel_config;
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
    pub kernel_config: Result<kernel_config::KernelConfig, kernel_config::KernelConfigError>,
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
        kernel_config: kernel_config::features(),
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
