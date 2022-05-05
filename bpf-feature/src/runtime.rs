use nix::sys::statfs::{statfs, PROC_SUPER_MAGIC};
use std::path::Path;
use thiserror::Error as ThisError;

#[cfg(feature = "serde")]
use crate::serde_ext;
#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;
#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum RuntimeError {
    #[error("procfs at /proc was not detected")]
    ProcfsNonExistent,
    #[error("parse failure: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("io: {0}")]
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

pub fn features() -> Result<Runtime, RuntimeError> {
    Runtime::verify_procfs_exists()?;

    Ok(Runtime {
        unprivileged_disabled: Runtime::procfs_read(Path::new(
            "/proc/sys/kernel/unprivileged_bpf_disabled",
        )),
        jit_enable: Runtime::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_enable")),
        jit_harden: Runtime::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_harden")),
        jit_kallsyms: Runtime::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_kallsyms")),
        jit_limit: Runtime::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_limit")),
    })
}
