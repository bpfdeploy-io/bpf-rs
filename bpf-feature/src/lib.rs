use std::{hash::Hash, path::Path};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum DetectError {
    #[error("failed to access capabilities")]
    CapAccess,
    #[error("missing CAP_SYS_ADMIN for full feature probe")]
    CapSysAdmin,
    #[error("{0}")]
    Procfs(String), // should be a further nested error type rather thanString?
    #[error("IO err: {0}")]
    IO(#[from] std::io::Error),
}

type ProcfsResult = Result<usize, DetectError>;

#[derive(Debug)]
pub struct Runtime {
    pub unprivileged_disabled: ProcfsResult,
    pub jit_enable: ProcfsResult,
    pub jit_harden: ProcfsResult,
    pub jit_kallsyms: ProcfsResult,
    pub jit_limit: ProcfsResult,
}

fn verify_procfs_exists() -> Result<(), DetectError> {
    // TODO: if this is the only use of nix
    // then consider just using libc
    use nix::sys::statfs::{statfs, PROC_SUPER_MAGIC};

    match statfs("/proc") {
        Err(err) => Err(DetectError::Procfs(format!(
            "error detecting /proc: {}",
            err
        ))),
        Ok(stat) => {
            if stat.filesystem_type() != PROC_SUPER_MAGIC {
                Err(DetectError::Procfs(
                    "/proc f_type not equal to PROC_SUPER_MAGIC".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn procfs_value(path: &Path) -> ProcfsResult {
    std::fs::read_to_string(path)?
        .trim()
        .parse()
        .or(Err(DetectError::Procfs("invalid parsing".into())))
}

fn probe_runtime() -> Result<Runtime, DetectError> {
    Ok(Runtime {
        unprivileged_disabled: procfs_value(Path::new(
            "/proc/sys/kernel/unprivileged_bpf_disabled",
        )),
        jit_enable: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_enable")),
        jit_harden: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_harden")),
        jit_kallsyms: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_kallsyms")),
        jit_limit: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_limit")),
    })
}

#[derive(Debug)]
pub struct System {
    pub runtime: Result<Runtime, DetectError>,
    // kernel_config: Result<KernelConfigFeatures, Error>,
}

fn system_features() -> Result<System, DetectError> {
    verify_procfs_exists()?;

    Ok(System {
        runtime: probe_runtime(),
    })
}

#[derive(Debug)]
pub struct Features {
    pub system: Result<System, DetectError>,
}

pub struct DetectOpts {
    privileged: bool,
}

impl Default for DetectOpts {
    fn default() -> Self {
        Self { privileged: true }
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
        system: system_features(),
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
