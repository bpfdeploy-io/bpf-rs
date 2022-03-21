use std::path::PathBuf;

use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum DetectError {
    #[error("failed to access capabilities")]
    CapAccess,
    #[error("missing CAP_SYS_ADMIN for full feature probe")]
    CapMissing,
    #[error("{0}")]
    Procfs(String), // A string or another nested error?
}

// struct KernelConfig {}

#[derive(Debug)]
struct ProcfsBased {
    privileged_bpf_syscall: Result<bool, DetectError>,
}

fn procfs_exists() -> Result<(), DetectError> {
    // TODO: if this is the only use of nix
    // then consider just using libc
    use nix::sys::statfs::{statfs, PROC_SUPER_MAGIC};

    match statfs("/proc") {
        Err(err) => Err(DetectError::Procfs(format!(
            "error looking for /proc: {}",
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

fn procfs_value(path: PathBuf) -> Result<usize, std::io::Error> {
    Ok(10)
}

fn procfs_based() -> Result<ProcfsBased, DetectError> {
    let unprivileged_bpf_disabled = procfs_value("/proc/sys/kernel/unprivileged_bpf_disabled".into())?;
    Ok(ProcfsBased {})
}

#[derive(Debug)]
pub struct System {
    // kernel_config: Result<KernelConfigFeatures, Error>,
    procfs_based: Result<ProcfsBased, DetectError>,
}

fn system_features() -> System {
    let procfs_based = procfs_exists().and_then(|_| procfs_based());
    System { procfs_based }
}

#[derive(Debug)]
pub struct Features {
    system: System,
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
                    return Err(DetectError::CapMissing);
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
