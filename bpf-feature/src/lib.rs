use thiserror::Error as ThisError;

#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "serde")]
mod serde_ext;

pub mod bpf;
pub mod kernel_config;
pub mod misc;
pub mod runtime;

#[derive(ThisError, Debug)]
pub enum DetectError {
    #[error("failed to access capabilities")]
    CapAccess,
    #[error("missing CAP_SYS_ADMIN for full feature probe")]
    CapSysAdmin,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Features {
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::flatten_result"))]
    pub runtime: Result<runtime::Runtime, runtime::RuntimeError>,
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
        runtime: runtime::features(),
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
