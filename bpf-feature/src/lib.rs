#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "serde")]
mod serde_ext;

pub mod bpf;
pub mod kernel_config;
pub mod misc;
pub mod runtime;

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
    full_helpers: bool,
}

impl Default for DetectOpts {
    fn default() -> Self {
        Self {
            full_helpers: false,
        }
    }
}

pub fn detect(opts: DetectOpts) -> Features {
    Features {
        runtime: runtime::features(),
        kernel_config: kernel_config::features(),
        bpf: bpf::features(bpf::BpfFeaturesOpts {
            full_helpers: opts.full_helpers,
        }),
        misc: misc::features(),
    }
}
