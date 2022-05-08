//! A library focused on detecting supported eBPF features on the current host
//!
//! # Background
//!
//! The approaches here taken are similar to the way [bpftool](https://github.com/libbpf/bpftool)
//! probes functionality on the host. We recommend users use the `bpftool feature`
//! subcommand for interactive display of eBPF feature support but we
//! developed this library for incorporating these detection techniques within Rust apps.
//!
//! ## Compatibility with bpftool
//!
//! This library is aimed to exactly match the detection features of `bpftool feature`. If
//! this is not the case, we consider [it a bug](https://github.com/bpfdeploy-io/bpf-rs/issues).
//!
//! As an example of this, we recreated the default output of `bpftool feature` here:
//! [`examples/feature-probe.rs`](https://github.com/bpfdeploy-io/bpf-rs/tree/main/bpf-feature/examples)
//!
//! # JSON
//!
//! We also support JSON output. This is powered by [Serde](https://github.com/serde-rs/serde),
//! a popular serialization crate. Note that the JSON output differs in structure
//! from the output of `bpftool feature probe --json` but semantically should be
//! identical.
//!
//! To see an example of JSON out, see the example
//! [`examples/json-dump.rs`](https://github.com/bpfdeploy-io/bpf-rs/tree/main/bpf-feature/examples).
//!
//! Serialization support is **NOT** enabled by default. Please pass in the `serde`
//! feature to enable.
//!
//! ## Other serialization formats
//!
//! Because of the abstraction Serde provides, we are not restricted to JSON and it
//! is possible to support other serialization formats. This should work out of the
//! box but if issues occur, please let us know.
//!
//! # Design
//!
//! For detecting all functionality, we've exported a singular function [`detect`]
//! that can be configured with options through [`DetectOpts`] (to pass in the
//! defaults you can use [`DetectOpts::default()`]):
//!
//! ```
//! use bpf_feature::{detect, DetectOpts};
//!
//! fn main() {
//!     let features = detect(DetectOpts::default());
//!     // ...
//! }
//! ```
//!
//! ## Modularity
//!
//! `detect` is not the only entrypoint publicly exported. We have organized
//! related features into modules that export specific detections through a
//! `features()` function:
//!
//! - [`bpf::features`]
//! - [`kernel_config::features`]
//! - [`runtime::features`]
//! - [`misc::features`]
//!
//! This means that in your application can choose which features to run:
//!
//! ```
//! use bpf_feature::kernel_config::{self, KERNEL_CONFIG_KEYS, KernelConfig};
//!
//! fn main() {
//!     match kernel_config::features() {
//!         Ok(KernelConfig { values }) => KERNEL_CONFIG_KEYS.iter().for_each(|&key| {
//!             match values.get(key) {
//!                 Some(value) => println!("{} is set to {}", key, value),
//!                 None => println!("{} is not set", key),
//!             };
//!         }),
//!         Err(err) => println!("skipping kernel config, {}", err),
//!     }
//! }
//! ```
//!
//!

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
    pub full_helpers: bool,
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
