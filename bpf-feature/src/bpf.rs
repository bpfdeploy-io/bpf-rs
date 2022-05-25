//! Features related specifically to eBPF program development
//!
//! This feature set can be used to determine which eBPF program types, maps &
//! helpers are available to your runtime.
use bpf_rs::libbpf_sys::bpf_prog_load;
use bpf_rs::{BpfHelper, BpfHelperIter, Error as BpfSysError, MapType, ProgramType};
use nix::errno::Errno;
use std::collections::HashMap;
use std::ptr;
use thiserror::Error as ThisError;

#[cfg(feature = "serde")]
use crate::serde_ext;
#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;
#[cfg(feature = "serde")]
use serde::Serialize;

/// Captures potential errors from detection techniques
#[non_exhaustive]
#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum BpfError {
    /// [`bpf(2)`](https://man7.org/linux/man-pages/man2/bpf.2.html) syscall is
    /// not available
    #[error("no bpf syscall on system")]
    NoBpfSyscall,
    /// If an error occurs during probing of a feature, we propagate it to the
    /// client
    #[error("bpf-rs::Error: {0}")]
    ProbeErr(#[from] BpfSysError),
}

/// Results for each eBPF detection technique
///
/// The determination of support for these features relies on the implementations
/// provided by [libbpf](https://github.com/libbpf/libbpf).
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Bpf {
    /// Attempts to load a simple program without error to determine if syscall
    /// is available
    pub has_bpf_syscall: bool,
    /// For each program type, we determine definite support or propagate
    /// the resulting error to the client.
    ///
    /// Internally, this relies on libbpf's `libbpf_probe_bpf_prog_type` implementation
    /// which currently attempts to load a basic program of each type to determine
    /// support
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::to_list"))]
    pub program_types: HashMap<ProgramType, Result<bool, BpfError>>,
    /// For each program type, we determine definite support or propagate
    /// the resulting error to the client
    ///
    /// Internally, this relies on libbpf's `libbpf_probe_bpf_map_type` implementation
    /// which currently attempts to create a map of each type to determine
    /// support
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::to_list"))]
    pub map_types: HashMap<MapType, Result<bool, BpfError>>,
    /// Returns a list of supported helpers (or error if probe fails) for each
    /// program type.
    ///
    /// Note: If the program type is **NOT** supported, then the list
    /// will be empty. If the program type is supported but an error occurs on the
    /// individual helper probe, that error will be propagated to the list.
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::to_list_inner"))]
    pub helpers: HashMap<ProgramType, Vec<Result<BpfHelper, BpfError>>>,
}

impl Bpf {
    fn probe_syscall() -> bool {
        Errno::clear();
        unsafe {
            bpf_prog_load(
                ProgramType::Unspec.into(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
            );
        }
        Errno::last() != Errno::ENOSYS
    }

    fn probe_program_types() -> HashMap<ProgramType, Result<bool, BpfError>> {
        ProgramType::iter()
            .map(|program_type| {
                (
                    program_type,
                    program_type.probe().map_err(|err| BpfError::ProbeErr(err)),
                )
            })
            .collect()
    }

    fn probe_map_types() -> HashMap<MapType, Result<bool, BpfError>> {
        MapType::iter()
            .map(|map_type| {
                (
                    map_type,
                    map_type.probe().map_err(|err| BpfError::ProbeErr(err)),
                )
            })
            .collect()
    }

    fn probe_helpers(full: bool) -> HashMap<ProgramType, Vec<Result<BpfHelper, BpfError>>> {
        ProgramType::iter()
            .map(|program_type| {
                // NOTE: Due to libbpf's `libbpf_probe_bpf_helper` implementation, it may return true
                // for helpers of **unsupported** program types so the user is forced to check
                // against this before probing for helper support.
                match program_type.probe() {
                    Ok(true) => {
                        let helpers = BpfHelperIter::new()
                            .filter_map(|helper| {
                                if !full {
                                    match helper {
                                        BpfHelper::TracePrintk
                                        | BpfHelper::TraceVprintk
                                        | BpfHelper::ProbeWriteUser => return None,
                                        _ => {}
                                    };
                                }

                                match program_type.probe_helper(helper) {
                                    Ok(true) => Some(Ok(helper)),
                                    Ok(false) => None,
                                    Err(err) => Some(Err(BpfError::ProbeErr(err))),
                                }
                            })
                            .collect();
                        (program_type, helpers)
                    }
                    Ok(false) | Err(_) => (program_type, vec![]),
                }
            })
            .collect()
    }
}

/// Options that can be passed into [`features`]
pub struct BpfFeaturesOpts {
    /// For compatibility purposes with bpftool, the helpers determined support for
    /// is not the complete set. A few always-available helpers are filtered out
    /// such as `bpf_trace_printk`, `bpf_trace_vprintk`, and `bpf_probe_write_user`.
    ///
    /// Default: `false`
    pub full_helpers: bool,
}

impl Default for BpfFeaturesOpts {
    fn default() -> Self {
        Self {
            full_helpers: false,
        }
    }
}

/// This module's main function to run [`Bpf`] feature detection set
pub fn features(opts: BpfFeaturesOpts) -> Result<Bpf, BpfError> {
    if !Bpf::probe_syscall() {
        return Err(BpfError::NoBpfSyscall);
    }

    Ok(Bpf {
        has_bpf_syscall: true,
        program_types: Bpf::probe_program_types(),
        map_types: Bpf::probe_map_types(),
        helpers: Bpf::probe_helpers(opts.full_helpers),
    })
}
