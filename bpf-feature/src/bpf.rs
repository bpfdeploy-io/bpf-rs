use crate::serde_ext;
use bpf_rs::libbpf_sys::{
    bpf_prog_load, BPF_FUNC_probe_write_user, BPF_FUNC_trace_printk, BPF_FUNC_trace_vprintk,
};
use bpf_rs::{BpfHelper, BpfHelperIter, Error as BpfSysError, MapType, ProgramType};
use nix::errno::Errno;
use std::collections::HashMap;
use std::ptr;
use thiserror::Error as ThisError;

#[cfg(feature = "serde")]
use serde::Serialize;

#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;

#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum BpfError {
    #[error("no bpf syscall on system")]
    NoBpfSyscall,
    #[error("bpf-rs::Error: {0}")]
    ProbeErr(#[from] BpfSysError),
}

pub struct BpfFeaturesOpts {
    pub full_helpers: bool,
}

impl Default for BpfFeaturesOpts {
    fn default() -> Self {
        Self {
            full_helpers: false,
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Bpf {
    pub has_bpf_syscall: bool,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::to_list"))]
    pub program_types: HashMap<ProgramType, Result<bool, BpfError>>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_ext::to_list"))]
    pub map_types: HashMap<MapType, Result<bool, BpfError>>,
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
                                    #[allow(non_upper_case_globals)]
                                    match helper.0 {
                                        BPF_FUNC_trace_printk
                                        | BPF_FUNC_trace_vprintk
                                        | BPF_FUNC_probe_write_user => return None,
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
