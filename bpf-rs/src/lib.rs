// DOCS: enable #![warn(missing_docs)]
// DOCS: enable #![warn(missing_doc_code_examples)]
//! `bpf-rs` is a safe, lean library for inspecting and querying eBPF objects. A lot of the
//! design & inspiration stems from [bpftool](https://github.com/libbpf/bpftool) internals and
//! [libbpf-rs](https://docs.rs/libbpf-rs).
//!
//! It is based upon the work of [libbpf-sys](https://github.com/libbpf/libbpf-sys) to safely create
//! wrappers around [libbpf](https://github.com/libbpf/libbpf).
//!
//! This crate is **NOT** meant to help with writing and loading of sophisticated eBPF programs
//! and maps. For that, we recommend [libbpf-rs](https://docs.rs/libbpf-rs) and
//! [libbpf-cargo](https://docs.rs/libbpf-cargo).
//!
mod helper;
pub mod insns;
mod map;
mod program;

// Re-exports
pub use helper::BpfHelper;
pub use libbpf_sys;
pub use map::MapType;
pub use program::{ProgramInfo, ProgramLicense, ProgramType};

use std::fmt::Debug;
use thiserror::Error as ThisError;

/// Propagates error variants from libbpf-sys
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("errno: {0}")]
    Errno(i32),
    #[error("error code: {0}")]
    Code(i32),
    #[error("unknown: {0}")]
    Unknown(i32),
}

// WARNING: Highly coupled to the proc macro bpf_rs_macros::Derive
trait StaticName {
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::libbpf_sys::__BPF_FUNC_MAX_ID;
    use super::*;

    #[test]
    fn bpf_helper_iter() {
        let count = BpfHelper::iter()
            .map(|helper| {
                let name = helper.name();
                assert_ne!(name, "<utf8err>");
                assert_ne!(name, "<unknown>");
            })
            .count();

        assert_eq!(count, usize::try_from(__BPF_FUNC_MAX_ID - 1).unwrap());

        let invalid_helper = BpfHelper::try_from(__BPF_FUNC_MAX_ID);
        assert!(invalid_helper.is_err());
    }

    #[test]
    fn program_license_ptr() {
        assert!(!ProgramLicense::GPL.as_ptr().is_null());
    }
}
