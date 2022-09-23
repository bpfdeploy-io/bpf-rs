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
pub mod attach_type;
pub mod descriptor;
mod error;
mod helper;
pub mod insns;
mod map;
mod program;

// Re-exports; should consider removing some in future? (breaking change)
pub use helper::BpfHelper;
pub use libbpf_sys;
pub use map::MapType;
pub use program::{ProgramInfo, ProgramLicense, ProgramType};

type BpfObjId = u32;

// WARNING: Highly coupled to the proc macro bpf_rs_macros::Derive
// Trait can't be part of the bpf_rs_macros crate because a proc crate
// can only export macros
trait StaticName {
    fn name(&self) -> &'static str;
}
