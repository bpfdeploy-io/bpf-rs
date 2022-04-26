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
pub mod insns;

use libbpf_sys::{
    _bpf_helper_func_names, libbpf_probe_bpf_helper, libbpf_probe_bpf_map_type,
    libbpf_probe_bpf_prog_type, __BPF_FUNC_MAX_ID,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{
    ffi::CStr,
    fmt::{Debug, Display},
    os::raw,
    ptr,
    time::Duration,
};
use thiserror::Error as ThisError;

pub use libbpf_sys;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("errno: {0}")]
    Errno(i32),
    #[error("error code: {0}")]
    Code(i32),
    #[error("unknown: {0}")]
    Unknown(i32),
}

/// eBPF program type variants. Based off of [kernel header's](https://github.com/torvalds/linux/blob/b253435746d9a4a701b5f09211b9c14d3370d0da/include/uapi/linux/bpf.h#L922)
/// `enum bpf_prog_type`
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramType {
    Unspec = 0,
    SocketFilter,
    Kprobe,
    SchedCls,
    SchedAct,
    Tracepoint,
    Xdp,
    PerfEvent,
    CgroupSkb,
    CgroupSock,
    LwtIn,
    LwtOut,
    LwtXmit,
    SockOps,
    SkSkb,
    CgroupDevice,
    SkMsg,
    RawTracepoint,
    CgroupSockAddr,
    LwtSeg6local,
    LircMode2,
    SkReuseport,
    FlowDissector,
    CgroupSysctl,
    RawTracepointWritable,
    CgroupSockopt,
    Tracing,
    StructOps,
    Ext,
    Lsm,
    SkLookup,
    Syscall,
}

impl ProgramType {
    /// Based off of bpftool's
    /// [`prog_type_name`](https://github.com/libbpf/bpftool/blob/9443d42430017ed2d04d7ab411131525ced62d6a/src/prog.c#L39),
    /// returns a human-readable name of the eBPF program type.
    pub fn name(&self) -> &'static str {
        match *self {
            ProgramType::Unspec => "unspec",
            ProgramType::SocketFilter => "socket_filter",
            ProgramType::Kprobe => "kprobe",
            ProgramType::SchedCls => "sched_cls",
            ProgramType::SchedAct => "sched_act",
            ProgramType::Tracepoint => "tracepoint",
            ProgramType::Xdp => "xdp",
            ProgramType::PerfEvent => "perf_event",
            ProgramType::CgroupSkb => "cgroup_skb",
            ProgramType::CgroupSock => "cgroup_sock",
            ProgramType::LwtIn => "lwt_in",
            ProgramType::LwtOut => "lwt_out",
            ProgramType::LwtXmit => "lwt_xmit",
            ProgramType::SockOps => "sock_ops",
            ProgramType::SkSkb => "sk_skb",
            ProgramType::CgroupDevice => "cgroup_device",
            ProgramType::SkMsg => "sk_msg",
            ProgramType::RawTracepoint => "raw_tracepoint",
            ProgramType::CgroupSockAddr => "cgroup_sock_addr",
            ProgramType::LwtSeg6local => "lwt_seg6local",
            ProgramType::LircMode2 => "lirc_mode2",
            ProgramType::SkReuseport => "sk_reuseport",
            ProgramType::FlowDissector => "flow_dissector",
            ProgramType::CgroupSysctl => "cgroup_sysctl",
            ProgramType::RawTracepointWritable => "raw_tracepoint_writable",
            ProgramType::CgroupSockopt => "cgroup_sockopt",
            ProgramType::Tracing => "tracing",
            ProgramType::StructOps => "struct_ops",
            ProgramType::Ext => "ext",
            ProgramType::Lsm => "lsm",
            ProgramType::SkLookup => "sk_lookup",
            ProgramType::Syscall => "syscall",
        }
    }

    /// Determines if the eBPF program type is supported on the current platform
    pub fn probe(&self) -> Result<bool, Error> {
        match unsafe { libbpf_probe_bpf_prog_type((*self).into(), ptr::null()) } {
            negative if negative < 0 => Err(Error::Code(negative)),
            0 => Ok(false),
            1 => Ok(true),
            positive if positive > 1 => Err(Error::Unknown(positive)),
            _ => unreachable!(),
        }
    }

    /// Determines if the eBPF program helper function can be used my supported program types.
    ///
    /// **Note**: Due to libbpf's `libbpf_probe_bpf_helper`, this may return Ok(true) for unsupported program
    /// types. It is recommended to verify if the program type is supported before probing for helper
    /// support.
    pub fn probe_helper(&self, helper: BpfHelper) -> Result<bool, Error> {
        match unsafe { libbpf_probe_bpf_helper((*self).into(), helper.0, ptr::null()) } {
            negative if negative < 0 => Err(Error::Code(negative)),
            0 => Ok(false),
            1 => Ok(true),
            positive if positive > 1 => Err(Error::Unknown(positive)),
            _ => unreachable!(),
        }
    }

    /// Returns an ordered iterator over the [`ProgramType`] variants. The order is determined by the kernel
    /// header's [enum values](https://github.com/torvalds/linux/blob/b253435746d9a4a701b5f09211b9c14d3370d0da/include/uapi/linux/bpf.h#L922).
    ///
    /// **Note**: Skips [`ProgramType::Unspec`] since it's an invalid program type
    pub fn iter() -> impl Iterator<Item = ProgramType> {
        ProgramTypeIter(1)
    }
}

impl Display for ProgramType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

struct ProgramTypeIter(u32);

impl Iterator for ProgramTypeIter {
    type Item = ProgramType;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0;
        if next > ProgramType::Syscall.into() {
            None
        } else {
            self.0 = self.0 + 1;
            ProgramType::try_from_primitive(next).ok()
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ProgramInfo {
    pub name: String,
    pub ty: ProgramType,
    pub tag: [u8; 8],
    pub id: u32,
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: u64,
    pub xlated_prog_insns: u64,
    pub load_time: Duration,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub ifindex: u32,
    pub gpl_compatible: bool,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: u64,
    pub jited_func_lens: u64,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: u64,
    pub run_time_ns: u64,
    pub run_cnt: u64,
}

/// Collection of eBPF program license types (e.g. GPL)
///
/// Mostly a smaller wrapper for FFI use cases
#[non_exhaustive]
pub enum ProgramLicense {
    GPL,
}

impl ProgramLicense {
    /// Accepted license string with a nul byte at the end
    pub fn as_str_with_nul(&self) -> &'static str {
        match *self {
            ProgramLicense::GPL => "GPL\0",
        }
    }

    /// For FFI (such as using with `libbpf_sys`)
    pub fn as_ptr(&self) -> *const raw::c_char {
        CStr::from_bytes_with_nul(self.as_str_with_nul().as_bytes())
            .unwrap()
            .as_ptr()
    }
}

/// eBPF map type variants. Based off of [kernel header's](https://github.com/torvalds/linux/blob/b253435746d9a4a701b5f09211b9c14d3370d0da/include/uapi/linux/bpf.h#L880)
/// `enum bpf_map_type`
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapType {
    Unspec = 0,
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PerCpuHash,
    PerCpuArray,
    StackTrace,
    CgroupArray,
    LruHash,
    LruPerCpuHash,
    LpmTrie,
    ArrayOfMaps,
    HashOfMaps,
    DevMap,
    SockMap,
    CpuMap,
    XskMap,
    SockHash,
    CgroupStorage,
    ReusePortSockArray,
    PerCpuCgroupStorage,
    Queue,
    Stack,
    SkStorage,
    DevMapHash,
    StructOps,
    RingBuf,
    InodeStorage,
    TaskStorage,
    BloomFilter,
}

impl MapType {
    /// Based off of bpftool's
    /// [`map_type_name`](https://github.com/libbpf/bpftool/blob/9443d42430017ed2d04d7ab411131525ced62d6a/src/map.c#L25),
    /// returns a human-readable name of the eBPF map type.
    pub fn name(&self) -> &'static str {
        match *self {
            MapType::Unspec => "unspec",
            MapType::Hash => "hash",
            MapType::Array => "array",
            MapType::ProgArray => "prog_array",
            MapType::PerfEventArray => "perf_event_array",
            MapType::PerCpuHash => "percpu_hash",
            MapType::PerCpuArray => "percpu_array",
            MapType::StackTrace => "stack_trace",
            MapType::CgroupArray => "cgroup_array",
            MapType::LruHash => "lru_hash",
            MapType::LruPerCpuHash => "lru_percpu_hash",
            MapType::LpmTrie => "lpm_trie",
            MapType::ArrayOfMaps => "array_of_maps",
            MapType::HashOfMaps => "hash_of_maps",
            MapType::DevMap => "devmap",
            MapType::SockMap => "sockmap",
            MapType::CpuMap => "cpumap",
            MapType::XskMap => "xskmap",
            MapType::SockHash => "sockhash",
            MapType::CgroupStorage => "cgroup_storage",
            MapType::ReusePortSockArray => "reuseport_sockarray",
            MapType::PerCpuCgroupStorage => "percpu_cgroup_storage",
            MapType::Queue => "queue",
            MapType::Stack => "stack",
            MapType::SkStorage => "sk_storage",
            MapType::DevMapHash => "devmap_hash",
            MapType::StructOps => "struct_ops",
            MapType::RingBuf => "ringbuf",
            MapType::InodeStorage => "inode_storage",
            MapType::TaskStorage => "task_storage",
            MapType::BloomFilter => "bloom_filter",
        }
    }

    /// Determines if the eBPF map type is supported on the current platform
    pub fn probe(&self) -> Result<bool, Error> {
        match unsafe { libbpf_probe_bpf_map_type((*self).into(), ptr::null()) } {
            negative if negative < 0 => Err(Error::Code(negative)),
            0 => Ok(false),
            1 => Ok(true),
            positive if positive > 1 => Err(Error::Unknown(positive)),
            _ => unreachable!(),
        }
    }

    /// Returns an ordered iterator over the MapType variants. The order is determined by the kernel
    /// header's [enum values](https://github.com/torvalds/linux/blob/b253435746d9a4a701b5f09211b9c14d3370d0da/include/uapi/linux/bpf.h#L880).
    ///
    /// **Note**: Skips [`MapType::Unspec`] since it's an invalid map type
    pub fn iter() -> impl Iterator<Item = MapType> {
        MapTypeIter(1)
    }
}

impl Display for MapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

struct MapTypeIter(u32);

impl Iterator for MapTypeIter {
    type Item = MapType;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0;
        if next > MapType::BloomFilter.into() {
            None
        } else {
            self.0 = self.0 + 1;
            MapType::try_from_primitive(next).ok()
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BpfHelper(pub u32);

impl BpfHelper {
    pub fn name(&self) -> &'static str {
        match usize::try_from(self.0) {
            Ok(func_idx) => {
                if func_idx >= unsafe { _bpf_helper_func_names.len() } {
                    "<unknown>"
                } else {
                    let fn_name_ptr = unsafe { _bpf_helper_func_names[func_idx] };
                    let cstr = unsafe { CStr::from_ptr(fn_name_ptr) };
                    cstr.to_str().unwrap_or("<utf8err>")
                }
            }
            Err(_) => "<unknown>",
        }
    }
}

impl Display for BpfHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Debug for BpfHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple(format!("{}<{}>", "BpfHelper", &self.name()).as_str())
            .field(&self.0)
            .finish()
    }
}

pub struct BpfHelperIter(u32);

impl BpfHelperIter {
    // Skips unspec helper
    pub fn new() -> Self {
        Self(1)
    }
}

impl Iterator for BpfHelperIter {
    type Item = BpfHelper;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0;
        if next >= __BPF_FUNC_MAX_ID {
            None
        } else {
            self.0 = self.0 + 1;
            Some(BpfHelper(next))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_helper_iter() {
        let count = BpfHelperIter::new()
            .map(|helper| {
                let name = helper.name();
                assert_ne!(name, "<utf8err>");
                assert_ne!(name, "<unknown>");
            })
            .count();

        assert_eq!(count, usize::try_from(__BPF_FUNC_MAX_ID - 1).unwrap());

        let invalid_helper = BpfHelper(__BPF_FUNC_MAX_ID + 1);
        assert_eq!(invalid_helper.name(), "<unknown>");
    }

    #[test]
    fn program_license_ptr() {
        assert!(ProgramLicense::GPL.as_ptr().is_null() == false);
    }
}
