use libbpf_sys::{libbpf_probe_bpf_prog_type, libbpf_probe_bpf_map_type};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{ptr, time::Duration};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("errno: {0}")]
    Errno(i32),
    #[error("error code: {0}")]
    Code(i32),
    #[error("unknown: {0}")]
    Unknown(i32),
}

/// Must abide by enum bpf_prog_type in kernel headers
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

    pub fn probe(&self) -> Result<bool, Error> {
        match unsafe { libbpf_probe_bpf_prog_type((*self).into(), ptr::null()) } {
            negative if negative < 0 => Err(Error::Code(negative)),
            0 => Ok(false),
            1 => Ok(true),
            positive if positive > 1 => Err(Error::Unknown(positive)),
            _ => unreachable!(),
        }
    }

    /// Skips BPF_PROGRAM_TYPE_UNSPEC since it's an invalid program type
    pub fn iter() -> impl Iterator<Item = ProgramType> {
        ProgramTypeIter(1)
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
pub struct Program {
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

/// Must abide by enum bpf_map_type in kernel headers
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

    pub fn probe(&self) -> Result<bool, Error> {
        match unsafe { libbpf_probe_bpf_map_type((*self).into(), ptr::null()) } {
            negative if negative < 0 => Err(Error::Code(negative)),
            0 => Ok(false),
            1 => Ok(true),
            positive if positive > 1 => Err(Error::Unknown(positive)),
            _ => unreachable!(),
        }
    }

    /// Skips BPF_MAP_TYPE_UNSPEC since it's an invalid map type
    pub fn iter() -> impl Iterator<Item = MapType> {
        MapTypeIter(1)
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
