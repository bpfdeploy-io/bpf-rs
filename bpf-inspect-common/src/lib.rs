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

    pub fn probe_helper(&self, helper: BpfHelper) -> Result<bool, Error> {
        match unsafe { libbpf_probe_bpf_helper((*self).into(), helper.0, ptr::null()) } {
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

#[non_exhaustive]
pub enum ProgramLicense {
    GPL,
}

impl ProgramLicense {
    pub fn as_str_with_nul(&self) -> &'static str {
        match *self {
            ProgramLicense::GPL => "GPL\0",
        }
    }

    pub fn as_ptr(&self) -> *const raw::c_char {
        CStr::from_bytes_with_nul(self.as_str_with_nul().as_bytes())
            .unwrap()
            .as_ptr()
    }
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BpfHelper(u32);

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

pub mod bpf_asm {
    use libbpf_sys::{
        bpf_insn, BPF_JLT, BPF_JNE, BPF_REG_0, BPF_REG_1, BPF_SUB, _BPF_ALU64_IMM, _BPF_EXIT_INSN,
        _BPF_JMP32_IMM, _BPF_JMP_IMM, _BPF_MOV64_IMM,
    };
    use num_enum::{IntoPrimitive, TryFromPrimitive};

    #[repr(u8)]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum BpfRegister {
        R0 = BPF_REG_0 as u8,
        R1 = BPF_REG_1 as u8,
    }

    #[repr(u8)]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum BpfOp {
        Sub = BPF_SUB as u8,
    }

    #[repr(u8)]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum BpfJmp {
        JNE = BPF_JNE as u8,
        JLT = BPF_JLT as u8,
    }

    pub fn mov64_imm(reg: BpfRegister, imm: i32) -> bpf_insn {
        unsafe { _BPF_MOV64_IMM(reg.into(), imm) }
    }

    pub fn alu64_imm(op: BpfOp, reg: BpfRegister, imm: i32) -> bpf_insn {
        unsafe { _BPF_ALU64_IMM(op.into(), reg.into(), imm) }
    }

    pub fn jmp_imm(jmp: BpfJmp, reg: BpfRegister, imm: i32, off: i16) -> bpf_insn {
        unsafe { _BPF_JMP_IMM(jmp.into(), reg.into(), imm, off) }
    }

    pub fn jmp32_imm(jmp: BpfJmp, reg: BpfRegister, imm: i32, off: i16) -> bpf_insn {
        unsafe { _BPF_JMP32_IMM(jmp.into(), reg.into(), imm, off) }
    }

    pub fn exit() -> bpf_insn {
        unsafe { _BPF_EXIT_INSN() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

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
