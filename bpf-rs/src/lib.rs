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
pub mod insns;
mod program;

use bpf_rs_macros::Display;
#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;

use libbpf_sys::{libbpf_probe_bpf_map_type, __BPF_FUNC_MAX_ID};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{fmt::Debug, ptr};
use thiserror::Error as ThisError;

// Re-exports
pub use libbpf_sys;
pub use program::{ProgramInfo, ProgramLicense, ProgramType};

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

/// eBPF map type variants. Based off of [kernel header's](https://github.com/torvalds/linux/blob/b253435746d9a4a701b5f09211b9c14d3370d0da/include/uapi/linux/bpf.h#L880)
/// `enum bpf_map_type`
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Display, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
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

impl StaticName for MapType {
    /// Based off of bpftool's
    /// [`map_type_name`](https://github.com/libbpf/bpftool/blob/9443d42430017ed2d04d7ab411131525ced62d6a/src/map.c#L25),
    /// returns a human-readable name of the eBPF map type.
    fn name(&self) -> &'static str {
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
}

struct MapTypeIter(u32);

impl Iterator for MapTypeIter {
    type Item = MapType;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0;
        if next > MapType::BloomFilter.into() {
            None
        } else {
            self.0 += 1;
            MapType::try_from_primitive(next).ok()
        }
    }
}

/// eBPF helper functions. See [`bpf-helpers(7)`](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
///
/// The enum value represents the unique id reserved by the kernel to represent the helper function. This
/// unique id works almost as a counter with a max value:
/// [`__BPF_FUNC_MAX_ID`](https://github.com/torvalds/linux/blob/672c0c5173427e6b3e2a9bbb7be51ceeec78093a/include/uapi/linux/bpf.h#L5350).
/// This max limit changes between kernel versions due to the addition of eBPF helper functions.
///
/// For more information on eBPF helper functions, check out (although slightly outdated)
/// [Marsden's Oracle blog post](https://blogs.oracle.com/linux/post/bpf-in-depth-bpf-helper-functions).
#[non_exhaustive]
#[repr(u32)]
#[derive(Display, Debug, Copy, Clone, Hash, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
pub enum BpfHelper {
    Unspec = 0,
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    ProbeRead = 4,
    KtimeGetNs = 5,
    TracePrintk = 6,
    GetPrandomU32 = 7,
    GetSmpProcessorId = 8,
    SkbStoreBytes = 9,
    L3CsumReplace = 10,
    L4CsumReplace = 11,
    TailCall = 12,
    CloneRedirect = 13,
    GetCurrentPidTgid = 14,
    GetCurrentUidGid = 15,
    GetCurrentComm = 16,
    GetCgroupClassid = 17,
    SkbVlanPush = 18,
    SkbVlanPop = 19,
    SkbGetTunnelKey = 20,
    SkbSetTunnelKey = 21,
    PerfEventRead = 22,
    Redirect = 23,
    GetRouteRealm = 24,
    PerfEventOutput = 25,
    SkbLoadBytes = 26,
    GetStackid = 27,
    CsumDiff = 28,
    SkbGetTunnelOpt = 29,
    SkbSetTunnelOpt = 30,
    SkbChangeProto = 31,
    SkbChangeType = 32,
    SkbUnderCgroup = 33,
    GetHashRecalc = 34,
    GetCurrentTask = 35,
    ProbeWriteUser = 36,
    CurrentTaskUnderCgroup = 37,
    SkbChangeTail = 38,
    SkbPullData = 39,
    CsumUpdate = 40,
    SetHashInvalid = 41,
    GetNumaNodeId = 42,
    SkbChangeHead = 43,
    XdpAdjustHead = 44,
    ProbeReadStr = 45,
    GetSocketCookie = 46,
    GetSocketUid = 47,
    SetHash = 48,
    Setsockopt = 49,
    SkbAdjustRoom = 50,
    RedirectMap = 51,
    SkRedirectMap = 52,
    SockMapUpdate = 53,
    XdpAdjustMeta = 54,
    PerfEventReadValue = 55,
    PerfProgReadValue = 56,
    Getsockopt = 57,
    OverrideReturn = 58,
    SockOpsCbFlagsSet = 59,
    MsgRedirectMap = 60,
    MsgApplyBytes = 61,
    MsgCorkBytes = 62,
    MsgPullData = 63,
    Bind = 64,
    XdpAdjustTail = 65,
    SkbGetXfrmState = 66,
    GetStack = 67,
    SkbLoadBytesRelative = 68,
    FibLookup = 69,
    SockHashUpdate = 70,
    MsgRedirectHash = 71,
    SkRedirectHash = 72,
    LwtPushEncap = 73,
    LwtSeg6StoreBytes = 74,
    LwtSeg6AdjustSrh = 75,
    LwtSeg6Action = 76,
    RcRepeat = 77,
    RcKeydown = 78,
    SkbCgroupId = 79,
    GetCurrentCgroupId = 80,
    GetLocalStorage = 81,
    SkSelectReuseport = 82,
    SkbAncestorCgroupId = 83,
    SkLookupTcp = 84,
    SkLookupUdp = 85,
    SkRelease = 86,
    MapPushElem = 87,
    MapPopElem = 88,
    MapPeekElem = 89,
    MsgPushData = 90,
    MsgPopData = 91,
    RcPointerRel = 92,
    SpinLock = 93,
    SpinUnlock = 94,
    SkFullsock = 95,
    TcpSock = 96,
    SkbEcnSetCe = 97,
    GetListenerSock = 98,
    SkcLookupTcp = 99,
    TcpCheckSyncookie = 100,
    SysctlGetName = 101,
    SysctlGetCurrentValue = 102,
    SysctlGetNewValue = 103,
    SysctlSetNewValue = 104,
    Strtol = 105,
    Strtoul = 106,
    SkStorageGet = 107,
    SkStorageDelete = 108,
    SendSignal = 109,
    TcpGenSyncookie = 110,
    SkbOutput = 111,
    ProbeReadUser = 112,
    ProbeReadKernel = 113,
    ProbeReadUserStr = 114,
    ProbeReadKernelStr = 115,
    TcpSendAck = 116,
    SendSignalThread = 117,
    Jiffies64 = 118,
    ReadBranchRecords = 119,
    GetNsCurrentPidTgid = 120,
    XdpOutput = 121,
    GetNetnsCookie = 122,
    GetCurrentAncestorCgroupId = 123,
    SkAssign = 124,
    KtimeGetBootNs = 125,
    SeqPrintf = 126,
    SeqWrite = 127,
    SkCgroupId = 128,
    SkAncestorCgroupId = 129,
    RingbufOutput = 130,
    RingbufReserve = 131,
    RingbufSubmit = 132,
    RingbufDiscard = 133,
    RingbufQuery = 134,
    CsumLevel = 135,
    SkcToTcp6Sock = 136,
    SkcToTcpSock = 137,
    SkcToTcpTimewaitSock = 138,
    SkcToTcpRequestSock = 139,
    SkcToUdp6Sock = 140,
    GetTaskStack = 141,
    LoadHdrOpt = 142,
    StoreHdrOpt = 143,
    ReserveHdrOpt = 144,
    InodeStorageGet = 145,
    InodeStorageDelete = 146,
    DPath = 147,
    CopyFromUser = 148,
    SnprintfBtf = 149,
    SeqPrintfBtf = 150,
    SkbCgroupClassid = 151,
    RedirectNeigh = 152,
    PerCpuPtr = 153,
    ThisCpuPtr = 154,
    RedirectPeer = 155,
    TaskStorageGet = 156,
    TaskStorageDelete = 157,
    GetCurrentTaskBtf = 158,
    BprmOptsSet = 159,
    KtimeGetCoarseNs = 160,
    ImaInodeHash = 161,
    SockFromFile = 162,
    CheckMtu = 163,
    ForEachMapElem = 164,
    Snprintf = 165,
    SysBpf = 166,
    BtfFindByNameKind = 167,
    SysClose = 168,
    TimerInit = 169,
    TimerSetCallback = 170,
    TimerStart = 171,
    TimerCancel = 172,
    GetFuncIp = 173,
    GetAttachCookie = 174,
    TaskPtRegs = 175,
    GetBranchSnapshot = 176,
    TraceVprintk = 177,
    SkcToUnixSock = 178,
    KallsymsLookupName = 179,
    FindVma = 180,
    Loop = 181,
    Strncmp = 182,
    GetFuncArg = 183,
    GetFuncRet = 184,
    GetFuncArgCnt = 185,
    GetRetval = 186,
    SetRetval = 187,
    XdpGetBuffLen = 188,
    XdpLoadBytes = 189,
    XdpStoreBytes = 190,
    CopyFromUserTask = 191,
    SkbSetTstamp = 192,
    ImaFileHash = 193,
    KptrXchg = 194,
    MapLookupPercpuElem = 195,
}

impl StaticName for BpfHelper {
    fn name(&self) -> &'static str {
        match *self {
            BpfHelper::Unspec => "bpf_unspec",
            BpfHelper::MapLookupElem => "bpf_map_lookup_elem",
            BpfHelper::MapUpdateElem => "bpf_map_update_elem",
            BpfHelper::MapDeleteElem => "bpf_map_delete_elem",
            BpfHelper::ProbeRead => "bpf_probe_read",
            BpfHelper::KtimeGetNs => "bpf_ktime_get_ns",
            BpfHelper::TracePrintk => "bpf_trace_printk",
            BpfHelper::GetPrandomU32 => "bpf_get_prandom_u32",
            BpfHelper::GetSmpProcessorId => "bpf_get_smp_processor_id",
            BpfHelper::SkbStoreBytes => "bpf_skb_store_bytes",
            BpfHelper::L3CsumReplace => "bpf_l3_csum_replace",
            BpfHelper::L4CsumReplace => "bpf_l4_csum_replace",
            BpfHelper::TailCall => "bpf_tail_call",
            BpfHelper::CloneRedirect => "bpf_clone_redirect",
            BpfHelper::GetCurrentPidTgid => "bpf_get_current_pid_tgid",
            BpfHelper::GetCurrentUidGid => "bpf_get_current_uid_gid",
            BpfHelper::GetCurrentComm => "bpf_get_current_comm",
            BpfHelper::GetCgroupClassid => "bpf_get_cgroup_classid",
            BpfHelper::SkbVlanPush => "bpf_skb_vlan_push",
            BpfHelper::SkbVlanPop => "bpf_skb_vlan_pop",
            BpfHelper::SkbGetTunnelKey => "bpf_skb_get_tunnel_key",
            BpfHelper::SkbSetTunnelKey => "bpf_skb_set_tunnel_key",
            BpfHelper::PerfEventRead => "bpf_perf_event_read",
            BpfHelper::Redirect => "bpf_redirect",
            BpfHelper::GetRouteRealm => "bpf_get_route_realm",
            BpfHelper::PerfEventOutput => "bpf_perf_event_output",
            BpfHelper::SkbLoadBytes => "bpf_skb_load_bytes",
            BpfHelper::GetStackid => "bpf_get_stackid",
            BpfHelper::CsumDiff => "bpf_csum_diff",
            BpfHelper::SkbGetTunnelOpt => "bpf_skb_get_tunnel_opt",
            BpfHelper::SkbSetTunnelOpt => "bpf_skb_set_tunnel_opt",
            BpfHelper::SkbChangeProto => "bpf_skb_change_proto",
            BpfHelper::SkbChangeType => "bpf_skb_change_type",
            BpfHelper::SkbUnderCgroup => "bpf_skb_under_cgroup",
            BpfHelper::GetHashRecalc => "bpf_get_hash_recalc",
            BpfHelper::GetCurrentTask => "bpf_get_current_task",
            BpfHelper::ProbeWriteUser => "bpf_probe_write_user",
            BpfHelper::CurrentTaskUnderCgroup => "bpf_current_task_under_cgroup",
            BpfHelper::SkbChangeTail => "bpf_skb_change_tail",
            BpfHelper::SkbPullData => "bpf_skb_pull_data",
            BpfHelper::CsumUpdate => "bpf_csum_update",
            BpfHelper::SetHashInvalid => "bpf_set_hash_invalid",
            BpfHelper::GetNumaNodeId => "bpf_get_numa_node_id",
            BpfHelper::SkbChangeHead => "bpf_skb_change_head",
            BpfHelper::XdpAdjustHead => "bpf_xdp_adjust_head",
            BpfHelper::ProbeReadStr => "bpf_probe_read_str",
            BpfHelper::GetSocketCookie => "bpf_get_socket_cookie",
            BpfHelper::GetSocketUid => "bpf_get_socket_uid",
            BpfHelper::SetHash => "bpf_set_hash",
            BpfHelper::Setsockopt => "bpf_setsockopt",
            BpfHelper::SkbAdjustRoom => "bpf_skb_adjust_room",
            BpfHelper::RedirectMap => "bpf_redirect_map",
            BpfHelper::SkRedirectMap => "bpf_sk_redirect_map",
            BpfHelper::SockMapUpdate => "bpf_sock_map_update",
            BpfHelper::XdpAdjustMeta => "bpf_xdp_adjust_meta",
            BpfHelper::PerfEventReadValue => "bpf_perf_event_read_value",
            BpfHelper::PerfProgReadValue => "bpf_perf_prog_read_value",
            BpfHelper::Getsockopt => "bpf_getsockopt",
            BpfHelper::OverrideReturn => "bpf_override_return",
            BpfHelper::SockOpsCbFlagsSet => "bpf_sock_ops_cb_flags_set",
            BpfHelper::MsgRedirectMap => "bpf_msg_redirect_map",
            BpfHelper::MsgApplyBytes => "bpf_msg_apply_bytes",
            BpfHelper::MsgCorkBytes => "bpf_msg_cork_bytes",
            BpfHelper::MsgPullData => "bpf_msg_pull_data",
            BpfHelper::Bind => "bpf_bind",
            BpfHelper::XdpAdjustTail => "bpf_xdp_adjust_tail",
            BpfHelper::SkbGetXfrmState => "bpf_skb_get_xfrm_state",
            BpfHelper::GetStack => "bpf_get_stack",
            BpfHelper::SkbLoadBytesRelative => "bpf_skb_load_bytes_relative",
            BpfHelper::FibLookup => "bpf_fib_lookup",
            BpfHelper::SockHashUpdate => "bpf_sock_hash_update",
            BpfHelper::MsgRedirectHash => "bpf_msg_redirect_hash",
            BpfHelper::SkRedirectHash => "bpf_sk_redirect_hash",
            BpfHelper::LwtPushEncap => "bpf_lwt_push_encap",
            BpfHelper::LwtSeg6StoreBytes => "bpf_lwt_seg6_store_bytes",
            BpfHelper::LwtSeg6AdjustSrh => "bpf_lwt_seg6_adjust_srh",
            BpfHelper::LwtSeg6Action => "bpf_lwt_seg6_action",
            BpfHelper::RcRepeat => "bpf_rc_repeat",
            BpfHelper::RcKeydown => "bpf_rc_keydown",
            BpfHelper::SkbCgroupId => "bpf_skb_cgroup_id",
            BpfHelper::GetCurrentCgroupId => "bpf_get_current_cgroup_id",
            BpfHelper::GetLocalStorage => "bpf_get_local_storage",
            BpfHelper::SkSelectReuseport => "bpf_sk_select_reuseport",
            BpfHelper::SkbAncestorCgroupId => "bpf_skb_ancestor_cgroup_id",
            BpfHelper::SkLookupTcp => "bpf_sk_lookup_tcp",
            BpfHelper::SkLookupUdp => "bpf_sk_lookup_udp",
            BpfHelper::SkRelease => "bpf_sk_release",
            BpfHelper::MapPushElem => "bpf_map_push_elem",
            BpfHelper::MapPopElem => "bpf_map_pop_elem",
            BpfHelper::MapPeekElem => "bpf_map_peek_elem",
            BpfHelper::MsgPushData => "bpf_msg_push_data",
            BpfHelper::MsgPopData => "bpf_msg_pop_data",
            BpfHelper::RcPointerRel => "bpf_rc_pointer_rel",
            BpfHelper::SpinLock => "bpf_spin_lock",
            BpfHelper::SpinUnlock => "bpf_spin_unlock",
            BpfHelper::SkFullsock => "bpf_sk_fullsock",
            BpfHelper::TcpSock => "bpf_tcp_sock",
            BpfHelper::SkbEcnSetCe => "bpf_skb_ecn_set_ce",
            BpfHelper::GetListenerSock => "bpf_get_listener_sock",
            BpfHelper::SkcLookupTcp => "bpf_skc_lookup_tcp",
            BpfHelper::TcpCheckSyncookie => "bpf_tcp_check_syncookie",
            BpfHelper::SysctlGetName => "bpf_sysctl_get_name",
            BpfHelper::SysctlGetCurrentValue => "bpf_sysctl_get_current_value",
            BpfHelper::SysctlGetNewValue => "bpf_sysctl_get_new_value",
            BpfHelper::SysctlSetNewValue => "bpf_sysctl_set_new_value",
            BpfHelper::Strtol => "bpf_strtol",
            BpfHelper::Strtoul => "bpf_strtoul",
            BpfHelper::SkStorageGet => "bpf_sk_storage_get",
            BpfHelper::SkStorageDelete => "bpf_sk_storage_delete",
            BpfHelper::SendSignal => "bpf_send_signal",
            BpfHelper::TcpGenSyncookie => "bpf_tcp_gen_syncookie",
            BpfHelper::SkbOutput => "bpf_skb_output",
            BpfHelper::ProbeReadUser => "bpf_probe_read_user",
            BpfHelper::ProbeReadKernel => "bpf_probe_read_kernel",
            BpfHelper::ProbeReadUserStr => "bpf_probe_read_user_str",
            BpfHelper::ProbeReadKernelStr => "bpf_probe_read_kernel_str",
            BpfHelper::TcpSendAck => "bpf_tcp_send_ack",
            BpfHelper::SendSignalThread => "bpf_send_signal_thread",
            BpfHelper::Jiffies64 => "bpf_jiffies64",
            BpfHelper::ReadBranchRecords => "bpf_read_branch_records",
            BpfHelper::GetNsCurrentPidTgid => "bpf_get_ns_current_pid_tgid",
            BpfHelper::XdpOutput => "bpf_xdp_output",
            BpfHelper::GetNetnsCookie => "bpf_get_netns_cookie",
            BpfHelper::GetCurrentAncestorCgroupId => "bpf_get_current_ancestor_cgroup_id",
            BpfHelper::SkAssign => "bpf_sk_assign",
            BpfHelper::KtimeGetBootNs => "bpf_ktime_get_boot_ns",
            BpfHelper::SeqPrintf => "bpf_seq_printf",
            BpfHelper::SeqWrite => "bpf_seq_write",
            BpfHelper::SkCgroupId => "bpf_sk_cgroup_id",
            BpfHelper::SkAncestorCgroupId => "bpf_sk_ancestor_cgroup_id",
            BpfHelper::RingbufOutput => "bpf_ringbuf_output",
            BpfHelper::RingbufReserve => "bpf_ringbuf_reserve",
            BpfHelper::RingbufSubmit => "bpf_ringbuf_submit",
            BpfHelper::RingbufDiscard => "bpf_ringbuf_discard",
            BpfHelper::RingbufQuery => "bpf_ringbuf_query",
            BpfHelper::CsumLevel => "bpf_csum_level",
            BpfHelper::SkcToTcp6Sock => "bpf_skc_to_tcp6_sock",
            BpfHelper::SkcToTcpSock => "bpf_skc_to_tcp_sock",
            BpfHelper::SkcToTcpTimewaitSock => "bpf_skc_to_tcp_timewait_sock",
            BpfHelper::SkcToTcpRequestSock => "bpf_skc_to_tcp_request_sock",
            BpfHelper::SkcToUdp6Sock => "bpf_skc_to_udp6_sock",
            BpfHelper::GetTaskStack => "bpf_get_task_stack",
            BpfHelper::LoadHdrOpt => "bpf_load_hdr_opt",
            BpfHelper::StoreHdrOpt => "bpf_store_hdr_opt",
            BpfHelper::ReserveHdrOpt => "bpf_reserve_hdr_opt",
            BpfHelper::InodeStorageGet => "bpf_inode_storage_get",
            BpfHelper::InodeStorageDelete => "bpf_inode_storage_delete",
            BpfHelper::DPath => "bpf_d_path",
            BpfHelper::CopyFromUser => "bpf_copy_from_user",
            BpfHelper::SnprintfBtf => "bpf_snprintf_btf",
            BpfHelper::SeqPrintfBtf => "bpf_seq_printf_btf",
            BpfHelper::SkbCgroupClassid => "bpf_skb_cgroup_classid",
            BpfHelper::RedirectNeigh => "bpf_redirect_neigh",
            BpfHelper::PerCpuPtr => "bpf_per_cpu_ptr",
            BpfHelper::ThisCpuPtr => "bpf_this_cpu_ptr",
            BpfHelper::RedirectPeer => "bpf_redirect_peer",
            BpfHelper::TaskStorageGet => "bpf_task_storage_get",
            BpfHelper::TaskStorageDelete => "bpf_task_storage_delete",
            BpfHelper::GetCurrentTaskBtf => "bpf_get_current_task_btf",
            BpfHelper::BprmOptsSet => "bpf_bprm_opts_set",
            BpfHelper::KtimeGetCoarseNs => "bpf_ktime_get_coarse_ns",
            BpfHelper::ImaInodeHash => "bpf_ima_inode_hash",
            BpfHelper::SockFromFile => "bpf_sock_from_file",
            BpfHelper::CheckMtu => "bpf_check_mtu",
            BpfHelper::ForEachMapElem => "bpf_for_each_map_elem",
            BpfHelper::Snprintf => "bpf_snprintf",
            BpfHelper::SysBpf => "bpf_sys_bpf",
            BpfHelper::BtfFindByNameKind => "bpf_btf_find_by_name_kind",
            BpfHelper::SysClose => "bpf_sys_close",
            BpfHelper::TimerInit => "bpf_timer_init",
            BpfHelper::TimerSetCallback => "bpf_timer_set_callback",
            BpfHelper::TimerStart => "bpf_timer_start",
            BpfHelper::TimerCancel => "bpf_timer_cancel",
            BpfHelper::GetFuncIp => "bpf_get_func_ip",
            BpfHelper::GetAttachCookie => "bpf_get_attach_cookie",
            BpfHelper::TaskPtRegs => "bpf_task_pt_regs",
            BpfHelper::GetBranchSnapshot => "bpf_get_branch_snapshot",
            BpfHelper::TraceVprintk => "bpf_trace_vprintk",
            BpfHelper::SkcToUnixSock => "bpf_skc_to_unix_sock",
            BpfHelper::KallsymsLookupName => "bpf_kallsyms_lookup_name",
            BpfHelper::FindVma => "bpf_find_vma",
            BpfHelper::Loop => "bpf_loop",
            BpfHelper::Strncmp => "bpf_strncmp",
            BpfHelper::GetFuncArg => "bpf_get_func_arg",
            BpfHelper::GetFuncRet => "bpf_get_func_ret",
            BpfHelper::GetFuncArgCnt => "bpf_get_func_arg_cnt",
            BpfHelper::GetRetval => "bpf_get_retval",
            BpfHelper::SetRetval => "bpf_set_retval",
            BpfHelper::XdpGetBuffLen => "bpf_xdp_get_buff_len",
            BpfHelper::XdpLoadBytes => "bpf_xdp_load_bytes",
            BpfHelper::XdpStoreBytes => "bpf_xdp_store_bytes",
            BpfHelper::CopyFromUserTask => "bpf_copy_from_user_task",
            BpfHelper::SkbSetTstamp => "bpf_skb_set_tstamp",
            BpfHelper::ImaFileHash => "bpf_ima_file_hash",
            BpfHelper::KptrXchg => "bpf_kptr_xchg",
            BpfHelper::MapLookupPercpuElem => "bpf_map_lookup_percpu_elem",
        }
    }
}

/// Iterator for the eBPF helper functions
pub struct BpfHelperIter(u32);

impl BpfHelperIter {
    /// Creates an ordered iterator
    ///
    /// Order here is based on the ascending int ids used to represent the helper
    /// functions within the kernel. For most cases, this ordering property isn't
    /// needed.
    ///
    /// **Note**: Skips `unspec` helper since it's an invalid function
    pub fn new() -> Self {
        Self(1)
    }
}

impl Default for BpfHelperIter {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for BpfHelperIter {
    type Item = BpfHelper;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0;
        if next >= __BPF_FUNC_MAX_ID {
            None
        } else {
            self.0 += 1;
            BpfHelper::try_from_primitive(next).ok()
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

        let invalid_helper = BpfHelper::try_from(__BPF_FUNC_MAX_ID);
        assert!(invalid_helper.is_err());
    }

    #[test]
    fn program_license_ptr() {
        assert!(!ProgramLicense::GPL.as_ptr().is_null());
    }
}
