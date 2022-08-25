use bpf_rs_macros::Display;
#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;

use crate::{Error, StaticName};
use libbpf_sys::libbpf_probe_bpf_map_type;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{fmt::Debug, ptr};

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
