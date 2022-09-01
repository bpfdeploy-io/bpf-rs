use libbpf_sys::libbpf_probe_bpf_map_type;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{ffi::CStr, fmt::Debug, ptr};
use strum_macros::EnumIter;

use crate::{Error, StaticName};

use bpf_rs_macros::Display;
#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;

/// eBPF map type variants. Based off of [kernel header's](https://github.com/torvalds/linux/blob/b253435746d9a4a701b5f09211b9c14d3370d0da/include/uapi/linux/bpf.h#L880)
/// `enum bpf_map_type`
#[non_exhaustive]
#[repr(u32)]
#[derive(
    Debug, Display, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash, EnumIter,
)]
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
        let mut iter = <Self as strum::IntoEnumIterator>::iter();
        iter.next(); // Skip Unspec
        iter
    }
}

impl StaticName for MapType {
    /// A human-readable name of the eBPF map type.
    fn name(&self) -> &'static str {
        let name_ptr = unsafe { libbpf_sys::libbpf_bpf_map_type_str((*self).into()) };
        if name_ptr.is_null() {
            panic!("Map type enum value unknown to libbpf");
        }

        unsafe { CStr::from_ptr(name_ptr) }
            .to_str()
            .expect("Map type name has invalid utf8")
    }
}

#[cfg(test)]
mod tests {
    use crate::MapType;

    #[test]
    fn test_map_type() {
        assert_eq!(
            u32::from(MapType::BloomFilter),
            libbpf_sys::BPF_MAP_TYPE_BLOOM_FILTER
        );

        MapType::iter().for_each(|ty| assert!(!format!("{}", ty).is_empty()));

        // Confirm that the first in MapType::iter() is NOT unspec
        assert_ne!(MapType::iter().next().unwrap(), MapType::Unspec);
    }
}
