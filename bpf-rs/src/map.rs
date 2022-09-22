// HACK: The reason we have to do this hack is because of
// https://github.com/Peternator7/strum/issues/237
// strum generates a struct that by defaults propagates the same visibility
// as the original enum. We don't want that and it isn't configurable so we
// wrap it in a private module and re-export what we want public.
mod private_hack {
    use libbpf_sys::libbpf_probe_bpf_map_type;
    use num_enum::{IntoPrimitive, TryFromPrimitive};
    use std::{ffi::CStr, fmt::Debug, ptr};
    use strum_macros::EnumIter;

    use crate::{error::{self, Errno}, StaticName};

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
        pub fn probe(&self) -> Result<bool, Errno> {
            match error::from_libbpf_errno(unsafe {
                libbpf_probe_bpf_map_type((*self).into(), ptr::null())
            })? {
                0 => Ok(false),
                1 => Ok(true),
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
}

pub use private_hack::MapType;

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
