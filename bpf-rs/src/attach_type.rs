// HACK: The reason we have to do this hack is because of
// https://github.com/Peternator7/strum/issues/237
// strum generates a struct that by defaults propagates the same visibility
// as the original enum. We don't want that and it isn't configurable so we
// wrap it in a private module and re-export what we want public.
mod private_hack {
    use num_enum::{IntoPrimitive, TryFromPrimitive};
    use std::ffi::CStr;
    use strum_macros::EnumIter;

    use bpf_rs_macros::Display;
    #[cfg(feature = "serde")]
    use bpf_rs_macros::SerializeFromDisplay;

    use crate::StaticName;

    #[non_exhaustive]
    #[repr(u32)]
    #[derive(
        Clone, TryFromPrimitive, IntoPrimitive, Copy, Debug, Display, EnumIter, Hash, Eq, PartialEq,
    )]
    #[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
    pub enum AttachType {
        CgroupInetIngress,
        CgroupInetEgress,
        CgroupInetSockCreate,
        CgroupSockOps,
        SkSkbStreamParser,
        SkSkbStreamVerdict,
        CgroupDevice,
        SkMsgVerdict,
        CgroupInet4Bind,
        CgroupInet6Bind,
        CgroupInet4Connect,
        CgroupInet6Connect,
        CgroupInet4PostBind,
        CgroupInet6PostBind,
        CgroupUdp4Sendmsg,
        CgroupUdp6Sendmsg,
        LircMode2,
        FlowDissector,
        CgroupSysctl,
        CgroupUdp4Recvmsg,
        CgroupUdp6Recvmsg,
        CgroupGetsockopt,
        CgroupSetsockopt,
        TraceRawTp,
        TraceFentry,
        TraceFexit,
        ModifyReturn,
        LsmMac,
        TraceIter,
        CgroupInet4Getpeername,
        CgroupInet6Getpeername,
        CgroupInet4Getsockname,
        CgroupInet6Getsockname,
        XdpDevmap,
        CgroupInetSockRelease,
        XdpCpumap,
        SkLookup,
        Xdp,
        SkSkbVerdict,
        SkReuseportSelect,
        SkReuseportSelectOrMigrate,
        PerfEvent,
        TraceKprobeMulti,
        LsmCgroup,
    }

    impl AttachType {
        pub fn iter() -> impl Iterator<Item = AttachType> {
            // To prevent having library users need to import this trait
            <Self as strum::IntoEnumIterator>::iter()
        }
    }

    impl StaticName for AttachType {
        /// A human-readable name of the eBPF program attachment type.
        fn name(&self) -> &'static str {
            let attach_type_ptr = unsafe { libbpf_sys::libbpf_bpf_attach_type_str((*self).into()) };
            if attach_type_ptr.is_null() {
                panic!("Use of attachment type enum value that current version of libbpf does not understand");
            }

            unsafe { CStr::from_ptr(attach_type_ptr) }
                .to_str()
                .expect("Invalid utf8 error in attachment type name: {}")
        }
    }
}

pub use private_hack::AttachType;

#[cfg(test)]
mod tests {
    use crate::attach_type::AttachType;

    #[test]
    fn test_attach_types() {
        assert_eq!(
            u32::from(AttachType::LsmCgroup) + 1,
            libbpf_sys::__MAX_BPF_ATTACH_TYPE
        );

        AttachType::iter().for_each(|ty| assert!(!format!("{}", ty).is_empty()))
    }
}
