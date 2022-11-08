// HACK: The reason we have to do this hack is because of
// https://github.com/Peternator7/strum/issues/237
// strum generates a struct that by defaults propagates the same visibility
// as the original enum. We don't want that and it isn't configurable so we
// wrap it in a private module and re-export what we want public.
// Is this still the case?
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

use bitflags::bitflags;

#[cfg(feature = "serde")]
use serde::Serialize;

bitflags! {
    /// These flags are currently only related to cgroup attachment types, but
    /// that may change in the future: [Kernel src](https://github.com/torvalds/linux/blob/59f2f4b8a757412fce372f6d0767bdb55da127a8/include/uapi/linux/bpf.h#L1092)
    pub struct AttachFlags: std::os::raw::c_uint {
        const NONE = 0;
        const ALLOW_OVERRIDE = 1 << 0;
        const ALLOW_MULTI = 1 << 1;
        const REPLACE = 1 << 2;
    }
}

// TODO: This should eventually be replaced in bitflags v2?:
// Link: https://github.com/bitflags/bitflags/issues/262#issuecomment-1271229962
#[cfg(feature = "serde")]
impl Serialize for AttachFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut seq = serializer.serialize_seq(None)?;
        if !self.is_empty() {
            if self.contains(AttachFlags::ALLOW_OVERRIDE) {
                seq.serialize_element("ALLOW_OVERRIDE")?;
            }
            if self.contains(AttachFlags::ALLOW_MULTI) {
                seq.serialize_element("ALLOW_MULTI")?;
            }
            if self.contains(AttachFlags::REPLACE) {
                seq.serialize_element("REPLACE")?;
            }
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::AttachType;

    #[test]
    fn test_attach_types() {
        assert_eq!(
            u32::from(AttachType::LsmCgroup) + 1,
            libbpf_sys::__MAX_BPF_ATTACH_TYPE
        );

        AttachType::iter().for_each(|ty| assert!(!format!("{}", ty).is_empty()))
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_attach_flags_serialization() {
        use super::AttachFlags;
        use serde_test::{assert_ser_tokens, Token};

        let flags = AttachFlags::ALLOW_OVERRIDE | AttachFlags::REPLACE;
        assert_ser_tokens(
            &flags,
            &[
                Token::Seq { len: None },
                Token::String("ALLOW_OVERRIDE"),
                Token::String("REPLACE"),
                Token::SeqEnd,
            ],
        );

        let flags = AttachFlags::NONE;
        assert_ser_tokens(&flags, &[Token::Seq { len: None }, Token::SeqEnd]);

        let flags = AttachFlags::empty();
        assert_ser_tokens(&flags, &[Token::Seq { len: None }, Token::SeqEnd]);

        let flags = AttachFlags::all();
        assert_ser_tokens(
            &flags,
            &[
                Token::Seq { len: None },
                Token::String("ALLOW_OVERRIDE"),
                Token::String("ALLOW_MULTI"),
                Token::String("REPLACE"),
                Token::SeqEnd,
            ],
        );
    }
}
