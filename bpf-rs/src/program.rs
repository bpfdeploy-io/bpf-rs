use libbpf_sys::{libbpf_bpf_prog_type_str, libbpf_probe_bpf_helper, libbpf_probe_bpf_prog_type};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{ffi::CStr, os::raw, ptr, time::Duration};
use strum_macros::EnumIter;

use crate::{BpfHelper, Error, StaticName};

use bpf_rs_macros::Display;
#[cfg(feature = "serde")]
use bpf_rs_macros::SerializeFromDisplay;

#[non_exhaustive]
#[repr(u32)]
#[derive(
    Debug, Display, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash, EnumIter,
)]
#[cfg_attr(feature = "serde", derive(SerializeFromDisplay))]
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
        match unsafe { libbpf_probe_bpf_helper((*self).into(), helper.into(), ptr::null()) } {
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
        let mut iter = <Self as strum::IntoEnumIterator>::iter();
        iter.next(); // Skip Unspec
        iter
    }
}

impl StaticName for ProgramType {
    /// A human-readable name of the eBPF program type.
    fn name(&self) -> &'static str {
        let name_ptr = unsafe { libbpf_bpf_prog_type_str((*self).into()) };
        if name_ptr.is_null() {
            panic!("Program type enum value not understood by libbpf_bpf_prog_type_str");
        }

        match unsafe { CStr::from_ptr(name_ptr) }.to_str() {
            Ok(name_str) => name_str,
            Err(err) => panic!("Program type name has invalid utf8 character: {}", err),
        }
    }
}

/// eBPF program object info. Similar to (but not the same) kernel header's
/// [struct bpf_prog_info](https://github.com/torvalds/linux/blob/672c0c5173427e6b3e2a9bbb7be51ceeec78093a/include/uapi/linux/bpf.h#L5840)
#[derive(Debug)]
#[repr(C)]
pub struct ProgramInfo {
    /// Name of eBPF program
    ///
    /// **Note**: This is usually set on program load but is not required so it may be an
    /// empty string.
    pub name: String,
    /// Each eBPF program has a unique program type that determines its functionality and
    /// available features, such as helper functions.
    ///
    /// For more information, see [Marsden's blog post](https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types).
    pub ty: ProgramType,
    /// A SHA hash over the eBPF program instructions which can be used to
    /// correlate back to the original object file
    ///
    /// Multiple eBPF programs may share the same xlated instructions and therefore
    /// may have the same hashes so these are not guaranteed to be unique to each
    /// eBPF program. For that, you may want to use [`ProgramInfo::id`].
    pub tag: [u8; 8],
    /// A unique identifier for the eBPF program
    ///
    /// Unique here meaning since the boot time of the machine. The counter used
    /// to generate these identifiers resets back to 0 to reboot and the identifiers
    /// are reused.
    pub id: u32,
    /// The amount of instructions that were JIT-ed.
    ///
    /// This is useful when attempting to dump the JIT code of the program to
    /// pre-allocate the needed memory to write the instructions to.
    pub jited_prog_len: u32,
    /// The amount of instructions that were interpreted (post-translation by the verifier)
    ///
    /// This is useful when attempting to dump the xlated code of the program to
    /// pre-allocate the needed memory to write the instructions to.
    pub xlated_prog_len: u32,
    // REFACTOR: Should be a Rust pointer
    /// A u64-encoded pointer to the memory region containing JIT-ed instructions.
    pub jited_prog_insns: u64,
    // REFACTOR: Should be a Rust pointer
    /// A u64-encoded pointer to the memory region contained Xlated instructions.
    pub xlated_prog_insns: u64,
    pub load_time: Duration,
    /// User id of the creator of the program
    pub created_by_uid: u32,
    /// The count of maps currently used by the program
    pub nr_map_ids: u32,
    // TODO: Should be a Rust pointer
    /// A u64-encoded pointer to the memory region containing ids to maps used by the program.
    pub map_ids: u64,
    pub ifindex: u32,
    /// If the eBPF program has a GPL compatible license
    ///
    /// If the eBPF program has a proprietary license, then some features such
    /// as helper functions or even ability to create certain program types are not
    /// available.
    ///
    /// For more information, see the [kernel docs](https://www.kernel.org/doc/html/latest/bpf/bpf_licensing.html).
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

#[cfg(test)]
mod tests {
    use crate::{ProgramLicense, ProgramType};

    #[test]
    fn test_program_type() {
        assert_eq!(
            u32::from(ProgramType::Syscall),
            libbpf_sys::BPF_PROG_TYPE_SYSCALL
        );

        ProgramType::iter().for_each(|ty| {
            assert!(!format!("{}", ty).is_empty());
        });

        // Confirm that the first in ProgramType::iter() is NOT unspec
        assert_ne!(ProgramType::iter().next().unwrap(), ProgramType::Unspec);
    }

    #[test]
    fn test_program_license_ptr() {
        assert!(!ProgramLicense::GPL.as_ptr().is_null());
    }
}
