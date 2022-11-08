//! For a given kernel object (such as a cgroup, network name or device file) that we can
//! obtain a user fd to, we can query for its attached programs, either by [attach_type::AttachType]
//! or all of them (which iterates over all of [attach_type::AttachType])
use bitflags::bitflags;
use std::{collections::HashMap, os::unix::prelude::*, ptr};

use crate::{
    attach_type::{self, AttachFlags},
    error::{self, Errno},
    BpfProgramId,
};

bitflags! {
    pub struct QueryFlags: std::os::raw::c_uint {
        const NONE = 0;
        const EFFECTIVE = 1 << 0;
    }
}

pub struct KernelDescriptor<'a>(pub BorrowedFd<'a>);

impl KernelDescriptor<'_> {
    fn query_opts(
        query_flags: QueryFlags,
        attach_flags: u32,
        program_count: u32,
        program_ids: &mut Vec<BpfProgramId>,
    ) -> libbpf_sys::bpf_prog_query_opts {
        libbpf_sys::bpf_prog_query_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_prog_query_opts>()
                .try_into()
                .expect("Failed to convert usize into u64"),
            query_flags: query_flags.bits(),
            attach_flags,
            prog_cnt: program_count,
            prog_ids: program_ids.as_mut_ptr(),
            prog_attach_flags: ptr::null_mut(), // Not supported until https://lore.kernel.org/all/20220628174314.1216643-6-sdf@google.com/
            ..Default::default()
        }
    }
    // As of early 2022, you can have per-program attach flags so we'll have to
    // change this API eventually
    pub fn attached_program_ids_by_type(
        &self,
        attach_type: attach_type::AttachType,
        query_flags: QueryFlags,
    ) -> Result<(AttachFlags, Vec<BpfProgramId>), Errno> {
        // Grab count of programs first; estimated since it might change by next syscall
        let mut program_count: u32 = 0;

        error::from_libbpf_errno(unsafe {
            libbpf_sys::bpf_prog_query(
                self.0.as_raw_fd(),
                attach_type.into(),
                query_flags.bits(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut program_count as *mut _,
            )
        })?;

        if program_count == 0 {
            return Ok((AttachFlags::NONE, Vec::default()));
        }

        let mut program_ids = vec![0u32; program_count as usize];
        let mut opts_raw = Self::query_opts(query_flags, 0, program_count, &mut program_ids);

        error::from_libbpf_errno(unsafe {
            libbpf_sys::bpf_prog_query_opts(
                self.0.as_raw_fd(),
                attach_type.into(),
                &mut opts_raw as *mut _,
            )
        })?;

        // We use opts_raw.prog_cnt instead of program_count for accuracy
        // since count might have changed between syscalls
        program_ids.truncate(opts_raw.prog_cnt as usize);

        let attach_flags =
            AttachFlags::from_bits(opts_raw.attach_flags).unwrap_or(AttachFlags::NONE);

        Ok((attach_flags, program_ids))
    }

    pub fn attached_program_ids(
        &self,
        query_flags: QueryFlags,
    ) -> HashMap<attach_type::AttachType, Result<(AttachFlags, Vec<BpfProgramId>), Errno>> {
        attach_type::AttachType::iter()
            .flat_map(|attach_type| {
                match self.attached_program_ids_by_type(attach_type, query_flags) {
                    Ok((attach_flags, program_ids)) => {
                        if program_ids.is_empty() {
                            return None;
                        }

                        Some((attach_type, Ok((attach_flags, program_ids))))
                    }
                    Err(err) => {
                        if err == nix::errno::Errno::EINVAL {
                            return None;
                        }

                        Some((attach_type, Err(err)))
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{KernelDescriptor, QueryFlags};
    use crate::attach_type;
    use std::os::unix::prelude::*;

    #[test]
    #[ignore = "assumes environment"]
    fn test_kernel_descriptor() {
        let cgroup_file = std::fs::File::open("/sys/fs/cgroup/system.slice/upower.service")
            .expect("systemd's upower.service cgroup file does not exist");
        let cgroup_descriptor = KernelDescriptor(cgroup_file.as_fd());

        let (_, ingress_program_ids) = cgroup_descriptor
            .attached_program_ids_by_type(
                attach_type::AttachType::CgroupInetIngress,
                QueryFlags::NONE,
            )
            .unwrap();
        assert_eq!(ingress_program_ids.len(), 1);

        let all_program_ids = cgroup_descriptor.attached_program_ids(QueryFlags::NONE);
        assert_eq!(all_program_ids.len(), 2);
        assert_eq!(
            all_program_ids
                .get(&attach_type::AttachType::CgroupInetIngress)
                .unwrap()
                .as_ref()
                .unwrap()
                .1 // program_ids
                .len(),
            1
        );
        assert_eq!(
            all_program_ids
                .get(&attach_type::AttachType::CgroupInetEgress)
                .unwrap()
                .as_ref()
                .unwrap()
                .1 // program_ids
                .len(),
            1
        );
    }
}
