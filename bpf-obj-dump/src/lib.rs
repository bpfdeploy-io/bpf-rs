use libbpf_sys::bpf_prog_info;
use num_enum::TryFromPrimitive;
use std::{error::Error, ffi::c_void, num::TryFromIntError, os::unix::prelude::*, time::Duration};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
enum ObjDumpError {
    #[error("conversion error: {0}")]
    Conversion(#[from] TryFromIntError),
}

#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, TryFromPrimitive)]
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
    Unknown = u32::MAX,
}

#[derive(Debug)]
#[repr(C)]
pub struct ProgramInner {
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

#[derive(Debug)]
pub struct ProgramInfo {
    inner: ProgramInner,
}

impl ProgramInfo {
    fn from_raw(raw: libbpf_sys::bpf_prog_info) -> Self {
        let raw_name = &raw.name;
        let c = raw_name
            .iter()
            .take_while(|&&x| x != 0)
            .map(|&x| x as u8)
            .collect();
        let name = String::from_utf8(c).unwrap_or("(?)".into());
        let ty = match ProgramType::try_from(raw.type_) {
            Ok(ty) => ty,
            Err(_) => ProgramType::Unknown,
        };

        ProgramInfo {
            inner: ProgramInner {
                name,
                ty,
                tag: raw.tag,
                id: raw.id,
                jited_prog_len: raw.jited_prog_len,
                xlated_prog_len: raw.xlated_prog_len,
                jited_prog_insns: raw.jited_prog_insns,
                xlated_prog_insns: raw.xlated_prog_insns,
                load_time: Duration::from_nanos(raw.load_time),
                created_by_uid: raw.created_by_uid,
                nr_map_ids: raw.nr_map_ids,
                map_ids: raw.map_ids,
                ifindex: raw.ifindex,
                gpl_compatible: raw._bitfield_1.get_bit(0),
                netns_dev: raw.netns_dev,
                netns_ino: raw.netns_ino,
                nr_jited_ksyms: raw.nr_jited_ksyms,
                nr_jited_func_lens: raw.nr_jited_func_lens,
                jited_ksyms: raw.jited_ksyms,
                jited_func_lens: raw.jited_func_lens,
                btf_id: raw.btf_id,
                func_info_rec_size: raw.func_info_rec_size,
                func_info: raw.func_info,
                nr_func_info: raw.nr_func_info,
                nr_line_info: raw.nr_line_info,
                line_info: raw.line_info,
                jited_line_info: raw.jited_line_info,
                nr_jited_line_info: raw.nr_jited_line_info,
                line_info_rec_size: raw.line_info_rec_size,
                jited_line_info_rec_size: raw.jited_line_info_rec_size,
                nr_prog_tags: raw.nr_prog_tags,
                prog_tags: raw.prog_tags,
                run_time_ns: raw.run_time_ns,
                run_cnt: raw.run_cnt,
            },
        }
    }

    fn from_fd(fd: RawFd) -> Result<Self, ObjDumpError> {
        let mut info: bpf_prog_info = unsafe { std::mem::zeroed() };
        let info_ptr: *mut bpf_prog_info = &mut info;
        let mut info_len = std::mem::size_of::<bpf_prog_info>() as u32;
        let err = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd, info_ptr as *mut c_void, &mut info_len)
        };
        if err != 0 {
            todo!()
        } else {
            Ok(Self::from_raw(info))
        }
    }

    fn dump(fd: RawFd, dump_mode: ProgramDumpMode) -> Result<Self, Box<dyn Error>> {
        use std::mem::{size_of, zeroed};

        // Get initial sizes
        let mut info: bpf_prog_info = unsafe { zeroed() };
        let info_ptr: *mut bpf_prog_info = &mut info;
        let mut prog_info_size = std::mem::size_of::<bpf_prog_info>() as u32;
        let err = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd, info_ptr as *mut c_void, &mut prog_info_size)
        };

        if err != 0 {
            todo!("{}", err);
        }

        // Set up bare prog info & calculat needed mem for dump
        let mut bare: bpf_prog_info = unsafe { zeroed() };
        let prog_len: usize = match dump_mode {
            ProgramDumpMode::Xlated => {
                bare.xlated_prog_len = info.xlated_prog_len;
                info.xlated_prog_len.try_into()?
            }
            ProgramDumpMode::Jited => {
                bare.jited_prog_len = info.jited_prog_len;
                info.jited_prog_len.try_into()?
            }
        };

        // TODO: does an xlated dump needed the jited allocs here?
        bare.nr_jited_ksyms = info.nr_jited_ksyms;
        let jited_ksyms_size = usize::try_from(info.nr_jited_ksyms)? * size_of::<u64>();

        bare.nr_jited_func_lens = info.nr_jited_func_lens;
        let jited_func_size = usize::try_from(info.nr_jited_func_lens)? * size_of::<u32>();

        bare.nr_func_info = info.nr_func_info;
        bare.func_info_rec_size = info.func_info_rec_size;
        let jited_func_info_size =
            usize::try_from(info.nr_func_info)? * usize::try_from(info.func_info_rec_size)?;

        bare.nr_line_info = info.nr_line_info;
        bare.line_info_rec_size = info.line_info_rec_size;
        let line_info_size: usize =
            usize::try_from(info.nr_line_info)? * usize::try_from(info.line_info_rec_size)?;

        bare.nr_jited_line_info = info.nr_jited_line_info;
        bare.jited_line_info_rec_size = info.jited_line_info_rec_size;
        let jited_line_info_size: usize = usize::try_from(info.nr_jited_line_info)?
            * usize::try_from(info.jited_line_info_rec_size)?;

        // Alloc dump area and set ptrs
        let mem_needed: usize = prog_len
            + jited_ksyms_size
            + jited_func_size
            + jited_func_info_size
            + line_info_size
            + jited_line_info_size;

        let dump_alloc: Vec<u64> = vec![0; mem_needed + 1]; // Extra item for end-of-boundary ptrs

        match dump_mode {
            ProgramDumpMode::Xlated => {
                bare.xlated_prog_insns = dump_alloc.as_ptr() as u64;
            }
            ProgramDumpMode::Jited => {
                bare.jited_prog_insns = dump_alloc.as_ptr() as u64;
            }
        };

        bare.jited_ksyms = (&dump_alloc[prog_len] as *const u64) as u64;
        bare.jited_func_lens = (&dump_alloc[prog_len + jited_ksyms_size] as *const u64) as u64;
        bare.func_info =
            (&dump_alloc[prog_len + jited_ksyms_size + jited_func_size] as *const u64) as u64;
        bare.line_info = (&dump_alloc
            [prog_len + jited_ksyms_size + jited_func_size + jited_func_info_size]
            as *const u64) as u64;
        bare.jited_line_info = (&dump_alloc
            [prog_len + jited_ksyms_size + jited_func_size + jited_func_info_size + line_info_size]
            as *const u64) as u64;

        // Do dump
        let err = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(
                fd,
                (&mut bare as *mut bpf_prog_info) as *mut c_void,
                &mut prog_info_size,
            )
        };

        if err != 0 {
            todo!("{}", err);
        }

        Ok(Self::from_raw(bare))
    }
}

#[derive(Debug)]
pub enum ProgramDumpMode {
    Xlated,
    Jited,
}

// Not responsible for closing it
pub fn dump_program(fd: RawFd, dump_mode: ProgramDumpMode) -> Result<ProgramInfo, Box<dyn Error>> {
    ProgramInfo::dump(fd, dump_mode)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
