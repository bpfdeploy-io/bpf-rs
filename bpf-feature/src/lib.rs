use bpf_inspect_common::{
    bpf_asm::{alu64_imm, exit, jmp32_imm, jmp_imm, mov64_imm, BpfJmp, BpfOp, BpfRegister},
    BpfHelper, BpfHelperIter, Error as BpfInspectError, MapType, ProgramLicense, ProgramType,
};
use flate2::bufread::GzDecoder;
use libbpf_sys::{bpf_insn, bpf_prog_load, BPF_MAXINSNS};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    ptr,
};
use thiserror::Error as ThisError;
// TODO: if this is the only use of nix
// then consider just using libc
use nix::{
    errno::{errno, Errno},
    sys::{
        statfs::{statfs, PROC_SUPER_MAGIC},
        utsname,
    },
    unistd,
};

// TODO: consider splitting up so that library clients don't need to match against all of them?
#[derive(ThisError, Debug)]
pub enum DetectError {
    #[error("failed to access capabilities")]
    CapAccess,
    #[error("missing CAP_SYS_ADMIN for full feature probe")]
    CapSysAdmin,
    #[error("{0}")]
    Procfs(String), // TODO: should be a further nested error type rather thanString?
    #[error("{0}")]
    KernelConfig(&'static str),
    #[error("no bpf syscall on system")]
    NoBpfSyscall,
    #[error("failure to load bpf program")]
    BpfProgLoad,
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
pub enum ConfigValue {
    Y,
    N,
    M,
    Other(String),
    Unknown,
}

pub type KernelConfig = HashMap<&'static str, ConfigValue>;

const KERNEL_CONFIG_KEYS: [&'static str; 34] = [
    "CONFIG_BPF",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_HAVE_EBPF_JIT",
    "CONFIG_BPF_JIT",
    "CONFIG_BPF_JIT_ALWAYS_ON",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_DEBUG_INFO_BTF_MODULES",
    "CONFIG_CGROUPS",
    "CONFIG_CGROUP_BPF",
    "CONFIG_CGROUP_NET_CLASSID",
    "CONFIG_SOCK_CGROUP_DATA",
    "CONFIG_BPF_EVENTS",
    "CONFIG_KPROBE_EVENTS",
    "CONFIG_UPROBE_EVENTS",
    "CONFIG_TRACING",
    "CONFIG_FTRACE_SYSCALLS",
    "CONFIG_FUNCTION_ERROR_INJECTION",
    "CONFIG_BPF_KPROBE_OVERRIDE",
    "CONFIG_NET",
    "CONFIG_XDP_SOCKETS",
    "CONFIG_LWTUNNEL_BPF",
    "CONFIG_NET_ACT_BPF",
    "CONFIG_NET_CLS_ACT",
    "CONFIG_NET_SCH_INGRESS",
    "CONFIG_XFRM",
    "CONFIG_IP_ROUTE_CLASSID",
    "CONFIG_IPV6_SEG6_BPF",
    "CONFIG_BPF_LIRC_MODE2",
    "CONFIG_BPF_STREAM_PARSER",
    "CONFIG_NETFILTER_XT_MATCH_BPF",
    "CONFIG_BPFILTER",
    "CONFIG_BPFILTER_UMH",
    "CONFIG_TEST_BPF",
    "CONFIG_HZ",
];

fn probe_kernel_config() -> Result<KernelConfig, DetectError> {
    let utsn = utsname::uname();

    let config_reader: Box<dyn BufRead> =
        match File::open(format!("/boot/config-{}", utsn.release())) {
            Err(_) => {
                let compressed_config = File::open("/proc/config.gz")?;
                let decoder = GzDecoder::new(BufReader::new(compressed_config));
                Box::new(BufReader::new(decoder))
            }
            Ok(f) => Box::new(BufReader::new(f)),
        };

    let mut lines_iter = config_reader.lines();
    let _ = lines_iter
        .next()
        .transpose()?
        .ok_or(DetectError::KernelConfig("could not read config"))?;
    let line = lines_iter
        .next()
        .transpose()?
        .ok_or(DetectError::KernelConfig("could not read config"))?;

    if !line.starts_with("# Automatically generated file; DO NOT EDIT.") {
        return Err(DetectError::KernelConfig(
            "kernel config written with unknown data",
        ));
    }

    let mut options = HashMap::from(KERNEL_CONFIG_KEYS.map(|key| (key, ConfigValue::Unknown)));

    for line_item in lines_iter {
        let line = line_item?;
        if !line.starts_with("CONFIG_") {
            continue;
        }

        let pieces: Vec<_> = line.split("=").collect();
        if pieces.len() < 2 {
            continue;
        }

        for key in KERNEL_CONFIG_KEYS {
            if key != pieces[0] {
                continue;
            }

            options.insert(
                key,
                match pieces[1] {
                    "y" => ConfigValue::Y,
                    "m" => ConfigValue::M,
                    "n" => ConfigValue::N,
                    _ => ConfigValue::Other(pieces[1].to_string()),
                },
            );
        }
    }

    return Ok(options);
}

type ProcfsResult = Result<usize, DetectError>;

#[derive(Debug)]
pub struct Runtime {
    pub unprivileged_disabled: ProcfsResult,
    pub jit_enable: ProcfsResult,
    pub jit_harden: ProcfsResult,
    pub jit_kallsyms: ProcfsResult,
    pub jit_limit: ProcfsResult,
}

impl Runtime {
    fn verify_procfs_exists() -> Result<(), DetectError> {
        match statfs("/proc") {
            Err(err) => Err(DetectError::Procfs(format!(
                "error detecting /proc: {}",
                err
            ))),
            Ok(stat) => {
                if stat.filesystem_type() != PROC_SUPER_MAGIC {
                    Err(DetectError::Procfs(
                        "/proc f_type not equal to PROC_SUPER_MAGIC".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn procfs_value(path: &Path) -> ProcfsResult {
        std::fs::read_to_string(path)?
            .trim()
            .parse()
            .or(Err(DetectError::Procfs("invalid parsing".into())))
    }

    pub fn features() -> Result<Runtime, DetectError> {
        Self::verify_procfs_exists()?;

        Ok(Runtime {
            unprivileged_disabled: Self::procfs_value(Path::new(
                "/proc/sys/kernel/unprivileged_bpf_disabled",
            )),
            jit_enable: Self::procfs_value(Path::new("/proc/sys/net/core/bpf_jit_enable")),
            jit_harden: Self::procfs_value(Path::new("/proc/sys/net/core/bpf_jit_harden")),
            jit_kallsyms: Self::procfs_value(Path::new("/proc/sys/net/core/bpf_jit_kallsyms")),
            jit_limit: Self::procfs_value(Path::new("/proc/sys/net/core/bpf_jit_limit")),
        })
    }
}

#[derive(Debug)]
pub struct Bpf {
    pub has_bpf_syscall: bool,
    pub program_types: HashMap<ProgramType, Result<bool, BpfInspectError>>,
    pub map_types: HashMap<MapType, Result<bool, BpfInspectError>>,
    pub helpers: HashMap<ProgramType, Result<Vec<BpfHelper>, BpfInspectError>>,
}

impl Bpf {
    pub fn features() -> Result<Bpf, DetectError> {
        if !Self::probe_syscall() {
            return Err(DetectError::NoBpfSyscall);
        }

        Ok(Bpf {
            has_bpf_syscall: true,
            program_types: Self::probe_program_types(),
            map_types: Self::probe_map_types(),
            helpers: Self::probe_helpers(),
        })
    }

    fn probe_syscall() -> bool {
        Errno::clear();
        unsafe {
            bpf_prog_load(
                ProgramType::Unspec.into(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
            );
        }
        Errno::last() != Errno::ENOSYS
    }

    fn probe_program_types() -> HashMap<ProgramType, Result<bool, BpfInspectError>> {
        ProgramType::iter()
            .map(|program_type| (program_type, program_type.probe()))
            .collect()
    }

    fn probe_map_types() -> HashMap<MapType, Result<bool, BpfInspectError>> {
        MapType::iter()
            .map(|map_type| (map_type, map_type.probe()))
            .collect()
    }

    fn probe_helpers() -> HashMap<ProgramType, Result<Vec<BpfHelper>, BpfInspectError>> {
        ProgramType::iter()
            .map(|program_type| {
                let helpers = BpfHelperIter::new()
                    .filter_map(|helper| {
                        if program_type.probe_helper(helper).unwrap_or(false) {
                            Some(helper)
                        } else {
                            None
                        }
                    })
                    .collect();
                (program_type, Ok(helpers))
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct Misc {
    pub large_insn_limit: Result<bool, DetectError>,
    pub bounded_loops: Result<bool, DetectError>,
    pub isa_v2_ext: Result<bool, DetectError>,
    pub isa_v3_ext: Result<bool, DetectError>,
}

impl Misc {
    pub fn features() -> Misc {
        Misc {
            large_insn_limit: Self::probe_large_insn_limit(),
            bounded_loops: Self::probe_bounded_loops(),
            isa_v2_ext: Self::probe_isa_v2(),
            isa_v3_ext: Self::probe_isa_v3(),
        }
    }

    fn load_insns(insns: Vec<bpf_insn>) -> bool {
        Errno::clear();
        let fd = unsafe {
            bpf_prog_load(
                ProgramType::SocketFilter.into(),
                ptr::null(),
                ProgramLicense::GPL.as_ptr(),
                insns.as_ptr(),
                u64::try_from(insns.len()).unwrap_or(0u64),
                ptr::null(),
            )
        };

        let success = fd >= 0 || errno() == 0;

        if fd >= 0 {
            let _ = unistd::close(fd);
        }

        success
    }

    fn probe_large_insn_limit() -> Result<bool, DetectError> {
        let max_insns = usize::try_from(BPF_MAXINSNS).unwrap();
        let mut large_insn_prog = vec![mov64_imm(BpfRegister::R0, 1); max_insns + 1];
        large_insn_prog[max_insns] = exit();
        Ok(Self::load_insns(large_insn_prog))
    }

    fn probe_bounded_loops() -> Result<bool, DetectError> {
        let insns = vec![
            mov64_imm(BpfRegister::R0, 10),
            alu64_imm(BpfOp::Sub, BpfRegister::R0, 1),
            jmp_imm(BpfJmp::JNE, BpfRegister::R0, 0, -2),
            exit(),
        ];
        Ok(Self::load_insns(insns))
    }

    fn probe_isa_v2() -> Result<bool, DetectError> {
        let insns = vec![
            mov64_imm(BpfRegister::R0, 0),
            jmp_imm(BpfJmp::JLT, BpfRegister::R0, 0, 1),
            mov64_imm(BpfRegister::R0, 1),
            exit(),
        ];
        Ok(Self::load_insns(insns))
    }

    fn probe_isa_v3() -> Result<bool, DetectError> {
        let insns = vec![
            mov64_imm(BpfRegister::R0, 0),
            jmp32_imm(BpfJmp::JLT, BpfRegister::R0, 0, 1),
            mov64_imm(BpfRegister::R0, 1),
            exit(),
        ];
        Ok(Self::load_insns(insns))
    }
}

#[derive(Debug)]
pub struct Features {
    pub runtime: Result<Runtime, DetectError>,
    pub kernel_config: Result<KernelConfig, DetectError>,
    pub bpf: Result<Bpf, DetectError>,
    pub misc: Misc,
}

pub struct DetectOpts {
    privileged: bool,
}

impl Default for DetectOpts {
    fn default() -> Self {
        Self { privileged: true }
    }
}

pub fn detect(opts: DetectOpts) -> Result<Features, DetectError> {
    use caps::{CapSet, Capability::CAP_SYS_ADMIN};
    if opts.privileged {
        match caps::has_cap(None, CapSet::Effective, CAP_SYS_ADMIN) {
            Ok(is_capable) => {
                if !is_capable {
                    return Err(DetectError::CapSysAdmin);
                }
            }
            Err(_) => return Err(DetectError::CapAccess),
        }
    } else {
        match caps::clear(None, CapSet::Effective) {
            Ok(_) => {}
            Err(_) => return Err(DetectError::CapAccess),
        }
    }

    Ok(Features {
        runtime: Runtime::features(),
        kernel_config: probe_kernel_config(),
        bpf: Bpf::features(),
        misc: Misc::features(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
