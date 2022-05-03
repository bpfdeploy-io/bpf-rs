use bpf_rs::libbpf_sys::{
    bpf_insn, bpf_prog_load, BPF_FUNC_probe_write_user, BPF_FUNC_trace_printk,
    BPF_FUNC_trace_vprintk, BPF_MAXINSNS,
};
use bpf_rs::{
    insns::{alu64_imm, exit, jmp32_imm, jmp_imm, mov64_imm, AluOp, JmpOp, Register},
    BpfHelper, BpfHelperIter, Error as BpfSysError, MapType, ProgramLicense, ProgramType,
};
use flate2::bufread::GzDecoder;
use nix::{
    errno::{errno, Errno},
    sys::{
        statfs::{statfs, PROC_SUPER_MAGIC},
        utsname,
    },
    unistd,
};
#[cfg(feature = "serde")]
use serde::{ser::SerializeStruct, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    ptr,
};
use thiserror::Error as ThisError;

#[cfg(feature = "serde")]
mod serde_utils {
    use serde::ser::{SerializeMap, SerializeSeq};
    use std::collections::HashMap;

    pub fn flatten_result<S, T, E>(result: &Result<T, E>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: serde::ser::Serialize,
        E: serde::ser::Serialize,
    {
        match result {
            Ok(t) => t.serialize(serializer),
            Err(e) => e.serialize(serializer),
        }
    }

    pub fn to_list<S, K, E>(
        map: &HashMap<K, Result<bool, E>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        K: serde::ser::Serialize,
    {
        let mut seq = serializer.serialize_seq(None)?;
        for (k, v) in map.iter() {
            match v {
                Ok(true) => {
                    seq.serialize_element(k)?;
                }
                _ => {}
            };
        }
        seq.end()
    }

    pub fn to_list_inner<S, K, H, E>(
        map: &HashMap<K, Vec<Result<H, E>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        K: serde::ser::Serialize,
        H: serde::ser::Serialize,
    {
        let mut seq = serializer.serialize_map(None)?;
        for (k, v) in map.iter() {
            let ok_items: Vec<_> = v
                .iter()
                .filter_map(|r| match r {
                    Ok(h) => Some(h),
                    Err(_) => None,
                })
                .collect();
            seq.serialize_entry(k, &ok_items)?
        }
        seq.end()
    }
}

#[derive(ThisError, Debug)]
pub enum DetectError {
    #[error("failed to access capabilities")]
    CapAccess,
    #[error("missing CAP_SYS_ADMIN for full feature probe")]
    CapSysAdmin,
}

#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum KernelConfigError {
    #[error("can't open file")]
    NotFound,
    #[error("file data format unknown")]
    ContentsUnknown,
    #[error("can't read from file")]
    ReadFail,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum ConfigValue {
    Y,
    N,
    M,
    Other(String),
}

impl Display for ConfigValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigValue::Y => write!(f, "y"),
            ConfigValue::N => write!(f, "n"),
            ConfigValue::M => write!(f, "m"),
            ConfigValue::Other(value) => write!(f, "{}", value),
        }
    }
}

pub type KernelConfigValues = HashMap<&'static str, ConfigValue>;

pub const KERNEL_CONFIG_KEYS: [&'static str; 35] = [
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
    "CONFIG_NET_CLS_BPF",
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

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KernelConfig {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub values: KernelConfigValues,
}

impl KernelConfig {
    pub fn features() -> Result<KernelConfig, KernelConfigError> {
        return Ok(KernelConfig {
            values: Self::probe_kernel_config()?,
        });
    }

    fn probe_kernel_config() -> Result<KernelConfigValues, KernelConfigError> {
        let utsn = utsname::uname();

        let config_reader: Box<dyn BufRead> =
            match File::open(format!("/boot/config-{}", utsn.release())) {
                Err(_) => {
                    let compressed_config =
                        File::open("/proc/config.gz").map_err(|_| KernelConfigError::NotFound)?;
                    let decoder = GzDecoder::new(BufReader::new(compressed_config));
                    Box::new(BufReader::new(decoder))
                }
                Ok(f) => Box::new(BufReader::new(f)),
            };

        let mut lines_iter = config_reader.lines();
        let _ = lines_iter
            .next()
            .transpose()
            .map_err(|_| KernelConfigError::ReadFail)?
            .ok_or(KernelConfigError::ReadFail)?;
        let line = lines_iter
            .next()
            .transpose()
            .map_err(|_| KernelConfigError::ReadFail)?
            .ok_or(KernelConfigError::ReadFail)?;

        if !line.starts_with("# Automatically generated file; DO NOT EDIT.") {
            return Err(KernelConfigError::ContentsUnknown);
        }

        let mut options = HashMap::new();

        for line_item in lines_iter {
            let line = line_item.map_err(|_| KernelConfigError::ReadFail)?;
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
}

#[derive(ThisError, Debug)]
pub enum RuntimeError {
    #[error("procfs at /proc was not detected")]
    ProcfsNonExistent,
    #[error("std::num::ParseIntError: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("std::io::Error: {0}")]
    IO(#[from] std::io::Error),
}

type ProcfsResult = Result<usize, RuntimeError>;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Runtime {
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub unprivileged_disabled: ProcfsResult,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub jit_enable: ProcfsResult,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub jit_harden: ProcfsResult,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub jit_kallsyms: ProcfsResult,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub jit_limit: ProcfsResult,
}

impl Runtime {
    pub fn features() -> Result<Runtime, RuntimeError> {
        Self::verify_procfs_exists()?;

        Ok(Runtime {
            unprivileged_disabled: Self::procfs_read(Path::new(
                "/proc/sys/kernel/unprivileged_bpf_disabled",
            )),
            jit_enable: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_enable")),
            jit_harden: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_harden")),
            jit_kallsyms: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_kallsyms")),
            jit_limit: Self::procfs_read(Path::new("/proc/sys/net/core/bpf_jit_limit")),
        })
    }

    fn verify_procfs_exists() -> Result<(), RuntimeError> {
        match statfs("/proc") {
            Err(_) => Err(RuntimeError::ProcfsNonExistent),
            Ok(stat) => {
                if stat.filesystem_type() != PROC_SUPER_MAGIC {
                    Err(RuntimeError::ProcfsNonExistent)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn procfs_read(path: &Path) -> ProcfsResult {
        Ok(std::fs::read_to_string(path)?.trim().parse()?)
    }
}

#[derive(ThisError, Debug)]
pub enum BpfError {
    #[error("no bpf syscall on system")]
    NoBpfSyscall,
    #[error("bpf-rs::Error: {0}")]
    ProbeErr(#[from] BpfSysError),
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Bpf {
    pub has_bpf_syscall: bool,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_utils::to_list"))]
    pub program_types: HashMap<ProgramType, Result<bool, BpfError>>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_utils::to_list"))]
    pub map_types: HashMap<MapType, Result<bool, BpfError>>,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::to_list_inner")
    )]
    pub helpers: HashMap<ProgramType, Vec<Result<BpfHelper, BpfError>>>,
}

pub struct BpfFeaturesOpts {
    full_helpers: bool,
}

impl Default for BpfFeaturesOpts {
    fn default() -> Self {
        Self {
            full_helpers: false,
        }
    }
}

impl Bpf {
    pub fn features(opts: BpfFeaturesOpts) -> Result<Bpf, BpfError> {
        if !Self::probe_syscall() {
            return Err(BpfError::NoBpfSyscall);
        }

        Ok(Bpf {
            has_bpf_syscall: true,
            program_types: Self::probe_program_types(),
            map_types: Self::probe_map_types(),
            helpers: Self::probe_helpers(opts.full_helpers),
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

    fn probe_program_types() -> HashMap<ProgramType, Result<bool, BpfError>> {
        ProgramType::iter()
            .map(|program_type| {
                (
                    program_type,
                    program_type.probe().map_err(|err| BpfError::ProbeErr(err)),
                )
            })
            .collect()
    }

    fn probe_map_types() -> HashMap<MapType, Result<bool, BpfError>> {
        MapType::iter()
            .map(|map_type| {
                (
                    map_type,
                    map_type.probe().map_err(|err| BpfError::ProbeErr(err)),
                )
            })
            .collect()
    }

    fn probe_helpers(full: bool) -> HashMap<ProgramType, Vec<Result<BpfHelper, BpfError>>> {
        ProgramType::iter()
            .map(|program_type| {
                let helpers = BpfHelperIter::new()
                    .filter_map(|helper| {
                        if !full {
                            #[allow(non_upper_case_globals)]
                            match helper.0 {
                                BPF_FUNC_trace_printk
                                | BPF_FUNC_trace_vprintk
                                | BPF_FUNC_probe_write_user => return None,
                                _ => {}
                            };
                        }

                        match program_type.probe_helper(helper) {
                            Ok(true) => Some(Ok(helper)),
                            Ok(false) => None,
                            Err(err) => Some(Err(BpfError::ProbeErr(err))),
                        }
                    })
                    .collect();
                (program_type, helpers)
            })
            .collect()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Misc {
    pub large_insn_limit: bool,
    pub bounded_loops: bool,
    pub isa_v2_ext: bool,
    pub isa_v3_ext: bool,
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

    fn probe_large_insn_limit() -> bool {
        let max_insns = usize::try_from(BPF_MAXINSNS).unwrap();
        let mut large_insn_prog = vec![mov64_imm(Register::R0, 1); max_insns + 1];
        large_insn_prog[max_insns] = exit();
        Self::load_insns(large_insn_prog)
    }

    fn probe_bounded_loops() -> bool {
        let insns = vec![
            mov64_imm(Register::R0, 10),
            alu64_imm(AluOp::SUB, Register::R0, 1),
            jmp_imm(JmpOp::JNE, Register::R0, 0, -2),
            exit(),
        ];
        Self::load_insns(insns)
    }

    fn probe_isa_v2() -> bool {
        let insns = vec![
            mov64_imm(Register::R0, 0),
            jmp_imm(JmpOp::JLT, Register::R0, 0, 1),
            mov64_imm(Register::R0, 1),
            exit(),
        ];
        Self::load_insns(insns)
    }

    fn probe_isa_v3() -> bool {
        let insns = vec![
            mov64_imm(Register::R0, 0),
            jmp32_imm(JmpOp::JLT, Register::R0, 0, 1),
            mov64_imm(Register::R0, 1),
            exit(),
        ];
        Self::load_insns(insns)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Features {
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub runtime: Result<Runtime, RuntimeError>,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub kernel_config: Result<KernelConfig, KernelConfigError>,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_utils::flatten_result")
    )]
    pub bpf: Result<Bpf, BpfError>,
    pub misc: Misc,
}

pub struct DetectOpts {
    privileged: bool,
    full_helpers: bool,
}

impl Default for DetectOpts {
    fn default() -> Self {
        Self {
            privileged: true,
            full_helpers: false,
        }
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
        kernel_config: KernelConfig::features(),
        bpf: Bpf::features(BpfFeaturesOpts {
            full_helpers: opts.full_helpers,
        }),
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
