use flate2::bufread::GzDecoder;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    ptr::null,
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
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
}

fn probe_bpf_syscall() -> bool {
    Errno::clear();

    unsafe {
        libbpf_sys::bpf_prog_load(
            libbpf_sys::BPF_PROG_TYPE_UNSPEC,
            null(),
            null(),
            null(),
            0,
            null(),
        )
    };

    Errno::last() != Errno::ENOSYS
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

fn probe_runtime() -> Result<Runtime, DetectError> {
    Ok(Runtime {
        unprivileged_disabled: procfs_value(Path::new(
            "/proc/sys/kernel/unprivileged_bpf_disabled",
        )),
        jit_enable: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_enable")),
        jit_harden: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_harden")),
        jit_kallsyms: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_kallsyms")),
        jit_limit: procfs_value(Path::new("/proc/sys/net/core/bpf_jit_limit")),
    })
}

#[derive(Debug)]
pub struct System {
    pub runtime: Result<Runtime, DetectError>,
    pub kernel_config: Result<KernelConfig, DetectError>,
    pub has_bpf_syscall: bool,
}

fn system_features() -> Result<System, DetectError> {
    verify_procfs_exists()?;

    Ok(System {
        runtime: probe_runtime(),
        kernel_config: probe_kernel_config(),
        has_bpf_syscall: probe_bpf_syscall(),
    })
}

#[derive(Debug)]
pub struct Features {
    pub system: Result<System, DetectError>,
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
        system: system_features(),
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
