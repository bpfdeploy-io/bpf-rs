use bpf_feature::{detect, BpfError, DetectOpts, KernelConfig, Misc, KERNEL_CONFIG_KEYS};
use bpf_rs::{BpfHelper, MapType, ProgramType};

fn main() {
    let features = match detect(DetectOpts::default()) {
        Ok(features) => features,
        Err(err) => {
            println!("Error fetching features: {}", err);
            return;
        }
    };

    println!("Scanning system configuration...");
    match features.runtime {
        Err(_) => {
            println!("/* procfs not mounted, skipping related probes */");
        }
        Ok(runtime) => {
            match runtime.unprivileged_disabled {
                Ok(prop) => match prop {
                    0 => println!("bpf() syscall for unprivileged users is enabled"),
                    1 => {
                        println!("bpf() syscall restricted to privileged users (without recovery)")
                    }
                    2 => {
                        println!("bpf() syscall restricted to privileged users (admin can change)")
                    }
                    unknown => println!("bpf() syscall restriction has unknown value: {}", unknown),
                },
                Err(_) => println!("Unable to retrieve required privileges for bpf() syscall"),
            };

            match runtime.jit_enable {
                Ok(prop) => match prop {
                    0 => println!("JIT compiler is disabled"),
                    1 => println!("JIT compiler is enabled"),
                    2 => println!("JIT compiler is enabled with debugging traces in kernel logs"),
                    unknown => println!("JIT compiler status has unknown value: {}", unknown),
                },
                Err(_) => println!("Unable to retrieve JIT-compiler status"),
            }

            match runtime.jit_harden {
                Ok(prop) => match prop {
                    0 => println!("JIT compiler hardening is disabled"),
                    1 => println!("JIT compiler hardening is enabled for unprivileged users"),
                    2 => println!("JIT compiler hardening is enabled for all users"),
                    unknown => println!("JIT hardening status has unknown value: {}", unknown),
                },
                Err(_) => println!("Unable to retrieve JIT hardening status"),
            }

            match runtime.jit_kallsyms {
                Ok(prop) => match prop {
                    0 => println!("JIT compiler kallsyms exports are disabled"),
                    1 => println!("JIT compiler kallsyms exports are enabled for root"),
                    unknown => {
                        println!("JIT kallsyms exports status has unknown value: {}", unknown)
                    }
                },
                Err(_) => println!("Unable to retrieve JIT kallsyms export status"),
            }

            match runtime.jit_limit {
                Ok(prop) => println!("Global memory limit for JIT compiler for unprivileged users is {} bytes", prop),
                Err(_) => println!("Unable to retrieve global memory limit for JIT compiler for unprivileged users"),
            }
        }
    }

    match features.kernel_config {
        Ok(KernelConfig { values }) => KERNEL_CONFIG_KEYS.iter().for_each(|&key| {
            match values.get(key) {
                Some(value) => println!("{} is set to {}", key, value),
                None => println!("{} is not set", key),
            };
        }),
        Err(err) => println!("skipping kernel config, {}", err),
    }

    println!("\nScanning system call availability...");
    match features.bpf {
        Ok(bpf) => {
            println!("bpf() syscall is available");
            println!("\nScanning eBPF program types...");
            ProgramType::iter().for_each(|ref program_type| {
                match bpf.program_types.get(program_type) {
                    Some(Ok(true)) => println!("eBPF program_type {} is available", program_type),
                    _ => println!("eBPF program_type {} is NOT available", program_type),
                };
            });

            println!("\nScanning eBPF map types...");
            MapType::iter().for_each(|ref map_type| match bpf.map_types.get(map_type) {
                Some(Ok(true)) => println!("eBPF map_type {} is available", map_type),
                _ => println!("eBPF map_type {} is NOT available", map_type),
            });

            println!("\nScanning eBPF helper functions...");
            ProgramType::iter().for_each(|ref program_type| {
                println!("eBPF helpers supported for program type {}:", program_type);
                match bpf.program_types.get(program_type) {
                    Some(Ok(true)) => match bpf.helpers.get(program_type) {
                        Some(probes) => {
                            let (successes, failures): (
                                Vec<&Result<BpfHelper, BpfError>>,
                                Vec<&Result<BpfHelper, BpfError>>,
                            ) = probes.iter().partition(|probe| probe.is_ok());
                            if successes.len() == 0 && failures.len() > 0 {
                                println!("\tCould not determine which helpers are available");
                            } else {
                                successes.iter().for_each(|&helper| {
                                    println!("\t- {}", helper.as_ref().unwrap());
                                });
                            }
                        }
                        _ => {
                            println!("\tCould not determine which helpers are available");
                        }
                    },
                    Some(Ok(false)) => {
                        println!("\tProgram type not supported");
                    }
                    _ => {
                        println!("\tCould not determine which helpers are available");
                    }
                };
            });
        }
        Err(_) => println!("bpf() syscall is NOT available"),
    }

    println!("\nScanning miscellaneous eBPF features...");
    let Misc {
        large_insn_limit,
        bounded_loops,
        isa_v2_ext,
        isa_v3_ext,
    } = features.misc;
    println!(
        "Large program size limit {} available",
        if large_insn_limit { "is" } else { "is NOT" }
    );
    println!(
        "Bounded loop support {} available",
        if bounded_loops { "is" } else { "is NOT" }
    );
    println!(
        "ISA extension v2 {} available",
        if isa_v2_ext { "is" } else { "is NOT" }
    );
    println!(
        "ISA extension v3 {} available",
        if isa_v3_ext { "is" } else { "is NOT" }
    );
}
