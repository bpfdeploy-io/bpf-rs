use bpf_feature::{detect, DetectError, DetectOpts, RuntimeError};

fn main() {
    println!("Scanning system configuration...");
    let features = match detect(DetectOpts::default()) {
        Ok(features) => features,
        Err(err) => {
            eprintln!("Error fetching features: {}", err);
            return;
        }
    };

    match features.runtime {
        Err(_) => {
            eprintln!("/* procfs not mounted, skipping related probes */");
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
                Err(_) => eprintln!("Unable to retrieve required privileges for bpf() syscall"),
            };

            match runtime.jit_enable {
                Ok(prop) => match prop {
                    0 => println!("JIT compiler is disabled"),
                    1 => println!("JIT compiler is enabled"),
                    2 => println!("JIT compiler is enabled with debugging traces in kernel logs"),
                    unknown => println!("JIT compiler status has unknown value: {}", unknown),
                },
                Err(_) => eprintln!("Unable to retrieve JIT-compiler status"),
            }

            match runtime.jit_harden {
                Ok(prop) => match prop {
                    0 => println!("JIT compiler hardening is disabled"),
                    1 => println!("JIT compiler hardening is enabled for unprivileged users"),
                    2 => println!("JIT compiler hardening is enabled for all users"),
                    unknown => println!("JIT hardening status has unknown value: {}", unknown),
                },
                Err(_) => eprintln!("Unable to retrieve JIT hardening status"),
            }

            match runtime.jit_kallsyms {
                Ok(prop) => match prop {
                    0 => println!("JIT compiler kallsyms exports are disabled"),
                    1 => println!("JIT compiler kallsyms exports are enabled for root"),
                    unknown => {
                        println!("JIT kallsyms exports status has unknown value: {}", unknown)
                    }
                },
                Err(_) => eprintln!("Unable to retrieve JIT kallsyms export status"),
            }

            match runtime.jit_limit {
                Ok(prop) => println!("Global memory limit for JIT compiler for unprivileged users is {} bytes", prop),
                Err(_) => eprintln!("Unable to retrieve global memory limit for JIT compiler for unprivileged users"),
            }
        }
    }

    match features.kernel_config {
        Ok(_) => todo!(),
        Err(err) => eprintln!("skipping kernel config, {}", err)
    }
}
