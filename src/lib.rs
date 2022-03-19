struct KernelConfigFeatures {

}


fn procfs_exists() -> bool {
    // TODO: if this is the only use of nix
    // then consider just using libc
    use nix::sys::statfs::{statfs, PROC_SUPER_MAGIC};

    match statfs("/proc") {
        Err(_) => false,
        Ok(stat) => stat.filesystem_type() == PROC_SUPER_MAGIC,
    }
}

struct BpfSystemFeatures {

}

fn detect_system() {
    let system_features = BpfSystemFeatures {}
    if !procfs_exists() {
        return;
    }
}
struct BpfFeatures {
    system: BpfSystemFeatures,
}

fn check_cap() {}

fn detect(opts: DetectionOptions) {
    if opts.privileged {
        // check capabilities
        check_cap();
    }

    detect_system();
}

struct DetectionOptions {
    privileged: bool,

}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
