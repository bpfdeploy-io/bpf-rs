<div align="center">
  <h1>bpf-rs</h1>
  <p>
    A collection of Rust libraries for inspecting & managing eBPF objects.
  </p>
  <br>
</div>

## Crates

### [bpf-rs](./bpf-rs/)

[![crates.io badge](https://img.shields.io/crates/v/bpf-rs.svg)](https://crates.io/crates/bpf-rs)

A core library for inspecting and querying eBPF objects.

See [documentation here](https://docs.rs/bpf-rs/)

### [bpf-feature](./bpf-feature/)

A bpf feature detection library based on [bpftool](https://github.com/libbpf/bpftool)'s `feature` subcommand.

Clients can determine available bpf features (such as program & map types, kernel config values, bpf helper functions etc.) supported in their current kernels.

Example: [feature-probe.rs](./bpf-feature/examples/feature-probe.rs)

### [bpf-obj-dump](./bpf-obj-dump/)

A work-in-progress library to aid in the dumping of eBPF programs and maps.


## Licenses

Most, if not all, of the crates published here fall under the permissive [BSD 2-Clause](https://choosealicense.com/licenses/bsd-2-clause/#) license.

## Acknowledgements

A lot of the techniques here were inspired by [bpftool](https://github.com/libbpf/bpftool), [libbpf](https://github.com/libbpf/libbpf) and [libbpf-rs](https://github.com/libbpf/libbpf-rs)
