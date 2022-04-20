# bpf-inspect

A collection of Rust libraries for inspecting & managing eBPF objects.

## Crates

### bpf-feature

A bpf feature detection library based on [bpftool](https://github.com/libbpf/bpftool)'s `feature` subcommand.

This allows clients to use feature detection (such as reading procfs values, kernel configuration, probe detection, etc.) in their own bpf monitoring applications.

[Example of use: feature-probe.rs](./bpf-feature/examples/feature-probe.rs)

### bpf-obj-dump

A work-in-progress library to aid in the dumping of eBPF programs and maps.

### bpf-inspect-common

A collection of bpf utilities shared amongst the other crates.

### libbpf-sys

Vendoring of the [libbpf-sys](https://github.com/libbpf/libbpf-sys) Rust bindings to generate some of our own customizations. We hope to remove the vendoring shortly and send our changes upstream.


## Acknowledgements

A lot of the techniques here were inspired by [bpftool](https://github.com/libbpf/bpftool), [libbpf](https://github.com/libbpf/libbpf) and [libbpf-rs](https://github.com/libbpf/libbpf-rs)
