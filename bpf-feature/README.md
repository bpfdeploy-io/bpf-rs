# bpf-feature

 A Rust library for BPF feature detection

## Background

[eBPF](https://ebpf.io/) support is a moving target when it comes to Linux versions. Knowing what our kernels currently support is necessary to determine which BPF features we can enable in the programs we write.

The checks here are modeled after [bpftool](https://github.com/libbpf/bpftool)'s feature probe functionality.

## Installation

Using cargo-edit:

```sh
$ cargo add bpf-feature
```

Or in a Cargo.toml file:

```toml
[dependencies]
bpf-feature = "0.0.1"
```



