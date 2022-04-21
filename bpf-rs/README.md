# bpf-rs

`bpf-rs` is a safe, lean library for inspecting and querying eBPF objects. A lot of the design & inspiration stems from [bpftool](https://github.com/libbpf/bpftool) and [libbpf-rs](https://docs.rs/libbpf-rs).

It is based upon the work of [libbpf-sys](https://github.com/libbpf/libbpf-sys) to safely create wrappers around [libbpf](https://github.com/libbpf/libbpf).

## Non goals

This crate is **NOT** meant to help with writing and loading of eBPF programs and maps. For that, we recommend [libbpf-rs](https://docs.rs/libbpf-rs) and [libbpf-cargo](https://docs.rs/libbpf-cargo).


## Installation

[![crates.io badge](https://img.shields.io/crates/v/bpf-rs.svg)](https://crates.io/crates/bpf-rs)

To use in your project, add into your `Cargo.toml`:

```toml
[dependencies]
bpf-rs = "0.0.5"
```

See [documentation here](https://docs.rs/bpf-rs/0.0.5/bpf_rs/)