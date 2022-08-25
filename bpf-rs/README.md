<div align="center">
  <h1>bpf-rs</h1>
    <p>
      A safe, flexible library for inspecting and querying eBPF objects.
    </p>
  <br>
</div>

## Background

It is based upon the work of [libbpf-sys](https://github.com/libbpf/libbpf-sys) to safely create wrappers around [libbpf](https://github.com/libbpf/libbpf). A lot of the design & inspiration stems from [bpftool](https://github.com/libbpf/bpftool) and [libbpf-rs](https://docs.rs/libbpf-rs).

This crate is **NOT** meant to help with the writing and loading of eBPF programs and maps. For that, we highly recommend [libbpf-rs](https://docs.rs/libbpf-rs) and [libbpf-cargo](https://docs.rs/libbpf-cargo).

The goal of this library is to aid in eBPF clients interested in managing and monitoring their host's eBPF objects. As an example of this use case, check out [bpf-feature](https://docs.rs/bpf-feature/latest/bpf_feature/).

## Install

[![crates.io badge](https://img.shields.io/crates/v/bpf-rs.svg)](https://crates.io/crates/bpf-rs)
[![crates.io badge](https://img.shields.io/crates/l/bpf-rs.svg)](https://crates.io/crates/bpf-rs)
[![crates.io badge](https://img.shields.io/docsrs/bpf-rs/latest.svg)](https://docs.rs/bpf-rs)

To use in your project, add into your `Cargo.toml`:

```toml
[dependencies]
bpf-rs = "0.2.0"
```

or using [cargo-edit](https://github.com/killercup/cargo-edit):

```sh
$ cargo add bpf-rs
```

## Documentation

See [documentation here](https://docs.rs/bpf-rs/)

## License

[BSD 2-Clause](https://choosealicense.com/licenses/bsd-2-clause) - Maintained by [bpfdeploy.io](https://bpfdeploy.io)
