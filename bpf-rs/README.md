<div align="center">
  <h1>bpf-rs</h1>
    <p>
      A safe, lean library for inspecting and querying eBPF objects.
    </p>
  <br>
</div>

## Background

It is based upon the work of [libbpf-sys](https://github.com/libbpf/libbpf-sys) to safely create wrappers around [libbpf](https://github.com/libbpf/libbpf). A lot of the design & inspiration stems from [bpftool](https://github.com/libbpf/bpftool) and [libbpf-rs](https://docs.rs/libbpf-rs).

This crate is **NOT** meant to help with writing and loading of eBPF programs and maps. For that, we recommend [libbpf-rs](https://docs.rs/libbpf-rs) and [libbpf-cargo](https://docs.rs/libbpf-cargo).

## Installation

[![crates.io badge](https://img.shields.io/crates/v/bpf-rs.svg)](https://crates.io/crates/bpf-rs)

To use in your project, add into your `Cargo.toml`:

```toml
[dependencies]
bpf-rs = "0.0.7"
```

or using [cargo-edit](https://github.com/killercup/cargo-edit):

```sh
$ cargo add bpf-rs
```

## Documentation

See [documentation here](https://docs.rs/bpf-rs/)

## License

[BSD 2-Clause](https://choosealicense.com/licenses/bsd-2-clause) - Maintained by [bpfdeploy.io](https://bpfdeploy.io)
