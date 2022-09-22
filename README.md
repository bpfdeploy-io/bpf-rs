<div align="center">
  <h1>bpf-rs</h1>
  <p>
    A collection of Rust crates for inspecting & managing eBPF objects.
  </p>
  <br>
</div>

## [bpf-rs](./bpf-rs/)

[![crates.io badge](https://img.shields.io/crates/v/bpf-rs.svg)](https://crates.io/crates/bpf-rs)
[![crates.io badge](https://img.shields.io/crates/l/bpf-rs.svg)](https://crates.io/crates/bpf-rs)
[![crates.io badge](https://img.shields.io/docsrs/bpf-rs/latest.svg)](https://docs.rs/bpf-rs)

A core library for managing eBPF objects, focused on ergonomics and serialization.

See [documentation here](https://docs.rs/bpf-rs/)

## [bpf-feature](./bpf-feature/)

[![crates.io badge](https://img.shields.io/crates/v/bpf-feature.svg)](https://crates.io/crates/bpf-feature)
[![crates.io badge](https://img.shields.io/crates/l/bpf-feature.svg)](https://crates.io/crates/bpf-feature)
[![crates.io badge](https://img.shields.io/docsrs/bpf-feature/latest.svg)](https://docs.rs/bpf-feature)

An eBPF feature detection library based on [bpftool](https://github.com/libbpf/bpftool)'s `feature` subcommand.

Clients can determine available bpf features (such as program & map types, kernel config values, bpf helper functions etc.) supported in their current kernels.

See [documentation here](https://docs.rs/bpf-feature/)

See [examples here](./bpf-feature/examples/)

## [bpf-obj-dump](./bpf-obj-dump/)

[![crates.io badge](https://img.shields.io/badge/status-WIP-yellow.svg)]()

A work-in-progress library to aid in the dumping of eBPF programs and maps.

## Contributing & Testing

The development here was based on a Debian-based distro on the x86_64 arch against a v5.18 Linux kernel version.
The eBPF landscape is progressing quickly but with an eye towards backward compatibility.
We aim to do the same so if an issue occurs in your environment, please feel free to file an issue.

### Testing

This project uses [just](https://github.com/casey/just) as its task runner. You can run tests locally with:

```bash
$ just test
```

## Licenses

Most, if not all, of the crates published here fall under the permissive [BSD 2-Clause](https://choosealicense.com/licenses/bsd-2-clause/#) license.

## Acknowledgements

A lot of the techniques here were inspired by [bpftool](https://github.com/libbpf/bpftool), [libbpf](https://github.com/libbpf/libbpf) and [libbpf-rs](https://github.com/libbpf/libbpf-rs). We aim to support these efforts by contributing back and directly referencing them as the canonical implementations.

 Maintained by [bpfdeploy.io](https://bpfdeploy.io)
