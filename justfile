default:
    @just --list

test:
    cd ./bpf-rs && cargo test --all-features
    cd ./bpf-feature && cargo test --all-features
    cd ./bpf-rs-macros && cargo test --all-features

build-example example:
    cargo build --all-features --example {{example}}

run example:
    just build-example {{example}}
    ./target/debug/examples/{{example}}

sudo-run example:
    just build-example {{example}}
    sudo ./target/debug/examples/{{example}}

fmt:
    cargo fmt

clippy:
    cargo clippy --tests -- -D warnings

alias r := run
alias t := test
