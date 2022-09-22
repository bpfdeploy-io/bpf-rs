default:
    @just --list

build:
    cargo build --all-features

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

# Depends on the cargo runner being sudo
examples-snapshot:
    cd ./bpf-feature && (cargo run --example feature-probe --all-features > ./examples/feature-probe-example.txt)
    cd ./bpf-feature && (cargo run --example json-dump --all-features > ./examples/json-dump-example.json)

alias b := build
alias r := run
alias t := test
