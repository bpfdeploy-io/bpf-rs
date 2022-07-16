default:
    @just --list

test:
    cargo test --all-features

sudotest:
    sudo -E "PATH=$PATH" $(which cargo) t --all-features

build-example example:
    cargo build --all-features --example {{example}}

run example:
    just build-example {{example}}
    ./target/debug/examples/{{example}}

sudorun example:
    just build-example {{example}}
    sudo ./target/debug/examples/{{example}}

fmt:
    cargo fmt

clippy:
    cargo clippy --tests -- -D warnings

alias r := run
alias t := test
