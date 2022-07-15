default:
    @just --list

test:
    cargo test --all-features

build-example example:
    cargo build --all-features --example {{example}}

run example:
    just build-example {{example}}
    ./target/debug/examples/{{example}}

sudorun example:
    just build-example {{example}}
    sudo ./target/debug/examples/{{example}}

alias r := run
alias sr := sudorun
alias t := test
