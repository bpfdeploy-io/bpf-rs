use std::env;

use bpf_rs::libbpf_sys;
use bpf_obj_dump::{dump_program, ProgramDumpMode};

fn main() {
    let mut args = env::args();
    if args.len() < 2 {
        panic!("not enough args")
    }
    let _ = args.next().unwrap();
    let id = args.next().unwrap().parse::<u32>().unwrap();
    let prog_fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) };
    println!("{:#?}", dump_program(prog_fd, ProgramDumpMode::Xlated));
}
