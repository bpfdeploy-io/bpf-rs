use bpf_obj_dump::{dump_program, ProgramDumpMode};

fn main() {
    let prog_fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(27) };
    println!("{:#?}", dump_program(prog_fd, ProgramDumpMode::Jited));
}
