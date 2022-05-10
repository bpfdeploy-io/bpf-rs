//! Features for miscellaneous eBPF subsystem properties
use bpf_rs::{
    insns::{alu64_imm, exit, jmp32_imm, jmp_imm, mov64_imm, AluOp, JmpOp, Register},
    libbpf_sys::{bpf_insn, bpf_prog_load, BPF_MAXINSNS},
    ProgramLicense, ProgramType,
};
use nix::{
    errno::{errno, Errno},
    unistd,
};
use std::ptr;

#[cfg(feature="serde")]
use serde::Serialize;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Misc {
    pub large_insn_limit: bool,
    pub bounded_loops: bool,
    pub isa_v2_ext: bool,
    pub isa_v3_ext: bool,
}

impl Misc {
    fn load_insns(insns: Vec<bpf_insn>) -> bool {
        Errno::clear();
        let fd = unsafe {
            bpf_prog_load(
                ProgramType::SocketFilter.into(),
                ptr::null(),
                ProgramLicense::GPL.as_ptr(),
                insns.as_ptr(),
                u64::try_from(insns.len()).unwrap_or(0u64),
                ptr::null(),
            )
        };

        let success = fd >= 0 || errno() == 0;

        if fd >= 0 {
            let _ = unistd::close(fd);
        }

        success
    }

    fn probe_large_insn_limit() -> bool {
        let max_insns = usize::try_from(BPF_MAXINSNS).unwrap();
        let mut large_insn_prog = vec![mov64_imm(Register::R0, 1); max_insns + 1];
        large_insn_prog[max_insns] = exit();
        Self::load_insns(large_insn_prog)
    }

    fn probe_bounded_loops() -> bool {
        let insns = vec![
            mov64_imm(Register::R0, 10),
            alu64_imm(AluOp::SUB, Register::R0, 1),
            jmp_imm(JmpOp::JNE, Register::R0, 0, -2),
            exit(),
        ];
        Self::load_insns(insns)
    }

    fn probe_isa_v2() -> bool {
        let insns = vec![
            mov64_imm(Register::R0, 0),
            jmp_imm(JmpOp::JLT, Register::R0, 0, 1),
            mov64_imm(Register::R0, 1),
            exit(),
        ];
        Self::load_insns(insns)
    }

    fn probe_isa_v3() -> bool {
        let insns = vec![
            mov64_imm(Register::R0, 0),
            jmp32_imm(JmpOp::JLT, Register::R0, 0, 1),
            mov64_imm(Register::R0, 1),
            exit(),
        ];
        Self::load_insns(insns)
    }
}

pub fn features() -> Misc {
    Misc {
        large_insn_limit: Misc::probe_large_insn_limit(),
        bounded_loops: Misc::probe_bounded_loops(),
        isa_v2_ext: Misc::probe_isa_v2(),
        isa_v3_ext: Misc::probe_isa_v3(),
    }
}
