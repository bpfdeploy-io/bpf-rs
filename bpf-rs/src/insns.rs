//! Primitives for the eBPF instruction set. See [kernel documentation](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html)
//!
//! The exports here should allow for the creation of eBPF programs that can be loaded into the kernel.
//! The functions provide a convenient away to create valid instructions.
//!
//! The exported functions currently return the underlying libbpf_sys's bpf_insn binding of
//! so loading the program  through other libbpf_sys functions should work.
//! In the future, we should provide convenient functions to encapsulate this.
//!
use libbpf_sys as sys;
use libbpf_sys::{
    bpf_insn, BPF_JLT, BPF_JNE, _BPF_ALU64_IMM, _BPF_EXIT_INSN, _BPF_JMP32_IMM, _BPF_JMP_IMM,
    _BPF_MOV64_IMM,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};

// TODO: Instruction classes

/// Register variants
///
/// Source: [kernel tree](https://github.com/torvalds/linux/blob/d569e86915b7f2f9795588591c8d5ea0b66481cb/tools/include/uapi/linux/bpf.h#L53)
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    R0 = sys::BPF_REG_0 as u8,
    R1 = sys::BPF_REG_1 as u8,
    R2 = sys::BPF_REG_2 as u8,
    R3 = sys::BPF_REG_3 as u8,
    R4 = sys::BPF_REG_4 as u8,
    R5 = sys::BPF_REG_5 as u8,
    R6 = sys::BPF_REG_6 as u8,
    R7 = sys::BPF_REG_7 as u8,
    R8 = sys::BPF_REG_8 as u8,
    R9 = sys::BPF_REG_9 as u8,
    R10 = sys::BPF_REG_10 as u8,
}

/// Arithmetic instructions
///
/// These are meant to be used with the BPF_ALU and BPF_ALU64 instruction classes.
///
/// In the pseudo-code described below, `dst` and `src` can refer to registers or immediate values
/// depending on other bits set within the opcode.
///
/// Source: [kernel tree](https://github.com/torvalds/linux/blob/d569e86915b7f2f9795588591c8d5ea0b66481cb/tools/include/uapi/linux/bpf_common.h#L31)
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AluOp {
    /// `dst += src`
    Add = sys::BPF_ADD as u8,
    /// `dst -= src`
    Sub = sys::BPF_SUB as u8,
    /// `dst *= src`
    Mul = sys::BPF_MUL as u8,
    /// `dst /= src`
    Div = sys::BPF_DIV as u8,
    /// `dst |= src`
    Or = sys::BPF_OR as u8,
    /// `dst &= src`
    And = sys::BPF_AND as u8,
    /// `dst <<= src`
    Lsh = sys::BPF_LSH as u8,
    /// `dst >>= src`
    Rsh = sys::BPF_RSH as u8,
    /// `dst = ~src`
    Neg = sys::BPF_NEG as u8,
    /// `dst %= src`
    Mod = sys::BPF_MOD as u8,
    /// `dst ^= src`
    Xor = sys::BPF_XOR as u8,
    /// `dst = src`
    Mov = sys::BPF_MOV as u8,
    /// `dst >>= src` (with sign extension)
    Arsh = sys::BPF_ARSH as u8,
    /// Byte swap operations. See [kernel docs](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#byte-swap-instructions)
    End = sys::BPF_END as u8,
}

/// Jump operations
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JmpOp {
    JNE = BPF_JNE as u8,
    JLT = BPF_JLT as u8,
}

pub fn mov64_imm(reg: Register, imm: i32) -> bpf_insn {
    unsafe { _BPF_MOV64_IMM(reg.into(), imm) }
}

pub fn alu64_imm(op: AluOp, reg: Register, imm: i32) -> bpf_insn {
    unsafe { _BPF_ALU64_IMM(op.into(), reg.into(), imm) }
}

pub fn jmp_imm(jmp: JmpOp, reg: Register, imm: i32, off: i16) -> bpf_insn {
    unsafe { _BPF_JMP_IMM(jmp.into(), reg.into(), imm, off) }
}

pub fn jmp32_imm(jmp: JmpOp, reg: Register, imm: i32, off: i16) -> bpf_insn {
    unsafe { _BPF_JMP32_IMM(jmp.into(), reg.into(), imm, off) }
}

pub fn exit() -> bpf_insn {
    unsafe { _BPF_EXIT_INSN() }
}
