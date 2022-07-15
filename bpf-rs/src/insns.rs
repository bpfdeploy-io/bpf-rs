// TODO: #![warn(missing_docs)]
// TODO: #![warn(missing_doc_code_examples)]
//! Primitives for the eBPF instruction set. See [kernel docs](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html)
//! for the canonical details
//!
//! The exports here should allow for the creation of simple eBPF programs that can be loaded into the kernel.
//! The functions provide a convenient away to create valid instructions.
//!
//! The exported functions currently return the underlying libbpf_sys's `bpf_insn` binding
//! so loading the program  through other libbpf_sys functions should work.
//! In the future, we should provide convenient functions to encapsulate this.
//!
//! # Instruction set (ISA) versions
//!
//! Not all of the instructions currently available were released at the same time. Instructions (mostly for jump ops)
//! have been added over time, resulting in different versions of the eBPF instruction set. We will denote
//! if an operation is part of the v2 or v3 instruction set.
//!
//! For more info, see [BPF Design Q&A](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-why-bpf-jlt-and-bpf-jle-instructions-were-not-introduced-in-the-beginning)
//! and [Paul Chaignon's blog post](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html)
//!
//! # Example
//!
//! As an example use case of the primitives here, for feature detection we can run a small eBPF
//! program that determines if [bounded loops](https://lwn.net/Articles/794934/)
//! (introduced in the v5.3 kernel) are supported:
//!
//!```
//! # fn load_insns<S>(v: Vec<S>) -> bool { true }
//! use bpf_rs::insns::*;
//! // Inspired by bpftool's feature probing
//! let bounded_loops_insns = vec![
//!     mov64_imm(Register::R0, 10),
//!     alu64_imm(AluOp::SUB, Register::R0, 1),
//!     jmp_imm(JmpOp::JNE, Register::R0, 0, -2),
//!     exit(),
//! ];
//! // Returns true if program was successfully loaded into the kernel
//! let bounded_loops_supported: bool = load_insns(bounded_loops_insns);
//!```
//!
use libbpf_sys as sys;
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Instruction classes
///
/// **Note**: 32-bit ALU ops are denoted with [`Class::ALU`] and 64-bit ALU ops are
/// [`Class::ALU64`] yet 32-bit jump ops are in [`Class::JMP32`] and 64-bit jump ops are in [`Class::JMP`].
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Immediate loads
    LD = sys::BPF_LD as u8,
    /// Register loads
    LDX = sys::BPF_LDX as u8,
    /// Immediate stores
    ST = sys::BPF_ST as u8,
    /// Register stores
    STX = sys::BPF_STX as u8,
    /// Arithmetic operations (32-bit)
    ALU = sys::BPF_ALU as u8,
    /// Arithmetic operation (64-bit)
    ALU64 = sys::BPF_ALU64 as u8,
    /// Jump operations (64-bit)
    JMP = sys::BPF_JMP as u8,
    /// Jump operations (32-bit)
    JMP32 = sys::BPF_JMP32 as u8,
}

/// # eBPF Registers
///
/// Quoting the [kernel documentation](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#registers-and-calling-convention)
/// on eBPF registers:
///
/// > eBPF has **10 general purpose registers** and a read-only frame pointer register, all of which are 64-bits wide.
/// >
/// > The eBPF calling convention is defined as:
/// >
/// >  - `R0`: return value from function calls, and exit value for eBPF programs
/// >
/// >  - `R1` - `R5`: arguments for function calls
/// >
/// >  - `R6` - `R9`: callee saved registers that function calls will preserve
/// >
/// >  - `R10`: read-only frame pointer to access stack
/// >
/// > `R0` - `R5` are scratch registers and eBPF programs needs to spill/fill them if necessary across calls.
///
/// Source: [kernel tree](https://github.com/torvalds/linux/blob/d569e86915b7f2f9795588591c8d5ea0b66481cb/tools/include/uapi/linux/bpf.h#L53)
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    /// Usually used as either the return value in function calls or as the exit value in programs
    R0 = sys::BPF_REG_0 as u8,
    ///
    R1 = sys::BPF_REG_1 as u8,
    ///
    R2 = sys::BPF_REG_2 as u8,
    ///
    R3 = sys::BPF_REG_3 as u8,
    ///
    R4 = sys::BPF_REG_4 as u8,
    ///
    R5 = sys::BPF_REG_5 as u8,
    ///
    R6 = sys::BPF_REG_6 as u8,
    ///
    R7 = sys::BPF_REG_7 as u8,
    ///
    R8 = sys::BPF_REG_8 as u8,
    ///
    R9 = sys::BPF_REG_9 as u8,
    /// Read-only frame pointer register
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
    ADD = sys::BPF_ADD as u8,
    /// `dst -= src`
    SUB = sys::BPF_SUB as u8,
    /// `dst *= src`
    MUL = sys::BPF_MUL as u8,
    /// `dst /= src`
    DIV = sys::BPF_DIV as u8,
    /// `dst |= src`
    OR = sys::BPF_OR as u8,
    /// `dst &= src`
    AND = sys::BPF_AND as u8,
    /// `dst <<= src`
    LSH = sys::BPF_LSH as u8,
    /// `dst >>= src`
    RSH = sys::BPF_RSH as u8,
    /// `dst = ~src`
    NEG = sys::BPF_NEG as u8,
    /// `dst %= src`
    MOD = sys::BPF_MOD as u8,
    /// `dst ^= src`
    XOR = sys::BPF_XOR as u8,
    /// `dst = src`
    MOV = sys::BPF_MOV as u8,
    /// `dst >>= src` (with sign extension)
    ARSH = sys::BPF_ARSH as u8,
    /// Byte swap operations. See [kernel docs](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#byte-swap-instructions)
    END = sys::BPF_END as u8,
}

/// Jump operations
///
/// To be used with the BPF_JMP and BPF_JMP32 instruction classes
///
/// See [kernel docs](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#jump-instructions)
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JmpOp {
    /// Only allowed with the BPF_JMP instruction class
    JA = sys::BPF_JA as u8,
    JEQ = sys::BPF_JEQ as u8,
    JGT = sys::BPF_JGT as u8,
    JGE = sys::BPF_JGE as u8,
    JSET = sys::BPF_JSET as u8,
    JNE = sys::BPF_JNE as u8,
    JSGT = sys::BPF_JSGT as u8,
    JSGE = sys::BPF_JSGE as u8,
    CALL = sys::BPF_CALL as u8,
    EXIT = sys::BPF_EXIT as u8,
    /// Part of [ISA v2](./#instruction-set-isa-versions)
    JLT = sys::BPF_JLT as u8,
    /// Part of [ISA v2](./#instruction-set-isa-versions)
    JLE = sys::BPF_JLE as u8,
    /// Part of [ISA v2](./#instruction-set-isa-versions)
    JSLT = sys::BPF_JSLT as u8,
    /// Part of [ISA v2](./#instruction-set-isa-versions)
    JSLE = sys::BPF_JSLE as u8,
}

#[repr(u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrcOp {
    K = sys::BPF_K as u8,
    X = sys::BPF_X as u8,
}

// Since Rust lacks native support for bitfields, rust-bindgen tries its best.
// Hopefully this is good enough, but if not we'll need helpers from libbpf-sys.
fn create_bpf_insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> sys::bpf_insn {
    return sys::bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: sys::bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    };
}

pub fn alu64_imm(op: AluOp, dst: Register, imm: i32) -> sys::bpf_insn {
    create_bpf_insn(
        u8::from(op) | u8::from(SrcOp::K) | u8::from(Class::ALU64),
        dst.into(),
        0,
        0,
        imm,
    )
}

pub fn mov64_imm(dst: Register, imm: i32) -> sys::bpf_insn {
    alu64_imm(AluOp::MOV, dst, imm)
}

pub fn alu64_reg(op: AluOp, dst: Register, src: Register) -> sys::bpf_insn {
    create_bpf_insn(
        u8::from(op) | u8::from(SrcOp::X) | u8::from(Class::ALU64),
        dst.into(),
        src.into(),
        0,
        0,
    )
}

pub fn mov64_reg(dst: Register, src: Register) -> sys::bpf_insn {
    alu64_reg(AluOp::MOV, dst, src)
}

pub fn jmp_imm(jmp: JmpOp, dst: Register, imm: i32, off: i16) -> sys::bpf_insn {
    create_bpf_insn(
        u8::from(jmp) | u8::from(SrcOp::K) | u8::from(Class::JMP),
        dst.into(),
        0,
        off,
        imm,
    )
}

pub fn jmp32_imm(jmp: JmpOp, dst: Register, imm: i32, off: i16) -> sys::bpf_insn {
    create_bpf_insn(
        u8::from(jmp) | u8::from(SrcOp::K) | u8::from(Class::JMP32),
        dst.into(),
        0,
        off,
        imm,
    )
}

pub fn exit() -> sys::bpf_insn {
    create_bpf_insn(u8::from(JmpOp::EXIT) | u8::from(Class::JMP), 0, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpfdeploy_libbpf_sys as sys;

    #[test]
    fn test_abi_compat() {
        let dst = Register::R2;
        let imm = 123123;

        vec![
            (
                unsafe { sys::_BPF_MOV64_IMM(dst.into(), imm) },
                mov64_imm(dst, imm),
            ),
            (
                unsafe { sys::_BPF_ALU64_IMM(AluOp::MOV.into(), dst.into(), imm) },
                alu64_imm(AluOp::MOV, dst, imm),
            ),
            (
                unsafe { sys::_BPF_JMP_IMM(JmpOp::JNE.into(), dst.into(), 32, 10) },
                jmp_imm(JmpOp::JNE, dst, 32, 10),
            ),
            (
                unsafe { sys::_BPF_JMP32_IMM(JmpOp::JNE.into(), dst.into(), 1000, 500) },
                jmp32_imm(JmpOp::JNE, dst, 1000, 500),
            ),
            (unsafe { sys::_BPF_EXIT_INSN() }, exit()),
        ]
        .iter()
        .for_each(|(expected_insn, observed_insn)| {
            assert_eq!(expected_insn.code, observed_insn.code);
            assert_eq!(expected_insn.dst_reg(), observed_insn.dst_reg());
            assert_eq!(expected_insn.src_reg(), observed_insn.src_reg());
            assert_eq!(expected_insn.off, observed_insn.off);
            assert_eq!(expected_insn.imm, observed_insn.imm);
        })
    }
}
