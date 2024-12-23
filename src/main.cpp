#include <iostream>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <cstdio>

#include "x86_64.hpp"

constexpr u8 OPTYPE_REG_REG = 1 << 0;
constexpr u8 OPTYPE_REG_IMM = 1 << 1;
constexpr u8 OPTYPE_REG_MEM = 1 << 2;
constexpr u8 OPTYPE_MEM_REG = 1 << 3;

constexpr u8 OP_ORDER_REG_RM = 0;
constexpr u8 OP_ORDER_RM_REG = 1;

const x86_64::EncodingData mov_encoding[] {
    {
        0x00,
        {0x00},
        {0x8B, 0x00, 0x00},
        OPTYPE_REG_REG, // TODO: more types
    },
    {
        0x00,
        {0x00},
        {0x8A, 0x00, 0x00},
        OPTYPE_REG_REG, // TODO: more types
    },
    {
        0x00,
        {0x00},
        {0x89, 0x00, 0x00},
        OPTYPE_REG_REG,
    }
};

const x86_64::EncodingData add_encoding[] {
    {
        0x01,
        {0x00},
        {0x03, 0x00, 0x00},
        OPTYPE_REG_REG,
    },
    {
        0x01,
        {0x00},
        {0x81, 0x00, 0x00},
        OPTYPE_REG_REG,
    },
};

const x86_64::EncodingData call_encoding[] {
    {
        0x02,
        {0x00},
        {0xE8, 0x00, 0x00},
        OPTYPE_REG_REG,
    }
};

// static const InstructionData encode_r(EncodingData data, u8 r1) {

// }

// static const x86_64::InstructionData encode_i(EncodingData data, x86_64::ImmediateValue imm) {
//     x86_64::InstructionData insn;

//     insn.set_opcode_3b(
//         data.enc_opcode[0],
//         data.enc_opcode[1],
//         data.enc_opcode[2]);

//     switch(imm.size) {
//         case 1:
//         {
//             insn.set_immediate(imm.val.byte, 1);
//             break;
//         }
//         case 2:
//         {
//             insn.set_immediate(imm.val.word, 2);
//             break;
//         }
//         case 4:
//         {
//             insn.set_immediate(imm.val.dword, 4);
//             break;
//         }
//         case 8:
//         {
//             insn.set_immediate(imm.val.qword, 8);
//             break;
//         }
//         default:
//         {
//             break;
//         }
//     }
//     return insn;
// }

// // r1 = reg, r2 = r/m
// static const InstructionData encode_rr(EncodingData data, u8 r1, u8 r2) {
//     InstructionData insn;

//     if(IS_REG_16_BIT(r1) || IS_REG_16_BIT(r2)) {
//         insn.push_prefix(0x66);
//     }

//     bool rex_needed = false;
//     u8 rex = REX_BASE;
//     if(IS_REG_64_BIT(r1) || IS_REG_64_BIT(r2)) {
//         rex |= REX_W;
//         rex_needed = true;
//     }
//     if(IS_REG_EXTENDED(r1)) {
//         rex |= REX_R;
//         rex_needed = true;
//     }
//     if(IS_REG_EXTENDED(r2)) {
//         rex |= REX_B;
//         rex_needed = true;
//     }
//     if(r1 == REG_SPL || r2 == REG_SPL
//         || r1 == REG_BPL || r2 == REG_BPL
//         || r1 == REG_SIL || r2 == REG_SIL
//         || r1 == REG_DIL || r2 == REG_DIL) {
//         // These need a REX prefix to access
//         rex_needed = true;
//     }
    
//     if(rex_needed) {
//         insn.set_rex(rex);
//     }

//     insn.set_opcode_3b(
//         data.enc_opcode[0],
//         data.enc_opcode[1],
//         data.enc_opcode[2]);

//     insn.set_modrm(3, r1 % 8, r2 % 8);
//     return insn;
// }

// // r1 = r/m
// static const InstructionData encode_ri(EncodingData data, u8 r1, ImmediateValue imm) {
//     InstructionData insn;

//     if(IS_REG_16_BIT(r1)) {
//         insn.push_prefix(0x66);
//     }

//     bool rex_needed = false;
//     u8 rex = REX_BASE;
//     if(IS_REG_64_BIT(r1)) {
//         rex |= REX_W;
//         rex_needed = true;
//     }
//     if(IS_REG_EXTENDED(r1)) {
//         rex |= REX_R;
//         rex_needed = true;
//     }
//     if(r1 == REG_SPL
//         || r1 == REG_BPL
//         || r1 == REG_SIL
//         || r1 == REG_DIL) {
//         // These need a REX prefix to access
//         rex_needed = true;
//     }
    
//     if(rex_needed) {
//         insn.set_rex(rex);
//     }

//     insn.set_opcode_3b(
//         data.enc_opcode[0],
//         data.enc_opcode[1],
//         data.enc_opcode[2]);

//     insn.set_modrm(3, 0, r1 % 8);

//     switch(imm.size) {
//         case 1:
//         {
//             insn.set_immediate(imm.val.byte, 1);
//             break;
//         }
//         case 2:
//         {
//             insn.set_immediate(imm.val.word, 2);
//             break;
//         }
//         case 4:
//         {
//             insn.set_immediate(imm.val.dword, 4);
//             break;
//         }
//         case 8:
//         {
//             insn.set_immediate(imm.val.qword, 8);
//             break;
//         }
//         default:
//         {
//             break;
//         }
//     }
//     return insn;
// }

// // [base]: no SIB
// // [base+disp]: no SIB

// // [base+index*scale]: SIB
// // [index*scale+disp]: SIB
// // [base+index*scale+disp]: SIB
// static const InstructionData encode_rm(EncodingData data, u8 r1, AddressValue addr) {
//     InstructionData insn;

//     if(IS_REG_16_BIT(r1)) {
//         insn.push_prefix(0x66);
//     }

//     if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
//         insn.push_prefix(0x67);
//     }

//     bool rex_needed = false;
//     u8 rex = REX_BASE;
//     if(IS_REG_64_BIT(r1)) {
//         rex |= REX_W;
//         rex_needed = true;
//     }
//     if(IS_REG_EXTENDED(r1)) {
//         rex |= REX_R;
//         rex_needed = true;
//     }
//     if(addr.is_index_valid() && IS_REG_EXTENDED(addr.index)) {
//         rex |= REX_X;
//         rex_needed = true;
//     }
//     if(addr.is_base_valid() && IS_REG_EXTENDED(addr.base)) {
//         rex |= REX_B;
//         rex_needed = true;
//     }
//     if(r1 == REG_SPL
//         || r1 == REG_BPL
//         || r1 == REG_SIL
//         || r1 == REG_DIL) {
//         // These need a REX prefix to access
//         rex_needed = true;
//     }

//     if(rex_needed) {
//         insn.set_rex(rex);
//     }

//     insn.set_opcode_3b(
//         data.enc_opcode[0],
//         data.enc_opcode[1],
//         data.enc_opcode[2]);
    
//     bool has_sib = addr.is_index_valid(); // We only need an SIB byte if we have a scaled index
//     bool has_displacement = addr.displacement > 0;

//     insn.set_modrm(
//         has_displacement && addr.is_base_valid() ? 2 : 0, // If we have no base, we omit mod 10
//         ENCODE_REG(r1),
//         has_sib ? 4 : ENCODE_REG(addr.base));

//     has_displacement |= (!addr.is_base_valid() && addr.is_index_valid()); // Edge case

//     if(has_sib) {
//         insn.set_sib(addr.scale, ENCODE_REG(addr.index), !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base));
//         if(((insn.sib & 3) == 0b101) || has_displacement) {
//             insn.set_displacement(addr.displacement, 4);
//         }
//     } else {
//         if(has_displacement) {
//             insn.set_displacement(addr.displacement, 4);
//         }
//     }

//     return insn;
// }

static void print_bytes(const std::vector<u8> &bytes) {
    for(u8 b : bytes) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (u32)b << " ";
    }
    std::cout << std::endl;
}

int main() {
    std::vector<u8> bytes;
    x86_64::InstructionData insn;

    std::cout << "mov rax, rcx" << std::endl;
    insn = x86_64::encode_rr(mov_encoding[0], x86_64::REG_RAX, x86_64::REG_RCX);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov edx, r12d" << std::endl;
    insn = x86_64::encode_rr(mov_encoding[0], x86_64::REG_EDX, x86_64::REG_R12D);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov cx, ax" << std::endl;
    insn = x86_64::encode_rr(mov_encoding[0], x86_64::REG_CX, x86_64::REG_AX);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov r8w, dx" << std::endl;
    insn = x86_64::encode_rr(mov_encoding[0], x86_64::REG_R8W, x86_64::REG_DX);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov al, spl" << std::endl;
    insn = x86_64::encode_rr(mov_encoding[1], x86_64::REG_AL, x86_64::REG_SPL);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov spl, al" << std::endl;
    insn = x86_64::encode_rr(mov_encoding[1], x86_64::REG_SPL, x86_64::REG_AL);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "add rax, rdx" << std::endl;
    insn = x86_64::encode_rr(add_encoding[0], x86_64::REG_RAX, x86_64::REG_RDX);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "add ecx, r12d" << std::endl;
    insn = x86_64::encode_rr(add_encoding[0], x86_64::REG_CX, x86_64::REG_R12W);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "add rcx, 0x1234" << std::endl;
    x86_64::ImmediateValue imm = {0};
    imm.size = 4;
    imm.type = x86_64::ImmediateValue::IMM_INT;
    imm.val.word = 0x1234;
    insn = x86_64::encode_ri(add_encoding[1], x86_64::REG_RCX, imm);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov rax, [rcx]" << std::endl;
    x86_64::AddressValue addr1;
    addr1.base = x86_64::REG_RCX;
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_RAX, addr1);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov rax, [rcx*4]" << std::endl;
    x86_64::AddressValue addr2;
    addr2.index = x86_64::REG_RCX;
    addr2.scale = 2; // 1 << 2
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_RAX, addr2);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov rax, [rcx+0x1234]" << std::endl;
    x86_64::AddressValue addr3;
    addr3.base = x86_64::REG_RCX;
    addr3.displacement = 0x1234;
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_RAX, addr3);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov rax, [rcx*4+0x1234]" << std::endl;
    x86_64::AddressValue addr4;
    addr4.index = x86_64::REG_RCX;
    addr4.scale = 2; // 1 << 2;
    addr4.displacement = 0x1234;
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_RAX, addr4);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov rax, [rcx+rdi]" << std::endl;
    x86_64::AddressValue addr5;
    addr5.base = x86_64::REG_RCX;
    addr5.index = x86_64::REG_RDI;
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_RAX, addr5);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov rax, [rdi+rcx*4+0x1234]" << std::endl;
    x86_64::AddressValue addr6;
    addr6.base = x86_64::REG_RDI;
    addr6.index = x86_64::REG_RCX;
    addr6.scale = 2; // 1 << 2
    addr6.displacement = 0x1234;
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_RAX, addr6);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov ax, [r12d+ecx*4+0x1234]" << std::endl;
    x86_64::AddressValue addr7;
    addr7.base = x86_64::REG_R12D;
    addr7.index = x86_64::REG_RCX;
    addr7.scale = 2; // 1 << 2
    addr7.displacement = 0x1234;
    insn = x86_64::encode_rm(mov_encoding[0], x86_64::REG_AX, addr7);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "mov [rax], rcx" << std::endl;
    x86_64::AddressValue addr8;
    addr8.base = x86_64::REG_RAX;
    insn = x86_64::encode_rm(mov_encoding[2], x86_64::REG_RCX, addr8);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    std::cout << "call 0x12345678" << std::endl;
    x86_64::ImmediateValue call_addr = {0};
    call_addr.type = x86_64::ImmediateValue::IMM_INT;
    call_addr.size = 4;
    call_addr.val.dword = 0x12345678;
    insn = x86_64::encode_i(call_encoding[0], call_addr);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    return 0;
}