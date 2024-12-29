#include "x86_64.hpp"

#include <unordered_map>
#include <iostream>
#include <cassert>
#include <algorithm>

static x86_64::OperatingMode current_mode = x86_64::MODE_64_BIT;

/* For each instruction, the encodings are sorted in ascending order by their opcode */
static std::unordered_map<u8, x86_64::EncodingList> instructions = {
    {x86_64::ADD, {
        {x86_64::ADD, {0x00}, {0x00, 0x00, 0x00}, 1, x86_64::OP_EN_MR, 0, true},
        {x86_64::ADD, {0x00}, {0x01, 0x00, 0x00}, 1, x86_64::OP_EN_MR, 0, false},
        {x86_64::ADD, {0x00}, {0x02, 0x00, 0x00}, 1, x86_64::OP_EN_RM, 0, true},
        {x86_64::ADD, {0x00}, {0x03, 0x00, 0x00}, 1, x86_64::OP_EN_RM, 0, false},
        {x86_64::ADD, {0x00}, {0x80, 0x00, 0x00}, 1, x86_64::OP_EN_MI, 0, true},
        {x86_64::ADD, {0x00}, {0x81, 0x00, 0x00}, 1, x86_64::OP_EN_MI, 0, false},
    }},
    {x86_64::SUB, {
        {x86_64::SUB, {0x00}, {0x28, 0x00, 0x00}, 1, x86_64::OP_EN_MR, 0, true},
        {x86_64::SUB, {0x00}, {0x29, 0x00, 0x00}, 1, x86_64::OP_EN_MR, 0, false},
        {x86_64::SUB, {0x00}, {0x2A, 0x00, 0x00}, 1, x86_64::OP_EN_RM, 0, true},
        {x86_64::SUB, {0x00}, {0x2B, 0x00, 0x00}, 1, x86_64::OP_EN_RM, 0, false},
        {x86_64::SUB, {0x00}, {0x80, 0x00, 0x00}, 1, x86_64::OP_EN_MI, 5, true},
        {x86_64::SUB, {0x00}, {0x81, 0x00, 0x00}, 1, x86_64::OP_EN_MI, 5, false},
    }},
    {x86_64::IMUL, {
        /* TODO: needs RMI encoding support */
        {x86_64::IMUL, {0x00}, {0x0F, 0xAF, 0x00}, 2, x86_64::OP_EN_RM, 0, false},
    }},
    {x86_64::DIV, {
        {x86_64::DIV, {0x00}, {0xF6, 0x00, 0x00}, 1, x86_64::OP_EN_M, 6, true},
        {x86_64::DIV, {0x00}, {0xF7, 0x00, 0x00}, 1, x86_64::OP_EN_M, 6, false},
    }},
    {x86_64::IDIV, {
        {x86_64::DIV, {0x00}, {0xF6, 0x00, 0x00}, 1, x86_64::OP_EN_M, 7, true},
        {x86_64::DIV, {0x00}, {0xF7, 0x00, 0x00}, 1, x86_64::OP_EN_M, 7, false},
    }},
    {x86_64::MOV, {
        {x86_64::MOV, {0x00}, {0x88, 0x00, 0x00}, 1, x86_64::OP_EN_MR, 0, true},
        {x86_64::MOV, {0x00}, {0x89, 0x00, 0x00}, 1, x86_64::OP_EN_MR, 0, false},
        {x86_64::MOV, {0x00}, {0x8A, 0x00, 0x00}, 1, x86_64::OP_EN_RM, 0, true},
        {x86_64::MOV, {0x00}, {0x8B, 0x00, 0x00}, 1, x86_64::OP_EN_RM, 0, false},
        {x86_64::MOV, {0x00}, {0xB0, 0x00, 0x00}, 1, x86_64::OP_EN_OI, 0, true},
        {x86_64::MOV, {0x00}, {0xB8, 0x00, 0x00}, 1, x86_64::OP_EN_OI, 0, false},
        {x86_64::MOV, {0x00}, {0xC6, 0x00, 0x00}, 1, x86_64::OP_EN_MI, 0, true},
        {x86_64::MOV, {0x00}, {0xC7, 0x00, 0x00}, 1, x86_64::OP_EN_MI, 0, false},
    }},
    {x86_64::CALL, {
        {x86_64::CALL, {0x00}, {0xE8, 0x00, 0x00}, 1, x86_64::OP_EN_D, 0, false},
        {x86_64::CALL, {0x00}, {0xFF, 0x00, 0x00}, 1, x86_64::OP_EN_M, 2, false},
    }},
    {x86_64::JMP, {
        {x86_64::JMP, {0x00}, {0xE9, 0x00, 0x00}, 1, x86_64::OP_EN_D, 0, false},
        {x86_64::JMP, {0x00}, {0xFF, 0x00, 0x00}, 1, x86_64::OP_EN_M, 4, false},
    }},
    {x86_64::PUSH, {
        {x86_64::PUSH, {0x00}, {0x50, 0x00, 0x00}, 1, x86_64::OP_EN_O, 0, false},
        {x86_64::PUSH, {0x00}, {0x68, 0x00, 0x00}, 1, x86_64::OP_EN_I, 0, false},
        {x86_64::PUSH, {0x00}, {0x6A, 0x00, 0x00}, 1, x86_64::OP_EN_I, 0, true},
        {x86_64::PUSH, {0x00}, {0xFF, 0x00, 0x00}, 1, x86_64::OP_EN_M, 6, false},
    }},
    {x86_64::POP, {
        {x86_64::POP, {0x00}, {0x8F, 0x00, 0x00}, 1, x86_64::OP_EN_M, false},
        {x86_64::POP, {0x00}, {0x58, 0x00, 0x00}, 1, x86_64::OP_EN_O, false},
    }},
    {x86_64::RET, {
        {x86_64::RET, {0x00}, {0xC3, 0x00, 0x00}, 1, x86_64::OP_EN_ZO, false},
    }},
    {x86_64::SYSCALL, {
        {x86_64::SYSCALL, {0x00}, {0x0F, 0x05, 0x00}, 2, x86_64::OP_EN_ZO, false},
    }},
};

/* Some instructions are 64 bit by default in long mode and do not need a REX prefix when encoding */
static std::vector<u8> default_64_bit_opcdoes = {
    x86_64::PUSH,
    x86_64::POP
};

static inline bool is_default_64_bit(u8 opcode) {
    return std::find(default_64_bit_opcdoes.begin(), default_64_bit_opcdoes.end(), opcode) != default_64_bit_opcdoes.end();
}

x86_64::InstructionData x86_64::encode_zo(x86_64::EncodingData data) {
    x86_64::InstructionData insn;
    insn.set_opcode(data.enc_opcode, data.opcode_size);
    return insn;
}

x86_64::InstructionData x86_64::encode_r(x86_64::EncodingData data, x86_64::Reg reg) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(reg)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(reg) && !is_default_64_bit(data.opcode)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(reg)) {
        if(data.encode_operand_in_opcode()) {
            /* 
             * Usually REX.B is used for extending the ModR/M.rm field, but in this case
             * it is used to extend the operand encoded in the opcode.
             */
            rex |= x86_64::REX_B;
        } else {
            rex |= x86_64::REX_R;
        }
        rex_needed = true;
    }
    if(reg == x86_64::REG_SPL
        || reg == x86_64::REG_BPL
        || reg == x86_64::REG_SIL
        || reg == x86_64::REG_DIL) {
        /* These need a REX prefix to access */
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    if(data.encode_operand_in_opcode()) {
        data.enc_opcode[data.opcode_size - 1] |= ENCODE_REG(reg);
    }
    insn.set_opcode(data.enc_opcode, data.opcode_size);

    return insn;
}

x86_64::InstructionData x86_64::encode_i(x86_64::EncodingData data, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    switch(imm.size) {
        case 1:
        {
            insn.set_immediate(imm.val.byte, 1);
            break;
        }
        case 2:
        {
            insn.set_immediate(imm.val.word, 2);
            break;
        }
        case 4:
        {
            insn.set_immediate(imm.val.dword, 4);
            break;
        }
        case 8:
        {
            insn.set_immediate(imm.val.qword, 8);
            break;
        }
        default:
        {
            break;
        }
    }
    return insn;
}

x86_64::InstructionData x86_64::encode_m(x86_64::EncodingData data, x86_64::MemoryValue mem) {
    x86_64::InstructionData insn;

    x86_64::AddressValue addr = mem.addr;

    if(mem.size == 2) {
        /* Operand size override prefix */
        insn.push_prefix(0x66);
    }

    if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
        /* Address size override prefix */
        insn.push_prefix(0x67);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(mem.size == 8 && !is_default_64_bit(data.opcode)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(addr.is_index_valid() && IS_REG_EXTENDED(addr.index)) {
        rex |= x86_64::REX_X;
        rex_needed = true;
    }
    if(addr.is_base_valid() && IS_REG_EXTENDED(addr.base)) {
        rex |= x86_64::REX_B;
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(addr.is_base_valid() && !addr.is_index_valid() && addr.displacement == 0) { /* [base] */
        insn.set_modrm(0, data.default_modrm_reg, ENCODE_REG(addr.base));
    } else if(addr.is_base_valid() && !addr.is_index_valid() && addr.displacement > 0) { /* [base+disp(8/32)] */
        bool is_disp8 = addr.is_displacement_8_bit();
        insn.set_modrm(is_disp8 ? 0b01 : 0b10, data.default_modrm_reg, ENCODE_REG(addr.base));
        insn.set_displacement(addr.displacement, is_disp8 ? 1 : 4);
    } else if(addr.is_base_valid() && addr.is_index_valid() && addr.displacement == 0) { /* [base+(index*scale)] */
        insn.set_modrm(0, data.default_modrm_reg, 0b100);
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), ENCODE_REG(addr.base));
    } else if(addr.is_base_valid() && addr.is_index_valid() && addr.displacement > 0) { /* [base+(index*scale)+disp(8/32)] */
        bool is_disp8 = addr.is_displacement_8_bit();
        insn.set_modrm(is_disp8 ? 0b01 : 0b10, data.default_modrm_reg, 0b100);
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), ENCODE_REG(addr.base));
        insn.set_displacement(addr.displacement, is_disp8 ? 1 : 4);
    } else if(!addr.is_base_valid() && addr.is_index_valid()) { /* [(index*scale)+disp32] */
        insn.set_modrm(0, data.default_modrm_reg, 0b100);
        insn.set_sib(addr.scale, addr.index, 0b101);
        insn.set_displacement(addr.displacement, 4);
    } else if(!addr.is_base_valid() && !addr.is_base_valid()) { /* [disp32] */
        insn.set_modrm(0, data.default_modrm_reg, 0b100);
        insn.set_sib(0, 0b100, 0b101);
        insn.set_displacement(addr.displacement, 4);
    }

    return insn;
}

x86_64::InstructionData x86_64::encode_rr(x86_64::EncodingData data, x86_64::Reg reg, x86_64::Reg rm) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(reg) || IS_REG_16_BIT(rm)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if((IS_REG_64_BIT(reg) || IS_REG_64_BIT(rm)) && !is_default_64_bit(data.opcode)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(reg)) {
        rex |= x86_64::REX_R;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(rm)) {
        rex |= x86_64::REX_B;
        rex_needed = true;
    }
    if(reg == x86_64::REG_SPL || rm == x86_64::REG_SPL
        || reg == x86_64::REG_BPL || rm == x86_64::REG_BPL
        || reg == x86_64::REG_SIL || rm == x86_64::REG_SIL
        || reg == x86_64::REG_DIL || rm == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }
    
    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    insn.set_modrm(3, ENCODE_REG(reg), ENCODE_REG(rm));
    return insn;
}

x86_64::InstructionData x86_64::encode_ri(x86_64::EncodingData data, x86_64::Reg r, bool is_rm, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(r)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(r) && !is_default_64_bit(data.opcode)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(r)) {
        if(is_rm || data.encode_operand_in_opcode()) {
            /* 
             * Usually REX.B is used for extending the ModR/M.rm field, but in this case
             * it is used to extend the operand encoded in the opcode.
             */
            rex |= x86_64::REX_B;
        } else {
            rex |= x86_64::REX_R;
        }
        rex_needed = true;
    }
    if(r == x86_64::REG_SPL
        || r == x86_64::REG_BPL
        || r == x86_64::REG_SIL
        || r == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }
    
    if(rex_needed) {
        insn.set_rex(rex);
    }

    if(data.encode_operand_in_opcode()) {
        data.enc_opcode[data.opcode_size - 1] |= ENCODE_REG(r);
    }
    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(!data.encode_operand_in_opcode()) {
        insn.set_modrm(3, data.default_modrm_reg, r % 8);
    }

    switch(imm.size) {
        case 1:
        {
            insn.set_immediate(imm.val.byte, 1);
            break;
        }
        case 2:
        {
            insn.set_immediate(imm.val.word, 2);
            break;
        }
        case 4:
        {
            insn.set_immediate(imm.val.dword, 4);
            break;
        }
        case 8:
        {
            insn.set_immediate(imm.val.qword, 8);
            break;
        }
        default:
        {
            break;
        }
    }
    return insn;
}

x86_64::InstructionData x86_64::encode_rm(x86_64::EncodingData data, x86_64::Reg reg, x86_64::MemoryValue mem) {
    x86_64::InstructionData insn;

    x86_64::AddressValue addr = mem.addr;

    if(IS_REG_16_BIT(reg)) {
        /* Operand size override prefix */
        insn.push_prefix(0x66);
    }

    if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
        /* Address size override prefix */
        insn.push_prefix(0x67);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(reg) && !is_default_64_bit(data.opcode)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(reg)) {
        rex |= x86_64::REX_R;
        rex_needed = true;
    }
    if(addr.is_index_valid() && IS_REG_EXTENDED(addr.index)) {
        rex |= x86_64::REX_X;
        rex_needed = true;
    }
    if(addr.is_base_valid() && IS_REG_EXTENDED(addr.base)) {
        rex |= x86_64::REX_B;
        rex_needed = true;
    }
    if(reg == x86_64::REG_SPL
        || reg == x86_64::REG_BPL
        || reg == x86_64::REG_SIL
        || reg == x86_64::REG_DIL) {
        /* These need a REX prefix to access */
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(addr.is_base_valid() && !addr.is_index_valid() && addr.displacement == 0) { /* [base] */
        insn.set_modrm(0, ENCODE_REG(reg), ENCODE_REG(addr.base));
    } else if(addr.is_base_valid() && !addr.is_index_valid() && addr.displacement > 0) { /* [base+disp(8/32)] */
        bool is_disp8 = addr.is_displacement_8_bit();
        insn.set_modrm(is_disp8 ? 0b01 : 0b10, ENCODE_REG(reg), ENCODE_REG(addr.base));
        insn.set_displacement(addr.displacement, is_disp8 ? 1 : 4);
    } else if(addr.is_base_valid() && addr.is_index_valid() && addr.displacement == 0) { /* [base+(index*scale)] */
        insn.set_modrm(0, ENCODE_REG(reg), 0b100);
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), ENCODE_REG(addr.base));
    } else if(addr.is_base_valid() && addr.is_index_valid() && addr.displacement > 0) { /* [base+(index*scale)+disp(8/32)] */
        bool is_disp8 = addr.is_displacement_8_bit();
        insn.set_modrm(is_disp8 ? 0b01 : 0b10, ENCODE_REG(reg), 0b100);
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), ENCODE_REG(addr.base));
        insn.set_displacement(addr.displacement, is_disp8 ? 1 : 4);
    } else if(!addr.is_base_valid() && addr.is_index_valid()) { /* [(index*scale)+disp32] */
        insn.set_modrm(0, ENCODE_REG(reg), 0b100);
        insn.set_sib(addr.scale, addr.index, 0b101);
        insn.set_displacement(addr.displacement, 4);
    } else if(!addr.is_base_valid() && !addr.is_base_valid()) { /* [disp32] */
        insn.set_modrm(0, ENCODE_REG(reg), 0b100);
        insn.set_sib(0, 0b100, 0b101);
        insn.set_displacement(addr.displacement, 4);
    }

    return insn;
}

x86_64::InstructionData x86_64::encode_mi(x86_64::EncodingData data, x86_64::MemoryValue mem, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    x86_64::AddressValue addr = mem.addr;

    if(imm.size == 2) {
        /* Operand size override prefix */
        insn.push_prefix(0x66);
    }

    if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
        /* Address size override prefix */
        insn.push_prefix(0x67);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(imm.size == 8 && !is_default_64_bit(data.opcode)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(addr.is_index_valid() && IS_REG_EXTENDED(addr.index)) {
        rex |= x86_64::REX_X;
        rex_needed = true;
    }
    if(addr.is_base_valid() && IS_REG_EXTENDED(addr.base)) {
        rex |= x86_64::REX_B;
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(addr.is_base_valid() && !addr.is_index_valid() && addr.displacement == 0) { /* [base] */
        insn.set_modrm(0, data.default_modrm_reg, ENCODE_REG(addr.base));
    } else if(addr.is_base_valid() && !addr.is_index_valid() && addr.displacement > 0) { /* [base+disp(8/32)] */
        bool is_disp8 = addr.is_displacement_8_bit();
        insn.set_modrm(is_disp8 ? 0b01 : 0b10, data.default_modrm_reg, ENCODE_REG(addr.base));
        insn.set_displacement(addr.displacement, is_disp8 ? 1 : 4);
    } else if(addr.is_base_valid() && addr.is_index_valid() && addr.displacement == 0) { /* [base+(index*scale)] */
        insn.set_modrm(0, data.default_modrm_reg, 0b100);
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), ENCODE_REG(addr.base));
    } else if(addr.is_base_valid() && addr.is_index_valid() && addr.displacement > 0) { /* [base+(index*scale)+disp(8/32)] */
        bool is_disp8 = addr.is_displacement_8_bit();
        insn.set_modrm(is_disp8 ? 0b01 : 0b10, data.default_modrm_reg, 0b100);
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), ENCODE_REG(addr.base));
        insn.set_displacement(addr.displacement, is_disp8 ? 1 : 4);
    } else if(!addr.is_base_valid() && addr.is_index_valid()) { /* [(index*scale)+disp32] */
        insn.set_modrm(0, data.default_modrm_reg, 0b100);
        insn.set_sib(addr.scale, addr.index, 0b101);
        insn.set_displacement(addr.displacement, 4);
    } else if(!addr.is_base_valid() && !addr.is_base_valid()) { /* [disp32] */
        insn.set_modrm(0, data.default_modrm_reg, 0b100);
        insn.set_sib(0, 0b100, 0b101);
        insn.set_displacement(addr.displacement, 4);
    }

    switch(imm.size) {
        case 1:
        {
            insn.set_immediate(imm.val.byte, 1);
            break;
        }
        case 2:
        {
            insn.set_immediate(imm.val.word, 2);
            break;
        }
        case 4:
        {
            insn.set_immediate(imm.val.dword, 4);
            break;
        }
        case 8:
        {
            insn.set_immediate(imm.val.qword, 8);
            break;
        }
        default:
        {
            break;
        }
    }

    return insn;
}

x86_64::InstructionData x86_64::encode_zo(u8 opcode) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_ZO) {
            return x86_64::encode_zo(d);
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_r(u8 opcode, x86_64::Reg r1) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_R || d.op_en == x86_64::OP_EN_M || d.op_en == x86_64::OP_EN_O) {
            return x86_64::encode_r(d, r1);
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_i(u8 opcode, x86_64::ImmediateValue imm) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_I || d.op_en == x86_64::OP_EN_D) {
            if(imm.size == 1) {
                if(d.is_8_bit) {
                    return x86_64::encode_i(d, imm);
                }
            } else {
                return x86_64::encode_i(d, imm);
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_m(u8 opcode, x86_64::MemoryValue mem) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_M) {
            /* I don't think we need to test for 8 bits here */
            return x86_64::encode_m(d, mem);
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_rr(u8 opcode, x86_64::Reg r1, x86_64::Reg r2) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_MR || d.op_en == x86_64::OP_EN_RM) {
            if(IS_REG_8_BIT(r1) && IS_REG_8_BIT(r2)) {
                if(d.is_8_bit) {
                    if(d.op_en == x86_64::OP_EN_RM) {
                        return x86_64::encode_rr(d, r1, r2);
                    } else if(d.op_en == x86_64::OP_EN_MR) {
                        return x86_64::encode_rr(d, r2, r1);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.op_en == x86_64::OP_EN_RM) {
                        return x86_64::encode_rr(d, r1, r2);
                    } else if(d.op_en == x86_64::OP_EN_MR) {
                        return x86_64::encode_rr(d, r2, r1);
                    }
                }
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_ri(u8 opcode, x86_64::Reg r1, x86_64::ImmediateValue imm) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_OI || d.op_en == x86_64::OP_EN_MI) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    if(d.op_en == x86_64::OP_EN_OI) {
                        /* If the type is OI, we cannot have r/m because only reg can be encoded in the opcode */
                        return x86_64::encode_ri(d, r1, false, imm);
                    } else if(d.op_en == x86_64::OP_EN_MI) {
                        return x86_64::encode_ri(d, r1, true, imm);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.op_en == x86_64::OP_EN_OI) {
                        /* If the type is OI, we cannot have r/m because only reg can be encoded in the opcode */
                        return x86_64::encode_ri(d, r1, false, imm);
                    } else if(d.op_en == x86_64::OP_EN_MI) {
                        return x86_64::encode_ri(d, r1, true, imm);
                    }
                }
            }
        }
    }

    return x86_64::InstructionData();
}

/*
 * Both this and encode_mr use encode_rm internally. This is because both operands are encoded
 * the same way, the only thing that determines the direction is the opcode.
 */
x86_64::InstructionData x86_64::encode_rm(u8 opcode, x86_64::Reg r1, x86_64::MemoryValue mem) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_RM) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    return x86_64::encode_rm(d, r1, mem);
                }
            } else {
                if(!d.is_8_bit) {
                    return x86_64::encode_rm(d, r1, mem);
                }
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_mr(u8 opcode, x86_64::MemoryValue mem, x86_64::Reg r1) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OP_EN_MR) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    return x86_64::encode_rm(d, r1, mem);
                }
            } else {
                if(!d.is_8_bit) {
                    return x86_64::encode_rm(d, r1, mem);
                }
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_mi(u8 opcode, x86_64::MemoryValue mem, x86_64::ImmediateValue imm) {
    for(EncodingData d : instructions[opcode]) {
        /* Note: we don't check for OI because we're moving imm to r/m which cannot be encoded in the opcode */
        if(d.op_en == x86_64::OP_EN_MI) {
            if(imm.size == 1) {
                if(d.is_8_bit) {
                    return x86_64::encode_mi(d, mem, imm);
                }
            } else {
                if(!d.is_8_bit) {
                    return x86_64::encode_mi(d, mem, imm);
                }
            }
        }
    }

    return x86_64::InstructionData();
}

void x86_64::set_mode(x86_64::OperatingMode mode) {
    current_mode = mode;
}

x86_64::OperatingMode x86_64::get_current_mode() {
    return current_mode;
}