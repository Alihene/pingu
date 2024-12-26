#include "x86_64.hpp"

#include <unordered_map>
#include <iostream>
#include <cassert>
#include <algorithm>

static x86_64::OperatingMode current_mode = x86_64::MODE_64_BIT;

/* For each instruction, the encodings are sorted in ascending order by their opcode */
static std::unordered_map<u8, x86_64::EncodingList> instructions = {
    {x86_64::ADD, {
        {
            x86_64::ADD,
            {0x00},
            {0x00, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MR,
            // x86_64::OPERAND_DIRECTION_RM_REG,
            0,
            true
        },
        {
            x86_64::ADD,
            {0x00},
            {0x01, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MR,
            // x86_64::OPERAND_DIRECTION_RM_REG,
            0,
            false
        },
        {
            x86_64::ADD,
            {0x00},
            {0x02, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_RM,
            // x86_64::OPERAND_DIRECTION_REG_RM,
            0,
            true
        },
        {
            x86_64::ADD,
            {0x00},
            {0x03, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_RM,
            // x86_64::OPERAND_DIRECTION_REG_RM,
            0,
            false
        },
        {
            x86_64::ADD,
            {0x00},
            {0x80, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MI,
            // x86_64::OPERAND_DIRECTION_RM_IMM,
            0,
            true
        },
        {
            x86_64::ADD,
            {0x00},
            {0x81, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MI,
            // x86_64::OPERAND_DIRECTION_RM_IMM,
            0,
            false
        },
    }},

    {x86_64::MOV, {
        {
            x86_64::MOV,
            {0x00},
            {0x88, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MR,
            // x86_64::OPERAND_DIRECTION_RM_REG,
            0,
            true
        },
        {
            x86_64::MOV,
            {0x00},
            {0x89, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MR,
            // x86_64::OPERAND_DIRECTION_RM_REG,
            0,
            false
        },
        {
            x86_64::MOV,
            {0x00},
            {0x8A, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_RM,
            // x86_64::OPERAND_DIRECTION_REG_RM,
            0,
            true
        },
        {
            x86_64::MOV,
            {0x00},
            {0x8B, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_RM,
            // x86_64::OPERAND_DIRECTION_REG_RM,
            0,
            false
        },
        // TODO: opcode B0
        {
            x86_64::MOV,
            {0x00},
            {0xB8, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_OI,
            // x86_64::OPERAND_DIRECTION_REG_IMM,
            0,
            false
        },
        {
            x86_64::MOV,
            {0x00},
            {0xC6, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MI,
            // x86_64::OPERAND_DIRECTION_RM_IMM,
            0,
            true
        },
        {
            x86_64::MOV,
            {0x00},
            {0xC7, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_MI,
            // x86_64::OPERAND_DIRECTION_RM_IMM,
            0,
            false
        },
    }},
    {x86_64::PUSH, {
        {
            x86_64::PUSH,
            {0x00},
            {0x50, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_O,
            // x86_64::OPERAND_DIRECTION_RM,
            0,
            false
        },
        {
            x86_64::PUSH,
            {0x00},
            {0xFF, 0x00, 0x00},
            1,
            x86_64::OPERAND_ENCODING_M,
            // x86_64::OPERAND_DIRECTION_RM,
            6,
            false
        },
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
    
    /* We only need a SIB byte if we have a scaled index */
    bool has_sib = addr.is_index_valid();

    bool has_displacement = addr.displacement > 0;

    u8 mod;
    if(has_displacement && addr.is_base_valid()) {
        if(addr.is_displacement_8_bit()) {
            /* We can save space by using an 8 bit displacement if we can (not required) */
            mod = 1;
        } else {
            mod = 2;
        }
    } else {
        /*
         * Either we have no displacement at all, or we do but since we don't have a base,
         * the SIB byte indicates the displacement. Either way, mod must be 00 in this case.
         */
        mod = 0;
    }

    insn.set_modrm(
        mod,
        data.default_modrm_reg,
        has_sib ? 4 : ENCODE_REG(addr.base));

    /*
     * Something like [rcx*4] would actually be encoded as [rcx*4+0x0].
     * We need to account for this in case we are missing a base.
     */
    has_displacement |= (!addr.is_base_valid() && addr.is_index_valid());

    if(has_sib) {
        /* 101 (BP) is used to show that there is no base */
        u8 sib_base = !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base);

        insn.set_sib(addr.scale, ENCODE_REG(addr.index), sib_base);

        /* SIB.base = 101 indicates that there is a displacement value */
        if(sib_base == 0b101 || has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
    } else {
        if(has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
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
    
    /* We only need a SIB byte if we have a scaled index */
    bool has_sib = addr.is_index_valid();

    bool has_displacement = addr.displacement > 0;

    u8 mod;
    if(has_displacement && addr.is_base_valid()) {
        if(addr.is_displacement_8_bit()) {
            /* We can save space by using an 8 bit displacement if we can (not required) */
            mod = 1;
        } else {
            mod = 2;
        }
    } else {
        /*
         * Either we have no displacement at all, or we do but since we don't have a base,
         * the SIB byte indicates the displacement. Either way, mod must be 00 in this case.
         */
        mod = 0;
    }

    insn.set_modrm(
        mod,
        ENCODE_REG(reg),
        has_sib ? 4 : ENCODE_REG(addr.base));

    /*
     * Something like [rcx*4] would actually be encoded as [rcx*4+0x0].
     * We need to account for this in case we are missing a base.
     */
    has_displacement |= (!addr.is_base_valid() && addr.is_index_valid());

    if(has_sib) {
        /* 101 (BP) is used to show that there is no base */
        u8 sib_base = !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base);

        insn.set_sib(addr.scale, ENCODE_REG(addr.index), sib_base);

        /* SIB.base = 101 indicates that there is a displacement value */
        if(sib_base == 0b101 || has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
    } else {
        if(has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
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
    
    /* We only need a SIB byte if we have a scaled index */
    bool has_sib = addr.is_index_valid();

    bool has_displacement = addr.displacement > 0;

    u8 mod;
    if(has_displacement && addr.is_base_valid()) {
        if(addr.is_displacement_8_bit()) {
            /* We can save space by using an 8 bit displacement if we can (not required) */
            mod = 1;
        } else {
            mod = 2;
        }
    } else {
        /*
         * Either we have no displacement at all, or we do but since we don't have a base,
         * the SIB byte indicates the displacement. Either way, mod must be 00 in this case.
         */
        mod = 0;
    }

    insn.set_modrm(
        mod,
        data.default_modrm_reg,
        has_sib ? 4 : ENCODE_REG(addr.base));

    /*
     * Something like [rcx*4] would actually be encoded as [rcx*4+0x0].
     * We need to account for this in case we are missing a base.
     */
    has_displacement |= (!addr.is_base_valid() && addr.is_index_valid()); // Edge case

    if(has_sib) {
        /* 101 (BP) is used to show that there is no base */
        u8 sib_base = !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base);

        insn.set_sib(addr.scale, ENCODE_REG(addr.index), sib_base);

        /* SIB.base = 101 indicates that there is a displacement value */
        if(((insn.sib & 3) == 0b101) || has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
    } else {
        if(has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
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

x86_64::InstructionData x86_64::encode_r(u8 opcode, x86_64::Reg r1) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OPERAND_ENCODING_R || d.op_en == x86_64::OPERAND_ENCODING_M || d.op_en == x86_64::OPERAND_ENCODING_O) {
            return x86_64::encode_r(d, r1);
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_i(u8 opcode, x86_64::ImmediateValue imm) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OPERAND_ENCODING_I) {
            return x86_64::encode_i(d, imm);
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_m(u8 opcode, x86_64::MemoryValue mem) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OPERAND_ENCODING_M) {
            return x86_64::encode_m(d, mem);
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_rr(u8 opcode, x86_64::Reg r1, x86_64::Reg r2) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_en == x86_64::OPERAND_ENCODING_MR || d.op_en == x86_64::OPERAND_ENCODING_RM) {
            if(IS_REG_8_BIT(r1) && IS_REG_8_BIT(r2)) {
                if(d.is_8_bit) {
                    if(d.op_en == x86_64::OPERAND_ENCODING_RM) {
                        return x86_64::encode_rr(d, r1, r2);
                    } else if(d.op_en == x86_64::OPERAND_ENCODING_MR) {
                        return x86_64::encode_rr(d, r2, r1);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.op_en == x86_64::OPERAND_ENCODING_RM) {
                        return x86_64::encode_rr(d, r1, r2);
                    } else if(d.op_en == x86_64::OPERAND_ENCODING_MR) {
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
        if(d.op_en == x86_64::OPERAND_ENCODING_OI || d.op_en == x86_64::OPERAND_ENCODING_MI) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    if(d.op_en == x86_64::OPERAND_ENCODING_OI) {
                        /* If the type is OI, we cannot have r/m because only reg can be encoded in the opcode */
                        return x86_64::encode_ri(d, r1, false, imm);
                    } else if(d.op_en == x86_64::OPERAND_ENCODING_MI) {
                        return x86_64::encode_ri(d, r1, true, imm);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.op_en == x86_64::OPERAND_ENCODING_OI) {
                        /* If the type is OI, we cannot have r/m because only reg can be encoded in the opcode */
                        return x86_64::encode_ri(d, r1, false, imm);
                    } else if(d.op_en == x86_64::OPERAND_ENCODING_MI) {
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
        if(d.op_en == x86_64::OPERAND_ENCODING_RM) {
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
        if(d.op_en == x86_64::OPERAND_ENCODING_MR) {
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
        if(d.op_en == x86_64::OPERAND_ENCODING_MI) {
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