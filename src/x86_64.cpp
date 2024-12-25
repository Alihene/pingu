#include "x86_64.hpp"

#include <unordered_map>
#include <iostream>
#include <cassert>

static x86_64::OperatingMode current_mode = x86_64::MODE_64_BIT;

static std::unordered_map<u8, x86_64::EncodingList> instructions;

void x86_64::init() {
    instructions[x86_64::ADD] = {
        {
            x86_64::ADD,
            {0x00},
            {0x80, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_IMM,
            x86_64::OPERAND_DIRECTION_RM_IMM,
            true,
            false
        },
        {
            x86_64::ADD,
            {0x00},
            {0x81, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_IMM,
            x86_64::OPERAND_DIRECTION_RM_IMM,
            false,
            false
        },
        {
            x86_64::ADD,
            {0x00},
            {0x00, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_RM_REG,
            true,
            false
        },
        {
            x86_64::ADD,
            {0x00},
            {0x01, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_RM_REG,
            false,
            false
        },
        {
            x86_64::ADD,
            {0x00}, {0x02, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_REG_RM,
            true,
            false
        },
        {
            x86_64::ADD,
            {0x00},
            {0x03, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_REG_RM,
            false,
            false
        }
    };

    instructions[x86_64::MOV] = {
        {
            x86_64::MOV,
            {0x00},
            {0x89, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_RM_REG,
            false,
            false
        },
        {
            x86_64::MOV,
            {0x00},
            {0x8B, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_REG_RM,
            false,
            false
        },
        {
            x86_64::MOV,
            {0x00},
            {0x88, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_RM_REG,
            true,
            false
        },
        {
            x86_64::MOV,
            {0x00},
            {0x8A, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_REG | x86_64::OPTYPE_REG_MEM,
            x86_64::OPERAND_DIRECTION_REG_RM,
            true,
            false
        },
        {
            x86_64::MOV,
            {0x00},
            {0xB8, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_IMM,
            x86_64::OPERAND_DIRECTION_REG_IMM,
            false,
            true
        },
        {
            x86_64::MOV,
            {0x00},
            {0xC7, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_IMM,
            x86_64::OPERAND_DIRECTION_RM_IMM,
            false,
            false,
        },
        {
            x86_64::MOV,
            {0x00},
            {0xC6, 0x00, 0x00},
            1,
            x86_64::OPTYPE_REG_IMM,
            x86_64::OPERAND_DIRECTION_RM_IMM,
            true,
            false,
        }
    };
}

x86_64::InstructionData x86_64::encode_r_rm(x86_64::EncodingData data, x86_64::Reg rm) {
    x86_64::InstructionData insn;

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(IS_REG_16_BIT(rm)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(rm)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(rm)) {
        rex |= x86_64::REX_B;
        rex_needed = true;
    }
    if(rm == x86_64::REG_SPL
        || rm == x86_64::REG_BPL
        || rm == x86_64::REG_SIL
        || rm == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    return insn;
}

x86_64::InstructionData x86_64::encode_r_reg(x86_64::EncodingData data, x86_64::Reg reg) {
    x86_64::InstructionData insn;

    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(IS_REG_16_BIT(reg)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(reg)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(reg)) {
        rex |= x86_64::REX_B;
        rex_needed = true;
    }
    if(reg == x86_64::REG_SPL
        || reg == x86_64::REG_BPL
        || reg == x86_64::REG_SIL
        || reg == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

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

x86_64::InstructionData x86_64::encode_rr(x86_64::EncodingData data, x86_64::Reg reg, x86_64::Reg rm) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(reg) || IS_REG_16_BIT(rm)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(reg) || IS_REG_64_BIT(rm)) {
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

    insn.set_modrm(3, reg % 8, rm % 8);
    return insn;
}

x86_64::InstructionData x86_64::encode_ri(x86_64::EncodingData data, x86_64::Reg r, bool is_rm, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(r)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(r)) {
        rex |= x86_64::REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(r)) {
        if(is_rm) {
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

    if(data.enc_operand_in_opcode) {
        data.enc_opcode[data.opcode_size - 1] |= ENCODE_REG(r);
    }
    insn.set_opcode(data.enc_opcode, data.opcode_size);

    if(!data.enc_operand_in_opcode) {
        insn.set_modrm(3, 0, r % 8);
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

x86_64::InstructionData x86_64::encode_rm(x86_64::EncodingData data, x86_64::Reg reg, x86_64::AddressValue addr) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(reg)) {
        insn.push_prefix(0x66);
    }

    if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
        insn.push_prefix(0x67);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(IS_REG_64_BIT(reg)) {
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
        // These need a REX prefix to access
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode(data.enc_opcode, data.opcode_size);
    
    bool has_sib = addr.is_index_valid(); // We only need an SIB byte if we have a scaled index
    bool has_displacement = addr.displacement > 0;

    insn.set_modrm(
        has_displacement && addr.is_base_valid() ? (addr.is_displacement_8_bit() ? 1 : 2) : 0, // If we have no base, set mod to 00
        ENCODE_REG(reg),
        has_sib ? 4 : ENCODE_REG(addr.base));

    has_displacement |= (!addr.is_base_valid() && addr.is_index_valid()); // Edge case

    if(has_sib) {
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base));
        if(((insn.sib & 3) == 0b101) || has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
    } else {
        if(has_displacement) {
            insn.set_displacement(addr.displacement, addr.is_displacement_8_bit() ? 1 : 4);
        }
    }

    return insn;
}

/* addr is stored in the the ModR/M.rm field */
x86_64::InstructionData x86_64::encode_mi(x86_64::EncodingData data, x86_64::AddressValue addr, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    if(imm.size == 2) {
        insn.push_prefix(0x66);
    }

    if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
        insn.push_prefix(0x67);
    }

    bool rex_needed = false;
    u8 rex = x86_64::REX_BASE;
    if(imm.size == 8) {
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
    
    bool has_sib = addr.is_index_valid(); // We only need an SIB byte if we have a scaled index
    bool has_displacement = addr.displacement > 0;

    insn.set_modrm(
        has_displacement && addr.is_base_valid() ? (addr.is_displacement_8_bit() ? 1 : 2) : 0, // If we have no base, we set mod to 00
        0,
        has_sib ? 4 : ENCODE_REG(addr.base));

    has_displacement |= (!addr.is_base_valid() && addr.is_index_valid()); // Edge case

    if(has_sib) {
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base));
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

x86_64::InstructionData x86_64::encode_i(u8 opcode, x86_64::ImmediateValue imm) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_type & x86_64::OPTYPE_IMM) {
            return x86_64::encode_i(d, imm);
        }
    }

    return x86_64::InstructionData();
}

/* 
 * r1 = src
 * r2 = dst
 */
x86_64::InstructionData x86_64::encode_rr(u8 opcode, x86_64::Reg r1, x86_64::Reg r2) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_type & x86_64::OPTYPE_REG_REG) {
            if(IS_REG_8_BIT(r1) && IS_REG_8_BIT(r2)) {
                if(d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_REG_RM) {
                        return x86_64::encode_rr(d, r1, r2);
                    } else if(d.direction == x86_64::OPERAND_DIRECTION_RM_REG) {
                        return x86_64::encode_rr(d, r2, r1);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_REG_RM) {
                        return x86_64::encode_rr(d, r1, r2);
                    } else if(d.direction == x86_64::OPERAND_DIRECTION_RM_REG) {
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
        if(d.op_type & x86_64::OPTYPE_REG_IMM) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_RM_IMM || d.direction == x86_64::OPERAND_DIRECTION_REG_IMM) {
                        return x86_64::encode_ri(d, r1, true, imm);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_RM_IMM || d.direction == x86_64::OPERAND_DIRECTION_REG_IMM) {
                        return x86_64::encode_ri(d, r1, true, imm);
                    }
                }
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_rm(u8 opcode, x86_64::Reg r1, x86_64::AddressValue addr) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_type & x86_64::OPTYPE_REG_MEM) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_REG_RM) {
                        return x86_64::encode_rm(d, r1, addr);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_REG_RM) {
                        return x86_64::encode_rm(d, r1, addr);
                    }
                }
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_mr(u8 opcode, x86_64::AddressValue addr, x86_64::Reg r1) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_type & x86_64::OPTYPE_REG_MEM) {
            if(IS_REG_8_BIT(r1)) {
                if(d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_RM_REG) {
                        return x86_64::encode_rm(d, r1, addr);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_RM_REG) {
                        return x86_64::encode_rm(d, r1, addr);
                    }
                }
            }
        }
    }

    return x86_64::InstructionData();
}

x86_64::InstructionData x86_64::encode_mi(u8 opcode, x86_64::AddressValue addr, x86_64::ImmediateValue imm) {
    for(EncodingData d : instructions[opcode]) {
        if(d.op_type & x86_64::OPTYPE_REG_IMM) {
            if(imm.size == 1) {
                if(d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_RM_IMM) {
                        return x86_64::encode_mi(d, addr, imm);
                    }
                }
            } else {
                if(!d.is_8_bit) {
                    if(d.direction == x86_64::OPERAND_DIRECTION_RM_IMM) {
                        return x86_64::encode_mi(d, addr, imm);
                    }
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